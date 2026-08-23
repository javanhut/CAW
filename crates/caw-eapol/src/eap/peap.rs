//! PEAP (type 25) with inner MSCHAPv2 — the Enterprise deployment.
//!
//! # Two EAP conversations, one inside the other
//!
//! The outer conversation carries a TLS handshake, fragmented exactly as
//! EAP-TLS fragments one. Once the tunnel stands, the *inner* conversation
//! begins: complete EAP packets, headers and all, as TLS application data. The
//! server asks for an identity again — this time the real one — and then runs
//! MSCHAPv2.
//!
//! ```text
//!   outer:  Request/PEAP(Start) ... TLS handshake ... Request/PEAP(data)
//!                                                         │
//!   inner:                        ┌──────────────────────────────────────┐
//!                                 │ Request/Identity → real username     │
//!                                 │ Request/MSCHAPv2 ↔ challenge, S=...  │
//!                                 │ Request/TLV(Result=Success)          │
//!                                 └──────────────────────────────────────┘
//!   outer:  EAP-Success, and the MSK comes from the *tunnel*, not the inner
//!           method.
//! ```
//!
//! # Why the result arrives as a TLV
//!
//! The outer EAP-Success is unprotected — anyone in range can forge one. PEAP
//! therefore carries its real verdict as a Result TLV *inside* the tunnel,
//! where it is covered by TLS. caw honours the outer Success only because
//! [`Peap::msk`](EapMethod::msk) stays `None` until the protected exchange has
//! completed, so
//! the check in [`Dot1xProvider`](crate::Dot1xProvider) does the work.
//!
//! # Not implemented: cryptobinding
//!
//! The Cryptobinding TLV ties the inner method's keys to the tunnel's, which
//! defends against an attacker relaying the inner exchange through a tunnel of
//! their own. That attack requires the client to accept a server certificate
//! it should not have, which validated PEAP already prevents; Microsoft NPS
//! does not require cryptobinding by default and neither does FreeRADIUS. It
//! is the obvious next thing to add here, not a gap that is safe to ignore
//! forever.

use zeroize::Zeroizing;

use super::mschapv2::Mschapv2;
use super::packet::{EapCode, EapPacket, eap_type};
use super::tls::{TlsConfig, Tunnel, TunnelEvent, export};
use crate::{EapMethod, Error};

/// TLV type 3, the Result TLV. Bit 15 is the mandatory flag, which this TLV
/// always carries.
const TLV_RESULT: u16 = 3;
const TLV_MANDATORY: u16 = 0x8000;
const TLV_RESULT_SUCCESS: u16 = 1;
const TLV_RESULT_FAILURE: u16 = 2;

/// PEAP with MSCHAPv2 inside.
pub struct Peap {
    tunnel: Tunnel,
    /// The identity sent *inside* the tunnel. The outer one that
    /// [`Dot1xProvider`](crate::Dot1xProvider) sends is normally `anonymous`;
    /// this is the one that identifies the user, and it never crosses the air
    /// in clear text.
    inner_identity: String,
    inner: Mschapv2,
    /// Exported when the tunnel completes, released only once the protected
    /// Result TLV says the server accepted us.
    tunnel_msk: Option<Zeroizing<[u8; export::MSK_LEN]>>,
    authenticated: bool,
}

impl Peap {
    pub fn new(
        config: &TlsConfig,
        identity: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, Error> {
        let identity = identity.into();
        Ok(Self {
            // TLS 1.2 only: PEAP has no specification over TLS 1.3, so the
            // key export nobody has agreed on would be caw's invention.
            tunnel: Tunnel::new_tls12(config)?,
            inner: Mschapv2::new(identity.clone(), password)?,
            inner_identity: identity,
            tunnel_msk: None,
            authenticated: false,
        })
    }

    /// Handle one inner EAP packet, returning the inner reply to tunnel back.
    fn phase2(&mut self, plaintext: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let packet = EapPacket::parse(plaintext)?;
        let id = packet.identifier;

        match packet.code {
            EapCode::Request => match packet.eap_type().ok_or(Error::Malformed)? {
                eap_type::IDENTITY => Ok(Some(EapPacket::response(
                    id,
                    eap_type::IDENTITY,
                    self.inner_identity.as_bytes(),
                ))),
                eap_type::MSCHAPV2 => Ok(self
                    .inner
                    .on_request(packet.type_data())?
                    .map(|td| EapPacket::response(id, eap_type::MSCHAPV2, &td))),
                eap_type::TLV => self.on_result_tlv(id, packet.type_data()),
                // Nak inside the tunnel just as outside it: a server that
                // opens phase 2 with GTC should be told what caw can do.
                _ => Ok(Some(EapPacket::nak(id, &[eap_type::MSCHAPV2]))),
            },
            // PEAPv0 replaces the inner Success with the Result TLV, so this
            // is a server that ended phase 2 early. Nothing to say; the TLV or
            // the outer Success decides.
            EapCode::Success => Ok(None),
            EapCode::Failure => Err(Error::Rejected),
            EapCode::Response => Ok(None),
        }
    }

    fn on_result_tlv(&mut self, id: u8, type_data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match find_result_tlv(type_data).ok_or(Error::Malformed)? {
            TLV_RESULT_SUCCESS => {}
            TLV_RESULT_FAILURE => return Err(Error::Rejected),
            _ => return Err(Error::Malformed),
        }
        // The server said yes inside the tunnel — but MSCHAPv2's authenticator
        // response is what proves it knows the password rather than merely
        // holding a certificate we trusted. Without that, a compromised or
        // misissued certificate would be enough to harvest the exchange.
        if !self.inner.authenticated() {
            return Err(Error::PrematureSuccess);
        }
        self.authenticated = true;
        Ok(Some(EapPacket::response(
            id,
            eap_type::TLV,
            &result_tlv(TLV_RESULT_SUCCESS),
        )))
    }
}

/// Encode a Result TLV.
fn result_tlv(result: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&(TLV_MANDATORY | TLV_RESULT).to_be_bytes());
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&result.to_be_bytes());
    out
}

/// Find the Result TLV in a run of TLVs, skipping any others the server sent.
fn find_result_tlv(mut data: &[u8]) -> Option<u16> {
    while data.len() >= 4 {
        let tlv_type = u16::from_be_bytes([data[0], data[1]]) & !TLV_MANDATORY;
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let value = data.get(4..4 + len)?;
        if tlv_type == TLV_RESULT {
            return Some(u16::from_be_bytes([*value.first()?, *value.get(1)?]));
        }
        data = &data[4 + len..];
    }
    None
}

impl EapMethod for Peap {
    fn type_code(&self) -> u8 {
        eap_type::PEAP
    }

    fn on_request(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self.tunnel.on_request(data)? {
            TunnelEvent::Reply(type_data) => Ok(Some(type_data)),
            TunnelEvent::Established { plaintext } => {
                if self.tunnel_msk.is_none() {
                    // Exported while the session is fresh. PEAPv0 reuses
                    // EAP-TLS's label; the type code separates them under
                    // TLS 1.3, which PEAP never reaches.
                    self.tunnel_msk = Some(Zeroizing::new(export::export_msk(
                        self.tunnel.connection(),
                        eap_type::PEAP,
                        export::TLS12_LABEL_EAP_TLS,
                    )?));
                }
                if plaintext.is_empty() {
                    // The handshake just finished; the server speaks first
                    // inside the tunnel.
                    return Ok(Some(self.tunnel.empty_reply()));
                }
                match self.phase2(&plaintext)? {
                    Some(inner) => Ok(Some(self.tunnel.send_tunnelled(&inner)?)),
                    None => Ok(Some(self.tunnel.empty_reply())),
                }
            }
        }
    }

    /// `None` until the protected Result TLV arrived *and* MSCHAPv2 verified
    /// the server. That is what makes the unauthenticated outer EAP-Success
    /// safe to act on: without key material,
    /// [`Dot1xProvider`](crate::Dot1xProvider) refuses it.
    fn msk(&self) -> Option<[u8; 64]> {
        if self.authenticated {
            self.tunnel_msk.as_deref().copied()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_tlv_round_trips() {
        assert_eq!(
            find_result_tlv(&result_tlv(TLV_RESULT_SUCCESS)),
            Some(TLV_RESULT_SUCCESS)
        );
        assert_eq!(
            find_result_tlv(&result_tlv(TLV_RESULT_FAILURE)),
            Some(TLV_RESULT_FAILURE)
        );
    }

    /// The mandatory bit is part of the type field, not of the type.
    #[test]
    fn the_result_tlv_is_mandatory() {
        assert_eq!(result_tlv(TLV_RESULT_SUCCESS)[0] & 0x80, 0x80);
    }

    /// Servers may send a Cryptobinding TLV alongside the Result; skipping to
    /// the one we understand must not depend on the order they arrive in.
    #[test]
    fn finds_the_result_among_other_tlvs() {
        let mut data = vec![0x80, 0x0c, 0x00, 0x03, 1, 2, 3];
        data.extend_from_slice(&result_tlv(TLV_RESULT_SUCCESS));
        assert_eq!(find_result_tlv(&data), Some(TLV_RESULT_SUCCESS));
    }

    #[test]
    fn ignores_a_tlv_run_with_no_result_in_it() {
        assert_eq!(find_result_tlv(&[0x80, 0x0c, 0x00, 0x02, 1, 2]), None);
    }

    #[test]
    fn rejects_a_tlv_longer_than_its_buffer() {
        assert_eq!(find_result_tlv(&[0x80, 0x03, 0x00, 0x40, 0, 1]), None);
    }
}
