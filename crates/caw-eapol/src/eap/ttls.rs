//! EAP-TTLS (type 21, RFC 5281) with inner PAP.
//!
//! # What TTLS carries instead of EAP
//!
//! PEAP tunnels EAP packets. TTLS tunnels *RADIUS attributes*, encoded as
//! Diameter AVPs, which is why it can run legacy methods that were never
//! given an EAP type — PAP among them. Two AVPs are the entire inner
//! exchange:
//!
//! ```text
//!   User-Name     (AVP 1)   the real username
//!   User-Password (AVP 2)   the password, in clear text, zero-padded to 16
//! ```
//!
//! In clear text. Inside the tunnel, so on the wire it is TLS application
//! data — but the RADIUS server receives the password itself rather than a
//! verifier, which is exactly why TTLS-PAP is the method operators pick when
//! their back end is LDAP or a Unix password database.
//!
//! It also means [`TlsConfig::danger_accept_any_server_certificate`](super::tls::TlsConfig::danger_accept_any_server_certificate)
//! is worse here than anywhere else in caw: with TTLS-PAP, an unvalidated
//! tunnel hands the plaintext password to whoever answered the association.
//! PEAP at least makes an attacker grind MSCHAPv2 afterwards.
//!
//! # Why PAP and not MSCHAPv2
//!
//! TTLS can carry either, and this implements the one that covers the
//! deployments: a site that has MSCHAPv2 back ends runs PEAP, and a site that
//! runs TTLS is usually running it precisely because its back end only has
//! the plaintext password to compare against.

use zeroize::Zeroizing;

use super::packet::eap_type;
use super::tls::{TlsConfig, Tunnel, TunnelEvent, export};
use crate::{EapMethod, Error};

/// RADIUS attribute numbers, which double as AVP codes in the IETF vendor
/// space (RFC 5281 §10.1).
const AVP_USER_NAME: u32 = 1;
const AVP_USER_PASSWORD: u32 = 2;

/// The AVP is mandatory: a server that does not understand it must reject the
/// exchange rather than ignore the attribute and authenticate somebody.
const AVP_FLAG_MANDATORY: u8 = 0x40;

/// AVP Code, Flags, and a 24-bit Length.
const AVP_HDR_LEN: usize = 8;

/// EAP-TTLS with inner PAP.
pub struct Ttls {
    tunnel: Tunnel,
    /// The identity sent inside the tunnel, distinct from the anonymous outer
    /// one [`Dot1xProvider`](crate::Dot1xProvider) sends.
    username: String,
    password: Zeroizing<String>,
    credentials_sent: bool,
    msk: Option<Zeroizing<[u8; export::MSK_LEN]>>,
}

impl Ttls {
    pub fn new(
        config: &TlsConfig,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            // TLS 1.2 only, for the same reason as PEAP: RFC 5281 predates
            // TLS 1.3 and nothing specifies the key export over it.
            tunnel: Tunnel::new_tls12(config)?,
            username: username.into(),
            password: Zeroizing::new(password.into()),
            credentials_sent: false,
            msk: None,
        })
    }

    fn credentials(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        encode_avp(&mut out, AVP_USER_NAME, self.username.as_bytes());

        // RFC 5281 §11.2.3: the password is padded with zeros to a multiple of
        // 16 octets so its length does not leak through the TLS record size,
        // and the AVP Length covers the padding.
        let mut padded = Zeroizing::new(self.password.as_bytes().to_vec());
        let remainder = padded.len() % 16;
        if remainder != 0 {
            let width = padded.len() + (16 - remainder);
            padded.resize(width, 0);
        }
        encode_avp(&mut out, AVP_USER_PASSWORD, &padded);
        out
    }
}

/// Append one AVP, padding the whole thing out to a 4-octet boundary.
///
/// The Length field counts the header and the data but *not* that trailing
/// padding, which is the detail every AVP encoder gets wrong once.
fn encode_avp(out: &mut Vec<u8>, code: u32, data: &[u8]) {
    let len = AVP_HDR_LEN + data.len();
    out.extend_from_slice(&code.to_be_bytes());
    out.push(AVP_FLAG_MANDATORY);
    out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    out.extend_from_slice(data);
    out.resize(out.len() + (4 - len % 4) % 4, 0);
}

impl EapMethod for Ttls {
    fn type_code(&self) -> u8 {
        eap_type::TTLS
    }

    fn on_request(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self.tunnel.on_request(data)? {
            TunnelEvent::Reply(type_data) => Ok(Some(type_data)),
            TunnelEvent::Established { .. } => {
                if self.credentials_sent {
                    // PAP has no inner reply: the server answers with the
                    // outer EAP-Success or EAP-Failure. Anything arriving here
                    // is a server we have nothing to say to.
                    return Ok(Some(self.tunnel.empty_reply()));
                }
                self.msk = Some(Zeroizing::new(export::export_msk(
                    self.tunnel.connection(),
                    eap_type::TTLS,
                    export::TLS12_LABEL_TTLS,
                )?));
                self.credentials_sent = true;
                let avps = self.credentials();
                Ok(Some(self.tunnel.send_tunnelled(&avps)?))
            }
        }
    }

    /// Available once the credentials have gone into a tunnel whose server
    /// certificate validated. PAP gives the client nothing further to check —
    /// the proof that the AP really is on this network is the 4-way handshake,
    /// which only succeeds if the RADIUS server handed it this same MSK.
    fn msk(&self) -> Option<[u8; 64]> {
        self.msk.as_deref().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn avp(code: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_avp(&mut out, code, data);
        out
    }

    #[test]
    fn an_avp_carries_its_code_flags_and_length() {
        let wire = avp(AVP_USER_NAME, b"user@example.net");
        assert_eq!(&wire[..4], 1u32.to_be_bytes());
        assert_eq!(wire[4], AVP_FLAG_MANDATORY);
        assert_eq!(&wire[5..8], &[0, 0, 24]);
        assert_eq!(&wire[8..], b"user@example.net");
    }

    /// The Length field excludes the alignment padding; the buffer includes
    /// it. Conflating the two shifts every AVP after the first.
    #[test]
    fn padding_aligns_the_next_avp_without_being_counted() {
        let wire = avp(AVP_USER_NAME, b"abc");
        assert_eq!(&wire[5..8], &[0, 0, 11], "length counts header + data only");
        assert_eq!(wire.len(), 12, "but the AVP occupies a multiple of four");
        assert_eq!(&wire[11..], &[0]);
    }

    #[test]
    fn a_password_is_padded_to_a_multiple_of_sixteen() {
        let ttls_password = |p: &str| {
            let mut padded = p.as_bytes().to_vec();
            let remainder = padded.len() % 16;
            if remainder != 0 {
                padded.resize(padded.len() + (16 - remainder), 0);
            }
            let wire = avp(AVP_USER_PASSWORD, &padded);
            u32::from_be_bytes([0, wire[5], wire[6], wire[7]]) as usize - AVP_HDR_LEN
        };
        assert_eq!(ttls_password("short"), 16);
        assert_eq!(ttls_password("exactly16chars!!"), 16);
        assert_eq!(ttls_password("seventeen chars!!"), 32);
    }

    /// An empty password must still produce an AVP, or the server sees a
    /// missing attribute rather than a wrong password.
    #[test]
    fn an_empty_password_still_gets_an_avp() {
        let wire = avp(AVP_USER_PASSWORD, &[]);
        assert_eq!(wire.len(), AVP_HDR_LEN);
        assert_eq!(&wire[5..8], &[0, 0, 8]);
    }
}
