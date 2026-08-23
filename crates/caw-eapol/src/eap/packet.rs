//! EAP packet framing, RFC 3748 §4.
//!
//! EAPOL packet type 0 carries exactly one of these. The layout is trivial —
//! four header octets and a payload — but two details of it are load-bearing
//! and neither is obvious from the diagram:
//!
//!   * The Length field counts the header it sits in, so the payload is
//!     `Length - 4`. Reading it as a payload length yields a parser that
//!     drifts four bytes on every packet and only fails once a method starts
//!     caring about its own trailing octets.
//!   * Octets beyond Length are link-layer padding and MUST be ignored, not
//!     rejected. An AP that pads an EAPOL frame to the Ethernet minimum is
//!     doing nothing wrong, and a station that refuses those frames simply
//!     never authenticates on that AP.

use crate::Error;

/// Code, Identifier, Length. The Type octet is *not* here: Success and Failure
/// have none, so it belongs to the payload rather than the header.
pub const EAP_HDR_LEN: usize = 4;

/// EAP method type codes, RFC 3748 §6.2 and the IANA registry.
pub mod eap_type {
    /// The one type every peer must implement.
    pub const IDENTITY: u8 = 1;
    /// A displayable message. Answered with an empty response, never ignored:
    /// a silent peer looks dead to the authenticator.
    pub const NOTIFICATION: u8 = 2;
    /// Response-only. "Not that method — one of these instead."
    pub const NAK: u8 = 3;
    /// EAP-TLS, RFC 5216.
    pub const TLS: u8 = 13;
    /// EAP-TTLS, RFC 5281.
    pub const TTLS: u8 = 21;
    /// PEAP, draft-josefsson-pppext-eap-tls-eap.
    pub const PEAP: u8 = 25;
    /// EAP-MSCHAPv2, draft-kamath-pppext-eap-mschapv2. PEAP's inner method.
    pub const MSCHAPV2: u8 = 26;
    /// Extensions (TLV), which is how PEAPv0 signals its result inside the
    /// tunnel instead of trusting the unprotected outer EAP-Success.
    pub const TLV: u8 = 33;
}

/// RFC 3748 §4 Code field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

impl EapCode {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Success),
            4 => Ok(Self::Failure),
            other => Err(Error::UnsupportedEapCode(other)),
        }
    }
}

/// One EAP packet, borrowing its payload from the buffer it was parsed from.
#[derive(Clone, Copy)]
pub struct EapPacket<'a> {
    pub code: EapCode,
    /// Echoed by the response. This is the whole of EAP's retransmission
    /// protocol: there is no sequence number and no window.
    pub identifier: u8,
    /// Everything after the header, trimmed to the declared Length. For a
    /// Request or Response that is the Type octet followed by its Type-Data;
    /// for Success and Failure it is empty.
    pub data: &'a [u8],
}

impl<'a> EapPacket<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        let [code, identifier, hi, lo, rest @ ..] = buf else {
            return Err(Error::Malformed);
        };
        let declared = u16::from_be_bytes([*hi, *lo]) as usize;
        // A Length below the header size is not a truncated packet, it is a
        // nonsensical one; `checked_sub` is what keeps it from wrapping into a
        // huge payload length.
        let payload_len = declared.checked_sub(EAP_HDR_LEN).ok_or(Error::Malformed)?;
        let data = rest.get(..payload_len).ok_or(Error::Malformed)?;
        Ok(Self {
            code: EapCode::from_u8(*code)?,
            identifier: *identifier,
            data,
        })
    }

    /// The method type, for the two codes that carry one.
    pub fn eap_type(&self) -> Option<u8> {
        match self.code {
            EapCode::Request | EapCode::Response => self.data.first().copied(),
            EapCode::Success | EapCode::Failure => None,
        }
    }

    /// The payload after the Type octet — what an [`EapMethod`](crate::EapMethod)
    /// is handed.
    pub fn type_data(&self) -> &'a [u8] {
        self.data.get(1..).unwrap_or(&[])
    }

    /// Build a packet. `payload` is the Type octet and its data, or empty.
    pub fn encode(code: EapCode, identifier: u8, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(EAP_HDR_LEN + payload.len())
            .expect("an EAP packet is at most 64 KiB by construction");
        let mut buf = Vec::with_capacity(len as usize);
        buf.push(code as u8);
        buf.push(identifier);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// A Response of one method type. The identifier must be the request's:
    /// an authenticator matches replies by nothing else.
    pub fn response(identifier: u8, eap_type: u8, type_data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + type_data.len());
        payload.push(eap_type);
        payload.extend_from_slice(type_data);
        Self::encode(EapCode::Response, identifier, &payload)
    }

    /// A legacy Nak: "I cannot do the method you asked for, offer me one of
    /// these instead."
    ///
    /// Without it an authenticator that opens with, say, EAP-MD5 gets silence
    /// and the exchange stalls until it times out. Nak is what turns "caw does
    /// not implement that" into a renegotiation rather than a hang.
    pub fn nak(identifier: u8, desired: &[u8]) -> Vec<u8> {
        // RFC 3748 §5.3.1: at least one octet, and 0 means "no acceptable
        // method" — a legitimate answer, so an empty list is encoded that way
        // rather than as a zero-length Nak, which is malformed.
        if desired.is_empty() {
            Self::response(identifier, eap_type::NAK, &[0])
        } else {
            Self::response(identifier, eap_type::NAK, desired)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let wire = EapPacket::encode(EapCode::Request, 0x42, &[eap_type::IDENTITY, b'h', b'i']);
        assert_eq!(wire, vec![1, 0x42, 0, 7, 1, b'h', b'i']);

        let p = EapPacket::parse(&wire).unwrap();
        assert_eq!(p.code, EapCode::Request);
        assert_eq!(p.identifier, 0x42);
        assert_eq!(p.eap_type(), Some(eap_type::IDENTITY));
        assert_eq!(p.type_data(), b"hi");
    }

    #[test]
    fn success_has_no_type() {
        let wire = EapPacket::encode(EapCode::Success, 9, &[]);
        assert_eq!(wire, vec![3, 9, 0, 4]);
        let p = EapPacket::parse(&wire).unwrap();
        assert_eq!(p.code, EapCode::Success);
        assert_eq!(p.eap_type(), None);
        assert!(p.data.is_empty());
    }

    /// An AP padding an EAPOL frame to the Ethernet minimum must not make the
    /// packet unparseable, and the padding must not reach the method.
    #[test]
    fn padding_past_the_declared_length_is_ignored() {
        let mut wire = EapPacket::encode(EapCode::Request, 1, &[eap_type::IDENTITY]);
        wire.extend_from_slice(&[0u8; 40]);
        let p = EapPacket::parse(&wire).unwrap();
        assert_eq!(p.data, &[eap_type::IDENTITY]);
        assert!(p.type_data().is_empty());
    }

    #[test]
    fn rejects_a_length_that_does_not_cover_the_header() {
        // Length 3: smaller than the header it is defined to include.
        assert!(matches!(
            EapPacket::parse(&[1, 1, 0, 3]),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn rejects_a_length_longer_than_the_buffer() {
        assert!(matches!(
            EapPacket::parse(&[1, 1, 0, 32, 1]),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn rejects_a_truncated_header() {
        assert!(matches!(
            EapPacket::parse(&[1, 1, 0]),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn rejects_an_unknown_code() {
        assert!(matches!(
            EapPacket::parse(&[9, 1, 0, 4]),
            Err(Error::UnsupportedEapCode(9))
        ));
    }

    #[test]
    fn nak_names_the_method_we_can_do() {
        let wire = EapPacket::nak(7, &[eap_type::PEAP]);
        let p = EapPacket::parse(&wire).unwrap();
        assert_eq!(p.code, EapCode::Response);
        assert_eq!(p.identifier, 7);
        assert_eq!(p.eap_type(), Some(eap_type::NAK));
        assert_eq!(p.type_data(), &[eap_type::PEAP]);
    }

    /// A zero-length Nak is malformed, so "nothing acceptable" is spelled with
    /// the reserved type 0 instead.
    #[test]
    fn nak_with_nothing_to_offer_says_type_zero() {
        let wire = EapPacket::nak(7, &[]);
        assert_eq!(EapPacket::parse(&wire).unwrap().type_data(), &[0]);
    }
}
