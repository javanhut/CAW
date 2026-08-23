//! EAP and 802.1X: how an Enterprise network produces a PMK.
//!
//! # The shape of the thing
//!
//! WPA2/3-Enterprise replaces the shared passphrase with a conversation
//! between the station and a RADIUS server that the access point only relays.
//! That conversation is EAP, it rides EAPOL packet type 0, and it ends with
//! both ends holding a Master Session Key that the AP has been told over
//! RADIUS. `PMK = MSK[0..32]`, and from there the 4-way handshake in
//! [`crate`] is byte-for-byte the same as it is for a home network.
//!
//! ```text
//!   station                    AP                RADIUS server
//!      │   EAP-Request/Identity │◄──────────────────┤
//!      │◄───────────────────────┤                   │
//!      ├───────────────────────►│──────────────────►│  anonymous identity
//!      │      ... method ...    │      relayed      │
//!      │◄──────────────────────►│◄─────────────────►│  TLS, and what it wraps
//!      │      EAP-Success       │◄──────────────────┤  + MSK, over RADIUS
//!      │◄───────────────────────┤                   │
//!      │      4-way handshake   │                   │
//!      │◄──────────────────────►│                   │  PMK = MSK[0..32]
//! ```
//!
//! # Layering
//!
//! [`Dot1xProvider`] owns the outer conversation — identity, Nak, duplicate
//! requests, and the rule that an unauthenticated EAP-Success proves nothing.
//! One [`EapMethod`](crate::EapMethod) owns the rest. [`packet`] and [`frag`]
//! are the two pieces of framing they share, and neither knows what TLS is:
//! they are compiled and tested in the default build, because a declared
//! fragment length is an allocation request from a peer that has not
//! authenticated yet, and that bounds check should not be feature-gated.
//!
//! # `enterprise`
//!
//! The actual methods — EAP-TLS, PEAP and TTLS — need a TLS stack, and every
//! `rustls` crypto provider available today is either C or an alpha. They sit
//! behind the `enterprise` cargo feature, which is off by default; see
//! the `eap::tls::provider` module for the decision that gate is holding open.

pub mod dot1x;
pub mod frag;
pub mod packet;

pub use dot1x::{Dot1xProvider, pmk_from_msk};
pub use frag::{Exchange, Fragment, Fragmenter, Incoming, Reassembler};
pub use packet::{EAP_HDR_LEN, EapCode, EapPacket, eap_type};

#[cfg(feature = "enterprise")]
pub mod mschapv2;
#[cfg(feature = "enterprise")]
pub mod peap;
#[cfg(feature = "enterprise")]
pub mod tls;
#[cfg(feature = "enterprise")]
pub mod ttls;

#[cfg(feature = "enterprise")]
pub use peap::Peap;
#[cfg(feature = "enterprise")]
pub use tls::{EapTls, TlsConfig};
#[cfg(feature = "enterprise")]
pub use ttls::Ttls;

/// Collapse this crate's errors into the vocabulary [`caw_crypto::PmkProvider`]
/// speaks.
///
/// `caw-crypto` sits below this crate, so its error type cannot name EAP
/// failures. The mapping keeps the distinction that matters to a caller — did
/// the peer reject us, or did we get bytes we could not parse — and drops the
/// rest into the log message the `Display` impl already carries.
impl From<crate::Error> for caw_crypto::Error {
    fn from(e: crate::Error) -> Self {
        use crate::Error as E;
        match e {
            E::Crypto(inner) => inner,
            // The peer said no, or said yes in a way we must not believe.
            E::Rejected | E::PrematureSuccess | E::Timeout => Self::AuthFailed,
            // Bytes that do not decode, whatever layer noticed.
            E::Malformed
            | E::FragmentOutOfOrder
            | E::FragmentTooLarge
            | E::UnsupportedPacketType(_)
            | E::UnsupportedEapCode(_)
            | E::UnsupportedDescriptor(_) => Self::Malformed,
            #[cfg(feature = "enterprise")]
            E::Tls(_) | E::NoCryptoProvider | E::CertificateStore(_) => Self::AuthFailed,
            _ => Self::Protocol,
        }
    }
}
