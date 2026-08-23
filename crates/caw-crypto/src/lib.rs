//! WPA key derivation, and the authentication methods that produce a PMK.
//!
//! # Why the trait lives here
//!
//! Every WPA flavour ends in the same place: a 256-bit Pairwise Master Key fed
//! to the 4-way handshake. What differs is only how that PMK is obtained, and
//! critically *when* and *over which transport*:
//!
//! | Method   | Stage      | Transport                        |
//! |----------|------------|----------------------------------|
//! | PSK      | local      | none — derived from the passphrase |
//! | SAE      | pre-assoc  | 802.11 authentication frames     |
//! | OWE      | assoc      | Diffie-Hellman in assoc IEs      |
//! | 802.1X   | post-assoc | EAPOL-EAP, after association     |
//!
//! A trait that assumed one transport would break on the others, so
//! [`PmkProvider`] reports its [`AuthStage`] and exchanges opaque frames. The
//! caller owns the sockets and decides where a frame goes.
//!
//! # Sans-IO
//!
//! Nothing here touches a socket or a clock. Providers consume bytes and
//! return [`Step`]s. That keeps every state machine unit-testable against
//! published RFC vectors on any host — no kernel, no radio, no container.
#![forbid(unsafe_code)]

use zeroize::{Zeroize, ZeroizeOnDrop};

mod kdf;
mod keywrap;
mod mic;
mod psk;
mod sae;

pub use kdf::{derive_ptk, kdf_sha256, prf_sha1};
pub use keywrap::unwrap_key_data;
pub use mic::{KeyDescriptorVersion, MIC_LEN, compute_mic, verify_mic};
pub use psk::{PskProvider, derive_pmk};
pub use sae::{SEED_LEN, SaeProvider};

/// Pairwise Master Key: the output of authentication, input to the 4-way.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pmk(pub [u8; 32]);

/// Pairwise Transient Key, derived per-association from the PMK.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ptk {
    /// EAPOL-Key Confirmation Key — computes the handshake MIC.
    pub kck: [u8; 16],
    /// EAPOL-Key Encryption Key — unwraps the GTK.
    pub kek: [u8; 16],
    /// Temporal Key — installed into the driver for CCMP.
    pub tk: [u8; 16],
}

/// When a provider runs, relative to association.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthStage {
    /// Computed locally; no exchange (PSK).
    Local,
    /// Runs before association, over 802.11 auth frames (SAE).
    PreAssoc,
    /// Runs after association, over EAPOL (802.1X).
    PostAssoc,
}

/// What the caller should do next.
pub enum Step {
    /// Transmit these bytes on the transport implied by [`AuthStage`].
    Send(Vec<u8>),
    /// Await more input or the timeout.
    Wait,
    /// Authentication succeeded.
    Done(Pmk),
}

/// Everything a provider needs about the peer.
pub struct AuthContext<'a> {
    pub ssid: &'a [u8],
    pub bssid: [u8; 6],
    pub own_mac: [u8; 6],
    pub akm: caw_80211::Akm,
}

/// Produces a PMK. Implemented by PSK and SAE here, by 802.1X in `caw-eapol`.
pub trait PmkProvider {
    fn stage(&self) -> AuthStage;

    /// Begin. `Local` providers return [`Step::Done`] immediately.
    fn start(&mut self, ctx: &AuthContext<'_>) -> Result<Step, Error>;

    /// Feed a received frame, stripped of its transport header.
    fn on_frame(&mut self, ctx: &AuthContext<'_>, frame: &[u8]) -> Result<Step, Error>;

    /// The retransmit timer fired.
    fn on_timeout(&mut self, ctx: &AuthContext<'_>) -> Result<Step, Error>;
}

#[derive(Debug)]
pub enum Error {
    /// The peer's MIC did not verify — wrong passphrase, or a downgrade attempt.
    MicMismatch,
    Malformed,
    UnsupportedAkm,
    /// SAE rejected the exchange.
    AuthFailed,
    /// The EAPOL-Key descriptor version asks for a MIC algorithm caw does not
    /// implement. Version 1 is the TKIP pairing, and caw joins CCMP networks
    /// only.
    UnsupportedVersion,
    /// AES key unwrap failed its integrity check: the KEK is wrong, or the
    /// wrapped key data was tampered with in flight.
    KeyUnwrapFailed,
    /// A provider was driven in a way its stage never produces — a frame
    /// delivered to a `Local` provider, say. A caller bug, not a peer's.
    Protocol,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::MicMismatch => write!(f, "EAPOL-Key MIC mismatch (wrong passphrase?)"),
            Error::Malformed => write!(f, "malformed input"),
            Error::UnsupportedAkm => write!(f, "unsupported AKM suite"),
            Error::AuthFailed => write!(f, "authentication rejected"),
            Error::UnsupportedVersion => write!(f, "unsupported EAPOL-Key descriptor version"),
            Error::KeyUnwrapFailed => write!(f, "key unwrap integrity check failed"),
            Error::Protocol => write!(f, "authentication driven out of order"),
        }
    }
}

impl std::error::Error for Error {}

/// Decode a test vector. Vectors are quoted from their RFC or standard as hex
/// so they stay diff-able against the published text.
#[cfg(test)]
pub(crate) fn hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex vector has an odd number of digits"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex vector has a non-hex digit"))
        .collect()
}
