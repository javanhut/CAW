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

/// WPA2-Personal: PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256).
pub struct PskProvider {
    _passphrase: String,
}

/// WPA3-Personal: Dragonfly over NIST P-256, commit/confirm.
pub struct SaeProvider {
    _passphrase: String,
}

/// Derives the PTK from a PMK and the two nonces. The KDF and MIC algorithm
/// both depend on the negotiated AKM, which is why it is threaded through.
pub fn derive_ptk(
    _pmk: &Pmk,
    _akm: caw_80211::Akm,
    _aa: [u8; 6],
    _spa: [u8; 6],
    _anonce: &[u8; 32],
    _snonce: &[u8; 32],
) -> Result<Ptk, Error> {
    todo!("PRF-384/512, or SHA-256/384 KDF for the newer AKMs")
}

#[derive(Debug)]
pub enum Error {
    /// The peer's MIC did not verify — wrong passphrase, or a downgrade attempt.
    MicMismatch,
    Malformed,
    UnsupportedAkm,
    /// SAE rejected the exchange.
    AuthFailed,
}
