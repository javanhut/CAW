//! Connection policy and the connection state machine.
//!
//! This is the brain: it decides which BSS to join, assembles the right
//! [`PmkProvider`](caw_crypto::PmkProvider) for a network's security,
//! sequences authentication -> association -> key install -> address
//! configuration, and handles rekey, roaming and reconnect.
//!
//! Sans-IO, like the layers below it. [`Connection::poll`] consumes an
//! [`Input`] and returns [`Action`]s for `cawd` to carry out. The daemon owns
//! every socket and timer; this crate owns every decision. A full connection,
//! including a 4-way handshake, can therefore be driven in a unit test — which
//! is how every test in this crate works.
//!
//! # What is not sans-IO
//!
//! [`profile`] reads and writes files, because saved networks have to live
//! somewhere and the format is a decision of this crate's. It is called
//! *around* [`Connection::poll`], never from inside it: the daemon loads
//! profiles at startup and writes one back when an [`Action::SaveProfile`]
//! asks it to.
//!
//! Three things inside `poll` are not pure either, and each is deliberate.
//! [`caw_eapol::FourWay::new`] and [`caw_crypto::SaeProvider::new`] draw a
//! nonce from `getrandom`: a state machine that took its randomness as a
//! parameter would push the one value that must never be predictable out to
//! the caller, and both crates expose a `with_seed` constructor for tests
//! instead. And with the `enterprise` feature on, assembling an 802.1X
//! provider reads the trust anchor the profile names — see `auth::assemble` for why
//! that path is a file and not bytes in the profile.
#![forbid(unsafe_code)]

mod auth;
mod conn;
pub mod policy;
pub mod profile;
mod rsn;

#[cfg(test)]
mod tests;

pub use auth::{DeviceCaps, Offload};
pub use conn::{
    ASSOC_TIMEOUT_MS, AUTH_TIMEOUT_MS, Action, AssocRequest, BACKOFF_BASE_MS, BACKOFF_MAX_MS,
    Command, Connection, Device, Failure, GroupKey, Input, KeyInstall, LeaseEvent, PairwiseKey,
    SCAN_TIMEOUT_MS, State, TimerId,
};
pub use profile::{Credential, EnterpriseMethod, Profile, Secret};
pub use rsn::StationRsn;

/// Failures of the one thing in this crate that touches the filesystem.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// A profile file that is not the JSON this crate writes, or that names a
    /// security level it does not know.
    Malformed(serde_json::Error),
    /// An SSID of zero length names no network, so it cannot key a profile.
    EmptySsid,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Error::Io(std::io::Error::from_raw_os_error(e.raw_os_error()))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Malformed(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "profile store: {e}"),
            Error::Malformed(e) => write!(f, "unreadable profile: {e}"),
            Error::EmptySsid => write!(f, "a profile needs a non-empty SSID"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Malformed(e) => Some(e),
            Error::EmptySsid => None,
        }
    }
}
