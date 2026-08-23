//! nl80211: wireless device control.
//!
//! Enumerates PHYs, triggers and collects scans, drives association, installs
//! pairwise and group keys, and carries SAE's management frames via
//! `NL80211_CMD_EXTERNAL_AUTH` / `NL80211_CMD_FRAME`.
//!
//! Note that on mac80211 softmac drivers the kernel does *not* perform the
//! 4-way handshake; this crate associates and installs keys, but the handshake
//! itself belongs to `caw-eapol`.
//!
//! Everything that decides what bytes to send, or what received bytes mean,
//! is a pure function over slices — [`msg`] encodes, [`Bss`], [`Event`],
//! [`Wiphy`] and [`Family`] decode. [`sock`] is the only module that opens a
//! file descriptor, which is what makes the wire format testable without a
//! radio.
#![forbid(unsafe_code)]

mod attr;
mod bss;
mod consts;
mod event;
mod family;
pub mod msg;
mod sock;
mod wiphy;

#[cfg(test)]
mod tests;

pub use attr::{Attrs, GENL_HDRLEN, NLA_TYPE_MASK, Nest, genlmsghdr};
pub use bss::{Bss, mbm_to_dbm};
pub use consts::*;
pub use event::{ConnectStatus, Event};
pub use family::{Family, Groups};
pub use msg::{Connect, KeyScope};
pub use sock::{Events, NL80211_FAMILY_NAME, Nl80211, resolve_genl_family};
pub use wiphy::{ExtFeatures, IfType, Interface, Wiphy};

#[derive(Debug)]
pub enum Error {
    Netlink(caw_netlink::Error),
    /// The kernel registered no such generic-netlink family. For `nl80211`
    /// that means cfg80211 is not loaded, so there is no wireless stack to
    /// talk to at all — worth distinguishing from a command that failed.
    NoFamily(String),
    /// A multicast group whose id has no bit in `bind`'s 32-bit mask, which
    /// reaches ids 1 through 32. See [`Groups::mask`] for why that mask is
    /// what caw has to work with.
    GroupOutOfRange {
        name: &'static str,
        id: u32,
    },
}

impl From<caw_netlink::Error> for Error {
    fn from(e: caw_netlink::Error) -> Self {
        Error::Netlink(e)
    }
}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Error::Netlink(caw_netlink::Error::Io(e))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Netlink(e) => write!(f, "{e}"),
            Error::NoFamily(name) if name == NL80211_FAMILY_NAME => {
                write!(f, "no wireless stack: the kernel has no nl80211 family")
            }
            Error::NoFamily(name) => write!(f, "no generic netlink family {name:?}"),
            Error::GroupOutOfRange { name, id } => write!(
                f,
                "nl80211 multicast group {name} has id {id}, outside the 1..=32 a netlink bind mask can reach"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Netlink(e) => Some(e),
            _ => None,
        }
    }
}
