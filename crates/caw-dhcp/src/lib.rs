//! Address configuration: DHCPv4, and IPv6 router discovery with SLAAC.
//!
//! Sans-IO like the authentication machines: the protocol state lives here,
//! the sockets and timers live in `cawd`. [`Dhcp4`] consumes datagrams and
//! timer expiries and returns [`Action`]s; it opens nothing and reads no
//! clock, so an entire lease lifetime is exercisable in a unit test.
//!
//! The exceptions are deliberate and both are one function deep:
//! [`Dhcp4Socket`], the UDP shell the daemon sends through, and [`new_xid`],
//! which reads the kernel's entropy pool.
//!
//! Applying the result — addresses, routes, resolver config — is `caw-rtnl`'s
//! and `caw-core`'s job, not this crate's.
#![forbid(unsafe_code)]

mod client;
mod ipv6;
mod message;
mod options;
// The socket needs `AF_INET` and `SO_BROADCAST`; the protocol above it needs
// neither, and stays compilable on any host so its tests can run there.
#[cfg(target_os = "linux")]
mod socket;

use std::net::Ipv4Addr;

pub use client::{Action, Dhcp4, Input, Lease, Reason, State, Timer};
pub use ipv6::{PrefixInfo, ROUTER_ADVERTISEMENT, RouterAdvert, eui64_interface_id, slaac_address};
pub use message::{BOOTREPLY, BOOTREQUEST, FLAG_BROADCAST, MAGIC_COOKIE, Message};
// The option codes are part of the surface because [`Message::get`] takes one.
pub use options::{
    DhcpOption, MessageType, OPT_CLIENT_ID, OPT_DNS, OPT_HOSTNAME, OPT_LEASE_TIME,
    OPT_MESSAGE_TYPE, OPT_PARAM_REQUEST, OPT_REQUESTED_IP, OPT_ROUTER, OPT_SERVER_ID,
    OPT_SUBNET_MASK, OPT_T1, OPT_T2,
};
#[cfg(target_os = "linux")]
pub use socket::{CLIENT_PORT, Dhcp4Socket, SERVER_PORT};

/// A transaction id for a new exchange.
///
/// From `getrandom`, never from a counter or a clock-seeded generator: the
/// transaction id is the only thing tying a reply to this client's request, so
/// anything predictable lets an attacker who cannot see the request forge a
/// reply to it.
#[cfg(target_os = "linux")]
pub fn new_xid() -> Result<u32, Error> {
    let mut bytes = [0u8; 4];
    let mut filled = 0;
    // `getrandom` may return short, and a partially filled transaction id
    // would be partly zero.
    while filled < bytes.len() {
        filled +=
            rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty())?;
    }
    Ok(u32::from_ne_bytes(bytes))
}

/// Convert a subnet mask to a prefix length.
///
/// The kernel configures an address with a prefix length while DHCP sends a
/// mask, so this sits between them. A mask with holes in it — `255.0.255.0` —
/// has no prefix length at all; returning `None` rather than a plausible
/// number keeps a broken server from quietly putting the interface on the
/// wrong subnet.
pub fn prefix_len_from_mask(mask: Ipv4Addr) -> Option<u8> {
    let bits = mask.to_bits();
    let len = bits.leading_ones();
    (bits.count_ones() == len).then_some(len as u8)
}

/// The mask a prefix length describes. `None` above 32.
pub fn mask_from_prefix_len(prefix_len: u8) -> Option<Ipv4Addr> {
    match prefix_len {
        0 => Some(Ipv4Addr::UNSPECIFIED),
        1..=32 => Some(Ipv4Addr::from_bits(u32::MAX << (32 - prefix_len))),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// The bytes are not a well-formed DHCP message or Router Advertisement.
    Malformed,
    /// The message parsed, but left out an option the configuration needs.
    /// Holds the option code.
    Incomplete(u8),
    /// The server refused the request.
    Nak,
    Io(rustix::io::Errno),
    ShortSend,
}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed => write!(f, "malformed message"),
            Error::Incomplete(code) => write!(f, "server did not send option {code}"),
            Error::Nak => write!(f, "server refused the request"),
            Error::Io(e) => write!(f, "dhcp io: {e}"),
            Error::ShortSend => write!(f, "short dhcp send"),
        }
    }
}

impl std::error::Error for Error {}

/// A DHCPACK datagram, as a home router emits it: BOOTP fixed part, magic
/// cookie, then message type, server id, lease and both timers, mask, router,
/// two resolvers and an assigned hostname, padded to the 300-byte minimum.
/// Shared by the wire tests and the state-machine tests.
#[cfg(test)]
pub(crate) const ACK_CAPTURE: [u8; 300] = [
    0x02, 0x01, 0x06, 0x00, 0x39, 0x03, 0xf3, 0x26, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18, 0xc0, 0xa8, 0x01, 0x01, //
    0x00, 0x00, 0x00, 0x00, 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63, //
    0x35, 0x01, 0x05, 0x36, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x33, 0x04, 0x00, //
    0x00, 0xa8, 0xc0, 0x3a, 0x04, 0x00, 0x00, 0x54, 0x60, 0x3b, 0x04, 0x00, //
    0x00, 0x93, 0xa8, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0xc0, //
    0xa8, 0x01, 0x01, 0x06, 0x08, 0xc0, 0xa8, 0x01, 0x01, 0x08, 0x08, 0x08, //
    0x08, 0x0c, 0x05, 0x72, 0x61, 0x76, 0x65, 0x6e, 0xff, 0x00, 0x00, 0x00, //
];

/// The MAC in [`ACK_CAPTURE`]'s `chaddr`.
#[cfg(test)]
pub(crate) const CAPTURE_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];

/// The transaction id in [`ACK_CAPTURE`].
#[cfg(test)]
pub(crate) const CAPTURE_XID: u32 = 0x3903_f326;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_to_prefix_len() {
        assert_eq!(
            prefix_len_from_mask(Ipv4Addr::new(255, 255, 255, 0)),
            Some(24)
        );
        assert_eq!(
            prefix_len_from_mask(Ipv4Addr::new(255, 255, 240, 0)),
            Some(20)
        );
        assert_eq!(prefix_len_from_mask(Ipv4Addr::UNSPECIFIED), Some(0));
        assert_eq!(prefix_len_from_mask(Ipv4Addr::BROADCAST), Some(32));
        // Holes in the mask mean it does not describe a prefix at all.
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 0, 255, 0)), None);
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 0, 1)), None);
    }

    #[test]
    fn prefix_len_and_mask_agree() {
        for len in 0..=32u8 {
            let mask = mask_from_prefix_len(len).unwrap();
            assert_eq!(prefix_len_from_mask(mask), Some(len));
        }
        assert_eq!(mask_from_prefix_len(33), None);
    }
}
