//! rtnetlink notifications: interfaces appearing, going away, losing carrier.
//!
//! A second rtnetlink socket, subscribed to the multicast groups and never
//! used for requests. Mixing the two on one socket would mean telling an
//! unsolicited notification apart from the reply to a dump in flight, which
//! is exactly the distinction `caw-nl80211` keeps two sockets to avoid.
//!
//! Decoding is a pure function over the message body, so the interesting part
//! is testable without a kernel; the socket around it is a shell.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use caw_netlink::{HDR_LEN, align};
use rustix::io::Errno;
use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType, netlink};

// rtnetlink message types.
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;

// Multicast group ids. A netlink bind mask carries group `n` in bit `n - 1`.
const RTNLGRP_LINK: u32 = 1;
const RTNLGRP_IPV4_IFADDR: u32 = 5;
const RTNLGRP_IPV6_IFADDR: u32 = 9;

// Interface flags from `struct ifinfomsg`.
const IFF_UP: u32 = 0x1;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x1_0000;

/// Length of `struct ifinfomsg`, and of `struct ifaddrmsg`, both of which put
/// the interface index in bytes 4..8.
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkEvent {
    /// A link's flags changed — including the carrier coming or going, which
    /// is what separates "the cable is out" from "the interface is down".
    Changed {
        ifindex: u32,
        up: bool,
        carrier: bool,
    },
    Removed {
        ifindex: u32,
    },
    /// An address was added or withdrawn on this interface.
    AddressChanged {
        ifindex: u32,
    },
}

impl LinkEvent {
    /// Decode one rtnetlink notification from its message type and payload.
    ///
    /// `None` for the message types caw does not act on — routes, neighbours,
    /// qdiscs — which arrive on the same groups.
    pub fn decode(kind: u16, payload: &[u8]) -> Option<Self> {
        match kind {
            RTM_NEWLINK | RTM_DELLINK => {
                let body = payload.get(..IFINFOMSG_LEN)?;
                let ifindex = u32::from_ne_bytes([body[4], body[5], body[6], body[7]]);
                if kind == RTM_DELLINK {
                    return Some(Self::Removed { ifindex });
                }
                let flags = u32::from_ne_bytes([body[8], body[9], body[10], body[11]]);
                Some(Self::Changed {
                    ifindex,
                    up: flags & IFF_UP != 0,
                    // IFF_RUNNING as well as IFF_LOWER_UP: virtual and older
                    // drivers report only one of the two.
                    carrier: flags & (IFF_LOWER_UP | IFF_RUNNING) != 0,
                })
            }
            RTM_NEWADDR | RTM_DELADDR => {
                let body = payload.get(..IFADDRMSG_LEN)?;
                Some(Self::AddressChanged {
                    ifindex: u32::from_ne_bytes([body[4], body[5], body[6], body[7]]),
                })
            }
            _ => None,
        }
    }
}

/// A netlink socket subscribed to rtnetlink's link and address groups.
pub struct LinkEvents {
    fd: OwnedFd,
    buf: Vec<u8>,
}

impl LinkEvents {
    pub fn open() -> Result<Self, Errno> {
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        let groups = (1 << (RTNLGRP_LINK - 1))
            | (1 << (RTNLGRP_IPV4_IFADDR - 1))
            | (1 << (RTNLGRP_IPV6_IFADDR - 1));
        rustix::net::bind(&fd, &netlink::SocketAddrNetlink::new(0, groups))?;
        Ok(Self {
            fd,
            buf: vec![0u8; 32 * 1024],
        })
    }

    /// Decode everything queued. An empty vector means nothing was waiting.
    pub fn read(&mut self) -> Vec<LinkEvent> {
        let mut out = Vec::new();
        loop {
            let (n, actual) =
                match rustix::net::recv(&self.fd, &mut self.buf[..], RecvFlags::empty()) {
                    Ok(v) => v,
                    Err(Errno::AGAIN) => return out,
                    Err(Errno::INTR) => continue,
                    Err(_) => return out,
                };
            // A datagram the kernel truncated cannot be parsed, but the ones
            // behind it can; drop it and keep draining.
            if actual > n {
                continue;
            }

            let mut rest = &self.buf[..n];
            while rest.len() >= HDR_LEN {
                let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                if len < HDR_LEN || len > rest.len() {
                    break;
                }
                let kind = u16::from_ne_bytes([rest[4], rest[5]]);
                if let Some(event) = LinkEvent::decode(kind, &rest[HDR_LEN..len]) {
                    out.push(event);
                }
                rest = &rest[align(len).min(rest.len())..];
            }
        }
    }
}

impl AsFd for LinkEvents {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `struct ifinfomsg`, which netlink writes in native endianness.
    fn ifinfomsg(ifindex: u32, flags: u32) -> Vec<u8> {
        let mut body = vec![0u8; IFINFOMSG_LEN];
        body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        body[8..12].copy_from_slice(&flags.to_ne_bytes());
        body
    }

    #[test]
    fn a_link_that_is_up_with_a_cable() {
        let body = ifinfomsg(3, IFF_UP | IFF_LOWER_UP | IFF_RUNNING);
        assert_eq!(
            LinkEvent::decode(RTM_NEWLINK, &body),
            Some(LinkEvent::Changed {
                ifindex: 3,
                up: true,
                carrier: true
            })
        );
    }

    /// The case worth telling apart: administratively up, nothing on the wire.
    #[test]
    fn a_link_that_is_up_without_one() {
        let body = ifinfomsg(3, IFF_UP);
        assert_eq!(
            LinkEvent::decode(RTM_NEWLINK, &body),
            Some(LinkEvent::Changed {
                ifindex: 3,
                up: true,
                carrier: false
            })
        );
    }

    #[test]
    fn a_link_going_away() {
        let body = ifinfomsg(7, IFF_UP);
        assert_eq!(
            LinkEvent::decode(RTM_DELLINK, &body),
            Some(LinkEvent::Removed { ifindex: 7 })
        );
    }

    #[test]
    fn an_address_change_names_its_interface() {
        let mut body = vec![0u8; IFADDRMSG_LEN];
        body[4..8].copy_from_slice(&9u32.to_ne_bytes());
        assert_eq!(
            LinkEvent::decode(RTM_NEWADDR, &body),
            Some(LinkEvent::AddressChanged { ifindex: 9 })
        );
        assert_eq!(
            LinkEvent::decode(RTM_DELADDR, &body),
            Some(LinkEvent::AddressChanged { ifindex: 9 })
        );
    }

    #[test]
    fn truncated_and_uninteresting_messages_are_ignored() {
        assert_eq!(LinkEvent::decode(RTM_NEWLINK, &[0u8; 4]), None);
        assert_eq!(LinkEvent::decode(RTM_NEWADDR, &[0u8; 2]), None);
        // RTM_NEWROUTE, which arrives on groups we did not subscribe to but
        // could still reach a socket that later did.
        assert_eq!(LinkEvent::decode(24, &[0u8; 32]), None);
    }
}
