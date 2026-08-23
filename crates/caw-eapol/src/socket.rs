//! The EAPOL packet socket.
//!
//! Deliberately the only module in this crate that touches the kernel. It
//! carries no protocol knowledge at all: bytes in, bytes out, and the state
//! machine in [`crate`] never sees it.
//!
//! `SOCK_DGRAM` rather than `SOCK_RAW`, so the kernel adds and strips the
//! Ethernet header itself. What is left on the socket is exactly the EAPOL
//! frame [`Eapol::parse`](crate::Eapol::parse) expects.
//!
//! **Known gap: the socket is not bound to its interface.** Binding an
//! `AF_PACKET` socket means passing a `sockaddr_ll`, and rustix 1.1.4 has no
//! type for one: `SocketAddrArg` is an `unsafe trait`, `SocketAddrAny::new` is
//! an `unsafe fn`, and this crate is `#![forbid(unsafe_code)]`. Two
//! consequences, both real:
//!
//!   * An unbound packet socket receives EAPOL from *every* interface, and
//!     also sees the frames this station sent. [`FourWay`](crate::FourWay)
//!     ignores anything without Key ACK set, which covers the echo, and the
//!     MIC covers a foreign authenticator — but message 1 has no MIC, so a
//!     caller with more than one wireless interface must filter by source
//!     itself.
//!   * There is no address to send *to* until something has been received.
//!     [`EapolSocket::recv`] keeps the sender's address and [`EapolSocket::send`]
//!     replies to it, which is enough for the 4-way handshake and every rekey
//!     — the authenticator always speaks first. An unsolicited EAPOL-Start,
//!     which 802.1X wants, is not possible until the socket can be bound.
//!
//! Closing the gap needs one `sockaddr_ll` type in rustix, and nothing here
//! above it.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::net::{
    AddressFamily, RecvFlags, SendFlags, SocketAddrAny, SocketFlags, SocketType, eth,
};

use crate::Error;

/// An `AF_PACKET` socket carrying EtherType 0x888E on one interface.
pub struct EapolSocket {
    fd: OwnedFd,
    ifindex: u32,
    /// The authenticator's address, learned from the first frame received.
    peer: Option<SocketAddrAny>,
}

impl EapolSocket {
    /// Open the socket. Needs `CAP_NET_RAW`.
    ///
    /// `ifindex` is recorded for the caller's benefit and does not yet
    /// constrain the socket; see the module docs.
    pub fn open(ifindex: u32) -> Result<Self, Error> {
        let fd = rustix::net::socket_with(
            AddressFamily::PACKET,
            SocketType::DGRAM,
            // Non-blocking because `cawd` drives this from its poll loop and
            // must never sit in a read.
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            // Already in network byte order: rustix pre-swaps the ETH_P_*
            // constants, which is the `htons(0x888E)` a packet socket wants.
            Some(eth::PAE),
        )?;
        Ok(Self {
            fd,
            ifindex,
            peer: None,
        })
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Read one frame, remembering who sent it.
    ///
    /// Returns the number of bytes written into `buf`. A frame longer than the
    /// buffer has already been truncated by the kernel, so it is reported
    /// rather than decoded: a short EAPOL-Key frame would fail its MIC and
    /// look like a wrong passphrase.
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let (len, untruncated, from) =
            rustix::net::recvfrom(&self.fd, &mut *buf, RecvFlags::TRUNC)?;
        if untruncated > len {
            return Err(Error::Malformed);
        }
        if let Some(from) = from {
            self.peer = Some(from);
        }
        Ok(len)
    }

    /// Send a frame back to whoever last spoke to us.
    pub fn send(&self, frame: &[u8]) -> Result<(), Error> {
        let peer = self.peer.as_ref().ok_or(Error::NoPeer)?;
        let sent = rustix::net::sendto(&self.fd, frame, SendFlags::empty(), peer)?;
        if sent != frame.len() {
            return Err(Error::ShortSend);
        }
        Ok(())
    }
}

impl AsFd for EapolSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
