//! The DHCPv4 socket.
//!
//! Kept apart from the state machine on purpose: everything else in this crate
//! is bytes in, actions out, and this is the one module that talks to the
//! kernel. It carries no protocol knowledge beyond the two port numbers.
//!
//! DHCP is bootstrapping, so the transport has to work before the interface
//! has an address. Two things make that possible here:
//!
//!   * the socket binds `0.0.0.0:68`, which needs no address on any interface;
//!   * the client sets the broadcast flag in its DISCOVER and REQUEST, so the
//!     server replies to `255.255.255.255` instead of unicasting to an address
//!     the interface does not yet answer for.
//!
//! **Known gap.** The exchange is not pinned to one interface. That normally
//! wants `SO_BINDTODEVICE`, or an `AF_PACKET` socket that skips the IP layer
//! altogether, and rustix 1.1.4 offers neither within this crate's rules:
//! there is no `SO_BINDTODEVICE` in `rustix::net::sockopt`, and addressing an
//! `AF_PACKET` socket means implementing the unsafe `SocketAddrArg` trait for
//! `sockaddr_ll`, which `#![forbid(unsafe_code)]` rules out. Until one of
//! those exists, the caller must pin the broadcast itself by installing a host
//! route for `255.255.255.255` on the target link before starting the
//! exchange — the same trick other DHCP clients use — and on a machine with
//! several links, must not run two exchanges at once.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, ipproto, sockopt};

use crate::Error;

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;

/// A UDP socket for one DHCPv4 exchange.
pub struct Dhcp4Socket {
    fd: OwnedFd,
}

impl Dhcp4Socket {
    /// Bind the client port. Needs `CAP_NET_BIND_SERVICE` or root, port 68
    /// being privileged.
    pub fn open() -> Result<Self, Error> {
        let fd = rustix::net::socket_with(
            AddressFamily::INET,
            SocketType::DGRAM,
            // Non-blocking because `cawd` drives this from its poll loop and
            // must never sit in a read.
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(ipproto::UDP),
        )?;
        // A previous exchange may still hold the port in the kernel's tables,
        // and a client that cannot rebind after a restart cannot renew.
        sockopt::set_socket_reuseaddr(&fd, true)?;
        sockopt::set_socket_broadcast(&fd, true)?;
        rustix::net::bind(&fd, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, CLIENT_PORT))?;
        Ok(Self { fd })
    }

    /// Send to the limited broadcast address, for DISCOVER, the first REQUEST
    /// and rebinding.
    pub fn send_broadcast(&self, data: &[u8]) -> Result<(), Error> {
        self.send_to(Ipv4Addr::BROADCAST, data)
    }

    /// Send to one server, for renewal.
    pub fn send_to(&self, server: Ipv4Addr, data: &[u8]) -> Result<(), Error> {
        let addr = SocketAddrV4::new(server, SERVER_PORT);
        let sent = rustix::net::sendto(&self.fd, data, SendFlags::empty(), &addr)?;
        if sent != data.len() {
            return Err(Error::ShortSend);
        }
        Ok(())
    }

    /// Read one datagram. The payload goes straight to
    /// [`Input::Datagram`](crate::Input::Datagram); the sender's address is not
    /// returned because a DHCP reply is identified by its transaction id and
    /// its server-id option, never by where it appears to come from.
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let (len, _untruncated) = rustix::net::recv(&self.fd, &mut *buf, RecvFlags::empty())?;
        Ok(len)
    }
}

impl AsFd for Dhcp4Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port 68 is privileged and the bind needs a real network stack, so this
    /// is the one test in the crate that will not run on a developer's laptop:
    /// `cargo test -p caw-dhcp -- --ignored` inside the dev container.
    #[test]
    #[ignore = "needs root and a kernel"]
    fn binds_the_client_port() {
        let socket = Dhcp4Socket::open().expect("bind 0.0.0.0:68");
        // SO_REUSEADDR has to make a second bind work, or a restarted daemon
        // could not renew a lease it still holds.
        let again = Dhcp4Socket::open().expect("rebind 0.0.0.0:68");
        drop((socket, again));
    }
}
