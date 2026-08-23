//! Address configuration: DHCPv4, DHCPv6, and IPv6 SLAAC.
//!
//! Sans-IO like the authentication machines: the protocol state lives here,
//! the sockets and timers live in `cawd`. DHCPv4 needs a raw socket because
//! the interface has no address yet when the exchange starts.
//!
//! Applying the result — addresses, routes, resolver config — is `caw-rtnl`'s
//! and `caw-core`'s job, not this crate's.
#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

/// What a completed lease gives us.
pub struct Lease {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_secs: u32,
    /// When to start renewing (T1), as a fraction of the lease.
    pub renew_secs: u32,
}

/// DHCPv4 client state machine (RFC 2131).
pub struct Dhcp4 {
    _xid: u32,
}

/// Learned from a Router Advertisement.
pub struct RouterAdvert {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub router: Ipv6Addr,
    /// The M flag: addresses come from DHCPv6, not SLAAC.
    pub managed: bool,
}

#[derive(Debug)]
pub enum Error {
    Malformed,
    Timeout,
    Nak,
}
