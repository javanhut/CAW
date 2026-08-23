//! rtnetlink: interfaces, addresses, routes.
//!
//! Backs `caw ports`, `caw port up`, `caw port info`, and the address/route
//! side of `caw port set`. Deliberately independent of the wireless stack so
//! ethernet management works on its own.
#![forbid(unsafe_code)]

/// A network interface as reported by the kernel.
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mac: [u8; 6],
    pub up: bool,
    pub carrier: bool,
    pub mtu: u32,
}

/// An address configured on a link.
pub struct Address {
    pub index: u32,
    pub addr: std::net::IpAddr,
    pub prefix_len: u8,
}

pub fn list_links() -> Result<Vec<Link>, caw_netlink::Error> {
    todo!("RTM_GETLINK dump")
}

pub fn set_link_up(_index: u32, _up: bool) -> Result<(), caw_netlink::Error> {
    todo!("RTM_NEWLINK with IFF_UP")
}
