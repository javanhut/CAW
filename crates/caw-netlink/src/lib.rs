//! AF_NETLINK transport and wire codec.
//!
//! The bottom of the stack: opens netlink sockets and encodes/decodes the
//! generic framing (`nlmsghdr`, `nlattr`, `genlmsghdr`) that both rtnetlink
//! and nl80211 are built from. Knows nothing about links or wireless.
//!
//! Sockets come from `rustix` on its `linux_raw` backend, so the syscalls are
//! issued directly rather than through libc.
#![forbid(unsafe_code)]

/// A netlink socket bound to a protocol family (`NETLINK_ROUTE`, `NETLINK_GENERIC`).
pub struct Socket {
    _priv: (),
}

/// Borrowed view of one netlink attribute.
pub struct Attr<'a> {
    pub kind: u16,
    pub payload: &'a [u8],
}

/// Iterates the attributes in a message payload.
pub struct Attrs<'a> {
    _rest: &'a [u8],
}

/// Builds a netlink request incrementally.
pub struct MsgBuilder {
    _buf: Vec<u8>,
}

/// Resolves a generic-netlink family name (e.g. `"nl80211"`) to its id.
pub fn resolve_genl_family(_sock: &mut Socket, _name: &str) -> Result<u16, Error> {
    todo!("CTRL_CMD_GETFAMILY")
}

#[derive(Debug)]
pub enum Error {
    Io,
    Truncated,
    /// The kernel replied with NLMSG_ERROR.
    Kernel(i32),
}
