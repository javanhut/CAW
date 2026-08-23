//! AF_NETLINK transport and wire codec.
//!
//! The bottom of the stack: opens netlink sockets and encodes/decodes the
//! generic framing (`nlmsghdr`, `nlattr`) that both rtnetlink and nl80211 are
//! built from. Knows nothing about links or wireless.
//!
//! Sockets come from `rustix` on its `linux_raw` backend, so the syscalls are
//! issued directly rather than through libc.
//!
//! Netlink is native-endian on the wire, so all integers here are encoded with
//! `to_ne_bytes`/`from_ne_bytes` rather than a fixed byte order.
#![forbid(unsafe_code)]

use std::os::fd::OwnedFd;

use rustix::net::{
    AddressFamily, Protocol, RecvFlags, SendFlags, SocketFlags, SocketType, netlink,
};

/// Length of `struct nlmsghdr`.
pub const HDR_LEN: usize = 16;
/// Length of `struct nlattr`.
pub const ATTR_HDR_LEN: usize = 4;

/// Netlink pads every message and attribute to a 4-byte boundary.
pub const fn align(len: usize) -> usize {
    (len + 3) & !3
}

// nlmsg_type values common to all families.
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;
/// Family-specific types start here.
pub const NLMSG_MIN_TYPE: u16 = 0x10;

// nlmsg_flags.
pub const NLM_F_REQUEST: u16 = 0x001;
pub const NLM_F_MULTI: u16 = 0x002;
pub const NLM_F_ACK: u16 = 0x004;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
/// Request a full table: `NLM_F_ROOT | NLM_F_MATCH`.
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
// Flags for NEW requests. Note these reuse the bit values of ROOT/MATCH; which
// meaning applies depends on the message type, per the kernel's ABI.
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

/// A netlink socket bound to a protocol family.
pub struct Socket {
    fd: OwnedFd,
    seq: u32,
    buf: Vec<u8>,
}

impl Socket {
    /// Open and bind a socket. `protocol` is `None` for `NETLINK_ROUTE`.
    pub fn open(protocol: Option<Protocol>) -> Result<Self, Error> {
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            protocol,
        )?;
        // pid 0 lets the kernel assign a unique port id, which is what we want
        // whenever more than one netlink socket may be open in this process.
        rustix::net::bind(&fd, &netlink::SocketAddrNetlink::new(0, 0))?;
        Ok(Self {
            fd,
            seq: 0,
            buf: vec![0u8; 64 * 1024],
        })
    }

    /// Open a `NETLINK_ROUTE` socket.
    pub fn route() -> Result<Self, Error> {
        Self::open(None)
    }

    /// Open a `NETLINK_GENERIC` socket, for nl80211 and friends.
    pub fn generic() -> Result<Self, Error> {
        Self::open(Some(netlink::GENERIC))
    }

    /// Sequence number for the next request.
    pub fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    pub fn send(&self, msg: &[u8]) -> Result<(), Error> {
        let sent = rustix::net::send(&self.fd, msg, SendFlags::empty())?;
        if sent != msg.len() {
            return Err(Error::ShortSend);
        }
        Ok(())
    }

    /// Send a request and feed every reply message to `handler` until the
    /// kernel signals the end of the dump.
    ///
    /// A dump is a multipart sequence terminated by `NLMSG_DONE`; a
    /// single-message reply ends after the first message. `NLMSG_ERROR` with a
    /// non-zero code aborts and is returned as [`Error::Kernel`]; with a zero
    /// code it is an ACK and ends the exchange.
    pub fn request<F>(&mut self, msg: &[u8], mut handler: F) -> Result<(), Error>
    where
        F: FnMut(Message<'_>) -> Result<(), Error>,
    {
        // Replies are matched on sequence number so that a stray message
        // cannot be mistaken for part of this exchange.
        let want_seq = msg
            .get(8..12)
            .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or(Error::Truncated)?;

        self.send(msg)?;
        loop {
            let (n, actual) = rustix::net::recv(&self.fd, &mut self.buf[..], RecvFlags::empty())?;
            // A datagram longer than the buffer has already been discarded by
            // the kernel; reporting it beats decoding a half message. Not
            // retried automatically because `request` also carries mutations,
            // which must not be sent twice.
            if actual > n {
                return Err(Error::Overrun);
            }
            let mut rest = &self.buf[..n];
            while rest.len() >= HDR_LEN {
                let msg = Message::parse(rest)?;
                let advance = align(msg.len as usize).min(rest.len());

                if msg.seq != want_seq {
                    rest = &rest[advance..];
                    continue;
                }

                match msg.kind {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_ERROR => {
                        // nlmsgerr: i32 error code, then the offending header.
                        let code = msg
                            .payload
                            .get(..4)
                            .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
                            .ok_or(Error::Truncated)?;
                        return if code == 0 {
                            Ok(()) // plain ACK
                        } else {
                            Err(Error::Kernel(-code))
                        };
                    }
                    NLMSG_NOOP => {}
                    NLMSG_OVERRUN => return Err(Error::Overrun),
                    _ => {
                        let multi = msg.flags & NLM_F_MULTI != 0;
                        handler(msg)?;
                        if !multi {
                            return Ok(());
                        }
                    }
                }
                rest = &rest[advance..];
            }
        }
    }
}

/// One netlink message: header fields plus its payload.
pub struct Message<'a> {
    pub len: u32,
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
    /// Everything after the 16-byte header, trimmed to the message length.
    pub payload: &'a [u8],
}

impl<'a> Message<'a> {
    fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < HDR_LEN {
            return Err(Error::Truncated);
        }
        let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if (len as usize) < HDR_LEN || len as usize > buf.len() {
            return Err(Error::Truncated);
        }
        Ok(Self {
            len,
            kind: u16::from_ne_bytes([buf[4], buf[5]]),
            flags: u16::from_ne_bytes([buf[6], buf[7]]),
            seq: u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]),
            pid: u32::from_ne_bytes([buf[12], buf[13], buf[14], buf[15]]),
            payload: &buf[HDR_LEN..len as usize],
        })
    }

    /// Interpret the payload as a fixed-size family header followed by
    /// attributes, returning an iterator over the attributes.
    pub fn attrs(&self, family_header_len: usize) -> Attrs<'a> {
        let start = align(family_header_len).min(self.payload.len());
        Attrs {
            rest: &self.payload[start..],
        }
    }
}

/// A borrowed netlink attribute.
pub struct Attr<'a> {
    pub kind: u16,
    pub payload: &'a [u8],
}

impl Attr<'_> {
    pub fn u32(&self) -> Option<u32> {
        let b = self.payload.get(..4)?;
        Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u8(&self) -> Option<u8> {
        self.payload.first().copied()
    }

    /// A NUL-terminated string attribute.
    pub fn str(&self) -> Option<&str> {
        let end = self.payload.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&self.payload[..end]).ok()
    }
}

/// Iterates the attributes in a message payload.
pub struct Attrs<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.len() < ATTR_HDR_LEN {
            return None;
        }
        let len = u16::from_ne_bytes([self.rest[0], self.rest[1]]) as usize;
        let kind = u16::from_ne_bytes([self.rest[2], self.rest[3]]);
        // A length below the header size, or past the end, means a malformed
        // stream; stop rather than loop forever or panic.
        if len < ATTR_HDR_LEN || len > self.rest.len() {
            return None;
        }
        let payload = &self.rest[ATTR_HDR_LEN..len];
        self.rest = &self.rest[align(len).min(self.rest.len())..];
        Some(Attr { kind, payload })
    }
}

/// Builds a netlink request.
pub struct MsgBuilder {
    buf: Vec<u8>,
}

impl MsgBuilder {
    pub fn new(kind: u16, flags: u16, seq: u32) -> Self {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // length, patched in finish
        buf.extend_from_slice(&kind.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid: kernel fills it in
        Self { buf }
    }

    /// Append a fixed family header, such as `ifinfomsg`.
    pub fn header(mut self, bytes: &[u8]) -> Self {
        self.buf.extend_from_slice(bytes);
        self.pad();
        self
    }

    pub fn attr(mut self, kind: u16, data: &[u8]) -> Self {
        let len = ATTR_HDR_LEN + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
        self
    }

    pub fn attr_u32(self, kind: u16, value: u32) -> Self {
        self.attr(kind, &value.to_ne_bytes())
    }

    /// A NUL-terminated string attribute, as the kernel expects for names.
    pub fn attr_str(self, kind: u16, value: &str) -> Self {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.attr(kind, &bytes)
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    /// Patch in the total length and yield the wire bytes.
    pub fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

#[derive(Debug)]
pub enum Error {
    Io(rustix::io::Errno),
    Truncated,
    ShortSend,
    /// A message did not fit the receive buffer, or the kernel signalled
    /// `NLMSG_OVERRUN`. The operation must be retried.
    Overrun,
    /// The kernel replied with `NLMSG_ERROR`. Holds a positive errno.
    Kernel(i32),
}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "netlink io: {e}"),
            Error::Truncated => write!(f, "truncated netlink message"),
            Error::ShortSend => write!(f, "short netlink send"),
            Error::Overrun => write!(f, "netlink message exceeded the receive buffer"),
            Error::Kernel(1) => write!(f, "operation not permitted (try running as root)"),
            Error::Kernel(errno) => write!(f, "kernel returned errno {errno}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligns_to_four() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
    }

    #[test]
    fn builder_patches_length_and_pads() {
        let msg = MsgBuilder::new(18, NLM_F_REQUEST, 7)
            .attr_str(3, "eth0")
            .finish();
        // 16 header + 4 attr header + 5 bytes "eth0\0" padded to 8.
        assert_eq!(msg.len(), 28);
        assert_eq!(u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]), 28);
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), 18);
    }

    #[test]
    fn attrs_round_trip() {
        let msg = MsgBuilder::new(0, 0, 0)
            .attr_str(3, "wlan0")
            .attr_u32(13, 1500)
            .finish();
        let parsed = Message::parse(&msg).unwrap();
        let attrs: Vec<_> = parsed.attrs(0).collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].str(), Some("wlan0"));
        assert_eq!(attrs[1].u32(), Some(1500));
    }

    #[test]
    fn malformed_attr_length_terminates_iteration() {
        // A zero-length attribute header must not spin forever.
        let bytes = [0u8, 0, 0, 0, 0, 0, 0, 0];
        let attrs = Attrs { rest: &bytes };
        assert_eq!(attrs.count(), 0);
    }
}
