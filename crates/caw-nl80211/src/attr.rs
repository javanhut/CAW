//! Attribute plumbing for generic netlink.
//!
//! `caw-netlink` walks the attributes of a message. nl80211 nests them:
//! `NL80211_ATTR_BSS` is itself a stream of attributes, and
//! `CTRL_ATTR_MCAST_GROUPS` is a stream of streams. The nested walk and its
//! matching builder live here rather than being pushed down into the transport
//! crate, which has no business knowing about wireless.

use caw_netlink::{ATTR_HDR_LEN, Attr, align};

/// Length of `struct genlmsghdr`: an 8-bit command, an 8-bit family version,
/// and two reserved bytes. It sits between the netlink header and the
/// attributes of every generic-netlink message.
pub const GENL_HDRLEN: usize = 4;

/// Netlink keeps two flags in the high bits of an attribute type.
/// `nla_nest_start` sets `NLA_F_NESTED` on everything it opens, so a type read
/// off the wire must be masked before it is compared with a constant —
/// unmasked, `NL80211_ATTR_BSS` arrives as `0x802f` and matches nothing.
pub const NLA_F_NESTED: u16 = 0x8000;
pub const NLA_F_NET_BYTEORDER: u16 = 0x4000;
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

/// Encode `struct genlmsghdr`.
pub fn genlmsghdr(cmd: u8, version: u8) -> [u8; GENL_HDRLEN] {
    [cmd, version, 0, 0]
}

/// The command of a generic-netlink message body.
pub fn genl_cmd(body: &[u8]) -> Option<u8> {
    body.first().copied()
}

/// Walks a raw attribute stream: a nested attribute's payload, or a message
/// body past its family header.
pub struct Attrs<'a> {
    rest: &'a [u8],
}

impl<'a> Attrs<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The attributes of a generic-netlink message body, stepping over the
    /// `genlmsghdr` in front of them.
    pub fn of_body(body: &'a [u8]) -> Self {
        Self::new(body.get(GENL_HDRLEN..).unwrap_or(&[]))
    }

    /// The first attribute of this type. Netlink permits duplicates and the
    /// kernel itself takes the first, so this matches its behaviour.
    pub fn find(mut self, kind: u16) -> Option<Attr<'a>> {
        self.find_map(|a| (a.kind == kind).then_some(a))
    }
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Attr<'a>> {
        let hdr = self.rest.get(..ATTR_HDR_LEN)?;
        let len = u16::from_ne_bytes([hdr[0], hdr[1]]) as usize;
        // A length below the header size, or past the end, means a malformed
        // stream; stop rather than loop forever or panic.
        if len < ATTR_HDR_LEN || len > self.rest.len() {
            return None;
        }
        let kind = u16::from_ne_bytes([hdr[2], hdr[3]]) & NLA_TYPE_MASK;
        let payload = &self.rest[ATTR_HDR_LEN..len];
        self.rest = &self.rest[align(len).min(self.rest.len())..];
        Some(Attr { kind, payload })
    }
}

/// `Attr` reads u8, u32 and strings; nl80211 also uses these widths.
pub fn u16_of(attr: &Attr<'_>) -> Option<u16> {
    let b = attr.payload.get(..2)?;
    Some(u16::from_ne_bytes([b[0], b[1]]))
}

pub fn i32_of(attr: &Attr<'_>) -> Option<i32> {
    attr.u32().map(|v| v as i32)
}

pub fn mac_of(attr: &Attr<'_>) -> Option<[u8; 6]> {
    attr.payload.get(..6)?.try_into().ok()
}

/// Builds the payload of a nested attribute.
///
/// `MsgBuilder` appends straight to the message, but a nest has to be finished
/// before its length is known, so it is assembled apart and handed over as one
/// attribute.
#[derive(Default)]
pub struct Nest {
    buf: Vec<u8>,
}

impl Nest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn attr(mut self, kind: u16, data: &[u8]) -> Self {
        let len = ATTR_HDR_LEN + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        self
    }

    pub fn attr_u8(self, kind: u16, value: u8) -> Self {
        self.attr(kind, &[value])
    }

    pub fn attr_u32(self, kind: u16, value: u32) -> Self {
        self.attr(kind, &value.to_ne_bytes())
    }

    /// A flag attribute: present with an empty payload, absent otherwise.
    pub fn flag(self, kind: u16) -> Self {
        self.attr(kind, &[])
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}
