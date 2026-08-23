//! The DHCP message: a BOOTP frame with a magic cookie and options bolted on.
//!
//! DHCP never got its own header. RFC 2131 reuses the BOOTP layout of RFC 951
//! verbatim and distinguishes itself by the four-byte cookie that precedes the
//! option area, which is why decoding starts by checking for it.

use std::net::Ipv4Addr;

use crate::Error;
use crate::options::{self, DhcpOption, MessageType, OPT_PAD, OVERLOAD_FILE, OVERLOAD_SNAME};

/// A client-to-server message.
pub const BOOTREQUEST: u8 = 1;
/// A server-to-client message.
pub const BOOTREPLY: u8 = 2;
/// `htype` for 10 Mb Ethernet, which is what every modern NIC still reports.
pub const HTYPE_ETHERNET: u8 = 1;

/// Ask the server to broadcast its reply. Required whenever the client cannot
/// yet receive a unicast, which is the case until an address is configured.
pub const FLAG_BROADCAST: u16 = 0x8000;

/// The cookie that turns a BOOTP frame into a DHCP one.
pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

// Field offsets in the fixed part.
const SNAME: usize = 44;
const FILE: usize = 108;
/// End of the BOOTP fixed part, where the cookie begins.
const FIXED_LEN: usize = 236;
/// RFC 1542 requires BOOTP relays to accept messages of at least this size,
/// and some drop anything shorter, so every message caw sends is padded to it.
const MIN_LEN: usize = 300;

/// A decoded DHCP message.
///
/// `sname` and `file` are the BOOTP server-name and boot-file fields, trimmed
/// at the first NUL. When option overload says they carry options instead,
/// they decode as empty and their options join [`Self::options`] — so
/// re-encoding a message that arrived overloaded puts everything in the option
/// area. That is a valid message; it is just not byte-identical to the input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    /// Seconds since the client began the exchange. Relays use it to decide
    /// when to step in.
    pub secs: u16,
    pub flags: u16,
    /// The client's current address, set only once it has one.
    pub ciaddr: Ipv4Addr,
    /// The address the server is assigning.
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    /// Client hardware address, padded to 16 bytes whatever `hlen` says.
    pub chaddr: [u8; 16],
    pub sname: String,
    pub file: String,
    pub options: Vec<DhcpOption>,
}

impl Message {
    /// An empty client request for `mac`.
    pub fn request(xid: u32, mac: [u8; 6]) -> Self {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&mac);
        Self {
            op: BOOTREQUEST,
            htype: HTYPE_ETHERNET,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: String::new(),
            file: String::new(),
            options: Vec::new(),
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let cookie = buf.get(FIXED_LEN..FIXED_LEN + 4).ok_or(Error::Malformed)?;
        if cookie != MAGIC_COOKIE {
            return Err(Error::Malformed);
        }

        let mut options = Vec::new();
        let overload = options::decode_into(&buf[FIXED_LEN + 4..], &mut options)?;

        // RFC 2131 §4.1 fills `file` before `sname`, so they are parsed in
        // that order to keep any duplicated option in the sender's precedence.
        // An overload declared inside an overloaded field is ignored: honouring
        // it could point back at the field being parsed.
        let mut file = String::new();
        let mut sname = String::new();
        if overload & OVERLOAD_FILE != 0 {
            options::decode_into(&buf[FILE..FIXED_LEN], &mut options)?;
        } else {
            file = text_field(&buf[FILE..FIXED_LEN]);
        }
        if overload & OVERLOAD_SNAME != 0 {
            options::decode_into(&buf[SNAME..FILE], &mut options)?;
        } else {
            sname = text_field(&buf[SNAME..FILE]);
        }

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&buf[28..44]);

        Ok(Self {
            op: buf[0],
            htype: buf[1],
            hlen: buf[2],
            hops: buf[3],
            xid: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            secs: u16::from_be_bytes([buf[8], buf[9]]),
            flags: u16::from_be_bytes([buf[10], buf[11]]),
            ciaddr: ipv4_at(buf, 12),
            yiaddr: ipv4_at(buf, 16),
            siaddr: ipv4_at(buf, 20),
            giaddr: ipv4_at(buf, 24),
            chaddr,
            sname,
            file,
            options,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MIN_LEN);
        buf.extend_from_slice(&[self.op, self.htype, self.hlen, self.hops]);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());
        for addr in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            buf.extend_from_slice(&addr.octets());
        }
        buf.extend_from_slice(&self.chaddr);
        text_out(&mut buf, &self.sname, FILE - SNAME);
        text_out(&mut buf, &self.file, FIXED_LEN - FILE);
        buf.extend_from_slice(&MAGIC_COOKIE);
        options::encode_all(&self.options, &mut buf);
        buf.resize(buf.len().max(MIN_LEN), OPT_PAD);
        buf
    }

    /// The first option with this code, if present.
    pub fn get(&self, code: u8) -> Option<&DhcpOption> {
        self.options.iter().find(|o| o.code() == code)
    }

    pub fn message_type(&self) -> Option<MessageType> {
        self.options.iter().find_map(|o| match o {
            DhcpOption::MessageType(mt) => Some(*mt),
            _ => None,
        })
    }

    /// Option 54: which server this message came from. Every DHCP reply worth
    /// acting on carries it, since it is how a client picks between offers and
    /// where it addresses its renewal.
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|o| match o {
            DhcpOption::ServerId(addr) => Some(*addr),
            _ => None,
        })
    }
}

fn ipv4_at(buf: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(buf[at], buf[at + 1], buf[at + 2], buf[at + 3])
}

/// A NUL-terminated, NUL-padded BOOTP text field.
fn text_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn text_out(buf: &mut Vec<u8>, value: &str, width: usize) {
    let bytes = value.as_bytes();
    // Leave room for the terminating NUL: a field filled to its last byte
    // would be read back as running into whatever follows.
    let len = bytes.len().min(width - 1);
    buf.extend_from_slice(&bytes[..len]);
    buf.resize(buf.len() + width - len, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ACK_CAPTURE, CAPTURE_MAC, CAPTURE_XID};

    fn discover() -> Message {
        let mut msg = Message::request(0xdead_beef, CAPTURE_MAC);
        msg.flags = FLAG_BROADCAST;
        msg.secs = 4;
        msg.sname = "corvus".to_owned();
        msg.file = "pxelinux.0".to_owned();
        msg.options = vec![
            DhcpOption::MessageType(MessageType::Discover),
            DhcpOption::RequestedIp(Ipv4Addr::new(192, 168, 1, 24)),
        ];
        msg
    }

    #[test]
    fn round_trips() {
        let msg = discover();
        let bytes = msg.encode();
        assert_eq!(bytes.len(), MIN_LEN);
        assert_eq!(Message::decode(&bytes).unwrap(), msg);
        // Encoding is stable, so a message that survives one round trip
        // survives every later one.
        assert_eq!(Message::decode(&bytes).unwrap().encode(), bytes);
    }

    #[test]
    fn decodes_a_captured_ack() {
        let msg = Message::decode(&ACK_CAPTURE).unwrap();
        assert_eq!(msg.op, BOOTREPLY);
        assert_eq!(msg.htype, HTYPE_ETHERNET);
        assert_eq!(msg.hlen, 6);
        assert_eq!(msg.xid, CAPTURE_XID);
        assert_eq!(msg.yiaddr, Ipv4Addr::new(192, 168, 1, 24));
        assert_eq!(msg.siaddr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(msg.chaddr[..6], CAPTURE_MAC);
        assert!(msg.sname.is_empty() && msg.file.is_empty());
        assert_eq!(msg.message_type(), Some(MessageType::Ack));
        assert_eq!(msg.server_id(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(msg.get(12), Some(&DhcpOption::HostName("raven".to_owned())));
    }

    #[test]
    fn rejects_a_missing_cookie() {
        let mut bytes = ACK_CAPTURE;
        bytes[236] = 0;
        assert_eq!(Message::decode(&bytes), Err(Error::Malformed));
    }

    #[test]
    fn reads_options_out_of_overloaded_fields() {
        // Option 52 says both `file` and `sname` hold options: the lease time
        // goes in `file`, the server id in `sname`.
        let mut bytes = discover().encode();
        bytes[FILE..FILE + 7].copy_from_slice(&[51, 4, 0, 0, 0xa8, 0xc0, options::OPT_END]);
        bytes[SNAME..SNAME + 7].copy_from_slice(&[54, 4, 192, 168, 1, 1, options::OPT_END]);
        let mut area = vec![options::OPT_OVERLOAD, 1, OVERLOAD_FILE | OVERLOAD_SNAME];
        area.push(options::OPT_END);
        bytes[FIXED_LEN + 4..FIXED_LEN + 4 + area.len()].copy_from_slice(&area);

        let msg = Message::decode(&bytes).unwrap();
        assert!(msg.file.is_empty() && msg.sname.is_empty());
        assert_eq!(msg.get(51), Some(&DhcpOption::LeaseTime(43_200)));
        assert_eq!(msg.server_id(), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn truncations_never_panic() {
        for n in 0..ACK_CAPTURE.len() {
            let result = Message::decode(&ACK_CAPTURE[..n]);
            // Anything short of the cookie cannot be a DHCP message; longer
            // prefixes are only decodable when the option area happens to end
            // cleanly, which is exactly what must not be assumed.
            if n < FIXED_LEN + 4 {
                assert_eq!(result, Err(Error::Malformed));
            }
        }
    }

    #[test]
    fn text_fields_stay_inside_their_width() {
        let mut msg = Message::request(1, CAPTURE_MAC);
        msg.file = "x".repeat(400);
        let bytes = msg.encode();
        assert_eq!(bytes.len(), MIN_LEN);
        // The last byte of the field is left as the terminating NUL.
        assert_eq!(
            Message::decode(&bytes).unwrap().file.len(),
            FIXED_LEN - FILE - 1
        );
    }
}
