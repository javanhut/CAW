//! rtnetlink: interfaces, addresses, routes.
//!
//! Backs `caw ports`, `caw port up` and `caw port info`. Deliberately
//! independent of the wireless stack so ethernet management works on its own.
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use caw_netlink::{Error, MsgBuilder, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, Socket};

// rtnetlink message types.
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_GETADDR: u16 = 22;

// Sizes of the fixed family headers that precede the attributes.
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;

// IFLA_* attribute types.
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_OPERSTATE: u16 = 16;

// IFA_* attribute types.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

// Interface flags.
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x1_0000;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// RFC 2863 operational state, which is more informative than `IFF_UP` alone:
/// a link can be administratively up while the cable is out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OperState {
    Unknown,
    NotPresent,
    Down,
    LowerLayerDown,
    Testing,
    Dormant,
    Up,
}

impl OperState {
    fn from_raw(v: u8) -> Self {
        match v {
            1 => Self::NotPresent,
            2 => Self::Down,
            3 => Self::LowerLayerDown,
            4 => Self::Testing,
            5 => Self::Dormant,
            6 => Self::Up,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NotPresent => "not-present",
            Self::Down => "down",
            Self::LowerLayerDown => "no-carrier",
            Self::Testing => "testing",
            Self::Dormant => "dormant",
            Self::Up => "up",
        }
    }
}

/// What kind of port this is, for display and for deciding which commands apply.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Loopback,
    Ethernet,
    Wireless,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Ethernet => "ethernet",
            Self::Wireless => "wireless",
        }
    }
}

/// A network interface as reported by the kernel.
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mac: Option<[u8; 6]>,
    pub mtu: u32,
    pub flags: u32,
    pub oper_state: OperState,
    pub kind: Kind,
}

impl Link {
    /// Administratively up.
    pub fn is_up(&self) -> bool {
        self.flags & IFF_UP != 0
    }

    /// The physical layer reports a usable link.
    pub fn has_carrier(&self) -> bool {
        self.flags & IFF_LOWER_UP != 0 || self.flags & IFF_RUNNING != 0
    }
}

/// An address configured on a link.
pub struct Address {
    pub index: u32,
    pub addr: IpAddr,
    pub prefix_len: u8,
}

/// A handle on an rtnetlink socket.
pub struct Rtnl {
    sock: Socket,
}

impl Rtnl {
    pub fn open() -> Result<Self, Error> {
        Ok(Self {
            sock: Socket::route()?,
        })
    }

    /// Every interface on the system.
    pub fn links(&mut self) -> Result<Vec<Link>, Error> {
        let seq = self.sock.next_seq();
        let req = MsgBuilder::new(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, seq)
            .header(&ifinfomsg(AF_UNSPEC, 0, 0, 0))
            .finish();

        let mut links = Vec::new();
        self.sock.request(&req, |msg| {
            let body = msg.payload;
            if body.len() < IFINFOMSG_LEN {
                return Err(Error::Truncated);
            }
            let index = i32::from_ne_bytes([body[4], body[5], body[6], body[7]]) as u32;
            let flags = u32::from_ne_bytes([body[8], body[9], body[10], body[11]]);

            let mut name = String::new();
            let mut mac = None;
            let mut mtu = 0;
            let mut oper = OperState::Unknown;

            for attr in msg.attrs(IFINFOMSG_LEN) {
                match attr.kind {
                    IFLA_IFNAME => name = attr.str().unwrap_or_default().to_owned(),
                    IFLA_MTU => mtu = attr.u32().unwrap_or(0),
                    IFLA_OPERSTATE => oper = OperState::from_raw(attr.u8().unwrap_or(0)),
                    // Only 6-byte addresses are Ethernet-style MACs; loopback
                    // and tunnels report other lengths.
                    IFLA_ADDRESS if attr.payload.len() == 6 => {
                        let mut m = [0u8; 6];
                        m.copy_from_slice(attr.payload);
                        mac = Some(m);
                    }
                    _ => {}
                }
            }

            let kind = classify(&name, flags);
            links.push(Link {
                index,
                name,
                mac,
                mtu,
                flags,
                oper_state: oper,
                kind,
            });
            Ok(())
        })?;

        links.sort_by_key(|l| l.index);
        Ok(links)
    }

    /// Every address configured on every link.
    pub fn addresses(&mut self) -> Result<Vec<Address>, Error> {
        let seq = self.sock.next_seq();
        let req = MsgBuilder::new(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, seq)
            .header(&[AF_UNSPEC, 0, 0, 0, 0, 0, 0, 0])
            .finish();

        let mut out = Vec::new();
        self.sock.request(&req, |msg| {
            let body = msg.payload;
            if body.len() < IFADDRMSG_LEN {
                return Err(Error::Truncated);
            }
            let family = body[0];
            let prefix_len = body[1];
            let index = u32::from_ne_bytes([body[4], body[5], body[6], body[7]]);

            // IFA_LOCAL is the address on this end of a point-to-point link;
            // where it is absent IFA_ADDRESS is the local address.
            let mut local = None;
            let mut addr = None;
            for attr in msg.attrs(IFADDRMSG_LEN) {
                match attr.kind {
                    IFA_LOCAL => local = parse_ip(family, attr.payload),
                    IFA_ADDRESS => addr = parse_ip(family, attr.payload),
                    _ => {}
                }
            }

            if let Some(ip) = local.or(addr) {
                out.push(Address {
                    index,
                    addr: ip,
                    prefix_len,
                });
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Bring a link administratively up or down.
    ///
    /// `ifi_change` is a mask telling the kernel which flag bits this request
    /// is allowed to touch, so only `IFF_UP` is affected.
    pub fn set_up(&mut self, index: u32, up: bool) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let flags = if up { IFF_UP } else { 0 };
        let req = MsgBuilder::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq)
            .header(&ifinfomsg(AF_UNSPEC, index, flags, IFF_UP))
            .finish();
        self.sock.request(&req, |_| Ok(()))
    }

    /// Look up one link by name.
    pub fn link_by_name(&mut self, name: &str) -> Result<Option<Link>, Error> {
        Ok(self.links()?.into_iter().find(|l| l.name == name))
    }
}

/// Encode `struct ifinfomsg`.
fn ifinfomsg(family: u8, index: u32, flags: u32, change: u32) -> [u8; IFINFOMSG_LEN] {
    let mut b = [0u8; IFINFOMSG_LEN];
    b[0] = family;
    // b[1] is padding, b[2..4] is ifi_type, left zero for requests.
    b[4..8].copy_from_slice(&(index as i32).to_ne_bytes());
    b[8..12].copy_from_slice(&flags.to_ne_bytes());
    b[12..16].copy_from_slice(&change.to_ne_bytes());
    b
}

fn parse_ip(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family {
        AF_INET if bytes.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        AF_INET6 if bytes.len() == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(bytes);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// Wireless interfaces in managed mode report `ARPHRD_ETHER` just like a wired
/// NIC, so the link type cannot distinguish them. The presence of a `phy80211`
/// node in sysfs can. This is a filesystem check, not a call out to another
/// tool; nl80211 will supersede it once the wireless layer lands.
fn classify(name: &str, flags: u32) -> Kind {
    if flags & IFF_LOOPBACK != 0 {
        return Kind::Loopback;
    }
    if std::path::Path::new(&format!("/sys/class/net/{name}/phy80211")).exists() {
        return Kind::Wireless;
    }
    Kind::Ethernet
}

/// Render a hardware address in the conventional colon-separated form.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifinfomsg_layout() {
        let b = ifinfomsg(AF_UNSPEC, 3, IFF_UP, IFF_UP);
        assert_eq!(b.len(), 16);
        assert_eq!(i32::from_ne_bytes([b[4], b[5], b[6], b[7]]), 3);
        assert_eq!(u32::from_ne_bytes([b[8], b[9], b[10], b[11]]), IFF_UP);
        assert_eq!(u32::from_ne_bytes([b[12], b[13], b[14], b[15]]), IFF_UP);
    }

    #[test]
    fn formats_mac() {
        assert_eq!(format_mac(&[0x02, 0, 0, 0, 0x01, 0]), "02:00:00:00:01:00");
    }

    #[test]
    fn parses_both_families() {
        assert_eq!(
            parse_ip(AF_INET, &[192, 168, 1, 5]),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)))
        );
        assert!(parse_ip(AF_INET6, &[0u8; 16]).is_some());
        // Wrong length for the family must not be accepted.
        assert_eq!(parse_ip(AF_INET, &[1, 2, 3]), None);
    }
}
