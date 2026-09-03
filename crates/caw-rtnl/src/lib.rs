//! rtnetlink: interfaces, addresses, routes.
//!
//! Backs `caw ports`, `caw port up` and `caw port info`. Deliberately
//! independent of the wireless stack so ethernet management works on its own.
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use caw_netlink::{
    Error, MsgBuilder, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REPLACE, NLM_F_REQUEST, Socket,
};

// rtnetlink message types.
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

// Sizes of the fixed family headers that precede the attributes.
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;

// IFLA_* attribute types.
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_OPERSTATE: u16 = 16;

// IFA_* attribute types.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;

// RTA_* attribute types.
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;

/// Metric of the route [`Rtnl::add_dhcp_probe_route`] installs. High enough
/// that any real default route wins, and distinct enough that
/// [`Rtnl::del_dhcp_probe_route`] can name the probe route and nothing else:
/// `RTM_DELROUTE` matches on metric when one is given.
const DHCP_PROBE_METRIC: u32 = 0x00FF_FFFF;

// struct rtmsg field values.
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

// Interface flags.
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x1_0000;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// What the kernel answers to `RTM_DELROUTE` for a route that is not there.
const ESRCH: i32 = 3;

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

    /// Put an IPv4 address on a link, replacing any previous instance of it.
    ///
    /// This is what turns a DHCP lease into a working interface, so its
    /// absence was the "caw-rtnl cannot add an address" half of the address
    /// configuration gap. `NLM_F_REPLACE` because a renewed lease is the same
    /// address arriving again, and a client that errors with EEXIST on its own
    /// renewal deconfigures itself once an hour.
    pub fn add_address(&mut self, index: u32, addr: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        // The directed broadcast address of the subnet, which the kernel does
        // not derive on its own for RTM_NEWADDR.
        let hostmask = u32::MAX.checked_shr(prefix_len as u32).unwrap_or(0);
        let brd = Ipv4Addr::from_bits(addr.to_bits() | hostmask);
        let req = MsgBuilder::new(
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        )
        .header(&ifaddrmsg(AF_INET, prefix_len, index))
        .attr(IFA_LOCAL, &addr.octets())
        .attr(IFA_ADDRESS, &addr.octets())
        .attr(IFA_BROADCAST, &brd.octets())
        .finish();
        self.sock.request(&req, |_| Ok(()))
    }

    /// Remove one IPv4 address from a link.
    ///
    /// DHCP can hand out a different address after a reconnect. Deleting the
    /// previous lease keeps it from remaining as a secondary address and
    /// being selected as the source of later traffic.
    pub fn del_address(&mut self, index: u32, addr: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = MsgBuilder::new(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, seq)
            .header(&ifaddrmsg(AF_INET, prefix_len, index))
            .attr(IFA_LOCAL, &addr.octets())
            .attr(IFA_ADDRESS, &addr.octets())
            .finish();
        self.sock.request(&req, |_| Ok(()))
    }

    /// Install the default route through `gateway` on `index`.
    pub fn add_default_route(&mut self, index: u32, gateway: Ipv4Addr) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = MsgBuilder::new(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        )
        .header(&rtmsg(AF_INET, 0, RT_SCOPE_UNIVERSE))
        .attr(RTA_GATEWAY, &gateway.octets())
        .attr_u32(RTA_OIF, index)
        .finish();
        self.sock.request(&req, |_| Ok(()))
    }

    /// Route the limited broadcast address out one interface.
    ///
    /// A UDP socket with no bound device needs a route to send to
    /// 255.255.255.255, and an interface that is mid-DHCP has no address from
    /// which the kernel could infer one. This is how the DHCPv4 socket gets
    /// its DISCOVER off the machine; `SO_BINDTODEVICE` would express it
    /// better, but rustix does not carry that option and this crate does not
    /// carry `unsafe`.
    pub fn add_broadcast_route(&mut self, index: u32) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = MsgBuilder::new(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        )
        .header(&rtmsg(AF_INET, 32, RT_SCOPE_LINK))
        .attr(RTA_DST, &Ipv4Addr::BROADCAST.octets())
        .attr_u32(RTA_OIF, index)
        .finish();
        self.sock.request(&req, |_| Ok(()))
    }

    /// Make every IPv4 source look reachable through `index`, so the kernel
    /// lets DHCP replies in while the interface still has no address.
    ///
    /// [`add_broadcast_route`](Self::add_broadcast_route) gets the DISCOVER
    /// out; this is its counterpart for the way back. Linux runs reverse-path
    /// filtering on incoming broadcasts too (`rp_filter`, which systemd sets
    /// to loose mode on every interface), and a DHCPOFFER from a server the
    /// machine has no route to fails that check and is dropped as a martian —
    /// `IPv4: martian source 255.255.255.255 from 192.168.1.254` in the
    /// kernel log — before any socket sees it. Mid-exchange there is no route
    /// to anything, so every offer is dropped and the client retransmits
    /// forever.
    ///
    /// A link-scope default route out `index` at a metric nothing real uses
    /// satisfies the filter in both strict and loose mode without competing
    /// with any route the lease later installs. The caller removes it with
    /// [`del_dhcp_probe_route`](Self::del_dhcp_probe_route) once the exchange
    /// is over, either way. A DHCP client on a packet socket would need none
    /// of this; see `caw_dhcp::Dhcp4Socket` for why there is not one.
    pub fn add_dhcp_probe_route(&mut self, index: u32) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = MsgBuilder::new(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            seq,
        )
        .header(&rtmsg(AF_INET, 0, RT_SCOPE_LINK))
        .attr_u32(RTA_OIF, index)
        .attr_u32(RTA_PRIORITY, DHCP_PROBE_METRIC)
        .finish();
        self.sock.request(&req, |_| Ok(()))
    }

    /// Remove the route [`add_dhcp_probe_route`](Self::add_dhcp_probe_route)
    /// installed. Matching on the probe metric keeps this from touching a
    /// default route the lease put on the same interface. A route that is
    /// already gone is not an error: the outcome asked for is the one in place.
    pub fn del_dhcp_probe_route(&mut self, index: u32) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = MsgBuilder::new(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, seq)
            .header(&rtmsg(AF_INET, 0, RT_SCOPE_LINK))
            .attr_u32(RTA_OIF, index)
            .attr_u32(RTA_PRIORITY, DHCP_PROBE_METRIC)
            .finish();
        match self.sock.request(&req, |_| Ok(())) {
            Err(Error::Kernel(ESRCH)) => Ok(()),
            other => other,
        }
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

/// Encode `struct ifaddrmsg`.
fn ifaddrmsg(family: u8, prefix_len: u8, index: u32) -> [u8; IFADDRMSG_LEN] {
    let mut b = [0u8; IFADDRMSG_LEN];
    b[0] = family;
    b[1] = prefix_len;
    // b[2] flags, b[3] scope: zero is flag-free and RT_SCOPE_UNIVERSE.
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    b
}

/// Encode `struct rtmsg` for a unicast route in the main table.
fn rtmsg(family: u8, dst_len: u8, scope: u8) -> [u8; RTMSG_LEN] {
    let mut b = [0u8; RTMSG_LEN];
    b[0] = family;
    b[1] = dst_len;
    // b[2] src_len, b[3] tos: zero.
    b[4] = RT_TABLE_MAIN;
    b[5] = RTPROT_BOOT;
    b[6] = scope;
    b[7] = RTN_UNICAST;
    // b[8..12] rtm_flags: zero.
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
