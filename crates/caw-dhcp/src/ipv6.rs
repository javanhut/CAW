//! IPv6 autoconfiguration: Router Advertisements (RFC 4861) and SLAAC
//! addresses (RFC 4862).
//!
//! IPv6 splits the job DHCPv4 does alone. The router announces the prefix and
//! whether it is usable for stateless configuration; the M and O flags say
//! whether a DHCPv6 server has to be consulted for the address or for the rest
//! of the configuration. Only that decision is made here — the parser is
//! sans-IO like the DHCPv4 machine, and receiving the advertisement is the
//! daemon's job.

use std::net::Ipv6Addr;

use crate::Error;

/// ICMPv6 type 134.
pub const ROUTER_ADVERTISEMENT: u8 = 134;

/// Type, code, checksum, hop limit, flags, and three lifetimes.
const RA_HDR_LEN: usize = 16;

// Neighbour Discovery option types.
const OPT_PREFIX_INFO: u8 = 3;
/// RFC 8106 recursive DNS servers, the IPv6 equivalent of DHCP option 6.
const OPT_RDNSS: u8 = 25;

const FLAG_MANAGED: u8 = 0x80;
const FLAG_OTHER: u8 = 0x40;
const PREFIX_ON_LINK: u8 = 0x80;
const PREFIX_AUTONOMOUS: u8 = 0x40;

/// One prefix information option.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PrefixInfo {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    /// L: addresses inside the prefix are reachable without a router.
    pub on_link: bool,
    /// A: the prefix may be used to form an address. Without it the prefix is
    /// routing information only, and an address must come from DHCPv6.
    pub autonomous: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
}

impl PrefixInfo {
    /// The SLAAC address this prefix gives an interface, if it may be used for
    /// one at all.
    pub fn slaac(&self, mac: [u8; 6]) -> Option<Ipv6Addr> {
        self.autonomous
            .then(|| slaac_address(self.prefix, self.prefix_len, mac))
            .flatten()
    }
}

/// A parsed Router Advertisement.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RouterAdvert {
    pub hop_limit: u8,
    /// M: take the address from DHCPv6 rather than forming one from a prefix.
    pub managed: bool,
    /// O: take DNS and the rest of the configuration from DHCPv6, even where
    /// the address is formed locally.
    pub other_config: bool,
    /// Seconds this router may serve as a default route. Zero means it is
    /// advertising itself as not a default router, which is how a router
    /// withdraws without disappearing.
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub prefixes: Vec<PrefixInfo>,
    /// RFC 8106 RDNSS addresses.
    pub dns: Vec<Ipv6Addr>,
}

impl RouterAdvert {
    /// Decode an ICMPv6 message body, starting at the type byte.
    ///
    /// The checksum is not verified: it covers an IPv6 pseudo-header that is
    /// not in this buffer, and the kernel has already checked it before any
    /// ICMPv6 message reaches userspace.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < RA_HDR_LEN || buf[0] != ROUTER_ADVERTISEMENT || buf[1] != 0 {
            return Err(Error::Malformed);
        }
        let mut advert = Self {
            hop_limit: buf[4],
            managed: buf[5] & FLAG_MANAGED != 0,
            other_config: buf[5] & FLAG_OTHER != 0,
            router_lifetime: u16::from_be_bytes([buf[6], buf[7]]),
            reachable_time: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            retrans_timer: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            prefixes: Vec::new(),
            dns: Vec::new(),
        };

        let mut i = RA_HDR_LEN;
        while i < buf.len() {
            let header = buf.get(i..i + 2).ok_or(Error::Malformed)?;
            // RFC 4861 §4.6 states the length in units of eight octets and
            // forbids zero. Accepting zero would loop here forever, which is
            // the whole attack.
            let len = header[1] as usize * 8;
            if len == 0 {
                return Err(Error::Malformed);
            }
            let opt = buf.get(i..i + len).ok_or(Error::Malformed)?;
            i += len;

            match header[0] {
                OPT_PREFIX_INFO => advert.prefixes.push(prefix_info(opt)?),
                OPT_RDNSS => advert.dns.extend(rdnss(opt)?),
                // Source link-layer address, MTU, route information and the
                // rest carry nothing caw acts on.
                _ => {}
            }
        }
        Ok(advert)
    }

    /// The first prefix that can form an address on its own.
    pub fn autonomous_prefix(&self) -> Option<&PrefixInfo> {
        self.prefixes.iter().find(|p| p.autonomous)
    }
}

fn prefix_info(opt: &[u8]) -> Result<PrefixInfo, Error> {
    if opt.len() != 32 || opt[2] > 128 {
        return Err(Error::Malformed);
    }
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&opt[16..32]);
    Ok(PrefixInfo {
        prefix: Ipv6Addr::from(prefix),
        prefix_len: opt[2],
        on_link: opt[3] & PREFIX_ON_LINK != 0,
        autonomous: opt[3] & PREFIX_AUTONOMOUS != 0,
        valid_lifetime: u32::from_be_bytes([opt[4], opt[5], opt[6], opt[7]]),
        preferred_lifetime: u32::from_be_bytes([opt[8], opt[9], opt[10], opt[11]]),
    })
}

/// Type, length, two reserved bytes and a lifetime, then whole addresses.
fn rdnss(opt: &[u8]) -> Result<Vec<Ipv6Addr>, Error> {
    let addrs = opt.get(8..).ok_or(Error::Malformed)?;
    if addrs.is_empty() || !addrs.len().is_multiple_of(16) {
        return Err(Error::Malformed);
    }
    Ok(addrs
        .as_chunks::<16>()
        .0
        .iter()
        .copied()
        .map(Ipv6Addr::from)
        .collect())
}

/// The modified EUI-64 interface identifier for a MAC (RFC 4291 appendix A):
/// `ff fe` is inserted in the middle and the universal/local bit is inverted.
///
/// Deriving the identifier from the MAC makes the same host recognisable on
/// every network it joins, which is why RFC 7217 stable-privacy addressing —
/// a per-prefix identifier hashed from a secret key — is the better long-term
/// default and what caw should move to. EUI-64 stays for now because it is
/// what a prefix alone determines, and it makes the derivation testable
/// against the published vectors.
pub fn eui64_interface_id(mac: [u8; 6]) -> [u8; 8] {
    [
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// Form a SLAAC address from a prefix and a MAC.
///
/// Returns `None` unless the prefix is a /64: an EUI-64 identifier is exactly
/// 64 bits, and RFC 4862 requires the prefix and the identifier to add up to
/// the full address.
pub fn slaac_address(prefix: Ipv6Addr, prefix_len: u8, mac: [u8; 6]) -> Option<Ipv6Addr> {
    if prefix_len != 64 {
        return None;
    }
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(&prefix.octets()[..8]);
    octets[8..].copy_from_slice(&eui64_interface_id(mac));
    Some(Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Router Advertisement with the managed and other-config flags set, a
    /// source link-layer address caw ignores, a /64 prefix good for SLAAC, and
    /// one RDNSS server.
    fn advert() -> Vec<u8> {
        let mut buf = vec![
            ROUTER_ADVERTISEMENT,
            0,
            0x00, // checksum, verified by the kernel before we see it
            0x00,
            64,   // cur hop limit
            0xc0, // M and O
            0x07,
            0x08, // router lifetime 1800
            0x00,
            0x00,
            0x00,
            0x00, // reachable time
            0x00,
            0x00,
            0x00,
            0x00, // retrans timer
        ];
        // Source link-layer address: skipped, but it must not derail the walk.
        buf.extend_from_slice(&[1, 1, 0x00, 0x1c, 0x42, 0x00, 0x00, 0x08]);
        buf.extend_from_slice(&[OPT_PREFIX_INFO, 4, 64, 0xc0]);
        buf.extend_from_slice(&2_592_000u32.to_be_bytes()); // valid
        buf.extend_from_slice(&604_800u32.to_be_bytes()); // preferred
        buf.extend_from_slice(&[0, 0, 0, 0]); // reserved
        buf.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0xacab, 1, 0, 0, 0, 0).octets());
        buf.extend_from_slice(&[OPT_RDNSS, 3, 0, 0]);
        buf.extend_from_slice(&1_800u32.to_be_bytes());
        buf.extend_from_slice(&Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).octets());
        buf
    }

    #[test]
    fn decodes_flags_lifetimes_and_options() {
        let ra = RouterAdvert::decode(&advert()).unwrap();
        assert!(ra.managed && ra.other_config);
        assert_eq!(ra.hop_limit, 64);
        assert_eq!(ra.router_lifetime, 1800);
        assert_eq!(ra.prefixes.len(), 1);

        let prefix = ra.prefixes[0];
        assert_eq!(prefix.prefix_len, 64);
        assert!(prefix.on_link && prefix.autonomous);
        assert_eq!(prefix.valid_lifetime, 2_592_000);
        assert_eq!(prefix.preferred_lifetime, 604_800);
        assert_eq!(
            ra.dns,
            vec![Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)]
        );
    }

    #[test]
    fn rejects_anything_that_is_not_an_advertisement() {
        let mut buf = advert();
        buf[0] = 133; // Router Solicitation
        assert_eq!(RouterAdvert::decode(&buf), Err(Error::Malformed));
        buf[0] = ROUTER_ADVERTISEMENT;
        buf[1] = 1;
        assert_eq!(RouterAdvert::decode(&buf), Err(Error::Malformed));
    }

    #[test]
    fn rejects_a_zero_length_option() {
        // The classic denial of service: a length of zero advances the walk by
        // nothing, so a parser that trusts it never returns.
        let mut buf = advert();
        buf[RA_HDR_LEN + 1] = 0;
        assert_eq!(RouterAdvert::decode(&buf), Err(Error::Malformed));
    }

    #[test]
    fn rejects_an_option_running_past_the_end() {
        let mut buf = advert();
        buf[RA_HDR_LEN + 1] = 40;
        assert_eq!(RouterAdvert::decode(&buf), Err(Error::Malformed));
    }

    #[test]
    fn truncations_never_panic() {
        let buf = advert();
        for n in 0..buf.len() {
            let _ = RouterAdvert::decode(&buf[..n]);
        }
    }

    #[test]
    fn eui64_matches_the_published_example() {
        // RFC 4291 appendix A: 00:0c:29:0c:47:d5 becomes 020c:29ff:fe0c:47d5,
        // the universal/local bit having been inverted in the first octet.
        assert_eq!(
            eui64_interface_id([0x00, 0x0c, 0x29, 0x0c, 0x47, 0xd5]),
            [0x02, 0x0c, 0x29, 0xff, 0xfe, 0x0c, 0x47, 0xd5]
        );
        assert_eq!(
            slaac_address(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
                64,
                [0x00, 0x0c, 0x29, 0x0c, 0x47, 0xd5],
            ),
            Some(Ipv6Addr::new(
                0xfe80, 0, 0, 0, 0x020c, 0x29ff, 0xfe0c, 0x47d5
            ))
        );
    }

    #[test]
    fn slaac_needs_a_64_bit_prefix() {
        let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        assert!(slaac_address(prefix, 48, [0; 6]).is_none());
        assert!(slaac_address(prefix, 128, [0; 6]).is_none());
    }

    #[test]
    fn a_prefix_without_the_autonomous_flag_yields_no_address() {
        let mut buf = advert();
        // Clear A, keeping L: routing information only, address from DHCPv6.
        buf[RA_HDR_LEN + 8 + 3] = PREFIX_ON_LINK;
        let ra = RouterAdvert::decode(&buf).unwrap();
        assert!(ra.autonomous_prefix().is_none());
        assert!(
            ra.prefixes[0]
                .slaac([0x00, 0x1c, 0x42, 0x00, 0x00, 0x08])
                .is_none()
        );
    }

    #[test]
    fn forms_an_address_from_the_advertised_prefix() {
        let ra = RouterAdvert::decode(&advert()).unwrap();
        let prefix = ra.autonomous_prefix().unwrap();
        assert_eq!(
            prefix.slaac([0x00, 0x1c, 0x42, 0x00, 0x00, 0x08]),
            Some(Ipv6Addr::new(
                0x2001, 0x0db8, 0xacab, 0x0001, 0x021c, 0x42ff, 0xfe00, 0x0008
            ))
        );
    }
}
