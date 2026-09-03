//! The socket shell: everything in this crate that talks to the kernel.
//!
//! Deliberately thin. Each method builds a request with [`crate::msg`], hands
//! it to `caw-netlink`, and feeds the replies to a parser that knows nothing
//! about sockets. Commands and events use separate sockets, because a
//! multicast notification arriving mid-dump would otherwise have to be told
//! apart from the dump.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use caw_netlink::{HDR_LEN, Socket, align};
use rustix::net::{AddressFamily, RecvFlags, SocketFlags, SocketType, netlink};

use crate::attr::Attrs;
use crate::consts::*;
use crate::wiphy::WiphyChunk;
use crate::{Bss, Connect, Error, Event, Family, Interface, KeyScope, Wiphy, msg};

/// The nl80211 family name, as registered by cfg80211.
pub const NL80211_FAMILY_NAME: &str = "nl80211";

/// Ask the generic-netlink controller to resolve a family by name.
///
/// Generic netlink allocates `nlmsg_type` at registration, so nothing can be
/// sent to a family before this has run.
pub fn resolve_genl_family(sock: &mut Socket, name: &str) -> Result<Family, Error> {
    let seq = sock.next_seq();
    let req = msg::get_family(seq, name);

    let mut found = None;
    match sock.request(&req, |m| {
        found = Family::parse(m.payload);
        Ok(())
    }) {
        Ok(()) => {}
        // ENOENT here means no such family, which for nl80211 means cfg80211
        // is not loaded — worth saying plainly rather than as an errno.
        Err(caw_netlink::Error::Kernel(2)) => return Err(Error::NoFamily(name.to_owned())),
        Err(e) => return Err(e.into()),
    }
    found.ok_or_else(|| Error::NoFamily(name.to_owned()))
}

/// A handle on nl80211: a generic-netlink socket plus the resolved family.
pub struct Nl80211 {
    sock: Socket,
    family: Family,
}

impl Nl80211 {
    pub fn open() -> Result<Self, Error> {
        let mut sock = Socket::generic()?;
        let family = resolve_genl_family(&mut sock, NL80211_FAMILY_NAME)?;
        Ok(Self { sock, family })
    }

    pub fn family(&self) -> &Family {
        &self.family
    }

    /// Every wireless PHY on the system.
    pub fn wiphys(&mut self) -> Result<Vec<Wiphy>, Error> {
        let seq = self.sock.next_seq();
        let req = msg::get_wiphy(self.family.id, seq);

        let mut out: Vec<Wiphy> = Vec::new();
        self.sock.request(&req, |m| {
            let Some(chunk) = WiphyChunk::parse(&m) else {
                return Ok(());
            };
            // A split dump spreads one wiphy over several messages, each
            // naming the same index.
            match out.iter_mut().find(|w| w.index == chunk.index) {
                Some(existing) => chunk.merge_into(existing),
                None => out.push(chunk.into_wiphy()),
            }
            Ok(())
        })?;
        out.sort_by_key(|w| w.index);
        Ok(out)
    }

    /// Every wireless interface, across every PHY.
    pub fn interfaces(&mut self) -> Result<Vec<Interface>, Error> {
        let seq = self.sock.next_seq();
        let req = msg::get_interface(self.family.id, seq);

        let mut out = Vec::new();
        self.sock.request(&req, |m| {
            if let Some(iface) = Interface::parse(&m) {
                out.push(iface);
            }
            Ok(())
        })?;
        out.sort_by_key(|i| i.ifindex);
        Ok(out)
    }

    /// Start a scan. It completes asynchronously; watch for
    /// [`Event::ScanComplete`] and then call [`Nl80211::scan_results`].
    ///
    /// An empty `ssids` is a wildcard active scan; naming an SSID additionally
    /// probes for a network that hides it.
    pub fn trigger_scan(&mut self, ifindex: u32, ssids: &[&[u8]]) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = msg::trigger_scan(self.family.id, seq, ifindex, ssids);
        self.sock.request(&req, |_| Ok(()))?;
        Ok(())
    }

    /// The kernel's scan cache. Entries survive the scan that found them, so
    /// this answers without a radio being involved.
    pub fn scan_results(&mut self, ifindex: u32) -> Result<Vec<Bss>, Error> {
        let seq = self.sock.next_seq();
        let req = msg::get_scan(self.family.id, seq, ifindex);

        let mut out = Vec::new();
        self.sock.request(&req, |m| {
            if let Some(bss) = Attrs::of_body(m.payload)
                .find(NL80211_ATTR_BSS)
                .and_then(|a| Bss::parse(a.payload))
            {
                out.push(bss);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Associate. The result arrives as [`Event::Connected`] on the `mlme`
    /// group; the ACK to this request only says the kernel accepted it.
    pub fn connect(&mut self, ifindex: u32, req: &Connect<'_>) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let bytes = msg::connect(self.family.id, seq, ifindex, req);
        self.sock.request(&bytes, |_| Ok(()))?;
        Ok(())
    }

    pub fn disconnect(&mut self, ifindex: u32, reason: u16) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = msg::disconnect(self.family.id, seq, ifindex, reason);
        self.sock.request(&req, |_| Ok(()))?;
        Ok(())
    }

    /// Switch the station's 802.11 power saving on or off. See
    /// [`msg::set_power_save`] for what that does and does not cover.
    ///
    /// `EOPNOTSUPP` from the kernel means the driver offers no control over
    /// it, which is the case for an interface that is not a station.
    pub fn set_power_save(&mut self, ifindex: u32, enabled: bool) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = msg::set_power_save(self.family.id, seq, ifindex, enabled);
        self.sock.request(&req, |_| Ok(()))?;
        Ok(())
    }

    /// Install the pairwise key from a completed 4-way handshake.
    pub fn new_pairwise_key(
        &mut self,
        ifindex: u32,
        peer: [u8; 6],
        cipher: u32,
        key: &[u8],
    ) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = msg::new_pairwise_key(self.family.id, seq, ifindex, peer, cipher, key);
        self.sock.request(&req, |_| Ok(()))?;
        Ok(())
    }

    /// Install a group key. Making it the one broadcast traffic is decrypted
    /// with is a second step, [`Nl80211::set_default_key`].
    pub fn new_group_key(
        &mut self,
        ifindex: u32,
        idx: u8,
        cipher: u32,
        key: &[u8],
        rsc: &[u8],
    ) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = msg::new_group_key(self.family.id, seq, ifindex, idx, cipher, key, rsc);
        self.sock.request(&req, |_| Ok(()))?;
        Ok(())
    }

    pub fn set_default_key(&mut self, ifindex: u32, idx: u8, scope: KeyScope) -> Result<(), Error> {
        let seq = self.sock.next_seq();
        let req = msg::set_default_key(self.family.id, seq, ifindex, idx, scope);
        self.sock.request(&req, |_| Ok(()))?;
        Ok(())
    }

    /// Subscribe to this family's multicast groups on a socket of their own.
    pub fn events(&self) -> Result<Events, Error> {
        Events::open(&self.family)
    }
}

/// A socket subscribed to nl80211's multicast groups.
///
/// Non-blocking, and exposes its descriptor, because `cawd` polls it alongside
/// rtnetlink, the EAPOL socket and its timers.
pub struct Events {
    fd: OwnedFd,
    family_id: u16,
    buf: Vec<u8>,
}

impl Events {
    pub fn open(family: &Family) -> Result<Self, Error> {
        let groups = family.groups.mask()?;
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(netlink::GENERIC),
        )?;
        // Group membership is set here, in the bind address, rather than with
        // NETLINK_ADD_MEMBERSHIP; see `Groups::mask`.
        rustix::net::bind(&fd, &netlink::SocketAddrNetlink::new(0, groups))?;
        Ok(Self {
            fd,
            family_id: family.id,
            buf: vec![0u8; 64 * 1024],
        })
    }

    /// Decode everything the kernel has queued. An empty vector means nothing
    /// was waiting.
    pub fn read(&mut self) -> Result<Vec<Event>, Error> {
        let mut out = Vec::new();
        loop {
            let (n, actual) =
                match rustix::net::recv(&self.fd, &mut self.buf[..], RecvFlags::empty()) {
                    Ok(v) => v,
                    Err(rustix::io::Errno::AGAIN) => return Ok(out),
                    Err(e) => return Err(e.into()),
                };
            // A datagram the kernel had to truncate is unparseable, but the
            // ones behind it in the queue are not, so drop this one and keep
            // draining. No nl80211 notification comes close to 64 KiB.
            if actual > n {
                continue;
            }

            let mut rest = &self.buf[..n];
            while rest.len() >= HDR_LEN {
                let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
                if len < HDR_LEN || len > rest.len() {
                    break;
                }
                let kind = u16::from_ne_bytes([rest[4], rest[5]]);
                if kind == self.family_id
                    && let Some(event) = Event::decode(&rest[HDR_LEN..len])
                {
                    out.push(event);
                }
                rest = &rest[align(len).min(rest.len())..];
            }
        }
    }
}

impl AsFd for Events {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
