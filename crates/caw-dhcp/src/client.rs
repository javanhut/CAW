//! The DHCPv4 client state machine (RFC 2131).
//!
//! Sans-IO: [`Dhcp4::poll`] takes an [`Input`] and returns [`Action`]s. It
//! opens no socket and reads no clock, so a whole lease lifetime —
//! DISCOVER through renewal, rebinding and expiry — runs in a unit test with
//! no kernel and no network.
//!
//! ```text
//!   Init ──Start──► Selecting ──OFFER──► Requesting ──ACK──► Bound
//!                       ▲                     │                │
//!                       │                     NAK              T1
//!                       └─────────────────────┘                ▼
//!                                                          Renewing ──T2──► Rebinding
//!                                                              │                │
//!                                                             ACK              lease expiry
//!                                                              ▼                ▼
//!                                                            Bound            Init
//! ```

use std::net::Ipv4Addr;

use crate::message::{BOOTREPLY, FLAG_BROADCAST, Message};
use crate::options::{
    DhcpOption, MessageType, OPT_DNS, OPT_LEASE_TIME, OPT_ROUTER, OPT_SERVER_ID, OPT_SUBNET_MASK,
    OPT_T1, OPT_T2,
};
use crate::{Error, prefix_len_from_mask};

/// Options caw asks every server for. Requesting nothing it cannot use keeps
/// replies small enough to avoid option overload on most servers.
const PARAM_REQUEST: [u8; 6] = [
    OPT_SUBNET_MASK,
    OPT_ROUTER,
    OPT_DNS,
    OPT_LEASE_TIME,
    OPT_T1,
    OPT_T2,
];

/// RFC 2131 §4.4.5 floors the renewal retransmission interval at one minute,
/// so a short lease cannot turn into a busy loop.
const MIN_RENEW_INTERVAL: u32 = 60;

/// A configured address and everything that comes with it.
///
/// The timers are durations from the moment the lease was granted, not wall
/// clock instants: this crate has no clock, and the daemon that owns the
/// timers does.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Lease {
    pub addr: Ipv4Addr,
    /// Derived from the subnet mask option, because the kernel takes a prefix
    /// length and DHCP sends a mask.
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// The server that granted it, and where renewals are addressed.
    pub server: Ipv4Addr,
    pub lease_secs: u32,
    /// T1: start renewing with the granting server.
    pub renew_secs: u32,
    /// T2: give up on that server and broadcast to any.
    pub rebind_secs: u32,
}

impl Lease {
    /// Read a lease out of a DHCPACK.
    pub fn from_ack(msg: &Message) -> Result<Self, Error> {
        match msg.message_type() {
            Some(MessageType::Ack) => {}
            Some(MessageType::Nak) => return Err(Error::Nak),
            _ => return Err(Error::Malformed),
        }
        if msg.yiaddr.is_unspecified() {
            return Err(Error::Malformed);
        }

        let mask = match msg.get(OPT_SUBNET_MASK) {
            Some(DhcpOption::SubnetMask(m)) => *m,
            _ => return Err(Error::Incomplete(OPT_SUBNET_MASK)),
        };
        let prefix_len = prefix_len_from_mask(mask).ok_or(Error::Malformed)?;
        let lease_secs = match msg.get(OPT_LEASE_TIME) {
            Some(DhcpOption::LeaseTime(t)) => *t,
            _ => return Err(Error::Incomplete(OPT_LEASE_TIME)),
        };
        let server = msg.server_id().ok_or(Error::Incomplete(OPT_SERVER_ID))?;

        // A router of 0.0.0.0 is how some servers say "no gateway"; treating it
        // as one would install a default route to nowhere.
        let gateway = match msg.get(OPT_ROUTER) {
            Some(DhcpOption::Router(list)) => list.iter().copied().find(|a| !a.is_unspecified()),
            _ => None,
        };
        let dns = match msg.get(OPT_DNS) {
            Some(DhcpOption::Dns(list)) => list.clone(),
            _ => Vec::new(),
        };

        // RFC 2131 §4.4.5 defaults: half the lease, then seven eighths of it.
        // The u64 keeps an infinite lease (0xffffffff) from overflowing.
        let default_t1 = (u64::from(lease_secs) / 2) as u32;
        let default_t2 = (u64::from(lease_secs) * 7 / 8) as u32;
        // A server may set its own timers, but only inside the lease it just
        // granted. A T1 past expiry would leave caw waiting to renew an address
        // it no longer holds, so out-of-range values fall back to the defaults.
        let renew_secs = match msg.get(OPT_T1) {
            Some(DhcpOption::T1(t)) if *t > 0 && *t < lease_secs => *t,
            _ => default_t1,
        };
        let rebind_secs = match msg.get(OPT_T2) {
            Some(DhcpOption::T2(t)) if *t > renew_secs && *t < lease_secs => *t,
            _ => default_t2.max(renew_secs),
        };

        Ok(Self {
            addr: msg.yiaddr,
            prefix_len,
            gateway,
            dns,
            server,
            lease_secs,
            renew_secs,
            rebind_secs,
        })
    }

    pub fn netmask(&self) -> Ipv4Addr {
        crate::mask_from_prefix_len(self.prefix_len).unwrap_or(Ipv4Addr::BROADCAST)
    }
}

/// Where the exchange has got to. The names are RFC 2131's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// No lease and no exchange running. Reached at startup, after a NAK and
    /// after expiry; the caller restarts it with [`Input::Start`] and a fresh
    /// transaction id.
    Init,
    /// DISCOVER sent, waiting for offers.
    Selecting,
    /// An offer accepted, REQUEST sent, waiting for the ACK.
    Requesting,
    Bound,
    /// Past T1, renewing with the server that granted the lease.
    Renewing,
    /// Past T2, asking any server on the segment.
    Rebinding,
}

/// Timers the caller arms on the machine's behalf.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Timer {
    /// Nothing came back; send the current message again.
    Retransmit,
    /// T1.
    Renew,
    /// T2.
    Rebind,
    /// The lease is over.
    Expire,
}

/// Why a configured lease has to come off the interface.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    /// The server refused the address, typically because the client moved to
    /// a different segment.
    Nak,
    Expired,
}

/// What happens to the machine.
pub enum Input<'a> {
    /// Begin an exchange with a fresh transaction id. The id is a parameter
    /// rather than something the machine draws itself, because reading the
    /// system's entropy pool is I/O and this machine performs none; see
    /// [`crate::new_xid`].
    Start(u32),
    /// A UDP payload arrived on port 68. Anything that does not parse, or is
    /// not part of this exchange, is dropped silently — the socket sees every
    /// client's traffic on the segment.
    Datagram(&'a [u8]),
    Timeout(Timer),
}

/// What the caller must do. Nothing here is performed by this crate.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Action {
    /// Send to 255.255.255.255:67. The interface may still have no address,
    /// which is what [`crate::Dhcp4Socket`] exists for.
    Broadcast(Vec<u8>),
    /// Send to one server on port 67, from the leased address.
    Unicast { to: Ipv4Addr, data: Vec<u8> },
    /// Arm `timer` to fire in `secs` seconds, replacing any previous arming.
    SetTimer { timer: Timer, secs: u32 },
    /// The lease is ours: put it on the interface.
    Configured(Lease),
    /// Take the configuration back off; the address is no longer valid.
    Deconfigure(Reason),
}

/// One DHCPv4 exchange on one interface.
pub struct Dhcp4 {
    mac: [u8; 6],
    hostname: Option<String>,
    xid: u32,
    state: State,
    /// Option 54 of the offer or ack in play.
    server: Option<Ipv4Addr>,
    offered: Ipv4Addr,
    lease: Option<Lease>,
    tries: u32,
    /// Seconds spent in this exchange, for the BOOTP `secs` field. Summed from
    /// the intervals the machine asked for rather than read from a clock.
    elapsed: u32,
    renew_interval: u32,
}

impl Dhcp4 {
    /// `xid` should come from [`crate::new_xid`]; anything predictable lets an
    /// off-segment attacker forge replies.
    pub fn new(mac: [u8; 6], xid: u32) -> Self {
        Self {
            mac,
            hostname: None,
            xid,
            state: State::Init,
            server: None,
            offered: Ipv4Addr::UNSPECIFIED,
            lease: None,
            tries: 0,
            elapsed: 0,
            renew_interval: MIN_RENEW_INTERVAL,
        }
    }

    /// Send option 12, so the machine appears under its own name in the
    /// server's lease table and, on most home routers, in local DNS.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    pub fn xid(&self) -> u32 {
        self.xid
    }

    pub fn poll(&mut self, input: Input<'_>) -> Vec<Action> {
        match input {
            Input::Start(xid) => self.start(xid),
            Input::Datagram(bytes) => self.on_datagram(bytes),
            Input::Timeout(timer) => self.on_timeout(timer),
        }
    }

    fn start(&mut self, xid: u32) -> Vec<Action> {
        self.xid = xid;
        self.state = State::Selecting;
        self.server = None;
        self.offered = Ipv4Addr::UNSPECIFIED;
        self.lease = None;
        self.tries = 0;
        self.elapsed = 0;
        self.broadcast(self.discover())
    }

    fn on_datagram(&mut self, bytes: &[u8]) -> Vec<Action> {
        let Ok(msg) = Message::decode(bytes) else {
            return Vec::new();
        };
        if msg.op != BOOTREPLY || msg.xid != self.xid || msg.chaddr[..6] != self.mac {
            return Vec::new();
        }

        match (self.state, msg.message_type()) {
            (State::Selecting, Some(MessageType::Offer)) => self.on_offer(&msg),
            (State::Requesting | State::Renewing | State::Rebinding, Some(MessageType::Ack)) => {
                self.on_ack(&msg)
            }
            (State::Requesting | State::Renewing | State::Rebinding, Some(MessageType::Nak)) => {
                self.on_nak()
            }
            _ => Vec::new(),
        }
    }

    fn on_offer(&mut self, msg: &Message) -> Vec<Action> {
        // Without a server id there is nobody to address the REQUEST to, so
        // the offer is unusable; keep waiting for one that is.
        let Some(server) = msg.server_id() else {
            return Vec::new();
        };
        self.server = Some(server);
        self.offered = msg.yiaddr;
        self.state = State::Requesting;
        self.tries = 0;
        self.broadcast(self.request_selecting())
    }

    fn on_ack(&mut self, msg: &Message) -> Vec<Action> {
        // An ACK missing the mask or the lease time cannot configure anything.
        // Ignoring it leaves the retransmission timer running, which is the
        // right outcome: the exchange fails by timeout rather than by
        // installing half a configuration.
        let Ok(lease) = Lease::from_ack(msg) else {
            return Vec::new();
        };
        self.state = State::Bound;
        self.server = Some(lease.server);
        self.tries = 0;
        self.lease = Some(lease.clone());
        vec![
            Action::SetTimer {
                timer: Timer::Renew,
                secs: lease.renew_secs,
            },
            Action::SetTimer {
                timer: Timer::Rebind,
                secs: lease.rebind_secs,
            },
            Action::SetTimer {
                timer: Timer::Expire,
                secs: lease.lease_secs,
            },
            Action::Configured(lease),
        ]
    }

    fn on_nak(&mut self) -> Vec<Action> {
        self.state = State::Init;
        self.server = None;
        self.lease = None;
        vec![Action::Deconfigure(Reason::Nak)]
    }

    fn on_timeout(&mut self, timer: Timer) -> Vec<Action> {
        match timer {
            Timer::Retransmit => self.retransmit(),
            Timer::Renew if self.state == State::Bound => self.enter_renewing(),
            Timer::Rebind if matches!(self.state, State::Bound | State::Renewing) => {
                self.enter_rebinding()
            }
            Timer::Expire if self.lease.is_some() => {
                self.state = State::Init;
                self.server = None;
                self.lease = None;
                vec![Action::Deconfigure(Reason::Expired)]
            }
            // A timer that fires in a state it no longer applies to is stale,
            // not an error: the caller may have armed it before an ACK arrived.
            _ => Vec::new(),
        }
    }

    fn retransmit(&mut self) -> Vec<Action> {
        match self.state {
            State::Selecting => {
                self.age();
                self.broadcast(self.discover())
            }
            State::Requesting => {
                self.age();
                self.broadcast(self.request_selecting())
            }
            State::Renewing => {
                let secs = self.halve_renew_interval();
                let to = self.server.unwrap_or(Ipv4Addr::BROADCAST);
                vec![
                    Action::Unicast {
                        to,
                        data: self.request_renew(),
                    },
                    Action::SetTimer {
                        timer: Timer::Retransmit,
                        secs,
                    },
                ]
            }
            State::Rebinding => {
                let secs = self.halve_renew_interval();
                vec![
                    Action::Broadcast(self.request_renew()),
                    Action::SetTimer {
                        timer: Timer::Retransmit,
                        secs,
                    },
                ]
            }
            State::Init | State::Bound => Vec::new(),
        }
    }

    fn enter_renewing(&mut self) -> Vec<Action> {
        let Some(lease) = self.lease.clone() else {
            return Vec::new();
        };
        self.state = State::Renewing;
        // Half the time left until T2, per RFC 2131 §4.4.5.
        self.renew_interval =
            (lease.rebind_secs.saturating_sub(lease.renew_secs) / 2).max(MIN_RENEW_INTERVAL);
        let to = lease.server;
        vec![
            Action::Unicast {
                to,
                data: self.request_renew(),
            },
            Action::SetTimer {
                timer: Timer::Retransmit,
                secs: self.renew_interval,
            },
        ]
    }

    fn enter_rebinding(&mut self) -> Vec<Action> {
        let Some(lease) = self.lease.clone() else {
            return Vec::new();
        };
        self.state = State::Rebinding;
        self.renew_interval =
            (lease.lease_secs.saturating_sub(lease.rebind_secs) / 2).max(MIN_RENEW_INTERVAL);
        vec![
            Action::Broadcast(self.request_renew()),
            Action::SetTimer {
                timer: Timer::Retransmit,
                secs: self.renew_interval,
            },
        ]
    }

    fn broadcast(&self, data: Vec<u8>) -> Vec<Action> {
        vec![
            Action::Broadcast(data),
            Action::SetTimer {
                timer: Timer::Retransmit,
                secs: self.backoff(),
            },
        ]
    }

    /// Charge the interval that just elapsed to the BOOTP `secs` field and move
    /// on to the next, longer one.
    fn age(&mut self) {
        self.elapsed = self.elapsed.saturating_add(self.backoff());
        self.tries += 1;
    }

    /// RFC 2131 §4.1: four seconds, doubling to sixty-four, randomised by a
    /// second either way so that a segment full of clients returning after a
    /// power cut does not resynchronise on the server. The jitter is taken
    /// from a bit of the transaction id — itself from `getrandom` — which
    /// leaves this machine with neither a clock nor a generator of its own.
    fn backoff(&self) -> u32 {
        let base = 4u32 << self.tries.min(4);
        if (self.xid >> (self.tries & 31)) & 1 == 0 {
            base - 1
        } else {
            base + 1
        }
    }

    fn halve_renew_interval(&mut self) -> u32 {
        self.renew_interval = (self.renew_interval / 2).max(MIN_RENEW_INTERVAL);
        self.renew_interval
    }

    fn base(&self, kind: MessageType) -> Message {
        let mut msg = Message::request(self.xid, self.mac);
        msg.secs = self.elapsed.min(u16::MAX as u32) as u16;
        msg.options.push(DhcpOption::MessageType(kind));
        // Option 61, hardware type 1 followed by the MAC. Servers key their
        // lease table on it, so sending it keeps the same address across
        // reboots even where the MAC is randomised per association.
        let mut client_id = Vec::with_capacity(7);
        client_id.push(crate::message::HTYPE_ETHERNET);
        client_id.extend_from_slice(&self.mac);
        msg.options.push(DhcpOption::ClientId(client_id));
        if let Some(hostname) = &self.hostname {
            msg.options.push(DhcpOption::HostName(hostname.clone()));
        }
        msg.options
            .push(DhcpOption::ParameterRequest(PARAM_REQUEST.to_vec()));
        msg
    }

    fn discover(&self) -> Vec<u8> {
        let mut msg = self.base(MessageType::Discover);
        msg.flags = FLAG_BROADCAST;
        msg.encode()
    }

    /// The REQUEST that answers an offer. RFC 2131 table 5: the address goes in
    /// option 50 and the chosen server in option 54, because `ciaddr` is still
    /// zero at this point.
    fn request_selecting(&self) -> Vec<u8> {
        let mut msg = self.base(MessageType::Request);
        msg.flags = FLAG_BROADCAST;
        msg.options.push(DhcpOption::RequestedIp(self.offered));
        if let Some(server) = self.server {
            msg.options.push(DhcpOption::ServerId(server));
        }
        msg.encode()
    }

    /// The REQUEST that renews or rebinds. RFC 2131 table 5 again: here the
    /// address moves to `ciaddr` and options 50 and 54 must be absent, which is
    /// how a server tells a renewal from a fresh request.
    fn request_renew(&self) -> Vec<u8> {
        let mut msg = self.base(MessageType::Request);
        msg.ciaddr = self
            .lease
            .as_ref()
            .map_or(Ipv4Addr::UNSPECIFIED, |l| l.addr);
        msg.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::BOOTREPLY;
    use crate::{ACK_CAPTURE, CAPTURE_MAC, CAPTURE_XID};

    const SERVER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const OFFERED: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 24);

    fn offer(xid: u32) -> Vec<u8> {
        let mut msg = Message::request(xid, CAPTURE_MAC);
        msg.op = BOOTREPLY;
        msg.yiaddr = OFFERED;
        msg.options = vec![
            DhcpOption::MessageType(MessageType::Offer),
            DhcpOption::ServerId(SERVER),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::LeaseTime(43_200),
        ];
        msg.encode()
    }

    fn nak(xid: u32) -> Vec<u8> {
        let mut msg = Message::request(xid, CAPTURE_MAC);
        msg.op = BOOTREPLY;
        msg.options = vec![
            DhcpOption::MessageType(MessageType::Nak),
            DhcpOption::ServerId(SERVER),
        ];
        msg.encode()
    }

    fn sent(actions: &[Action]) -> Message {
        let bytes = actions
            .iter()
            .find_map(|a| match a {
                Action::Broadcast(data) => Some(data),
                Action::Unicast { data, .. } => Some(data),
                _ => None,
            })
            .expect("nothing was sent");
        Message::decode(bytes).unwrap()
    }

    fn timer(actions: &[Action], want: Timer) -> u32 {
        actions
            .iter()
            .find_map(|a| match a {
                Action::SetTimer { timer, secs } if *timer == want => Some(*secs),
                _ => None,
            })
            .unwrap_or_else(|| panic!("{want:?} was not armed"))
    }

    fn bound() -> (Dhcp4, Vec<Action>) {
        let mut client = Dhcp4::new(CAPTURE_MAC, CAPTURE_XID).with_hostname("corvus");
        client.poll(Input::Start(CAPTURE_XID));
        client.poll(Input::Datagram(&offer(CAPTURE_XID)));
        let actions = client.poll(Input::Datagram(&ACK_CAPTURE));
        (client, actions)
    }

    #[test]
    fn discover_offer_request_ack() {
        let mut client = Dhcp4::new(CAPTURE_MAC, CAPTURE_XID).with_hostname("corvus");

        let actions = client.poll(Input::Start(CAPTURE_XID));
        assert_eq!(client.state(), State::Selecting);
        let discover = sent(&actions);
        assert_eq!(discover.message_type(), Some(MessageType::Discover));
        // No address yet, so the reply has to come back as a broadcast.
        assert_eq!(discover.flags, FLAG_BROADCAST);
        assert_eq!(
            discover.get(crate::options::OPT_CLIENT_ID),
            Some(&DhcpOption::ClientId(vec![
                1, 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee
            ]))
        );
        assert_eq!(
            discover.get(crate::options::OPT_HOSTNAME),
            Some(&DhcpOption::HostName("corvus".to_owned()))
        );
        assert!(discover.get(crate::options::OPT_PARAM_REQUEST).is_some());
        assert!(timer(&actions, Timer::Retransmit) > 0);

        let actions = client.poll(Input::Datagram(&offer(CAPTURE_XID)));
        assert_eq!(client.state(), State::Requesting);
        let request = sent(&actions);
        assert_eq!(request.message_type(), Some(MessageType::Request));
        // Selecting: the address goes in option 50 and `ciaddr` stays zero.
        assert_eq!(request.get(50), Some(&DhcpOption::RequestedIp(OFFERED)));
        assert_eq!(request.server_id(), Some(SERVER));
        assert!(request.ciaddr.is_unspecified());

        let actions = client.poll(Input::Datagram(&ACK_CAPTURE));
        assert_eq!(client.state(), State::Bound);
        assert_eq!(timer(&actions, Timer::Renew), 21_600);
        assert_eq!(timer(&actions, Timer::Rebind), 37_800);
        assert_eq!(timer(&actions, Timer::Expire), 43_200);
        assert_eq!(
            actions.last(),
            Some(&Action::Configured(client.lease().unwrap().clone()))
        );
    }

    #[test]
    fn captured_ack_yields_the_expected_lease() {
        let (client, _) = bound();
        let lease = client.lease().unwrap();
        assert_eq!(
            *lease,
            Lease {
                addr: Ipv4Addr::new(192, 168, 1, 24),
                prefix_len: 24,
                gateway: Some(SERVER),
                dns: vec![SERVER, Ipv4Addr::new(8, 8, 8, 8)],
                server: SERVER,
                lease_secs: 43_200,
                renew_secs: 21_600,
                rebind_secs: 37_800,
            }
        );
        assert_eq!(lease.netmask(), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn renews_then_rebinds_then_expires() {
        let (mut client, _) = bound();

        let actions = client.poll(Input::Timeout(Timer::Renew));
        assert_eq!(client.state(), State::Renewing);
        // Renewal is unicast to the granting server; the address moves to
        // `ciaddr` and options 50 and 54 must be gone.
        assert!(matches!(actions[0], Action::Unicast { to, .. } if to == SERVER));
        let renew = sent(&actions);
        assert_eq!(renew.ciaddr, OFFERED);
        assert!(renew.get(50).is_none() && renew.get(54).is_none());
        assert!(timer(&actions, Timer::Retransmit) >= MIN_RENEW_INTERVAL);

        let actions = client.poll(Input::Timeout(Timer::Rebind));
        assert_eq!(client.state(), State::Rebinding);
        assert!(matches!(actions[0], Action::Broadcast(_)));
        assert_eq!(sent(&actions).ciaddr, OFFERED);

        let actions = client.poll(Input::Timeout(Timer::Expire));
        assert_eq!(client.state(), State::Init);
        assert_eq!(actions, vec![Action::Deconfigure(Reason::Expired)]);
        assert!(client.lease().is_none());
    }

    #[test]
    fn an_ack_while_renewing_rebinds_the_timers() {
        let (mut client, _) = bound();
        client.poll(Input::Timeout(Timer::Renew));
        let actions = client.poll(Input::Datagram(&ACK_CAPTURE));
        assert_eq!(client.state(), State::Bound);
        assert_eq!(timer(&actions, Timer::Expire), 43_200);
    }

    #[test]
    fn a_nak_drops_the_lease() {
        let mut client = Dhcp4::new(CAPTURE_MAC, CAPTURE_XID);
        client.poll(Input::Start(CAPTURE_XID));
        client.poll(Input::Datagram(&offer(CAPTURE_XID)));
        let actions = client.poll(Input::Datagram(&nak(CAPTURE_XID)));
        assert_eq!(actions, vec![Action::Deconfigure(Reason::Nak)]);
        assert_eq!(client.state(), State::Init);
    }

    #[test]
    fn ignores_traffic_belonging_to_another_client() {
        let mut client = Dhcp4::new(CAPTURE_MAC, CAPTURE_XID);
        client.poll(Input::Start(CAPTURE_XID));
        // Same segment, another exchange.
        assert!(
            client
                .poll(Input::Datagram(&offer(CAPTURE_XID ^ 1)))
                .is_empty()
        );
        // Our own request echoed back: an offer is a reply, a request is not.
        let mut own = Message::request(CAPTURE_XID, CAPTURE_MAC);
        own.options = vec![DhcpOption::MessageType(MessageType::Offer)];
        assert!(client.poll(Input::Datagram(&own.encode())).is_empty());
        assert_eq!(client.state(), State::Selecting);
    }

    #[test]
    fn malformed_datagrams_are_dropped_not_fatal() {
        let mut client = Dhcp4::new(CAPTURE_MAC, CAPTURE_XID);
        client.poll(Input::Start(CAPTURE_XID));
        for n in 0..ACK_CAPTURE.len() {
            assert!(client.poll(Input::Datagram(&ACK_CAPTURE[..n])).is_empty());
        }
        assert!(client.poll(Input::Datagram(&[])).is_empty());
        assert_eq!(client.state(), State::Selecting);
    }

    #[test]
    fn retransmission_backs_off_and_ages_the_secs_field() {
        let mut client = Dhcp4::new(CAPTURE_MAC, CAPTURE_XID);
        let mut secs = 0;
        let mut expect = |actions: &[Action], attempt: u32| {
            // 4 seconds doubling to a ceiling of 64, one second of jitter
            // either way.
            let base = 4u32 << attempt.min(4);
            let interval = timer(actions, Timer::Retransmit);
            assert!(
                interval == base - 1 || interval == base + 1,
                "{interval} vs {base}"
            );
            // The BOOTP `secs` field has to keep climbing, since relays use it
            // to decide when a client has waited long enough for them to help.
            let message = sent(actions);
            assert!(message.secs > secs || attempt == 0);
            secs = message.secs;
        };

        expect(&client.poll(Input::Start(CAPTURE_XID)), 0);
        for attempt in 1..7 {
            expect(&client.poll(Input::Timeout(Timer::Retransmit)), attempt);
        }
    }

    #[test]
    fn an_ack_without_a_mask_is_not_a_lease() {
        let mut msg = Message::request(CAPTURE_XID, CAPTURE_MAC);
        msg.op = BOOTREPLY;
        msg.yiaddr = OFFERED;
        msg.options = vec![
            DhcpOption::MessageType(MessageType::Ack),
            DhcpOption::ServerId(SERVER),
            DhcpOption::LeaseTime(600),
        ];
        assert_eq!(
            Lease::from_ack(&msg),
            Err(Error::Incomplete(crate::options::OPT_SUBNET_MASK))
        );
    }

    #[test]
    fn server_timers_outside_the_lease_fall_back_to_the_defaults() {
        let mut msg = Message::request(CAPTURE_XID, CAPTURE_MAC);
        msg.op = BOOTREPLY;
        msg.yiaddr = OFFERED;
        msg.options = vec![
            DhcpOption::MessageType(MessageType::Ack),
            DhcpOption::ServerId(SERVER),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::LeaseTime(3_600),
            // T1 and T2 both past expiry.
            DhcpOption::T1(7_200),
            DhcpOption::T2(9_000),
        ];
        let lease = Lease::from_ack(&msg).unwrap();
        assert_eq!(lease.renew_secs, 1_800);
        assert_eq!(lease.rebind_secs, 3_150);
    }

    #[test]
    fn an_infinite_lease_does_not_overflow_its_timers() {
        let mut msg = Message::request(CAPTURE_XID, CAPTURE_MAC);
        msg.op = BOOTREPLY;
        msg.yiaddr = OFFERED;
        msg.options = vec![
            DhcpOption::MessageType(MessageType::Ack),
            DhcpOption::ServerId(SERVER),
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::LeaseTime(u32::MAX),
        ];
        let lease = Lease::from_ack(&msg).unwrap();
        assert_eq!(lease.renew_secs, u32::MAX / 2);
        assert!(lease.rebind_secs > lease.renew_secs && lease.rebind_secs < u32::MAX);
    }

    #[test]
    fn a_nak_is_reported_as_such() {
        let msg = Message::decode(&nak(CAPTURE_XID)).unwrap();
        assert_eq!(Lease::from_ack(&msg), Err(Error::Nak));
    }
}
