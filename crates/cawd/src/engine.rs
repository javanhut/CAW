//! The seam between the daemon's descriptors and `caw-core`'s decisions.
//!
//! `caw-core` consumes an [`Input`] and returns [`Action`]s; this module
//! performs them against the sockets the reactor owns and turns what comes
//! back into the [`caw_ipc::Event`]s a waiting `caw connect` prints. Nothing
//! here chooses anything: which BSS to join, which AKM to negotiate and when
//! to give up are all decided in `caw-core`, and every branch below is either
//! a syscall or a rendering.
//!
//! # What cannot be performed yet
//!
//! Two actions have no transport under them, and each returns an error
//! naming what is missing rather than pretending to succeed:
//!
//!   * `SendMgmtFrame` — SAE's commit and confirm need `NL80211_CMD_FRAME`,
//!     which `caw-nl80211` does not encode.
//!   * `Associate` with an [`Offload`](caw_core::Offload) — a device that runs
//!     the handshake in firmware wants `NL80211_ATTR_PMK` or
//!     `NL80211_ATTR_SAE_PASSWORD` in the connect request, and
//!     `caw_nl80211::Connect` has no field for either.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use caw_core::{
    Action, Command, Connection, Device, DeviceCaps, Input, LeaseEvent, State, TimerId, profile,
};
use caw_dhcp::{Dhcp4, Dhcp4Socket};
use caw_eapol::EapolSocket;
use caw_ipc::{Event, Response, SecretKind};
use caw_nl80211::{Connect, KeyScope, Nl80211};
use caw_rtnl::{Rtnl, format_mac};

use crate::ipc::{ClientId, Server};
use crate::log;
use crate::reactor::Key;
use crate::timers::Timers;

/// The descriptors an action may be performed against.
///
/// Assembled per call rather than held, so the reactor keeps ownership of
/// every one of them and this module cannot outlive a socket it was handed.
pub struct Ports<'a> {
    pub nl: Option<&'a mut Nl80211>,
    pub eapol: &'a mut Option<EapolSocket>,
    pub rtnl: Option<&'a mut Rtnl>,
    /// The DHCPv4 exchange in progress, if any. Owned by the reactor so its
    /// socket sits in the poll set; driven from here.
    pub dhcp: &'a mut Option<DhcpRun>,
    pub timers: &'a mut Timers<Key>,
    pub server: &'a mut Server,
    pub now: Instant,
}

/// One DHCPv4 exchange: the state machine and the socket it speaks through.
pub struct DhcpRun {
    pub socket: Dhcp4Socket,
    pub machine: Dhcp4,
    /// The interface the exchange runs on, so the probe route can be taken
    /// off it again without asking the engine which link that was.
    pub ifindex: u32,
    /// Whether `Rtnl::add_dhcp_probe_route` succeeded and has not been undone.
    pub probe_route: bool,
}

impl Ports<'_> {
    fn nl(&mut self) -> Result<&mut Nl80211, String> {
        match self.nl.as_mut() {
            Some(nl) => Ok(nl),
            None => Err(NO_WIRELESS.to_owned()),
        }
    }
}

/// How many times an action may feed an input back into the state machine
/// before the daemon decides the two are talking past each other.
///
/// A fetch of scan results is an action that produces an input, so the loop is
/// real; a bound on it is what stops a bug in either half from becoming a
/// daemon that spins at 100% with a connection half up.
const MAX_TURNS: usize = 32;

const NO_WIRELESS: &str = "no wireless stack: the kernel has no nl80211 family";

pub struct Engine {
    core: Option<Connection>,
    device: Option<Device>,
    /// The client watching the connection in progress. It gets the events and
    /// the final response; everybody else sees the outcome in `caw status`.
    watcher: Option<ClientId>,
    /// The outstanding [`Event::NeedSecret`], so a secret from another client
    /// or an old prompt cannot be slipped into this connection.
    pending_secret: Option<PendingSecret>,
    next_token: u64,
    profile_dir: PathBuf,
}

struct PendingSecret {
    token: u64,
    client: ClientId,
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    pub fn new() -> Self {
        Self {
            core: None,
            device: None,
            watcher: None,
            pending_secret: None,
            next_token: 1,
            profile_dir: PathBuf::from(profile::DEFAULT_DIR),
        }
    }

    pub fn ifindex(&self) -> Option<u32> {
        self.device.map(|d| d.ifindex)
    }

    pub fn ssid(&self) -> Option<String> {
        let ssid = self.core.as_ref()?.ssid()?;
        Some(String::from_utf8_lossy(ssid).into_owned())
    }

    pub fn state_name(&self) -> String {
        format!("{:?}", self.state())
    }

    fn state(&self) -> State {
        self.core.as_ref().map_or(State::Idle, Connection::state)
    }

    /// Nothing joined and nothing being joined.
    ///
    /// What the reactor's autoconnect loop asks before it starts an attempt,
    /// so a link already up — or one `caw-core` is already re-establishing —
    /// is left alone.
    pub fn is_idle(&self) -> bool {
        self.state() == State::Idle
    }

    /// Join a network. Progress reaches `client` as events until the
    /// connection settles, one way or the other.
    pub fn connect(
        &mut self,
        ifindex: u32,
        ssid: &str,
        client: ClientId,
        ports: &mut Ports<'_>,
    ) -> Result<(), String> {
        if ssid.is_empty() {
            return Err("a network name cannot be empty".to_owned());
        }
        self.prepare(ifindex, ports)?;
        // A second connect supersedes the first, and `caw-core` tears the old
        // attempt down. Say so, or the client that asked for it waits on a
        // response that is never coming.
        if let Some(previous) = self.watcher.replace(client)
            && previous != client
        {
            ports.server.send(
                previous,
                Response::error("superseded by another connect request"),
            );
        }
        self.pending_secret = None;
        self.feed(
            Input::Command(Command::Connect {
                ssid: ssid.as_bytes().to_vec(),
            }),
            ports,
        );
        Ok(())
    }

    /// Join the strongest known network in range, with nobody watching.
    ///
    /// The one entry point with no [`ClientId`]: it is the daemon acting on
    /// its own, so there is nobody to prompt and nobody to answer. That is
    /// also why it cannot join a network with no saved credential —
    /// `Action::RequestSecret` with no watcher is reported as a failure — and
    /// why [`caw_core::policy::best_known`] only ever offers saved ones.
    ///
    /// This is where the profile store is first read on a machine that has not
    /// been told to connect to anything: [`Self::prepare`] loads it.
    pub fn autoconnect(&mut self, ifindex: u32, ports: &mut Ports<'_>) -> Result<(), String> {
        self.prepare(ifindex, ports)?;
        self.feed(Input::Command(Command::Autoconnect), ports);
        Ok(())
    }

    pub fn disconnect(
        &mut self,
        ssid: &str,
        client: ClientId,
        ports: &mut Ports<'_>,
    ) -> Result<(), String> {
        match self.ssid() {
            Some(current) if current == ssid => {}
            Some(current) => return Err(format!("connected to {current}, not {ssid}")),
            None => return Err("not connected".to_owned()),
        }
        self.watcher = Some(client);
        self.feed(Input::Command(Command::Disconnect), ports);
        Ok(())
    }

    /// Answer an [`Event::NeedSecret`].
    pub fn secret(
        &mut self,
        token: u64,
        value: caw_ipc::Secret,
        client: ClientId,
        ports: &mut Ports<'_>,
    ) -> Result<(), String> {
        // A secret is only ever accepted from the client that was asked, for
        // the prompt it was asked for. Otherwise any user on the machine could
        // answer somebody else's passphrase prompt with a passphrase of their
        // choosing and watch which network it joins.
        match self.pending_secret.take() {
            Some(pending) if pending.token == token && pending.client == client => {}
            Some(pending) => {
                self.pending_secret = Some(pending);
                return Err("no secret was asked of you".to_owned());
            }
            None => return Err("nothing is waiting for a secret".to_owned()),
        }

        self.feed(
            Input::Command(Command::Secret {
                value: profile::Secret::new(value.expose()),
            }),
            ports,
        );
        Ok(())
    }

    pub fn on_wireless(&mut self, event: caw_nl80211::Event, ports: &mut Ports<'_>) {
        self.feed(Input::Wireless(event), ports);
    }

    pub fn on_eapol(&mut self, frame: Vec<u8>, ports: &mut Ports<'_>) {
        self.feed(Input::Eapol(frame), ports);
    }

    pub fn on_dhcp_datagram(&mut self, bytes: &[u8], ports: &mut Ports<'_>) {
        if let Some(event) = Self::drive_dhcp(ports, caw_dhcp::Input::Datagram(bytes)) {
            self.feed(Input::Lease(event), ports);
        }
    }

    pub fn on_dhcp_timer(&mut self, timer: caw_dhcp::Timer, ports: &mut Ports<'_>) {
        if let Some(event) = Self::drive_dhcp(ports, caw_dhcp::Input::Timeout(timer)) {
            // An exchange that gave up has no socket worth polling and no
            // probe route worth keeping; a retry starts a fresh one.
            if matches!(event, LeaseEvent::Failed) {
                Self::stop_dhcp(ports);
            }
            self.feed(Input::Lease(event), ports);
        }
    }

    pub fn on_timer(&mut self, id: TimerId, ports: &mut Ports<'_>) {
        self.feed(Input::Timer(id), ports);
    }

    /// A client disconnected; stop streaming to it.
    ///
    /// The connection itself carries on: `caw connect` exiting after the link
    /// is up must not take the link down, which is the whole reason the daemon
    /// outlives the CLI.
    pub fn forget_client(&mut self, id: ClientId) {
        if self.watcher == Some(id) {
            self.watcher = None;
        }
        if self.pending_secret.as_ref().is_some_and(|p| p.client == id) {
            self.pending_secret = None;
        }
    }

    /// Leave the air cleanly on the way out.
    pub fn shut_down(&mut self, ports: &mut Ports<'_>) {
        if self.core.is_some() && !self.is_idle() {
            self.feed(Input::Command(Command::Disconnect), ports);
        }
    }

    /// Make sure there is a state machine, and an EAPOL socket for it to
    /// speak through, for this interface.
    fn prepare(&mut self, ifindex: u32, ports: &mut Ports<'_>) -> Result<(), String> {
        let device = self.describe(ifindex, ports)?;
        if self.device != Some(device) {
            let profiles = match profile::load_all(&self.profile_dir) {
                Ok(profiles) => profiles,
                // A profile store that cannot be read is not a reason to
                // refuse a connection the user is asking for by name.
                Err(e) => {
                    log::warn(format_args!("profiles: {e}"));
                    Vec::new()
                }
            };
            log::info(format_args!(
                "connection on ifindex {ifindex}, {} saved network(s)",
                profiles.len()
            ));
            self.core = Some(Connection::new(device, profiles));
            self.device = Some(device);
            *ports.eapol = None;
            Self::stop_dhcp(ports);
        }

        if ports.eapol.is_none() {
            *ports.eapol =
                Some(EapolSocket::open(ifindex).map_err(|e| {
                    format!("cannot open the EAPOL socket (needs CAP_NET_RAW): {e}")
                })?);
        }
        Ok(())
    }

    /// What `caw-core` needs to know about the interface: its address, which
    /// every key is derived from, and what its radio will do for itself.
    fn describe(&self, ifindex: u32, ports: &mut Ports<'_>) -> Result<Device, String> {
        let nl = ports.nl()?;
        let interface = nl
            .interfaces()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|i| i.ifindex == ifindex)
            .ok_or("no such wireless port")?;
        let mac = interface
            .mac
            .ok_or("the interface has no address to derive keys from")?;
        let caps = nl
            .wiphys()
            .map_err(|e| e.to_string())?
            .iter()
            .find(|w| w.index == interface.wiphy)
            .map(DeviceCaps::from)
            .unwrap_or_default();

        Ok(Device { ifindex, mac, caps })
    }

    /// Run the state machine until it stops asking for anything.
    fn feed(&mut self, input: Input, ports: &mut Ports<'_>) {
        let mut queue = VecDeque::from([input]);
        for _ in 0..MAX_TURNS {
            let Some(input) = queue.pop_front() else {
                return;
            };
            let Some(core) = self.core.as_mut() else {
                return;
            };
            for action in core.poll(input) {
                match self.perform(action, ports) {
                    Ok(Some(next)) => queue.push_back(next),
                    Ok(None) => {}
                    Err(e) => {
                        self.abort(e, ports);
                        return;
                    }
                }
            }
        }
        log::warn(format_args!(
            "the connection state machine did not settle in {MAX_TURNS} turns"
        ));
    }

    /// Perform one action, and hand back whatever it produced for the state
    /// machine to see next.
    fn perform(&mut self, action: Action, ports: &mut Ports<'_>) -> Result<Option<Input>, String> {
        match action {
            Action::TriggerScan { ifindex } => {
                match ports.nl()?.trigger_scan(ifindex, &[]) {
                    Ok(()) => {}
                    // The radio is already scanning. The same notification
                    // announces those results, so this is an answer and not a
                    // failure.
                    Err(caw_nl80211::Error::Netlink(caw_netlink::Error::Kernel(16))) => {}
                    Err(e) => return Err(e.to_string()),
                }
            }

            Action::FetchScanResults { ifindex } => {
                let results = ports
                    .nl()?
                    .scan_results(ifindex)
                    .map_err(|e| e.to_string())?;
                return Ok(Some(Input::ScanResults(results)));
            }

            Action::Associate(req) => {
                if req.offload.is_some() {
                    return Err("this device runs the handshake in firmware, which needs \
                         NL80211_ATTR_PMK support in caw-nl80211"
                        .to_owned());
                }
                let connect = Connect {
                    ssid: &req.ssid,
                    bssid: Some(req.bssid),
                    freq_mhz: Some(req.freq_mhz),
                    auth_type: req.auth_type,
                    wpa_versions: req.wpa_versions,
                    pairwise_ciphers: &req.pairwise_ciphers,
                    group_cipher: req.group_cipher,
                    akms: &req.akms,
                    mfp: req.mfp,
                    ies: &req.ies,
                };
                ports
                    .nl()?
                    .connect(req.ifindex, &connect)
                    .map_err(|e| e.to_string())?;
            }

            Action::Disconnect { reason } => {
                let ifindex = self.ifindex().ok_or("no interface to disconnect")?;
                ports
                    .nl()?
                    .disconnect(ifindex, reason)
                    .map_err(|e| e.to_string())?;
            }

            Action::SendEapol(frame) => {
                let eapol = ports.eapol.as_ref().ok_or("no EAPOL socket")?;
                eapol.send(&frame).map_err(|e| e.to_string())?;
            }

            Action::SendMgmtFrame(_) => {
                return Err(
                    "SAE needs NL80211_CMD_FRAME, which caw-nl80211 does not send yet".to_owned(),
                );
            }

            Action::InstallKeys(keys) => {
                let ifindex = self.ifindex().ok_or("no interface to key")?;
                let nl = ports.nl()?;
                if let Some(pairwise) = &keys.pairwise {
                    nl.new_pairwise_key(ifindex, pairwise.peer, pairwise.cipher, &pairwise.ptk.tk)
                        .map_err(|e| e.to_string())?;
                }
                // No `NL80211_ATTR_KEY_SEQ`: the GTK arrives with a receive
                // sequence counter that `caw_eapol::Gtk` does not carry, so
                // the device starts this key's replay window at zero.
                nl.new_group_key(
                    ifindex,
                    keys.group.gtk.index,
                    keys.group.cipher,
                    &keys.group.gtk.key,
                    &[],
                )
                .map_err(|e| e.to_string())?;
                nl.set_default_key(ifindex, keys.group.gtk.index, KeyScope::Multicast)
                    .map_err(|e| e.to_string())?;
            }

            Action::StartDhcp => {
                let ifindex = self.ifindex().ok_or("no interface for DHCP")?;
                let mac = self.device.map(|d| d.mac).ok_or("no device MAC for DHCP")?;

                // A restart mid-exchange must not leave the old run's probe
                // route behind untracked.
                Self::stop_dhcp(ports);

                // Two routes before the interface has an address; see
                // `Rtnl::add_broadcast_route` and `Rtnl::add_dhcp_probe_route`.
                // The first gets the DISCOVER out, the second lets the OFFER
                // back in past reverse-path filtering. Both best-effort: on a
                // machine that already carries them this is a no-op, and on
                // one where rtnetlink is gone the DISCOVER send will say so.
                let mut probe_route = false;
                if let Some(rtnl) = ports.rtnl.as_mut() {
                    if let Err(e) = rtnl.add_broadcast_route(ifindex) {
                        log::warn(format_args!("dhcp: broadcast route: {e}"));
                    }
                    match rtnl.add_dhcp_probe_route(ifindex) {
                        Ok(()) => probe_route = true,
                        Err(e) => log::warn(format_args!("dhcp: probe route: {e}")),
                    }
                }

                let socket = Dhcp4Socket::open().map_err(|e| {
                    format!("cannot open the DHCP socket (binding port 68 needs root): {e}")
                })?;
                let xid = caw_dhcp::new_xid().map_err(|e| e.to_string())?;
                let mut machine = Dhcp4::new(mac, xid);
                if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
                    let hostname = hostname.trim();
                    if !hostname.is_empty() {
                        machine = machine.with_hostname(hostname);
                    }
                }
                *ports.dhcp = Some(DhcpRun {
                    socket,
                    machine,
                    ifindex,
                    probe_route,
                });

                if let Some(event) = Self::drive_dhcp(ports, caw_dhcp::Input::Start(xid)) {
                    return Ok(Some(Input::Lease(event)));
                }
            }

            Action::ApplyLease(lease) => {
                let ifindex = self.ifindex().ok_or("no interface to configure")?;
                let rtnl = ports
                    .rtnl
                    .as_mut()
                    .ok_or("no rtnetlink socket to apply the lease")?;

                // A reconnect may receive a different address. This daemon
                // owns address configuration on its wireless interface, so
                // remove earlier IPv4 leases before installing the current
                // one. Otherwise every reconnect leaves another secondary
                // address behind and the kernel may source traffic from a
                // lease the DHCP server has already reassigned.
                let addresses = rtnl
                    .addresses()
                    .map_err(|e| format!("cannot list addresses before applying DHCP: {e}"))?;
                for address in addresses {
                    let IpAddr::V4(addr) = address.addr else {
                        continue;
                    };
                    if address.index == ifindex
                        && addr != lease.addr
                        && let Err(e) = rtnl.del_address(ifindex, addr, address.prefix_len)
                    {
                        log::warn(format_args!(
                            "dhcp: cannot remove stale {addr}/{}: {e}",
                            address.prefix_len
                        ));
                    }
                }
                rtnl.add_address(ifindex, lease.addr, lease.prefix_len)
                    .map_err(|e| format!("cannot add {}/{}: {e}", lease.addr, lease.prefix_len))?;
                if let Some(gateway) = lease.gateway {
                    rtnl.add_default_route(ifindex, gateway)
                        .map_err(|e| format!("cannot add the default route via {gateway}: {e}"))?;
                }
                // The lease has routes of its own now; the probe route that
                // let its OFFER in has done its job.
                Self::drop_probe_route(ports.dhcp, rtnl);
                // The resolver is a file, not a netlink object, and a lease
                // without working DNS looks exactly like no connection at
                // all. Failure to write it is worth a line, not the lease.
                if let Err(e) = write_resolv_conf(&lease.dns) {
                    log::warn(format_args!("dhcp: resolv.conf: {e}"));
                }
                log::info(format_args!(
                    "dhcp: {}/{} on ifindex {ifindex}{}",
                    lease.addr,
                    lease.prefix_len,
                    lease
                        .gateway
                        .map(|g| format!(", default route via {g}"))
                        .unwrap_or_default()
                ));
            }

            Action::SetTimer { id, millis } => {
                ports
                    .timers
                    .arm(Key::Core(id), Duration::from_millis(millis), ports.now);
            }

            Action::ClearTimer { id } => ports.timers.cancel(Key::Core(id)),

            Action::RequestSecret { prompt } => {
                let Some(client) = self.watcher else {
                    // Nobody is attached to answer. Saying so beats waiting
                    // for a prompt that will never be filled in.
                    return Err(
                        "this network needs a passphrase and no client is attached".to_owned()
                    );
                };
                let token = self.next_token;
                self.next_token += 1;
                self.pending_secret = Some(PendingSecret { token, client });
                ports.server.send(
                    client,
                    Event::NeedSecret {
                        token,
                        prompt,
                        kind: SecretKind::Passphrase,
                    },
                );
            }

            Action::SaveProfile(new) => {
                profile::save(&self.profile_dir, &new).map_err(|e| e.to_string())?;
                // Keep the in-memory copy in step, so a reconnect does not ask
                // for a passphrase that has just been written to disk.
                if let Some(core) = self.core.as_mut() {
                    core.insert_profile(*new);
                }
            }

            Action::Notify(state) => self.notify(state, ports),

            Action::Failed(failure) => {
                let terminal = failure.is_terminal();
                let reason = failure.to_string();
                log::info(format_args!("connection failed: {reason}"));
                if let Some(client) = self.watcher.take() {
                    ports.server.send(
                        client,
                        Event::Failed {
                            reason: reason.clone(),
                        },
                    );
                    ports.server.send(client, Response::error(reason));
                }
                self.pending_secret = None;
                if terminal {
                    // Nothing further will happen without a new command, so
                    // neither socket has a reason to stay open.
                    *ports.eapol = None;
                    Self::stop_dhcp(ports);
                }
            }
        }
        Ok(None)
    }

    /// Turn a state change into what the attached client sees.
    fn notify(&mut self, state: State, ports: &mut Ports<'_>) {
        let Some(client) = self.watcher else {
            return;
        };
        let bssid = self.core.as_ref().and_then(Connection::bssid);

        let event = match state {
            State::Scanning => Some(Event::Scanning),
            // The 4-way handshake is authentication as far as anyone waiting
            // on it is concerned, and the protocol has no separate event for
            // it. SAE reports the same thing earlier, from `Authenticating`.
            State::Authenticating | State::Handshaking => Some(Event::Authenticating),
            State::Associating => Some(Event::Associating {
                bssid: bssid.as_ref().map(format_mac).unwrap_or_default(),
            }),
            State::Configuring => Some(Event::Configuring),
            State::Connected => Some(Event::Connected),
            // Backing off is not an outcome; the client is still waiting.
            State::Reconnecting | State::Idle => None,
        };
        if let Some(event) = event {
            ports.server.send(client, event);
        }

        // Both ends of the lifecycle answer the request that started it.
        if matches!(state, State::Connected | State::Idle) {
            ports.server.send(client, Response::Ok);
            self.watcher = None;
        }
    }

    /// Push one input through the DHCP machine and perform what it asks.
    ///
    /// Returns the lease event to feed `caw-core`, if this input produced one.
    /// Associated rather than a method so it can run while `self` is borrowed.
    fn drive_dhcp(ports: &mut Ports<'_>, input: caw_dhcp::Input<'_>) -> Option<LeaseEvent> {
        let run = ports.dhcp.as_mut()?;
        let mut out = None;
        for action in run.machine.poll(input) {
            match action {
                caw_dhcp::Action::Broadcast(data) => {
                    if let Err(e) = run.socket.send_broadcast(&data) {
                        log::warn(format_args!("dhcp: broadcast send: {e}"));
                    }
                }
                caw_dhcp::Action::Unicast { to, data } => {
                    if let Err(e) = run.socket.send_to(to, &data) {
                        log::warn(format_args!("dhcp: send to {to}: {e}"));
                    }
                }
                caw_dhcp::Action::SetTimer { timer, secs } => {
                    ports.timers.arm(
                        Key::Dhcp(timer),
                        Duration::from_secs(secs.into()),
                        ports.now,
                    );
                }
                caw_dhcp::Action::Configured(lease) => {
                    out = Some(LeaseEvent::Acquired(lease));
                }
                caw_dhcp::Action::Deconfigure(reason) => {
                    out = Some(LeaseEvent::Lost(reason));
                }
                caw_dhcp::Action::Failed => {
                    out = Some(LeaseEvent::Failed);
                }
            }
        }
        out
    }

    /// End any DHCP exchange and disarm its timers.
    fn stop_dhcp(ports: &mut Ports<'_>) {
        use caw_dhcp::Timer;
        if let Some(rtnl) = ports.rtnl.as_mut() {
            Self::drop_probe_route(ports.dhcp, rtnl);
        }
        *ports.dhcp = None;
        for timer in [
            Timer::Retransmit,
            Timer::Renew,
            Timer::Rebind,
            Timer::Expire,
        ] {
            ports.timers.cancel(Key::Dhcp(timer));
        }
    }

    /// Take the probe route off the exchange's interface, once. Failure is a
    /// line in the log: a stray high-metric route is untidy, not harmful, and
    /// nothing that depends on it is still running.
    fn drop_probe_route(dhcp: &mut Option<DhcpRun>, rtnl: &mut Rtnl) {
        if let Some(run) = dhcp
            && run.probe_route
        {
            run.probe_route = false;
            if let Err(e) = rtnl.del_dhcp_probe_route(run.ifindex) {
                log::warn(format_args!("dhcp: removing the probe route: {e}"));
            }
        }
    }

    /// An action could not be performed. Report it the way `caw-core` reports
    /// a failure, so a client sees one shape of ending rather than two.
    fn abort(&mut self, reason: String, ports: &mut Ports<'_>) {
        log::warn(format_args!("{reason}"));
        if let Some(client) = self.watcher.take() {
            ports.server.send(
                client,
                Event::Failed {
                    reason: reason.clone(),
                },
            );
            ports.server.send(client, Response::error(reason));
        }
        self.pending_secret = None;
    }
}

/// Point the resolver at the lease's DNS servers.
///
/// Written atomically -- temp file, then rename -- because a half-written
/// resolv.conf turns every lookup on the machine into a parse error.
fn write_resolv_conf(servers: &[std::net::Ipv4Addr]) -> std::io::Result<()> {
    if servers.is_empty() {
        return Ok(());
    }
    let mut text = String::from("# Written by cawd from a DHCP lease.\n");
    for server in servers {
        text.push_str(&format!("nameserver {server}\n"));
    }
    let tmp = "/etc/.resolv.conf.cawd";
    std::fs::write(tmp, &text)?;
    std::fs::rename(tmp, "/etc/resolv.conf")
}
