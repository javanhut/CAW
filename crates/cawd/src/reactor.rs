//! The poll loop: every descriptor the daemon owns, in one place.
//!
//! Five kinds of descriptor — the nl80211 event socket, an rtnetlink event
//! socket, the EAPOL packet socket, the IPC listener with its clients, and a
//! `timerfd` — and one thread. Nothing here decides anything: a request
//! becomes an input to `caw-core`, and the actions that come back are
//! performed against these descriptors by [`crate::engine`].
//!
//! Blocking is never allowed. Every socket is non-blocking, `poll` has no
//! timeout of its own — the `timerfd` is the only deadline — and a client
//! that stops reading is dropped rather than waited for.
//!
//! There is no `signalfd`, which there would be in a sixth arm of
//! [`Reactor::dispatch`]; see the crate documentation for why it cannot exist
//! in safe Rust today, and what stops the daemon instead.

use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use caw_eapol::EapolSocket;
use caw_ipc::{ConnectionStatus, Event, NetworkSummary, PortSummary, Request, Response};
use caw_nl80211::{Events, IfType, Nl80211};
use caw_rtnl::{Kind, Rtnl, format_mac};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;

use crate::auth::Database;
use crate::engine::{Engine, Ports};
use crate::ipc::{ClientId, Server};
use crate::links::{LinkEvent, LinkEvents};
use crate::timers::{TimerFd, Timers};
use crate::{Error, log};

/// How long a client waits for a scan before being told it failed.
///
/// A full pass over both bands takes a few seconds on a slow radio, and the
/// kernel gives no progress in between; this is the point at which something
/// has gone wrong rather than gone slowly.
const SCAN_TIMEOUT: Duration = Duration::from_secs(15);

/// What a timer belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    /// A deadline `caw-core` asked for with [`caw_core::Action::SetTimer`].
    Core(caw_core::TimerId),
    /// A scan one client is waiting on. Keyed by client, because two of them
    /// can be waiting on the same scan with different deadlines.
    Scan(ClientId),
}

/// Which descriptor woke us.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Source {
    Timer,
    Listener,
    Client(ClientId),
    Wireless,
    Links,
    Eapol,
}

/// The nl80211 command socket and its event socket, which only exist on a
/// machine that has a wireless stack at all.
struct Wireless {
    nl: Nl80211,
    events: Events,
}

/// A scan a client is waiting for the kernel to finish.
struct PendingScan {
    client: ClientId,
    ifindex: u32,
}

pub struct Reactor {
    ipc: Server,
    timers: Timers<Key>,
    timerfd: TimerFd,
    engine: Engine,
    /// Absent when cfg80211 is not loaded. Port commands still work, so
    /// refusing to start would take away more than it protects.
    wireless: Option<Wireless>,
    /// Absent when rtnetlink cannot be opened, which on Linux means something
    /// is very wrong; the daemon still serves what it can.
    rtnl: Option<Rtnl>,
    links: Option<LinkEvents>,
    /// Opened when a connection starts, because it needs `CAP_NET_RAW` and an
    /// interface to belong to.
    eapol: Option<EapolSocket>,
    scans: Vec<PendingScan>,
    stopping: bool,
}

impl Reactor {
    pub fn new(socket: &std::path::Path) -> Result<Self, Error> {
        let ipc = Server::bind(socket)?;
        log::info(format_args!("listening on {}", socket.display()));

        let wireless = match Nl80211::open() {
            Ok(nl) => match nl.events() {
                Ok(events) => Some(Wireless { nl, events }),
                Err(e) => {
                    log::warn(format_args!("no wireless events: {e}"));
                    None
                }
            },
            Err(e) => {
                log::warn(format_args!("{e}"));
                None
            }
        };
        let rtnl = match Rtnl::open() {
            Ok(rtnl) => Some(rtnl),
            Err(e) => {
                log::warn(format_args!("no rtnetlink: {e}"));
                None
            }
        };
        let links = match LinkEvents::open() {
            Ok(links) => Some(links),
            Err(e) => {
                log::warn(format_args!("no link notifications: {e}"));
                None
            }
        };

        Ok(Self {
            ipc,
            timers: Timers::new(),
            timerfd: TimerFd::new()?,
            engine: Engine::new(),
            wireless,
            rtnl,
            links,
            eapol: None,
            scans: Vec::new(),
            stopping: false,
        })
    }

    pub fn run(&mut self) -> Result<(), Error> {
        while !self.stopping {
            let ready = match self.wait() {
                Ok(ready) => ready,
                // A signal interrupted the wait. Nothing is wrong; go round
                // again.
                Err(Errno::INTR) => continue,
                Err(e) => return Err(Error::Socket(e)),
            };
            for (source, revents) in ready {
                self.dispatch(source, revents);
            }
            for id in self.ipc.reap() {
                self.forget(id);
            }
            self.rearm()?;
        }
        self.shutdown();
        Ok(())
    }

    /// Block until something happens.
    ///
    /// Takes `&self` and returns owned sources so that the borrows the poll
    /// array holds on the descriptors end before anything is dispatched.
    fn wait(&self) -> Result<Vec<(Source, PollFlags)>, Errno> {
        let mut fds = Vec::with_capacity(4 + self.ipc.clients().len());
        let mut sources = Vec::with_capacity(fds.capacity());

        let mut watch = |fd, flags, source| {
            fds.push(PollFd::from_borrowed_fd(fd, flags));
            sources.push(source);
        };
        watch(self.timerfd.as_fd(), PollFlags::IN, Source::Timer);
        watch(self.ipc.listener(), PollFlags::IN, Source::Listener);
        if let Some(w) = &self.wireless {
            watch(w.events.as_fd(), PollFlags::IN, Source::Wireless);
        }
        if let Some(links) = &self.links {
            watch(links.as_fd(), PollFlags::IN, Source::Links);
        }
        if let Some(eapol) = &self.eapol {
            watch(eapol.as_fd(), PollFlags::IN, Source::Eapol);
        }
        for client in self.ipc.clients() {
            let flags = if client.has_pending_output() {
                PollFlags::IN | PollFlags::OUT
            } else {
                PollFlags::IN
            };
            watch(client.fd(), flags, Source::Client(client.id));
        }

        // No timeout: the timerfd is the only deadline the daemon has, which
        // keeps "when does this fire" in one place instead of two.
        poll(&mut fds, None)?;

        Ok(sources
            .into_iter()
            .zip(&fds)
            .filter(|(_, fd)| !fd.revents().is_empty())
            .map(|(source, fd)| (source, fd.revents()))
            .collect())
    }

    fn dispatch(&mut self, source: Source, revents: PollFlags) {
        match source {
            Source::Timer => self.on_timer(),
            Source::Listener => {
                for id in self.ipc.accept() {
                    let requests = self.ipc.read(id);
                    for request in requests {
                        self.handle(id, request);
                    }
                }
            }
            Source::Client(id) => {
                if revents.intersects(PollFlags::IN | PollFlags::HUP) {
                    for request in self.ipc.read(id) {
                        self.handle(id, request);
                    }
                }
                if revents.contains(PollFlags::OUT) {
                    self.ipc.flush(id);
                }
                if revents.intersects(PollFlags::ERR | PollFlags::NVAL) {
                    self.ipc.close(id);
                }
            }
            Source::Wireless => self.on_wireless(),
            Source::Links => self.on_links(),
            Source::Eapol => self.on_eapol(),
        }
    }

    /// Arm the timerfd for the nearest deadline in the wheel.
    fn rearm(&mut self) -> Result<(), Error> {
        let delay = self
            .timers
            .next_deadline()
            .map(|at| at.saturating_duration_since(Instant::now()));
        self.timerfd.arm(delay)?;
        Ok(())
    }

    fn on_timer(&mut self) {
        self.timerfd.drain();
        for key in self.timers.expired(Instant::now()) {
            match key {
                Key::Scan(client) => {
                    self.finish_scan(client, Response::error("scan timed out"));
                }
                Key::Core(id) => self.with_engine(|engine, ports| engine.on_timer(id, ports)),
            }
        }
    }

    fn on_wireless(&mut self) {
        let Some(wireless) = &mut self.wireless else {
            return;
        };
        // Drain into a vector first: handling an event needs the same socket
        // to fetch scan results from.
        let events = match wireless.events.read() {
            Ok(events) => events,
            Err(e) => {
                log::warn(format_args!("wireless events: {e}"));
                return;
            }
        };
        for event in events {
            // A scan notification has two audiences: whoever asked for `caw
            // scan`, and a connection that is waiting on the same results.
            // Both get it — the kernel's cache serves either without a second
            // pass over the air.
            match &event {
                caw_nl80211::Event::ScanComplete { ifindex, .. } => self.on_scan_done(*ifindex),
                caw_nl80211::Event::ScanAborted { ifindex, .. } => {
                    for client in self.waiting_on(*ifindex) {
                        self.finish_scan(client, Response::error("the kernel aborted the scan"));
                    }
                }
                _ => {}
            }
            self.with_engine(|engine, ports| engine.on_wireless(event, ports));
        }
    }

    fn on_links(&mut self) {
        let Some(links) = &mut self.links else {
            return;
        };
        for event in links.read() {
            // Carrier is what tells a connection worth re-establishing from an
            // interface someone took down on purpose, so it is worth saying
            // out loud even before `caw-core` acts on it.
            if let LinkEvent::Changed {
                ifindex,
                up,
                carrier,
            } = event
                && Some(ifindex) == self.engine.ifindex()
            {
                log::info(format_args!(
                    "link {ifindex}: {}, carrier {}",
                    if up { "up" } else { "down" },
                    if carrier { "present" } else { "lost" }
                ));
            }
        }
    }

    fn on_eapol(&mut self) {
        let mut frames = Vec::new();
        if let Some(eapol) = &mut self.eapol {
            let mut buf = [0u8; 2048];
            loop {
                match eapol.recv(&mut buf) {
                    Ok(n) => frames.push(buf[..n].to_vec()),
                    Err(caw_eapol::Error::Io(Errno::AGAIN)) => break,
                    Err(e) => {
                        log::warn(format_args!("eapol read: {e}"));
                        break;
                    }
                }
            }
        }
        for frame in frames {
            self.with_engine(|engine, ports| engine.on_eapol(frame, ports));
        }
    }

    /// Hand the engine the descriptors it may act on.
    ///
    /// A closure rather than a `ports()` accessor because the borrows have to
    /// be of the fields, not of the whole reactor: the engine is one field and
    /// the sockets are others, and only inside one function body can the
    /// compiler see that they do not overlap.
    fn with_engine<R>(&mut self, f: impl FnOnce(&mut Engine, &mut Ports<'_>) -> R) -> R {
        let mut ports = Ports {
            nl: self.wireless.as_mut().map(|w| &mut w.nl),
            eapol: &mut self.eapol,
            timers: &mut self.timers,
            server: &mut self.ipc,
            now: Instant::now(),
        };
        f(&mut self.engine, &mut ports)
    }

    /// A client went away; drop anything held on its behalf.
    fn forget(&mut self, id: ClientId) {
        self.scans.retain(|s| s.client != id);
        self.timers.cancel(Key::Scan(id));
        self.engine.forget_client(id);
    }

    fn handle(&mut self, id: ClientId, request: Request) {
        if request.is_state_changing() && !self.may_change_state(id) {
            self.ipc.send(
                id,
                Response::error(format!(
                    "permission denied: this needs root or membership of the {} group",
                    caw_ipc::GROUP
                )),
            );
            return;
        }

        match request {
            Request::ListPorts => match self.ports_summary(None) {
                Ok(ports) => self.ipc.send(id, Response::Ports(ports)),
                Err(e) => self.ipc.send(id, Response::error(e)),
            },
            Request::PortInfo { name } => match self.ports_summary(Some(&name)) {
                Ok(ports) => self.ipc.send(id, Response::Ports(ports)),
                Err(e) => self.ipc.send(id, Response::error(e)),
            },
            Request::PortUp { name, up } => match self.set_port_up(&name, up) {
                Ok(()) => self.ipc.send(id, Response::Ok),
                Err(e) => self.ipc.send(id, Response::error(e)),
            },
            Request::Scan { port } => {
                if let Err(e) = self.start_scan(id, port.as_deref()) {
                    self.ipc.send(id, Response::error(e));
                }
            }
            Request::Status => {
                let status = self.status();
                self.ipc.send(id, Response::Status(status));
            }
            Request::Connect { ssid, port } => {
                let ifindex = match self.wireless_ifindex(port.as_deref()) {
                    Ok(ifindex) => ifindex,
                    Err(e) => {
                        self.ipc.send(id, Response::error(e));
                        return;
                    }
                };
                if let Err(e) =
                    self.with_engine(|engine, ports| engine.connect(ifindex, &ssid, id, ports))
                {
                    self.ipc.send(id, Response::error(e));
                }
            }
            Request::Disconnect { ssid } => {
                if let Err(e) =
                    self.with_engine(|engine, ports| engine.disconnect(&ssid, id, ports))
                {
                    self.ipc.send(id, Response::error(e));
                }
            }
            Request::Secret { token, value } => {
                if let Err(e) =
                    self.with_engine(|engine, ports| engine.secret(token, value, id, ports))
                {
                    self.ipc.send(id, Response::error(e));
                }
            }
            Request::Shutdown => {
                log::info(format_args!("shutdown requested"));
                self.ipc.send(id, Response::Ok);
                self.stopping = true;
            }
        }
    }

    /// Read the group database afresh for each request that needs it, so a
    /// user added to the `caw` group does not have to wait for a restart.
    fn may_change_state(&self, id: ClientId) -> bool {
        let Some(client) = self.ipc.client(id) else {
            return false;
        };
        let allowed = Database::load().may_change_state(client.peer, caw_ipc::GROUP);
        if !allowed {
            log::warn(format_args!(
                "refused a state-changing request from uid {} (pid {})",
                client.peer.uid, client.peer.pid
            ));
        }
        allowed
    }

    fn ports_summary(&mut self, only: Option<&str>) -> Result<Vec<PortSummary>, String> {
        let rtnl = self.rtnl.as_mut().ok_or("rtnetlink is not available")?;
        let links = rtnl.links().map_err(|e| e.to_string())?;
        let addrs = rtnl.addresses().map_err(|e| e.to_string())?;

        let summary: Vec<PortSummary> = links
            .iter()
            .filter(|l| only.is_none_or(|name| l.name == name))
            .map(|l| PortSummary {
                name: l.name.clone(),
                mac: l.mac.as_ref().map(format_mac).unwrap_or_default(),
                up: l.is_up(),
                carrier: l.has_carrier(),
                wireless: l.kind == Kind::Wireless,
                addrs: addrs
                    .iter()
                    .filter(|a| a.index == l.index)
                    .map(|a| format!("{}/{}", a.addr, a.prefix_len))
                    .collect(),
            })
            .collect();

        match only {
            Some(name) if summary.is_empty() => Err(format!("no such port: {name}")),
            _ => Ok(summary),
        }
    }

    fn set_port_up(&mut self, name: &str, up: bool) -> Result<(), String> {
        let rtnl = self.rtnl.as_mut().ok_or("rtnetlink is not available")?;
        let link = rtnl
            .link_by_name(name)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("no such port: {name}"))?;
        rtnl.set_up(link.index, up).map_err(|e| e.to_string())
    }

    fn status(&mut self) -> ConnectionStatus {
        let ifindex = self.engine.ifindex();
        let (port, addrs) = match (ifindex, self.rtnl.as_mut()) {
            (Some(ifindex), Some(rtnl)) => {
                let name = rtnl
                    .links()
                    .ok()
                    .and_then(|links| {
                        links
                            .into_iter()
                            .find(|l| l.index == ifindex)
                            .map(|l| l.name)
                    })
                    .unwrap_or_default();
                let addrs = rtnl
                    .addresses()
                    .map(|addrs| {
                        addrs
                            .iter()
                            .filter(|a| a.index == ifindex)
                            .map(|a| format!("{}/{}", a.addr, a.prefix_len))
                            .collect()
                    })
                    .unwrap_or_default();
                (name, addrs)
            }
            _ => (String::new(), Vec::new()),
        };

        ConnectionStatus {
            port,
            ssid: self.engine.ssid(),
            state: self.engine.state_name(),
            addrs,
        }
    }

    fn start_scan(&mut self, client: ClientId, port: Option<&str>) -> Result<(), String> {
        let ifindex = self.wireless_ifindex(port)?;
        let wireless = self.wireless.as_mut().ok_or(NO_WIRELESS)?;
        match wireless.nl.trigger_scan(ifindex, &[]) {
            Ok(()) => {}
            // EBUSY means the radio is already scanning, which answers the
            // request just as well: the results land in the same cache and the
            // same notification announces them.
            Err(caw_nl80211::Error::Netlink(caw_netlink::Error::Kernel(16))) => {}
            Err(e) => return Err(e.to_string()),
        }

        self.scans.push(PendingScan { client, ifindex });
        self.timers
            .arm(Key::Scan(client), SCAN_TIMEOUT, Instant::now());
        self.ipc.send(client, Event::Scanning);
        Ok(())
    }

    /// The clients waiting on a scan of this interface.
    fn waiting_on(&self, ifindex: u32) -> Vec<ClientId> {
        self.scans
            .iter()
            .filter(|s| s.ifindex == ifindex)
            .map(|s| s.client)
            .collect()
    }

    fn on_scan_done(&mut self, ifindex: u32) {
        let waiting = self.waiting_on(ifindex);
        if waiting.is_empty() {
            return;
        }

        let response = match self.networks(ifindex) {
            Ok(networks) => Response::Networks(networks),
            Err(e) => Response::error(e),
        };
        for client in waiting {
            self.finish_scan(client, response.clone());
        }
    }

    fn networks(&mut self, ifindex: u32) -> Result<Vec<NetworkSummary>, String> {
        let wireless = self.wireless.as_mut().ok_or(NO_WIRELESS)?;
        let mut results = wireless
            .nl
            .scan_results(ifindex)
            .map_err(|e| e.to_string())?;
        // Strongest first: the list is read top down and the top of it is
        // what someone means by "the network".
        results.sort_by_key(|bss| std::cmp::Reverse(bss.signal_dbm));

        Ok(results
            .into_iter()
            .map(|bss| NetworkSummary {
                ssid: String::from_utf8_lossy(&bss.ssid).into_owned(),
                bssid: format_mac(&bss.bssid),
                signal_dbm: bss.signal_dbm,
                freq_mhz: bss.freq_mhz,
                security: bss.security.as_str().to_owned(),
                known: false,
            })
            .collect())
    }

    fn finish_scan(&mut self, client: ClientId, response: Response) {
        self.scans.retain(|s| s.client != client);
        self.timers.cancel(Key::Scan(client));
        self.ipc.send(client, response);
    }

    /// The interface a wireless request applies to.
    ///
    /// With no port named, the single station-mode interface is the obvious
    /// answer, and refusing to guess between several is better than picking
    /// the wrong radio.
    fn wireless_ifindex(&mut self, port: Option<&str>) -> Result<u32, String> {
        let wireless = self.wireless.as_mut().ok_or(NO_WIRELESS)?;
        let interfaces = wireless.nl.interfaces().map_err(|e| e.to_string())?;

        if let Some(name) = port {
            return interfaces
                .iter()
                .find(|i| i.name == name)
                .map(|i| i.ifindex)
                .ok_or_else(|| format!("{name} is not a wireless port"));
        }

        let mut stations = interfaces.iter().filter(|i| i.iftype == IfType::Station);
        match (stations.next(), stations.next()) {
            (Some(only), None) => Ok(only.ifindex),
            (None, _) => Err("no wireless port".to_owned()),
            (Some(_), Some(_)) => Err("several wireless ports; name one".to_owned()),
        }
    }

    /// Tear down before exiting, so the AP sees a station leaving rather than
    /// one that stopped answering.
    fn shutdown(&mut self) {
        self.with_engine(|engine, ports| engine.shut_down(ports));
        for client in self.ipc.clients().iter().map(|c| c.id).collect::<Vec<_>>() {
            self.ipc.flush(client);
        }
        log::info(format_args!("stopped"));
    }
}

const NO_WIRELESS: &str = "no wireless stack: the kernel has no nl80211 family";
