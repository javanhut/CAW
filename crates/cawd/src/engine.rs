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
//! Four actions have no transport under them, and each returns an error
//! naming what is missing rather than pretending to succeed:
//!
//!   * `SendMgmtFrame` — SAE's commit and confirm need `NL80211_CMD_FRAME`,
//!     which `caw-nl80211` does not encode.
//!   * `Associate` with an [`Offload`](caw_core::Offload) — a device that runs
//!     the handshake in firmware wants `NL80211_ATTR_PMK` or
//!     `NL80211_ATTR_SAE_PASSWORD` in the connect request, and
//!     `caw_nl80211::Connect` has no field for either.
//!   * `StartDhcp` and `ApplyLease` — the DHCP client is not in the poll set,
//!     and `caw-rtnl` cannot add an address or a route.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use caw_core::{Action, Command, Connection, Device, DeviceCaps, Input, State, TimerId, profile};
use caw_eapol::EapolSocket;
use caw_ipc::{Event, Response, SecretKind};
use caw_nl80211::{Connect, KeyScope, Nl80211};
use caw_rtnl::format_mac;

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
    pub timers: &'a mut Timers<Key>,
    pub server: &'a mut Server,
    pub now: Instant,
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
        let state = self.core.as_ref().map_or(State::Idle, Connection::state);
        format!("{state:?}")
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
        if self.core.is_some() && self.state_name() != "Idle" {
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
                return Err(
                    "address configuration is not wired up yet: the DHCP client is not in \
                     the reactor's poll set"
                        .to_owned(),
                );
            }

            Action::ApplyLease(_) => {
                return Err(
                    "caw-rtnl cannot add an address or a route yet, so a lease cannot be \
                     applied"
                        .to_owned(),
                );
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
                    // the packet socket has no reason to stay open.
                    *ports.eapol = None;
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
