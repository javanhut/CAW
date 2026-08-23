//! The connection state machine.
//!
//! ```text
//!     Idle
//!      |  connect
//!      v
//!   Scanning ---------- no matching BSS ------------+
//!      |  BSS chosen by policy                      |
//!      v                                            |
//!   Authenticating   (SAE runs here, pre-assoc)     |
//!      |                                            |
//!      v                                            v
//!   Associating ------- refused ----------------> failed
//!      |                                            ^
//!      v                                            |
//!   Handshaking      (4-way; 802.1X runs inside)    |
//!      |  keys installed via NL80211_CMD_NEW_KEY    |
//!      v                                            |
//!   Configuring      (DHCPv4 / SLAAC)               |
//!      |                                            |
//!      v                                            |
//!   Connected <---- rekey ----+                     |
//!      |  deauth / carrier loss|                    |
//!      v                       +-- group rekey EAPOL exchange
//!   Reconnecting -- backoff --> Scanning
//! ```
//!
//! `Connected` is not a resting state. The 4-way handshake stays alive for the
//! life of the association, answering the group rekey an AP performs about
//! once an hour; a station that does not answer is deauthenticated. That
//! obligation is the whole reason `cawd` is a daemon.

use std::fmt;

use caw_80211::{Akm, Cipher, RsnIe, Security};
use caw_crypto::{AuthContext, Pmk, PmkProvider, Step};
use caw_nl80211::{Bss, ConnectStatus, Event};

use crate::auth::{self, Auth, DeviceCaps, Offload};
use crate::policy;
use crate::profile::{Credential, Profile, Secret};
use crate::rsn::StationRsn;

/// How long to wait for a scan the kernel acknowledged but never finished.
pub const SCAN_TIMEOUT_MS: u64 = 10_000;
/// How long a pre-association exchange may take. SAE retransmits inside this.
pub const AUTH_TIMEOUT_MS: u64 = 3_000;
/// How long to wait for `NL80211_CMD_CONNECT` to report either way. Generous,
/// because the kernel's own SME may authenticate, associate and retry within
/// it.
pub const ASSOC_TIMEOUT_MS: u64 = 8_000;
/// First reconnect delay; it doubles from here.
pub const BACKOFF_BASE_MS: u64 = 1_000;
/// And stops doubling here. A minute is long enough not to hammer an AP that
/// is refusing us, short enough that a network coming back is noticed.
pub const BACKOFF_MAX_MS: u64 = 60_000;

/// 802.11 reason code 3: "deauthenticated because sending station is leaving".
const REASON_LEAVING: u16 = 3;

/// Where a connection is. Drives what `caw status` prints.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Idle,
    Scanning,
    /// SAE runs here, before association.
    Authenticating,
    Associating,
    /// The 4-way handshake; 802.1X runs inside this phase.
    Handshaking,
    Configuring,
    Connected,
    /// Lost the link; backing off before retry.
    Reconnecting,
}

/// The interface a connection runs on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Device {
    pub ifindex: u32,
    /// The station's own address. Hashed into every PTK and every SAE password
    /// element, so a randomised MAC has to be settled before connecting.
    pub mac: [u8; 6],
    pub caps: DeviceCaps,
}

/// Things that happen to a connection.
pub enum Input {
    Command(Command),
    /// A notification from the kernel's wireless stack.
    Wireless(Event),
    /// The kernel's scan cache, dumped in answer to
    /// [`Action::FetchScanResults`]. A `ScanComplete` event only says the
    /// cache is ready; reading it is a netlink dump, and dumps are the
    /// daemon's business.
    ScanResults(Vec<Bss>),
    /// One EAPOL frame with no Ethernet header — 4-way handshake, group rekey
    /// or 802.1X.
    Eapol(Vec<u8>),
    /// The daemon's DHCP client has something to report.
    Lease(LeaseEvent),
    Timer(TimerId),
}

pub enum Command {
    Connect {
        ssid: Vec<u8>,
    },
    /// Join the strongest network this machine has an autoconnecting profile
    /// for, choosing which one from the scan rather than being told.
    ///
    /// Ignored unless the connection is idle: a link already up, or an attempt
    /// already under way, is the outcome this asks for.
    Autoconnect,
    /// The credential [`Action::RequestSecret`] asked for.
    Secret {
        value: Secret,
    },
    Disconnect,
}

/// What the daemon's address configuration is doing.
///
/// `caw-dhcp` is a state machine of its own, with its own timers and its own
/// transaction id drawn from the kernel's entropy pool. The daemon drives it
/// and reports the outcome here, which keeps the one input this crate cannot
/// produce — randomness — out of the decision layer.
pub enum LeaseEvent {
    Acquired(caw_dhcp::Lease),
    /// The lease came off the interface; the link is still up.
    Lost(caw_dhcp::Reason),
    /// No server answered.
    Failed,
}

/// What the daemon should do. Never performed here.
pub enum Action {
    TriggerScan {
        ifindex: u32,
    },
    /// Dump `NL80211_CMD_GET_SCAN` and feed the results back as
    /// [`Input::ScanResults`].
    FetchScanResults {
        ifindex: u32,
    },
    Associate(Box<AssocRequest>),
    Disconnect {
        /// An 802.11 reason code.
        reason: u16,
    },
    /// A management frame body for `NL80211_CMD_FRAME`: SAE commit or confirm.
    SendMgmtFrame(Vec<u8>),
    SendEapol(Vec<u8>),
    /// Install keys via `NL80211_CMD_NEW_KEY`. A group rekey leaves the
    /// pairwise key alone; see [`KeyInstall::pairwise`].
    InstallKeys(Box<KeyInstall>),
    StartDhcp,
    ApplyLease(caw_dhcp::Lease),
    SetTimer {
        id: TimerId,
        millis: u64,
    },
    ClearTimer {
        id: TimerId,
    },
    /// Ask the user, via whichever CLI is attached.
    RequestSecret {
        prompt: String,
    },
    /// Persist this network. Writing it is [`crate::profile::save`]'s job,
    /// because a state machine does not open files.
    SaveProfile(Box<Profile>),
    Notify(State),
    /// The attempt is over and nothing further will happen without a new
    /// command. Never emitted alongside a retry.
    Failed(Failure),
}

/// The timers this machine arms. The daemon owns the `timerfd`s.
///
/// DHCP's timers are absent on purpose: `caw-dhcp` names its own, and the
/// daemon arms them for the client it drives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimerId {
    ScanTimeout,
    AuthTimeout,
    AssocTimeout,
    HandshakeRetry,
    ReconnectBackoff,
}

/// Everything `NL80211_CMD_CONNECT` needs, decided here.
///
/// Owned rather than borrowed like `caw_nl80211::Connect`, because it crosses
/// from the decision layer to the socket layer and the two do not share a
/// lifetime. The suite selectors are the kernel's 32-bit form.
pub struct AssocRequest {
    pub ifindex: u32,
    pub ssid: Vec<u8>,
    pub bssid: [u8; 6],
    pub freq_mhz: u32,
    /// `NL80211_AUTHTYPE_*`.
    pub auth_type: u32,
    /// `NL80211_WPA_VERSION_*`, a bitmask. Zero for an open network.
    pub wpa_versions: u32,
    pub pairwise_ciphers: Vec<u32>,
    pub group_cipher: Option<u32>,
    pub akms: Vec<u32>,
    /// `NL80211_MFP_*`.
    pub mfp: Option<u32>,
    /// The station's RSN element, headers and all. Not optional for a WPA
    /// network: an association request without one is refused with status 40.
    pub ies: Vec<u8>,
    /// Present when the device runs the handshake itself.
    pub offload: Option<Offload>,
}

/// Keys to install, in the order they appear here.
pub struct KeyInstall {
    /// `None` for a group rekey. Reinstalling a pairwise key resets its packet
    /// number and replays the keystream, which is the KRACK attack, so the
    /// distinction is not cosmetic.
    pub pairwise: Option<PairwiseKey>,
    pub group: GroupKey,
}

pub struct PairwiseKey {
    pub peer: [u8; 6],
    /// The kernel's 32-bit cipher selector.
    pub cipher: u32,
    pub ptk: caw_crypto::Ptk,
}

pub struct GroupKey {
    pub cipher: u32,
    pub gtk: caw_eapol::Gtk,
}

/// Why an attempt ended.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Failure {
    /// Nothing advertising that SSID was in the scan results.
    NotFound,
    /// An autoconnect found nothing it knows: every BSS in range either has no
    /// profile or has one with `autoconnect` turned off.
    NoKnownNetwork,
    /// The network is offering less than the profile recorded. This is the
    /// downgrade defence: an attacker cannot present an open network under a
    /// known name and collect whatever the machine sends next.
    Downgrade {
        recorded: Security,
        offered: Security,
    },
    /// Nothing the AP offers can be run with the credential in hand.
    UnsupportedSecurity,
    /// The network needs a credential and none was supplied.
    NoCredential,
    /// The AP refused the association, with its 802.11 status code. On a
    /// device that offloads the handshake a wrong passphrase surfaces here,
    /// because there is no EAPOL exchange left to fail.
    Refused(u16),
    /// No AP answered the association request.
    AssocTimeout,
    /// The handshake MIC did not verify: the passphrase is wrong. Terminal,
    /// because retrying with the same wrong credential is a loop.
    WrongCredential,
    /// The RSN element in message 3 is not the one the beacon advertised —
    /// somebody rewrote a beacon.
    RsnMismatch,
    /// SAE or 802.1X rejected the station.
    AuthFailed,
    /// The handshake failed for a reason that is not a bad credential.
    Handshake(String),
    /// The link went away.
    Disconnected { reason: u16, by_ap: bool },
    /// No address could be configured.
    Dhcp,
    /// The profile asks for something this build cannot do.
    Enterprise(String),
    /// A state this machine should not have been able to reach.
    Internal(String),
}

impl Failure {
    /// Whether retrying could ever succeed.
    ///
    /// The distinction that matters most is the wrong passphrase: a station
    /// that treats it as a transient error reassociates forever, and the user
    /// never learns what is wrong.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Failure::Downgrade { .. }
                | Failure::UnsupportedSecurity
                | Failure::NoCredential
                | Failure::WrongCredential
                | Failure::RsnMismatch
                | Failure::AuthFailed
                | Failure::Enterprise(_)
                | Failure::Internal(_)
        )
    }

    pub(crate) fn from_crypto(e: caw_crypto::Error) -> Self {
        match e {
            caw_crypto::Error::MicMismatch | caw_crypto::Error::KeyUnwrapFailed => {
                Failure::WrongCredential
            }
            caw_crypto::Error::AuthFailed => Failure::AuthFailed,
            other => Failure::Handshake(other.to_string()),
        }
    }

    fn from_eapol(e: caw_eapol::Error) -> Self {
        match e {
            // A MIC that does not verify, or key data that will not unwrap,
            // both mean the two ends derived different keys from different
            // passphrases. Nothing else produces either.
            caw_eapol::Error::Crypto(inner) => Failure::from_crypto(inner),
            caw_eapol::Error::RsnMismatch => Failure::RsnMismatch,
            caw_eapol::Error::Rejected | caw_eapol::Error::PrematureSuccess => Failure::AuthFailed,
            other => Failure::Handshake(other.to_string()),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::NotFound => write!(f, "no access point is advertising that network"),
            Failure::NoKnownNetwork => write!(f, "no saved network is in range"),
            Failure::Downgrade { recorded, offered } => write!(
                f,
                "refusing to join at {offered}: this network was saved as {recorded}"
            ),
            Failure::UnsupportedSecurity => {
                write!(f, "this network's security is not one caw can join")
            }
            Failure::NoCredential => write!(f, "this network needs a passphrase"),
            Failure::Refused(code) => write!(f, "the access point refused us (status {code})"),
            Failure::AssocTimeout => write!(f, "no answer from the access point"),
            Failure::WrongCredential => write!(f, "wrong passphrase"),
            Failure::RsnMismatch => write!(
                f,
                "the access point's security does not match its beacon (downgrade attack)"
            ),
            Failure::AuthFailed => write!(f, "authentication rejected"),
            Failure::Handshake(why) => write!(f, "handshake failed: {why}"),
            Failure::Disconnected { reason, by_ap } => {
                let who = if *by_ap { "access point" } else { "link" };
                write!(f, "disconnected by the {who} (reason {reason})")
            }
            Failure::Dhcp => write!(f, "no address could be configured"),
            Failure::Enterprise(why) => write!(f, "{why}"),
            Failure::Internal(why) => write!(f, "internal error: {why}"),
        }
    }
}

/// The network a connection is working towards.
struct Target {
    ssid: Vec<u8>,
    /// Typed for this attempt, when no profile held one.
    secret: Option<Secret>,
    /// Retry with backoff rather than reporting a failure, because a profile
    /// says this network should be joined whenever it is in range.
    retry: bool,
    /// Write a profile once the connection stands up.
    save: bool,
}

/// The suites and addresses of one association attempt against one BSS.
struct Choice {
    bssid: [u8; 6],
    freq_mhz: u32,
    signal_dbm: i32,
    /// What the network advertised; what a saved profile records.
    advertised: Security,
    /// What this association actually provides; what the downgrade check
    /// compares against.
    negotiated: Security,
    /// `None` for an open network.
    rsn: Option<Negotiated>,
    /// A roam keeps the address configuration, so success returns straight to
    /// `Connected` instead of running DHCP again.
    roaming: bool,
}

struct Negotiated {
    akm: Akm,
    pairwise: Cipher,
    group: Cipher,
    group_mgmt: Option<Cipher>,
    mfp_capable: bool,
    mfp_required: bool,
    /// The AP's element, byte for byte. Message 3 of the handshake repeats it
    /// under a MIC, and comparing the two is what closes the downgrade an
    /// attacker could otherwise perform by rewriting a beacon.
    beacon_ie: Vec<u8>,
}

/// One association attempt, from the moment a BSS is chosen.
struct Session {
    choice: Choice,
    auth: Auth,
    /// Names the PMK an SAE exchange derived, for the association request.
    pmkid: Option<[u8; 16]>,
    /// The station's RSN element as sent; message 2 repeats it verbatim.
    assoc_ie: Vec<u8>,
    /// Outlives the handshake: it answers group rekeys for the life of the
    /// association.
    handshake: Option<caw_eapol::FourWay>,
}

/// One wireless connection on one interface.
pub struct Connection {
    device: Device,
    /// What the daemon read out of the profile store at startup.
    profiles: Vec<Profile>,
    state: State,
    target: Option<Target>,
    session: Option<Session>,
    /// Consecutive failed attempts, for the backoff.
    attempts: u32,
    /// The timer this machine last asked for. Tracked so a transition clears
    /// exactly the timer that is running, and never one that is not.
    armed: Option<TimerId>,
    /// A BSS chosen and parked until the user supplies a passphrase. The BSS
    /// rather than the plan, because a credential can change which AKM is
    /// negotiated and the choice is worth making again with one in hand.
    pending: Option<Bss>,
}

impl Connection {
    pub fn new(device: Device, profiles: Vec<Profile>) -> Self {
        Self {
            device,
            profiles,
            state: State::Idle,
            target: None,
            session: None,
            attempts: 0,
            armed: None,
            pending: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The network being joined or held, if any.
    pub fn ssid(&self) -> Option<&[u8]> {
        self.target.as_ref().map(|t| t.ssid.as_slice())
    }

    /// The AP currently associated with, or being associated with.
    pub fn bssid(&self) -> Option<[u8; 6]> {
        self.session.as_ref().map(|s| s.choice.bssid)
    }

    /// What the current association actually negotiated, which is not always
    /// what the network advertised: a WPA2/WPA3 transition network joined with
    /// SAE is a WPA3 connection.
    pub fn security(&self) -> Option<Security> {
        self.session.as_ref().map(|s| s.choice.negotiated)
    }

    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    /// Add or replace a saved network, after the daemon has written it out.
    pub fn insert_profile(&mut self, profile: Profile) {
        self.profiles.retain(|p| p.ssid != profile.ssid);
        self.profiles.push(profile);
    }

    pub fn forget_profile(&mut self, ssid: &[u8]) {
        self.profiles.retain(|p| p.ssid != ssid);
    }

    pub fn poll(&mut self, input: Input) -> Vec<Action> {
        let mut out = Vec::new();
        match input {
            Input::Command(command) => self.on_command(command, &mut out),
            Input::Wireless(event) => self.on_wireless(event, &mut out),
            Input::ScanResults(scan) => self.on_scan_results(scan, &mut out),
            Input::Eapol(frame) => self.on_eapol(&frame, &mut out),
            Input::Lease(event) => self.on_lease(event, &mut out),
            Input::Timer(id) => self.on_timer(id, &mut out),
        }
        out
    }

    // -- commands ---------------------------------------------------------

    fn on_command(&mut self, command: Command, out: &mut Vec<Action>) {
        match command {
            Command::Connect { ssid } => {
                if self.state != State::Idle {
                    out.push(Action::Disconnect {
                        reason: REASON_LEAVING,
                    });
                }
                let profile = self.profiles.iter().find(|p| p.ssid == ssid);
                self.target = Some(Target {
                    retry: profile.is_some_and(|p| p.autoconnect),
                    save: profile.is_none(),
                    secret: None,
                    ssid,
                });
                self.session = None;
                self.pending = None;
                self.attempts = 0;
                self.start_scan(out);
            }

            // No target: which network to join is a question for the scan
            // results, and `select` answers it with `policy::best_known`.
            Command::Autoconnect => {
                if self.state != State::Idle {
                    return;
                }
                self.target = None;
                self.session = None;
                self.pending = None;
                self.attempts = 0;
                self.start_scan(out);
            }

            Command::Secret { value } => {
                let Some(target) = self.target.as_mut() else {
                    return;
                };
                target.secret = Some(value);
                // A BSS was chosen and parked waiting for exactly this.
                if let Some(bss) = self.pending.take() {
                    self.plan(bss, false, out);
                }
            }

            Command::Disconnect => {
                out.push(Action::Disconnect {
                    reason: REASON_LEAVING,
                });
                self.go_idle(out);
            }
        }
    }

    // -- scanning ---------------------------------------------------------

    fn start_scan(&mut self, out: &mut Vec<Action>) {
        self.enter(State::Scanning, out);
        out.push(Action::TriggerScan {
            ifindex: self.device.ifindex,
        });
        self.arm(TimerId::ScanTimeout, SCAN_TIMEOUT_MS, out);
    }

    fn on_scan_results(&mut self, scan: Vec<Bss>, out: &mut Vec<Action>) {
        match self.state {
            State::Scanning => self.select(scan, out),
            // A scan while associated is a roaming survey.
            State::Connected => self.consider_roam(scan, out),
            _ => {}
        }
    }

    /// Pick a BSS out of a scan and start working towards it.
    ///
    /// A target already set means `caw connect` named the network and only the
    /// BSS is open; no target means this scan came from
    /// [`Command::Autoconnect`], where policy chooses the network too. The
    /// chosen BSSID is carried out of the borrow rather than the BSS itself,
    /// so the profile lookup and the assignment below do not overlap.
    fn select(&mut self, scan: Vec<Bss>, out: &mut Vec<Action>) {
        let (bssid, discovered) = match self.target.as_ref() {
            Some(target) => match policy::best_bss(&scan, &target.ssid) {
                Some(bss) => (bss.bssid, None),
                None => {
                    self.fail(Failure::NotFound, out);
                    return;
                }
            },
            None => match policy::best_known(&scan, &self.profiles) {
                Some((bss, profile)) => (bss.bssid, Some(profile.ssid.clone())),
                None => {
                    self.fail(Failure::NoKnownNetwork, out);
                    return;
                }
            },
        };

        if let Some(ssid) = discovered {
            self.target = Some(Target {
                ssid,
                secret: None,
                // `best_known` only returns profiles with autoconnect set, so
                // this network is one to hold on to across a drop — the same
                // rule `Command::Connect` applies.
                retry: true,
                save: false,
            });
        }

        let bss = scan
            .into_iter()
            .find(|bss| bss.bssid == bssid)
            .expect("policy chose it out of this list");
        self.plan(bss, false, out);
    }

    /// Everything policy has to say about one BSS, before any key material is
    /// involved.
    fn evaluate(
        &self,
        bss: &Bss,
        credential: Option<&Credential>,
        roaming: bool,
    ) -> Result<Choice, Failure> {
        let rsn = match &bss.rsn {
            // caw joins CCMP networks and open ones. A WEP network reaches
            // here as "no RSN element plus the Privacy bit", which is why the
            // two are told apart by the classification and not by the element.
            None if bss.security == Security::Open => None,
            None => return Err(Failure::UnsupportedSecurity),
            Some(rsn) => Some(negotiate(rsn, credential)?),
        };

        let negotiated = match &rsn {
            Some(n) => policy::negotiated_security(n.akm, n.mfp_required),
            None => Security::Open,
        };

        // The floor is checked against what this association would actually
        // provide, not against what the beacon claims: a transition-mode
        // network joined with SAE is a WPA3 connection, and the same network
        // joined with PSK is not.
        if let Some(profile) = self.profile()
            && !profile.accepts(negotiated)
        {
            return Err(Failure::Downgrade {
                recorded: profile.min_security,
                offered: negotiated,
            });
        }

        Ok(Choice {
            bssid: bss.bssid,
            freq_mhz: bss.freq_mhz,
            signal_dbm: bss.signal_dbm,
            advertised: bss.security,
            negotiated,
            rsn,
            roaming,
        })
    }

    /// Decide how to join one BSS, and start doing it.
    fn plan(&mut self, bss: Bss, roaming: bool, out: &mut Vec<Action>) {
        let credential = self.credential(bss.rsn.is_none());
        let choice = match self.evaluate(&bss, credential.as_ref(), roaming) {
            Ok(choice) => choice,
            Err(failure) => {
                // A roam that will not plan is not a failure: staying on a
                // working association beats tearing it down for a candidate
                // that turned out to be unusable.
                if !roaming {
                    self.fail(failure, out);
                }
                return;
            }
        };

        let Some(credential) = credential else {
            // An enterprise network needs an identity and a trust anchor,
            // which is a profile's worth of configuration and not something to
            // prompt for in the middle of a connection.
            if choice.rsn.as_ref().is_some_and(|n| n.akm.is_enterprise()) {
                self.fail(Failure::NoCredential, out);
                return;
            }
            // Stop the scan timeout: a person typing a passphrase is not a
            // scan that failed, and reporting "no such network" because they
            // were slow would be a lie.
            self.disarm(out);
            out.push(Action::RequestSecret {
                prompt: format!("Passphrase for {}", caw_80211::Ssid(self.ssid_bytes())),
            });
            self.pending = Some(bss);
            return;
        };

        let ssid = self.ssid_bytes();
        let context = auth_context(&ssid, &choice, self.device.mac);
        let auth = match &choice.rsn {
            None => Auth::Open,
            Some(_) => match auth::assemble(context.akm, &credential, self.device.caps, &context) {
                Ok(auth) => auth,
                Err(failure) => {
                    self.fail(failure, out);
                    return;
                }
            },
        };

        let pre_assoc = matches!(auth, Auth::PreAssoc(_));
        self.session = Some(Session {
            choice,
            auth,
            pmkid: None,
            assoc_ie: Vec::new(),
            handshake: None,
        });

        // SAE is the one exchange that has to finish before the association
        // request goes out: the PMK it derives is named in that request.
        if pre_assoc {
            self.start_sae(out);
        } else {
            self.associate(out);
        }
    }

    // -- pre-association authentication (SAE) -----------------------------

    fn start_sae(&mut self, out: &mut Vec<Action>) {
        self.enter(State::Authenticating, out);
        self.drive_sae(SaeEvent::Start, out);
    }

    /// Feed the pre-association provider one event and act on what it says.
    fn drive_sae(&mut self, event: SaeEvent<'_>, out: &mut Vec<Action>) {
        let own_mac = self.device.mac;
        let Some(target) = self.target.as_ref() else {
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Auth::PreAssoc(provider) = &mut session.auth else {
            return;
        };

        let context = auth_context(&target.ssid, &session.choice, own_mac);
        let step = match event {
            SaeEvent::Start => provider.start(&context),
            SaeEvent::Frame(frame) => provider.on_frame(&context, frame),
            SaeEvent::Timeout => provider.on_timeout(&context),
        };
        self.on_sae_step(step, out);
    }

    fn on_sae_step(&mut self, step: Result<Step, caw_crypto::Error>, out: &mut Vec<Action>) {
        match step {
            Ok(Step::Send(frame)) => {
                out.push(Action::SendMgmtFrame(frame));
                self.arm(TimerId::AuthTimeout, AUTH_TIMEOUT_MS, out);
            }
            Ok(Step::Wait) => {}
            Ok(Step::Done(pmk)) => {
                let session = self.session.as_mut().expect("driving a session");
                // The PMKID has to be read off the provider before it is
                // dropped: the association request names the PMK by it, and
                // `PmkProvider` has no way to return one.
                if let Auth::PreAssoc(provider) = &session.auth {
                    session.pmkid = provider.pmkid();
                }
                session.auth = Auth::Ready(pmk);
                self.associate(out);
            }
            Err(e) => self.fail(Failure::from_crypto(e), out),
        }
    }

    // -- association ------------------------------------------------------

    fn associate(&mut self, out: &mut Vec<Action>) {
        let ifindex = self.device.ifindex;
        let ssid = self.target.as_ref().expect("a target is set").ssid.clone();
        let session = self.session.as_mut().expect("a session is planned");

        let mut request = AssocRequest {
            ifindex,
            ssid,
            bssid: session.choice.bssid,
            freq_mhz: session.choice.freq_mhz,
            auth_type: caw_nl80211::NL80211_AUTHTYPE_OPEN_SYSTEM,
            wpa_versions: 0,
            pairwise_ciphers: Vec::new(),
            group_cipher: None,
            akms: Vec::new(),
            mfp: None,
            ies: Vec::new(),
            offload: match std::mem::replace(&mut session.auth, Auth::Open) {
                Auth::Offloaded(offload) => Some(offload),
                other => {
                    session.auth = other;
                    None
                }
            },
        };

        if let Some(rsn) = &session.choice.rsn {
            let element = StationRsn {
                group: rsn.group,
                pairwise: rsn.pairwise,
                akm: rsn.akm,
                mfp_capable: rsn.mfp_capable,
                mfp_required: rsn.mfp_required,
                pmkid: session.pmkid,
                group_mgmt: rsn.mfp_capable.then_some(rsn.group_mgmt).flatten(),
            }
            .encode();

            request.auth_type = if rsn.akm.is_sae() {
                caw_nl80211::NL80211_AUTHTYPE_SAE
            } else {
                caw_nl80211::NL80211_AUTHTYPE_OPEN_SYSTEM
            };
            request.wpa_versions = if rsn.akm.is_sae() {
                caw_nl80211::NL80211_WPA_VERSION_2 | caw_nl80211::NL80211_WPA_VERSION_3
            } else {
                caw_nl80211::NL80211_WPA_VERSION_2
            };
            request.pairwise_ciphers = caw_nl80211::cipher_suite(rsn.pairwise)
                .into_iter()
                .collect();
            request.group_cipher = caw_nl80211::cipher_suite(rsn.group);
            request.akms = vec![caw_nl80211::akm_suite(rsn.akm)];
            request.mfp = Some(if rsn.mfp_required {
                caw_nl80211::NL80211_MFP_REQUIRED
            } else if rsn.mfp_capable {
                caw_nl80211::NL80211_MFP_OPTIONAL
            } else {
                caw_nl80211::NL80211_MFP_NO
            });
            request.ies = element.clone();
            session.assoc_ie = element;
        }

        self.enter(State::Associating, out);
        out.push(Action::Associate(Box::new(request)));
        self.arm(TimerId::AssocTimeout, ASSOC_TIMEOUT_MS, out);
    }

    fn on_associated(&mut self, out: &mut Vec<Action>) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        match std::mem::replace(&mut session.auth, Auth::Running) {
            // Nothing to key, or the device already did it: by the time it
            // reports the association, its keys are installed.
            Auth::Open | Auth::Offloaded(_) => {
                session.auth = Auth::Open;
                self.configured(out);
            }
            Auth::Ready(pmk) => self.start_handshake(pmk, out),
            // 802.1X speaks over EAPOL, which only exists once associated.
            Auth::PostAssoc(provider) => {
                session.auth = Auth::PostAssoc(provider);
                self.enter(State::Handshaking, out);
                self.drive_dot1x(None, out);
            }
            other => {
                session.auth = other;
                self.fail(
                    Failure::Internal("associated with no authentication staged".into()),
                    out,
                );
            }
        }
    }

    // -- the 4-way handshake ----------------------------------------------

    fn start_handshake(&mut self, pmk: Pmk, out: &mut Vec<Action>) {
        let own_mac = self.device.mac;
        let session = self
            .session
            .as_mut()
            .expect("associating implies a session");
        let rsn = session
            .choice
            .rsn
            .as_ref()
            .expect("a PMK implies a secured network");

        let config = caw_eapol::Config {
            akm: rsn.akm,
            own_mac,
            bssid: session.choice.bssid,
            assoc_rsn_ie: session.assoc_ie.clone(),
            beacon_rsn_ie: rsn.beacon_ie.clone(),
        };
        match caw_eapol::FourWay::new(pmk, config) {
            Ok(handshake) => {
                session.handshake = Some(handshake);
                self.enter(State::Handshaking, out);
            }
            Err(e) => self.fail(Failure::from_eapol(e), out),
        }
    }

    fn on_eapol(&mut self, frame: &[u8], out: &mut Vec<Action>) {
        if !matches!(self.state, State::Handshaking | State::Connected) {
            return;
        }
        // EAPOL carries two conversations on one EtherType. Routing by packet
        // type rather than by state is what lets an 802.1X exchange and the
        // handshake that follows it share the socket without a mode flag.
        match caw_eapol::Eapol::parse(frame).map(|e| e.packet_type) {
            Ok(caw_eapol::PacketType::Key) => self.drive_handshake(frame, out),
            Ok(caw_eapol::PacketType::Eap) => self.drive_dot1x(Some(frame), out),
            // EAPOL-Start and Logoff are an authenticator's to receive.
            Ok(_) => {}
            Err(_) => {}
        }
    }

    fn drive_handshake(&mut self, frame: &[u8], out: &mut Vec<Action>) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Some(handshake) = session.handshake.as_mut() else {
            return;
        };
        let result = handshake.poll(caw_eapol::Input::Frame(frame));
        self.on_handshake_actions(result, out);
    }

    fn on_handshake_actions(
        &mut self,
        result: Result<Vec<caw_eapol::Action>, caw_eapol::Error>,
        out: &mut Vec<Action>,
    ) {
        let actions = match result {
            Ok(actions) => actions,
            Err(e) => return self.fail(Failure::from_eapol(e), out),
        };

        let mut complete = false;
        for action in actions {
            match action {
                caw_eapol::Action::Send(frame) => out.push(Action::SendEapol(frame)),
                caw_eapol::Action::ArmTimer(millis) => {
                    self.arm(TimerId::HandshakeRetry, u64::from(millis), out);
                }
                caw_eapol::Action::DisarmTimer => self.disarm(out),
                caw_eapol::Action::Complete(keys) => {
                    out.push(Action::InstallKeys(Box::new(self.pairwise_install(keys))));
                    complete = true;
                }
                caw_eapol::Action::NewGtk(gtk) => {
                    out.push(Action::InstallKeys(Box::new(KeyInstall {
                        pairwise: None,
                        group: GroupKey {
                            cipher: self.group_suite(),
                            gtk,
                        },
                    })));
                }
            }
        }
        // Only the pairwise handshake finishing moves the connection on; a
        // group rekey leaves it exactly where it was.
        if complete {
            self.configured(out);
        }
    }

    fn pairwise_install(&self, keys: caw_eapol::Keys) -> KeyInstall {
        let session = self.session.as_ref().expect("keys imply a session");
        let rsn = session.choice.rsn.as_ref().expect("keys imply an RSN");
        KeyInstall {
            pairwise: Some(PairwiseKey {
                peer: session.choice.bssid,
                cipher: caw_nl80211::cipher_suite(rsn.pairwise)
                    .unwrap_or(caw_nl80211::WLAN_CIPHER_SUITE_CCMP),
                ptk: keys.ptk,
            }),
            group: GroupKey {
                cipher: self.group_suite(),
                gtk: keys.gtk,
            },
        }
    }

    fn group_suite(&self) -> u32 {
        self.session
            .as_ref()
            .and_then(|s| s.choice.rsn.as_ref())
            .and_then(|rsn| caw_nl80211::cipher_suite(rsn.group))
            .unwrap_or(caw_nl80211::WLAN_CIPHER_SUITE_CCMP)
    }

    // -- post-association authentication (802.1X) -------------------------

    fn drive_dot1x(&mut self, frame: Option<&[u8]>, out: &mut Vec<Action>) {
        let own_mac = self.device.mac;
        let Some(target) = self.target.as_ref() else {
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Auth::PostAssoc(provider) = &mut session.auth else {
            return;
        };
        let context = auth_context(&target.ssid, &session.choice, own_mac);
        let step = match frame {
            Some(frame) => provider.on_frame(&context, frame),
            None => provider.start(&context),
        };

        match step {
            Ok(Step::Send(frame)) => out.push(Action::SendEapol(frame)),
            Ok(Step::Wait) => {}
            // The MSK becomes the PMK, and from here the 4-way handshake is
            // the same one a home network runs.
            Ok(Step::Done(pmk)) => {
                session.auth = Auth::Running;
                self.start_handshake(pmk, out);
            }
            Err(e) => self.fail(Failure::from_crypto(e), out),
        }
    }

    // -- address configuration --------------------------------------------

    /// The link is keyed. Configure an address, unless this was a roam and the
    /// one we have is still valid.
    fn configured(&mut self, out: &mut Vec<Action>) {
        if self.session.as_ref().is_some_and(|s| s.choice.roaming) {
            self.enter(State::Connected, out);
            self.attempts = 0;
            return;
        }
        self.enter(State::Configuring, out);
        out.push(Action::StartDhcp);
    }

    fn on_lease(&mut self, event: LeaseEvent, out: &mut Vec<Action>) {
        match event {
            LeaseEvent::Acquired(lease) => {
                out.push(Action::ApplyLease(lease));
                self.enter(State::Connected, out);
                self.attempts = 0;
                self.save_profile(out);
            }
            // The address went away but the link did not: ask for another
            // rather than tearing down an association that still works.
            LeaseEvent::Lost(_) if self.state == State::Connected => {
                self.enter(State::Configuring, out);
                out.push(Action::StartDhcp);
            }
            LeaseEvent::Lost(_) => {}
            LeaseEvent::Failed => self.fail(Failure::Dhcp, out),
        }
    }

    /// Write down a network that was joined with a typed passphrase, once it
    /// has actually worked. Never before: a profile saved on a wrong
    /// passphrase is a profile that fails forever.
    fn save_profile(&mut self, out: &mut Vec<Action>) {
        let Some(target) = self.target.as_mut() else {
            return;
        };
        if !target.save {
            return;
        }
        let Some(secret) = target.secret.clone() else {
            return;
        };
        let Some(session) = self.session.as_ref() else {
            return;
        };
        target.save = false;

        let credential = match &session.choice.rsn {
            Some(_) => Credential::Passphrase(secret),
            None => Credential::None,
        };
        let profile = Profile::new(target.ssid.clone(), session.choice.advertised, credential);
        self.insert_profile(profile.clone());
        out.push(Action::SaveProfile(Box::new(profile)));
    }

    // -- roaming ----------------------------------------------------------

    fn consider_roam(&mut self, scan: Vec<Bss>, out: &mut Vec<Action>) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let Some(target) = self.target.as_ref() else {
            return;
        };
        let current = session.choice.bssid;
        // Trust a fresh reading over the one recorded when we associated: the
        // margin is meaningless if the two sides of it are minutes apart.
        let signal = scan
            .iter()
            .find(|bss| bss.bssid == current)
            .map_or(session.choice.signal_dbm, |bss| bss.signal_dbm);

        let Some(better) = policy::roam_target(&scan, &target.ssid, current, signal) else {
            if let Some(session) = self.session.as_mut() {
                session.choice.signal_dbm = signal;
            }
            return;
        };
        let bssid = better.bssid;
        let better = scan
            .into_iter()
            .find(|bss| bss.bssid == bssid)
            .expect("policy chose it out of this list");

        self.plan(better, true, out);
    }

    // -- events and timers -------------------------------------------------

    fn on_wireless(&mut self, event: Event, out: &mut Vec<Action>) {
        match event {
            Event::ScanComplete { .. }
                if matches!(self.state, State::Scanning | State::Connected) =>
            {
                out.push(Action::FetchScanResults {
                    ifindex: self.device.ifindex,
                });
            }
            Event::ScanComplete { .. } => {}
            Event::ScanAborted { .. } if self.state == State::Scanning => {
                self.fail(Failure::NotFound, out);
            }
            Event::ScanAborted { .. } => {}

            Event::Connected { status, .. } if self.state == State::Associating => match status {
                ConnectStatus::Success => self.on_associated(out),
                ConnectStatus::Refused(code) => self.fail(Failure::Refused(code), out),
                ConnectStatus::TimedOut => self.fail(Failure::AssocTimeout, out),
            },
            Event::Connected { .. } => {}

            Event::Disconnected { reason, by_ap } => {
                if self.state != State::Idle {
                    self.fail(Failure::Disconnected { reason, by_ap }, out);
                }
            }

            // The kernel is withdrawing an external authentication request it
            // made earlier; there is nothing left to answer.
            Event::ExternalAuth { abort: true, .. } if self.state == State::Authenticating => {
                self.fail(Failure::AuthFailed, out);
            }
            Event::ExternalAuth { .. } => {}

            Event::Frame(frame) if self.state == State::Authenticating => {
                self.drive_sae(SaeEvent::Frame(&frame), out);
            }
            Event::Frame(_) => {}
        }
    }

    fn on_timer(&mut self, id: TimerId, out: &mut Vec<Action>) {
        match (id, self.state) {
            // Not while a prompt is outstanding: the BSS was found, and the
            // wait is on the user.
            (TimerId::ScanTimeout, State::Scanning) if self.pending.is_none() => {
                self.fail(Failure::NotFound, out)
            }
            (TimerId::AssocTimeout, State::Associating) => self.fail(Failure::AssocTimeout, out),
            (TimerId::AuthTimeout, State::Authenticating) => self.drive_sae(SaeEvent::Timeout, out),
            (TimerId::HandshakeRetry, State::Handshaking | State::Connected) => {
                let Some(handshake) = self.session.as_mut().and_then(|s| s.handshake.as_mut())
                else {
                    return;
                };
                let result = handshake.poll(caw_eapol::Input::Timeout);
                self.on_handshake_actions(result, out);
            }
            (TimerId::ReconnectBackoff, State::Reconnecting) => self.start_scan(out),
            // A timer for a state we have already left. The daemon disarms on
            // request, but a expiry already in flight cannot be recalled.
            _ => {}
        }
    }

    // -- transitions -------------------------------------------------------

    fn enter(&mut self, state: State, out: &mut Vec<Action>) {
        // The handshake's retransmit timer survives into `Connected`, because
        // the exchange it belongs to does. Every other timer belongs to the
        // state that armed it.
        if self.armed.is_some() && self.armed != timer_of(state) {
            self.disarm(out);
        }
        self.state = state;
        out.push(Action::Notify(state));
    }

    fn go_idle(&mut self, out: &mut Vec<Action>) {
        self.disarm(out);
        self.state = State::Idle;
        self.target = None;
        self.session = None;
        self.pending = None;
        self.attempts = 0;
        out.push(Action::Notify(State::Idle));
    }

    /// End the attempt: either back off and try again, or report and stop.
    fn fail(&mut self, failure: Failure, out: &mut Vec<Action>) {
        // An association the kernel still believes in has to be torn down, or
        // it will sit there without keys. Not after a disconnection, which is
        // the kernel telling us it already has.
        let associated = matches!(
            self.state,
            State::Associating | State::Handshaking | State::Configuring | State::Connected
        );
        if associated && !matches!(failure, Failure::Disconnected { .. }) {
            out.push(Action::Disconnect {
                reason: REASON_LEAVING,
            });
        }
        self.session = None;
        self.pending = None;

        let retry = !failure.is_terminal() && self.target.as_ref().is_some_and(|t| t.retry);
        if retry {
            self.attempts += 1;
            self.enter(State::Reconnecting, out);
            let millis = backoff_ms(self.attempts);
            self.arm(TimerId::ReconnectBackoff, millis, out);
            return;
        }

        self.disarm(out);
        self.state = State::Idle;
        self.target = None;
        self.attempts = 0;
        out.push(Action::Failed(failure));
    }

    // -- helpers -----------------------------------------------------------

    fn arm(&mut self, id: TimerId, millis: u64, out: &mut Vec<Action>) {
        self.armed = Some(id);
        out.push(Action::SetTimer { id, millis });
    }

    fn disarm(&mut self, out: &mut Vec<Action>) {
        if let Some(id) = self.armed.take() {
            out.push(Action::ClearTimer { id });
        }
    }

    fn ssid_bytes(&self) -> Vec<u8> {
        self.target
            .as_ref()
            .map(|t| t.ssid.clone())
            .unwrap_or_default()
    }

    fn profile(&self) -> Option<&Profile> {
        let target = self.target.as_ref()?;
        self.profiles.iter().find(|p| p.ssid == target.ssid)
    }

    /// The credential to join with. `None` means one is needed and none is in
    /// hand, which is a prompt rather than a failure.
    fn credential(&self, open: bool) -> Option<Credential> {
        if open {
            return Some(Credential::None);
        }
        if let Some(profile) = self.profile() {
            return Some(profile.credential.clone());
        }
        self.target
            .as_ref()?
            .secret
            .clone()
            .map(Credential::Passphrase)
    }
}

/// What a pre-association provider is being told.
enum SaeEvent<'a> {
    Start,
    Frame(&'a [u8]),
    Timeout,
}

/// The peer a provider is authenticating against.
///
/// Built here rather than kept on the session because it borrows the SSID, and
/// a struct holding a reference into two other fields of the same object would
/// be a lifetime for no gain.
fn auth_context<'a>(ssid: &'a [u8], choice: &Choice, own_mac: [u8; 6]) -> AuthContext<'a> {
    AuthContext {
        ssid,
        bssid: choice.bssid,
        own_mac,
        // The default is never read: an open network runs no provider.
        akm: choice.rsn.as_ref().map_or(Akm::Psk, |n| n.akm),
    }
}

/// The suites to ask for on a secured network, or why none will do.
///
/// `credential` is `None` before one has been supplied; the AKM is then chosen
/// from the AP's list alone, which is enough to tell a network worth prompting
/// for from one caw could not join however good the passphrase.
fn negotiate(rsn: &RsnIe, credential: Option<&Credential>) -> Result<Negotiated, Failure> {
    let akm = policy::choose_akm(rsn, credential).ok_or(Failure::UnsupportedSecurity)?;
    let pairwise = policy::choose_pairwise(rsn).ok_or(Failure::UnsupportedSecurity)?;

    // WPA3 requires management frame protection; WPA2 uses it wherever the AP
    // offers it, because it is what stops a forged deauthentication.
    let mfp_required = rsn.mfp_required || akm.is_sae();
    Ok(Negotiated {
        akm,
        pairwise,
        group: rsn.group_cipher,
        group_mgmt: rsn.group_mgmt_cipher,
        mfp_capable: rsn.mfp_capable || mfp_required,
        mfp_required,
        beacon_ie: rsn.raw.clone(),
    })
}

/// The timer a state is waiting on, if any.
fn timer_of(state: State) -> Option<TimerId> {
    match state {
        State::Scanning => Some(TimerId::ScanTimeout),
        State::Authenticating => Some(TimerId::AuthTimeout),
        State::Associating => Some(TimerId::AssocTimeout),
        // The handshake arms its own retransmissions, and keeps arming them
        // for rekeys after the connection is up.
        State::Handshaking | State::Connected => Some(TimerId::HandshakeRetry),
        State::Reconnecting => Some(TimerId::ReconnectBackoff),
        State::Idle | State::Configuring => None,
    }
}

/// Exponential backoff, doubling from [`BACKOFF_BASE_MS`] and capped at
/// [`BACKOFF_MAX_MS`]. `attempt` counts from one.
fn backoff_ms(attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(u32::BITS - 1);
    BACKOFF_BASE_MS
        .saturating_mul(1u64 << shift.min(20))
        .min(BACKOFF_MAX_MS)
}
