//! Connection policy and the connection state machine.
//!
//! This is the brain: it decides which BSS to join, assembles the right
//! [`PmkProvider`] for a network's security, sequences association ->
//! authentication -> key install -> address configuration, and handles rekey,
//! roaming and reconnect.
//!
//! Sans-IO, like the layers below it. [`Connection::poll`] consumes an
//! [`Input`] and returns [`Action`]s for `cawd` to carry out. The daemon owns
//! every socket and timer; this crate owns every decision. A full connection,
//! including a 4-way handshake, can therefore be driven in a unit test.
#![forbid(unsafe_code)]

/// A saved network. Persisted 0600 under `/var/lib/caw/profiles/`.
pub struct Profile {
    pub ssid: Vec<u8>,
    pub security: caw_80211::Security,
    pub credential: Credential,
    pub autoconnect: bool,
    /// Refuse to join this SSID with weaker security than first seen, so an
    /// attacker cannot downgrade a WPA3 network to an open one.
    pub min_security: caw_80211::Security,
}

pub enum Credential {
    None,
    Passphrase(String),
    Enterprise {
        identity: String,
        anonymous_identity: Option<String>,
        method: EnterpriseMethod,
        ca_cert: Option<std::path::PathBuf>,
    },
}

pub enum EnterpriseMethod {
    Peap { password: String },
    Ttls { password: String },
    Tls { client_cert: std::path::PathBuf, key: std::path::PathBuf },
}

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

/// Things that happen to a connection.
pub enum Input {
    Command(Command),
    Wireless(caw_nl80211::Event),
    /// An EAPOL frame arrived — handshake or group rekey.
    Eapol(Vec<u8>),
    LeaseEvent,
    Timer(TimerId),
}

pub enum Command {
    Connect { ssid: Vec<u8> },
    Disconnect,
}

/// What the daemon should do. Never performed here.
pub enum Action {
    TriggerScan { ifindex: u32 },
    Associate { bssid: [u8; 6] },
    SendEapol(Vec<u8>),
    SendMgmtFrame(Vec<u8>),
    InstallKeys(caw_eapol::Keys),
    StartDhcp,
    ApplyLease(caw_dhcp::Lease),
    SetTimer { id: TimerId, millis: u64 },
    /// Ask the user, via whichever CLI is attached.
    RequestSecret { prompt: String },
    Notify(State),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimerId {
    ScanTimeout,
    AuthTimeout,
    HandshakeRetry,
    DhcpRetry,
    ReconnectBackoff,
}

/// One wireless connection on one interface.
pub struct Connection {
    _state: State,
}

impl Connection {
    pub fn poll(&mut self, _input: Input) -> Vec<Action> {
        todo!("the state machine")
    }
}
