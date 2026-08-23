//! The protocol between the `caw` CLI and the `cawd` daemon.
//!
//! Newline-delimited JSON over a Unix socket at `/run/caw/caw.sock`. No D-Bus:
//! it is a dependency the average user should not have to think about, and a
//! line-oriented socket is trivial to script against.
//!
//! Deliberately the only crate both binaries share, so the CLI stays thin and
//! never links the netlink or crypto stack.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Request {
    ListPorts,
    PortInfo { name: String },
    PortUp { name: String, up: bool },
    Scan { port: Option<String> },
    Connect { ssid: String, port: Option<String> },
    Disconnect { ssid: String },
    Status,
    /// Supply a secret the daemon asked for, keeping passphrases off argv
    /// where they would be visible in `ps`.
    Secret { token: u64, value: String },
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Ok,
    Ports(Vec<PortSummary>),
    Networks(Vec<NetworkSummary>),
    Status(ConnectionStatus),
    Error { message: String },
}

/// Pushed unsolicited while a request is in flight, so `caw connect` can show
/// progress through association, handshake and address configuration.
#[derive(Serialize, Deserialize)]
pub enum Event {
    Scanning,
    Associating { bssid: String },
    Authenticating,
    Configuring,
    Connected,
    Failed { reason: String },
    /// The daemon needs a credential; answer with [`Request::Secret`].
    NeedSecret { token: u64, prompt: String, kind: SecretKind },
}

#[derive(Serialize, Deserialize)]
pub enum SecretKind {
    Passphrase,
    Username,
    Password,
}

#[derive(Serialize, Deserialize)]
pub struct PortSummary {
    pub name: String,
    pub mac: String,
    pub up: bool,
    pub carrier: bool,
    pub wireless: bool,
    pub addrs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct NetworkSummary {
    pub ssid: String,
    pub bssid: String,
    pub signal_dbm: i32,
    pub freq_mhz: u32,
    /// Rendered form of `caw_80211::Security`, e.g. "WPA3-Personal".
    pub security: String,
    pub known: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub port: String,
    pub ssid: Option<String>,
    pub state: String,
    pub addrs: Vec<String>,
}
