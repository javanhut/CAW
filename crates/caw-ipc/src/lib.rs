//! The protocol between the `caw` CLI and the `cawd` daemon.
//!
//! Newline-delimited JSON over a Unix socket at [`SOCKET_PATH`]. No D-Bus:
//! it is a dependency the average user should not have to think about, and a
//! line-oriented socket is trivial to script against.
//!
//! Deliberately the only crate both binaries share, so the CLI stays thin and
//! never links the netlink or crypto stack.
//!
//! # Shape of an exchange
//!
//! A client writes [`Request`]s, one JSON object per line. The daemon answers
//! each with zero or more [`Event`]s followed by exactly one [`Response`] —
//! both arrive as [`ServerMessage`], which is untagged and so puts the inner
//! value on the wire unwrapped:
//!
//! ```text
//! -> {"Connect":{"ssid":"HomeNet","port":null}}
//! <- "Scanning"
//! <- {"Associating":{"bssid":"aa:bb:cc:dd:ee:ff"}}
//! <- {"NeedSecret":{"token":1,"prompt":"Passphrase for HomeNet","kind":"Passphrase"}}
//! -> {"Secret":{"token":1,"value":"hunter2"}}
//! <- "Connected"
//! <- "Ok"
//! ```
//!
//! Unit variants are bare strings rather than `{"Scanning":null}`, which is
//! what serde's external tagging produces; the decoder accepts either form.
//!
//! # Sans-IO
//!
//! Nothing here opens a socket. [`frame::Decoder`] takes whatever bytes a
//! non-blocking read produced and yields whole messages, which is what lets
//! `cawd` run the protocol from its `poll` loop, and [`frame::write`] works
//! against any [`std::io::Write`].
#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod frame;

pub use frame::{Decoder, Error as FrameError, encode, read, write};

/// Where the daemon listens. Created by systemd's `RuntimeDirectory=`, or by
/// `cawd` itself when it is run by hand.
pub const SOCKET_PATH: &str = "/run/caw/caw.sock";

/// Directory holding [`SOCKET_PATH`].
pub const RUNTIME_DIR: &str = "/run/caw";

/// Members of this group may issue state-changing requests without being root.
/// Created by `/usr/lib/sysusers.d/caw.conf`.
pub const GROUP: &str = "caw";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    ListPorts,
    PortInfo {
        name: String,
    },
    PortUp {
        name: String,
        up: bool,
    },
    Scan {
        port: Option<String>,
    },
    Connect {
        ssid: String,
        port: Option<String>,
    },
    Disconnect {
        ssid: String,
    },
    Status,
    /// Supply a secret the daemon asked for, keeping passphrases off argv
    /// where they would be visible in `ps`.
    Secret {
        token: u64,
        value: Secret,
    },
    /// Stop the daemon: tear the connection down cleanly and remove the
    /// socket. Privileged, like any other state change.
    Shutdown,
}

impl Request {
    /// What a caller must be allowed to do to issue this.
    ///
    /// Queries answer from the kernel and change nothing, so they are open to
    /// every user; anything that touches the radio, a link or a stored profile
    /// is not. `Secret` is a read here only in the sense that it grants no
    /// privilege of its own — the daemon still checks that the token belongs
    /// to a request that client made.
    pub fn is_state_changing(&self) -> bool {
        match self {
            Self::ListPorts | Self::PortInfo { .. } | Self::Scan { .. } | Self::Status => false,
            Self::Secret { .. } => false,
            Self::PortUp { .. }
            | Self::Connect { .. }
            | Self::Disconnect { .. }
            | Self::Shutdown => true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Ports(Vec<PortSummary>),
    Networks(Vec<NetworkSummary>),
    Status(ConnectionStatus),
    Error { message: String },
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

/// Pushed unsolicited while a request is in flight, so `caw connect` can show
/// progress through association, handshake and address configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Scanning,
    Associating {
        bssid: String,
    },
    Authenticating,
    Configuring,
    Connected,
    Failed {
        reason: String,
    },
    /// The daemon needs a credential; answer with [`Request::Secret`].
    NeedSecret {
        token: u64,
        prompt: String,
        kind: SecretKind,
    },
}

/// Everything the daemon writes to a client.
///
/// Untagged, so an [`Event`] and a [`Response`] each appear on the wire as
/// themselves — the form the CLI's progress output was designed around. The
/// two sets of variant names are disjoint, which is what keeps the decoding
/// unambiguous, and a test holds them that way.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerMessage {
    Event(Event),
    Response(Response),
}

impl From<Event> for ServerMessage {
    fn from(e: Event) -> Self {
        Self::Event(e)
    }
}

impl From<Response> for ServerMessage {
    fn from(r: Response) -> Self {
        Self::Response(r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretKind {
    Passphrase,
    Username,
    Password,
}

/// A credential in transit.
///
/// A newtype rather than a bare `String` for two reasons: it is wiped when
/// dropped, and its [`fmt::Debug`] is redacted, so a daemon that logs the
/// request it just parsed cannot put a passphrase in the journal.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Read the plaintext. Named to make each use site obvious in review.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortSummary {
    pub name: String,
    pub mac: String,
    pub up: bool,
    pub carrier: bool,
    pub wireless: bool,
    pub addrs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub ssid: String,
    pub bssid: String,
    pub signal_dbm: i32,
    pub freq_mhz: u32,
    /// Rendered form of `caw_80211::Security`, e.g. "WPA3-Personal".
    pub security: String,
    pub known: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub port: String,
    pub ssid: Option<String>,
    pub state: String,
    pub addrs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json<T: Serialize>(value: &T) -> String {
        serde_json::to_string(value).unwrap()
    }

    #[test]
    fn requests_match_the_documented_wire_form() {
        assert_eq!(
            json(&Request::Connect {
                ssid: "HomeNet".into(),
                port: None
            }),
            r#"{"Connect":{"ssid":"HomeNet","port":null}}"#
        );
        assert_eq!(json(&Request::ListPorts), r#""ListPorts""#);
        assert_eq!(
            json(&Request::Secret {
                token: 1,
                value: Secret::new("hunter2")
            }),
            r#"{"Secret":{"token":1,"value":"hunter2"}}"#
        );
    }

    #[test]
    fn events_match_the_documented_wire_form() {
        assert_eq!(
            json(&Event::NeedSecret {
                token: 1,
                prompt: "Passphrase for HomeNet".into(),
                kind: SecretKind::Passphrase,
            }),
            r#"{"NeedSecret":{"token":1,"prompt":"Passphrase for HomeNet","kind":"Passphrase"}}"#
        );
        assert_eq!(json(&Event::Scanning), r#""Scanning""#);
    }

    /// serde writes a unit variant as a bare string but the architecture
    /// document spells it `{"Scanning":null}`. Both have to parse, or a
    /// hand-written client following the document would be rejected.
    #[test]
    fn unit_variants_parse_in_either_form() {
        let bare: Event = serde_json::from_str(r#""Scanning""#).unwrap();
        let object: Event = serde_json::from_str(r#"{"Scanning":null}"#).unwrap();
        assert!(matches!(bare, Event::Scanning));
        assert!(matches!(object, Event::Scanning));
    }

    /// [`ServerMessage`] is untagged, so it can only stay unambiguous while no
    /// variant name appears in both halves.
    #[test]
    fn every_server_message_decodes_to_the_side_it_came_from() {
        let events = [
            Event::Scanning,
            Event::Associating {
                bssid: "aa:bb:cc:dd:ee:ff".into(),
            },
            Event::Authenticating,
            Event::Configuring,
            Event::Connected,
            Event::Failed {
                reason: "no such network".into(),
            },
            Event::NeedSecret {
                token: 7,
                prompt: "Passphrase".into(),
                kind: SecretKind::Passphrase,
            },
        ];
        for event in events {
            let wire = json(&ServerMessage::Event(event.clone()));
            assert_eq!(wire, json(&event), "an untagged event must not be wrapped");
            let back: ServerMessage = serde_json::from_str(&wire).unwrap();
            assert!(
                matches!(back, ServerMessage::Event(_)),
                "{wire} decoded as a response"
            );
        }

        let responses = [
            Response::Ok,
            Response::Ports(vec![]),
            Response::Networks(vec![]),
            Response::Status(ConnectionStatus {
                port: "wlan0".into(),
                ssid: None,
                state: "Idle".into(),
                addrs: vec![],
            }),
            Response::error("nope"),
        ];
        for response in responses {
            let wire = json(&ServerMessage::Response(response.clone()));
            assert_eq!(wire, json(&response));
            let back: ServerMessage = serde_json::from_str(&wire).unwrap();
            assert!(
                matches!(back, ServerMessage::Response(_)),
                "{wire} decoded as an event"
            );
        }
    }

    #[test]
    fn secrets_are_not_printed_by_debug() {
        let req = Request::Secret {
            token: 3,
            value: Secret::new("hunter2"),
        };
        let rendered = format!("{req:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn reads_are_open_and_mutations_are_not() {
        assert!(!Request::Status.is_state_changing());
        assert!(!Request::ListPorts.is_state_changing());
        assert!(!Request::Scan { port: None }.is_state_changing());
        assert!(!Request::PortInfo { name: "w".into() }.is_state_changing());
        assert!(
            Request::PortUp {
                name: "w".into(),
                up: true
            }
            .is_state_changing()
        );
        assert!(
            Request::Connect {
                ssid: "n".into(),
                port: None
            }
            .is_state_changing()
        );
        assert!(Request::Disconnect { ssid: "n".into() }.is_state_changing());
        assert!(Request::Shutdown.is_state_changing());
    }
}
