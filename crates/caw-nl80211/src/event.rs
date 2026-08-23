//! Decoding the notifications the kernel pushes on nl80211's multicast groups.
//!
//! Pure: it turns one message body into an [`Event`]. Which groups are
//! subscribed, and who reads the socket, is `sock`'s problem.

use crate::attr::{Attrs, genl_cmd, mac_of, u16_of};
use crate::consts::*;

/// Events the kernel pushes on the multicast groups we subscribe to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    /// A scan finished and its results are in the kernel's cache. The results
    /// themselves still have to be fetched with a `GET_SCAN` dump.
    ScanComplete {
        wiphy: u32,
        ifindex: u32,
    },
    ScanAborted {
        wiphy: u32,
        ifindex: u32,
    },
    /// The outcome of `NL80211_CMD_CONNECT`.
    Connected {
        /// The AP that answered. Absent when none did, and absent on some
        /// drivers even for a refusal.
        bssid: Option<[u8; 6]>,
        status: ConnectStatus,
    },
    Disconnected {
        /// An 802.11 reason code, or zero when caw asked for the disconnect
        /// itself.
        reason: u16,
        /// The AP ended it. This is the difference between a link worth
        /// re-establishing and one caw tore down on purpose.
        by_ap: bool,
    },
    /// SAE: the kernel wants userspace to run external authentication.
    ExternalAuth {
        bssid: [u8; 6],
        ssid: Vec<u8>,
        /// `NL80211_EXTERNAL_AUTH_ABORT` — the kernel is withdrawing a request
        /// it made earlier, not asking for a new exchange.
        abort: bool,
    },
    /// A management frame we registered interest in (SAE commit/confirm).
    Frame(Vec<u8>),
}

/// How an association attempt ended.
///
/// Three outcomes, not two, and the kernel does not spell them out the same
/// way: on a timeout it sends `NL80211_ATTR_TIMED_OUT` and *no* status code at
/// all, so treating a missing status as success would report a connection that
/// never happened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectStatus {
    Success,
    /// The 802.11 status code from the AP's association response. On a device
    /// that offloads the handshake this is also where a wrong passphrase
    /// surfaces, since there is no EAPOL exchange left to fail.
    Refused(u16),
    /// No AP answered.
    TimedOut,
}

impl Event {
    /// Decode one nl80211 notification from a netlink message body, that is
    /// from the `genlmsghdr` onwards.
    ///
    /// `None` for the many commands caw does not act on — regulatory changes,
    /// survey results, interface churn — which arrive on the same groups.
    pub fn decode(body: &[u8]) -> Option<Self> {
        let cmd = genl_cmd(body)?;
        let attrs = || Attrs::of_body(body);
        let find = |kind| attrs().find(kind);

        match cmd {
            NL80211_CMD_NEW_SCAN_RESULTS | NL80211_CMD_SCAN_ABORTED => {
                let wiphy = find(NL80211_ATTR_WIPHY).and_then(|a| a.u32()).unwrap_or(0);
                let ifindex = find(NL80211_ATTR_IFINDEX)
                    .and_then(|a| a.u32())
                    .unwrap_or(0);
                Some(if cmd == NL80211_CMD_NEW_SCAN_RESULTS {
                    Self::ScanComplete { wiphy, ifindex }
                } else {
                    Self::ScanAborted { wiphy, ifindex }
                })
            }
            NL80211_CMD_CONNECT => Some(Self::Connected {
                bssid: find(NL80211_ATTR_MAC).and_then(|a| mac_of(&a)),
                status: if find(NL80211_ATTR_TIMED_OUT).is_some() {
                    ConnectStatus::TimedOut
                } else {
                    match find(NL80211_ATTR_STATUS_CODE).and_then(|a| u16_of(&a)) {
                        None | Some(0) => ConnectStatus::Success,
                        Some(code) => ConnectStatus::Refused(code),
                    }
                },
            }),
            NL80211_CMD_DISCONNECT => Some(Self::Disconnected {
                reason: find(NL80211_ATTR_REASON_CODE)
                    .and_then(|a| u16_of(&a))
                    .unwrap_or(0),
                by_ap: find(NL80211_ATTR_DISCONNECTED_BY_AP).is_some(),
            }),
            // Note this carries NL80211_ATTR_BSSID, not NL80211_ATTR_MAC as
            // the association commands do.
            NL80211_CMD_EXTERNAL_AUTH => Some(Self::ExternalAuth {
                bssid: find(NL80211_ATTR_BSSID).and_then(|a| mac_of(&a))?,
                ssid: find(NL80211_ATTR_SSID).map(|a| a.payload.to_vec())?,
                abort: find(NL80211_ATTR_EXTERNAL_AUTH_ACTION).and_then(|a| a.u32())
                    == Some(NL80211_EXTERNAL_AUTH_ABORT),
            }),
            NL80211_CMD_FRAME => Some(Self::Frame(find(NL80211_ATTR_FRAME)?.payload.to_vec())),
            _ => None,
        }
    }
}
