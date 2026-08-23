//! Scan results: turning one `NL80211_ATTR_BSS` nest into a [`Bss`].
//!
//! Pure decoding — it takes the bytes the kernel sent and hands the
//! information elements straight to `caw-80211`, which owns every opinion
//! about what an RSN element means.

use caw_80211::{BeaconIes, RsnIe, Security};

use crate::attr::{Attrs, i32_of, mac_of, u16_of};
use crate::consts::*;

/// The Privacy bit of the 802.11 capability field. Without an RSN or WPA
/// element it is the only evidence that a network is WEP rather than open.
const CAPABILITY_PRIVACY: u16 = 1 << 4;

/// One BSS from a scan.
pub struct Bss {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub freq_mhz: u32,
    pub signal_dbm: i32,
    /// How long ago the kernel last heard this BSS. Scan results linger in the
    /// kernel's cache after the radio has moved on, so age is what separates a
    /// network that is still there from one that was.
    pub last_seen_ms: u32,
    /// The 802.11 capability field, kept because the Privacy bit is what
    /// classifies a WEP network and nl80211 reports it nowhere else.
    pub capability: u16,
    pub security: Security,
    pub rsn: Option<RsnIe>,
}

impl Bss {
    /// Stand-in for a BSS the driver reported without a signal strength.
    ///
    /// A few fullmac drivers send only `NL80211_BSS_SIGNAL_UNSPEC`, a 0..100
    /// scale with no defined mapping to dBm. Inventing a number would make an
    /// unknown reading outrank a measured one; this sorts last instead.
    pub const UNKNOWN_SIGNAL: i32 = i32::MIN;

    /// Decode the contents of a nested `NL80211_ATTR_BSS` attribute.
    ///
    /// `None` when the nest carries no BSSID, which is the one field that
    /// makes the entry addressable.
    pub fn parse(nested: &[u8]) -> Option<Self> {
        let mut bssid = None;
        let mut freq_mhz = 0;
        let mut signal_dbm = Self::UNKNOWN_SIGNAL;
        let mut last_seen_ms = 0;
        let mut capability = 0;
        // The kernel reports probe-response elements in
        // NL80211_BSS_INFORMATION_ELEMENTS and beacon elements separately.
        // Probe responses win: a hidden network answers a directed probe with
        // its real SSID while its beacon omits it.
        let mut ies: &[u8] = &[];
        let mut beacon_ies: &[u8] = &[];

        for attr in Attrs::new(nested) {
            match attr.kind {
                NL80211_BSS_BSSID => bssid = mac_of(&attr),
                NL80211_BSS_FREQUENCY => freq_mhz = attr.u32().unwrap_or(0),
                NL80211_BSS_CAPABILITY => capability = u16_of(&attr).unwrap_or(0),
                NL80211_BSS_SIGNAL_MBM => {
                    signal_dbm = i32_of(&attr).map_or(Self::UNKNOWN_SIGNAL, mbm_to_dbm);
                }
                NL80211_BSS_SEEN_MS_AGO => last_seen_ms = attr.u32().unwrap_or(0),
                NL80211_BSS_INFORMATION_ELEMENTS => ies = attr.payload,
                NL80211_BSS_BEACON_IES => beacon_ies = attr.payload,
                _ => {}
            }
        }

        let elements = if ies.is_empty() { beacon_ies } else { ies };
        let parsed = BeaconIes::parse(elements);
        Some(Self {
            bssid: bssid?,
            ssid: parsed
                .ssid
                .as_ref()
                .map(|s| s.0.clone())
                .unwrap_or_default(),
            freq_mhz,
            signal_dbm,
            last_seen_ms,
            capability,
            security: parsed.security(capability & CAPABILITY_PRIVACY != 0),
            rsn: parsed.rsn,
        })
    }
}

/// nl80211 reports signal strength in mBm; `Bss` carries whole dBm.
///
/// Rounded to nearest rather than truncated: Rust divides toward zero, so
/// truncating a negative reading rounds it up and would make every signal
/// report half a dB stronger than it is.
pub fn mbm_to_dbm(mbm: i32) -> i32 {
    (mbm + 50 * mbm.signum()) / 100
}
