//! nl80211: wireless device control.
//!
//! Enumerates PHYs, triggers and collects scans, drives association, installs
//! pairwise and group keys, and carries SAE's management frames via
//! `NL80211_CMD_EXTERNAL_AUTH` / `NL80211_CMD_FRAME`.
//!
//! Note that on mac80211 softmac drivers the kernel does *not* perform the
//! 4-way handshake; this crate associates and installs keys, but the handshake
//! itself belongs to `caw-eapol`.
#![forbid(unsafe_code)]

/// A wireless PHY and its capabilities.
pub struct Wiphy {
    pub index: u32,
    pub name: String,
    pub supports_ap: bool,
    /// `NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK`: the device can offload the
    /// handshake, letting us hand the PSK to the kernel instead of running it.
    pub offloads_4way_psk: bool,
    pub offloads_sae: bool,
}

/// One BSS from a scan.
pub struct Bss {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub freq_mhz: u32,
    pub signal_dbm: i32,
    pub security: caw_80211::Security,
    pub rsn: Option<caw_80211::RsnIe>,
}

/// Events the kernel pushes on the multicast groups we subscribe to.
pub enum Event {
    ScanComplete { wiphy: u32 },
    Connected { bssid: [u8; 6] },
    Disconnected { reason: u16 },
    /// SAE: the kernel wants userspace to run external authentication.
    ExternalAuth { bssid: [u8; 6], ssid: Vec<u8> },
    /// A management frame we registered interest in (SAE commit/confirm).
    Frame(Vec<u8>),
}

pub fn trigger_scan(_ifindex: u32) -> Result<(), caw_netlink::Error> {
    todo!("NL80211_CMD_TRIGGER_SCAN")
}

pub fn scan_results(_ifindex: u32) -> Result<Vec<Bss>, caw_netlink::Error> {
    todo!("NL80211_CMD_GET_SCAN dump")
}
