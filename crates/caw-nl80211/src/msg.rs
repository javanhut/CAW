//! Request encoders.
//!
//! Every nl80211 command caw sends is built here, as a function from
//! parameters to bytes. Nothing in this module touches a socket, so the exact
//! wire layout of a connect request or a key installation can be asserted in a
//! unit test on any host.

use caw_netlink::{MsgBuilder, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST};

use crate::attr::{Nest, genlmsghdr};
use crate::consts::*;

/// Ask the generic-netlink controller which id a family was given.
pub fn get_family(seq: u32, name: &str) -> Vec<u8> {
    MsgBuilder::new(GENL_ID_CTRL, NLM_F_REQUEST, seq)
        .header(&genlmsghdr(CTRL_CMD_GETFAMILY, 1))
        .attr_str(CTRL_ATTR_FAMILY_NAME, name)
        .finish()
}

/// Dump every wiphy.
///
/// `NL80211_ATTR_SPLIT_WIPHY_DUMP` asks the kernel to describe each wiphy
/// across several messages instead of one. It costs a merge on this side, but
/// a modern radio's full capability set does not fit in a single netlink
/// message and the kernel would rather truncate the dump than split it
/// uninvited.
pub fn get_wiphy(family: u16, seq: u32) -> Vec<u8> {
    MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_DUMP, seq)
        .header(&genlmsghdr(NL80211_CMD_GET_WIPHY, 0))
        .attr(NL80211_ATTR_SPLIT_WIPHY_DUMP, &[])
        .finish()
}

/// Dump every wireless interface.
pub fn get_interface(family: u16, seq: u32) -> Vec<u8> {
    MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_DUMP, seq)
        .header(&genlmsghdr(NL80211_CMD_GET_INTERFACE, 0))
        .finish()
}

/// Start a scan.
///
/// The kernel acknowledges the request and scans in the background; results
/// arrive as a `NEW_SCAN_RESULTS` notification on the `scan` multicast group.
///
/// An empty `ssids` still sends one zero-length entry, which is a wildcard
/// probe request: without any entry the kernel scans passively and will not
/// find an AP that only answers directed probes.
pub fn trigger_scan(family: u16, seq: u32, ifindex: u32, ssids: &[&[u8]]) -> Vec<u8> {
    let mut nest = Nest::new();
    if ssids.is_empty() {
        nest = nest.attr(1, &[]);
    }
    for (i, ssid) in ssids.iter().enumerate() {
        // The kernel counts these and ignores their types; numbering from one
        // keeps every entry a valid attribute.
        nest = nest.attr(i as u16 + 1, ssid);
    }
    MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_ACK, seq)
        .header(&genlmsghdr(NL80211_CMD_TRIGGER_SCAN, 0))
        .attr_u32(NL80211_ATTR_IFINDEX, ifindex)
        .attr(NL80211_ATTR_SCAN_SSIDS, &nest.finish())
        .finish()
}

/// Dump the kernel's scan cache for one interface.
pub fn get_scan(family: u16, seq: u32, ifindex: u32) -> Vec<u8> {
    MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_DUMP, seq)
        .header(&genlmsghdr(NL80211_CMD_GET_SCAN, 0))
        .attr_u32(NL80211_ATTR_IFINDEX, ifindex)
        .finish()
}

/// Everything `NL80211_CMD_CONNECT` needs to join one BSS.
///
/// The ciphers and AKMs are the 32-bit selectors the kernel wants, not the
/// parsed `caw-80211` enums, because what caw asks for has to match the AP's
/// RSN element exactly — the 4-way handshake MIC covers the element that
/// advertised it. [`crate::cipher_suite`] and [`crate::akm_suite`] convert.
#[derive(Clone, Default, Debug)]
pub struct Connect<'a> {
    pub ssid: &'a [u8],
    /// Pinning the BSSID keeps the kernel on the AP that policy chose rather
    /// than letting it pick another in the same ESS.
    pub bssid: Option<[u8; 6]>,
    /// Narrows the association to one channel, saving a scan of the band.
    pub freq_mhz: Option<u32>,
    /// `NL80211_AUTHTYPE_*`. The default, `OPEN_SYSTEM`, is correct for
    /// everything but SAE and WEP shared key.
    pub auth_type: u32,
    /// `NL80211_WPA_VERSION_*`, a bitmask. Zero for an open network.
    pub wpa_versions: u32,
    pub pairwise_ciphers: &'a [u32],
    pub group_cipher: Option<u32>,
    pub akms: &'a [u32],
    /// `NL80211_MFP_*` for 802.11w. WPA3 requires it.
    pub mfp: Option<u32>,
    /// Information elements to put in the association request, headers and
    /// all. For any WPA network this is the RSN element, and it is not
    /// optional: the crypto suites above only tell the kernel which keys to
    /// expect, and an association request that carries no RSN element is
    /// refused by the AP with status 40, "invalid information element".
    ///
    /// These are the station's own element — the chosen pairwise cipher and
    /// AKM, not the AP's whole advertised list — and the same bytes the 4-way
    /// handshake MIC will cover, which is why they are passed through
    /// verbatim rather than rebuilt here.
    pub ies: &'a [u8],
}

/// Associate.
///
/// The kernel's own SME drives authentication and association from here, but
/// it composes no information elements of its own: whatever `req.ies` carries
/// is what goes on the air.
///
/// Note what is deliberately absent: `NL80211_ATTR_CONTROL_PORT_OVER_NL80211`.
/// Without it the kernel delivers EAPOL frames to the netdev as ordinary
/// EtherType 0x888E traffic, which is where `caw-eapol`'s `AF_PACKET` socket
/// is waiting for them.
pub fn connect(family: u16, seq: u32, ifindex: u32, req: &Connect<'_>) -> Vec<u8> {
    let mut b = MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_ACK, seq)
        .header(&genlmsghdr(NL80211_CMD_CONNECT, 0))
        .attr_u32(NL80211_ATTR_IFINDEX, ifindex)
        .attr(NL80211_ATTR_SSID, req.ssid)
        .attr_u32(NL80211_ATTR_AUTH_TYPE, req.auth_type);

    if let Some(bssid) = req.bssid {
        b = b.attr(NL80211_ATTR_MAC, &bssid);
    }
    if let Some(freq) = req.freq_mhz {
        b = b.attr_u32(NL80211_ATTR_WIPHY_FREQ, freq);
    }
    if req.wpa_versions != 0 {
        b = b.attr_u32(NL80211_ATTR_WPA_VERSIONS, req.wpa_versions);
    }
    if !req.pairwise_ciphers.is_empty() {
        b = b.attr(
            NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
            &suites(req.pairwise_ciphers),
        );
    }
    if let Some(group) = req.group_cipher {
        b = b.attr_u32(NL80211_ATTR_CIPHER_SUITE_GROUP, group);
    }
    if !req.akms.is_empty() {
        b = b.attr(NL80211_ATTR_AKM_SUITES, &suites(req.akms));
    }
    if let Some(mfp) = req.mfp {
        b = b.attr_u32(NL80211_ATTR_USE_MFP, mfp);
    }
    if !req.ies.is_empty() {
        b = b.attr(NL80211_ATTR_IE, req.ies);
    }
    // A flag attribute, and the kernel's own switch between an open network
    // and one whose association must be followed by a key exchange.
    if req.group_cipher.is_some() || !req.pairwise_ciphers.is_empty() {
        b = b.attr(NL80211_ATTR_PRIVACY, &[]);
    }
    b.finish()
}

/// Leave the current network. `reason` is an 802.11 reason code; 3,
/// "deauthenticated because sending station is leaving", is the usual one.
pub fn disconnect(family: u16, seq: u32, ifindex: u32, reason: u16) -> Vec<u8> {
    MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_ACK, seq)
        .header(&genlmsghdr(NL80211_CMD_DISCONNECT, 0))
        .attr_u32(NL80211_ATTR_IFINDEX, ifindex)
        .attr(NL80211_ATTR_REASON_CODE, &reason.to_ne_bytes())
        .finish()
}

/// Install the pairwise key derived by the 4-way handshake.
///
/// Index 0 is the only one a station uses for a PTK. The peer address is what
/// tells the kernel this is a pairwise key rather than a group one.
pub fn new_pairwise_key(
    family: u16,
    seq: u32,
    ifindex: u32,
    peer: [u8; 6],
    cipher: u32,
    key: &[u8],
) -> Vec<u8> {
    MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_ACK, seq)
        .header(&genlmsghdr(NL80211_CMD_NEW_KEY, 0))
        .attr_u32(NL80211_ATTR_IFINDEX, ifindex)
        .attr(NL80211_ATTR_MAC, &peer)
        .attr(NL80211_ATTR_KEY_DATA, key)
        .attr(NL80211_ATTR_KEY_IDX, &[0])
        .attr_u32(NL80211_ATTR_KEY_CIPHER, cipher)
        .attr_u32(NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_PAIRWISE)
        .finish()
}

/// Install a group key.
///
/// `rsc` is the receive sequence counter from the handshake, without which the
/// first broadcast frames after a rekey are dropped as replays.
pub fn new_group_key(
    family: u16,
    seq: u32,
    ifindex: u32,
    idx: u8,
    cipher: u32,
    key: &[u8],
    rsc: &[u8],
) -> Vec<u8> {
    let mut b = MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_ACK, seq)
        .header(&genlmsghdr(NL80211_CMD_NEW_KEY, 0))
        .attr_u32(NL80211_ATTR_IFINDEX, ifindex)
        .attr(NL80211_ATTR_KEY_DATA, key)
        .attr(NL80211_ATTR_KEY_IDX, &[idx])
        .attr_u32(NL80211_ATTR_KEY_CIPHER, cipher)
        .attr_u32(NL80211_ATTR_KEY_TYPE, NL80211_KEYTYPE_GROUP);
    if !rsc.is_empty() {
        b = b.attr(NL80211_ATTR_KEY_SEQ, rsc);
    }
    b.finish()
}

/// Which traffic a default key covers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyScope {
    Unicast,
    Multicast,
    Both,
}

/// Make an installed key the default.
///
/// A station does this for the group key: `NEW_KEY` puts the GTK in the
/// device, and this says which index broadcast traffic is decrypted with.
pub fn set_default_key(family: u16, seq: u32, ifindex: u32, idx: u8, scope: KeyScope) -> Vec<u8> {
    let mut types = Nest::new();
    if matches!(scope, KeyScope::Unicast | KeyScope::Both) {
        types = types.flag(NL80211_KEY_DEFAULT_TYPE_UNICAST);
    }
    if matches!(scope, KeyScope::Multicast | KeyScope::Both) {
        types = types.flag(NL80211_KEY_DEFAULT_TYPE_MULTICAST);
    }
    MsgBuilder::new(family, NLM_F_REQUEST | NLM_F_ACK, seq)
        .header(&genlmsghdr(NL80211_CMD_SET_KEY, 0))
        .attr_u32(NL80211_ATTR_IFINDEX, ifindex)
        .attr(NL80211_ATTR_KEY_IDX, &[idx])
        .attr(NL80211_ATTR_KEY_DEFAULT, &[])
        .attr(NL80211_ATTR_KEY_DEFAULT_TYPES, &types.finish())
        .finish()
}

/// A suite list is one attribute holding the selectors end to end, not a nest.
fn suites(list: &[u32]) -> Vec<u8> {
    list.iter().flat_map(|s| s.to_ne_bytes()).collect()
}
