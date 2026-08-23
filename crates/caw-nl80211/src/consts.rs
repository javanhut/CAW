//! Kernel numbers, taken verbatim from `linux/nl80211.h` and
//! `linux/genetlink.h`.
//!
//! Names match the kernel's so that a value can be checked against the header
//! without a translation step. Only the commands, attributes and enumerations
//! caw actually uses are here; the full nl80211 surface is an order of
//! magnitude larger.

// Generic netlink controller: the family that hands out every other family's
// id, and the only one with a fixed `nlmsg_type`.
pub const GENL_ID_CTRL: u16 = 0x10;

pub const CTRL_CMD_GETFAMILY: u8 = 3;

pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;

pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

// nl80211 commands.
pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_NEW_WIPHY: u8 = 3;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
pub const NL80211_CMD_SET_KEY: u8 = 10;
pub const NL80211_CMD_NEW_KEY: u8 = 11;
pub const NL80211_CMD_GET_SCAN: u8 = 32;
pub const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
pub const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;
pub const NL80211_CMD_SCAN_ABORTED: u8 = 35;
pub const NL80211_CMD_CONNECT: u8 = 46;
pub const NL80211_CMD_DISCONNECT: u8 = 48;
pub const NL80211_CMD_FRAME: u8 = 59;
pub const NL80211_CMD_EXTERNAL_AUTH: u8 = 127;

// nl80211 attributes.
pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_WIPHY_NAME: u16 = 2;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_KEY_DATA: u16 = 7;
pub const NL80211_ATTR_KEY_IDX: u16 = 8;
pub const NL80211_ATTR_KEY_CIPHER: u16 = 9;
pub const NL80211_ATTR_KEY_SEQ: u16 = 10;
pub const NL80211_ATTR_KEY_DEFAULT: u16 = 11;
pub const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
pub const NL80211_ATTR_IE: u16 = 42;
pub const NL80211_ATTR_SCAN_SSIDS: u16 = 45;
pub const NL80211_ATTR_BSS: u16 = 47;
pub const NL80211_ATTR_FRAME: u16 = 51;
pub const NL80211_ATTR_SSID: u16 = 52;
pub const NL80211_ATTR_AUTH_TYPE: u16 = 53;
pub const NL80211_ATTR_REASON_CODE: u16 = 54;
pub const NL80211_ATTR_KEY_TYPE: u16 = 55;
pub const NL80211_ATTR_TIMED_OUT: u16 = 65;
pub const NL80211_ATTR_USE_MFP: u16 = 66;
pub const NL80211_ATTR_PRIVACY: u16 = 70;
pub const NL80211_ATTR_DISCONNECTED_BY_AP: u16 = 71;
pub const NL80211_ATTR_STATUS_CODE: u16 = 72;
pub const NL80211_ATTR_CIPHER_SUITES_PAIRWISE: u16 = 73;
pub const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 74;
pub const NL80211_ATTR_WPA_VERSIONS: u16 = 75;
pub const NL80211_ATTR_AKM_SUITES: u16 = 76;
pub const NL80211_ATTR_KEY_DEFAULT_TYPES: u16 = 110;
pub const NL80211_ATTR_SPLIT_WIPHY_DUMP: u16 = 174;
pub const NL80211_ATTR_EXT_FEATURES: u16 = 217;
pub const NL80211_ATTR_BSSID: u16 = 245;
pub const NL80211_ATTR_EXTERNAL_AUTH_ACTION: u16 = 260;

// `enum nl80211_bss`, the attributes nested inside NL80211_ATTR_BSS.
pub const NL80211_BSS_BSSID: u16 = 1;
pub const NL80211_BSS_FREQUENCY: u16 = 2;
pub const NL80211_BSS_CAPABILITY: u16 = 5;
pub const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
pub const NL80211_BSS_SIGNAL_MBM: u16 = 7;
pub const NL80211_BSS_SEEN_MS_AGO: u16 = 10;
pub const NL80211_BSS_BEACON_IES: u16 = 11;

// `enum nl80211_iftype`.
pub const NL80211_IFTYPE_UNSPECIFIED: u32 = 0;
pub const NL80211_IFTYPE_ADHOC: u32 = 1;
pub const NL80211_IFTYPE_STATION: u32 = 2;
pub const NL80211_IFTYPE_AP: u32 = 3;
pub const NL80211_IFTYPE_MONITOR: u32 = 6;
pub const NL80211_IFTYPE_MESH_POINT: u32 = 7;
pub const NL80211_IFTYPE_P2P_CLIENT: u32 = 8;
pub const NL80211_IFTYPE_P2P_GO: u32 = 9;
pub const NL80211_IFTYPE_P2P_DEVICE: u32 = 10;

// `enum nl80211_key_type`.
pub const NL80211_KEYTYPE_GROUP: u32 = 0;
pub const NL80211_KEYTYPE_PAIRWISE: u32 = 1;

// `enum nl80211_key_default_types`, nested inside NL80211_ATTR_KEY_DEFAULT_TYPES.
pub const NL80211_KEY_DEFAULT_TYPE_UNICAST: u16 = 1;
pub const NL80211_KEY_DEFAULT_TYPE_MULTICAST: u16 = 2;

// `enum nl80211_wpa_versions`. A bitmask, so an AP in WPA2/WPA3 transition
// mode is joined with versions 2 and 3 both set.
pub const NL80211_WPA_VERSION_1: u32 = 1;
pub const NL80211_WPA_VERSION_2: u32 = 2;
pub const NL80211_WPA_VERSION_3: u32 = 4;

// `enum nl80211_auth_type`.
pub const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;
pub const NL80211_AUTHTYPE_SHARED_KEY: u32 = 1;
pub const NL80211_AUTHTYPE_FT: u32 = 2;
pub const NL80211_AUTHTYPE_SAE: u32 = 4;

// `enum nl80211_mfp`.
pub const NL80211_MFP_NO: u32 = 0;
pub const NL80211_MFP_REQUIRED: u32 = 1;
pub const NL80211_MFP_OPTIONAL: u32 = 2;

// `enum nl80211_external_auth_action`.
pub const NL80211_EXTERNAL_AUTH_START: u32 = 0;
pub const NL80211_EXTERNAL_AUTH_ABORT: u32 = 1;

// Bit indices into the NL80211_ATTR_EXT_FEATURES bitmap. These three decide
// whether caw runs the handshake itself or hands the credential to the device,
// so they are the only ones the crate reads.
pub const NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK: u32 = 15;
pub const NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X: u32 = 16;
pub const NL80211_EXT_FEATURE_SAE_OFFLOAD: u32 = 38;

/// 00-0F-AC, the IEEE 802.11 OUI every standard suite selector carries.
const OUI_IEEE: [u8; 3] = [0x00, 0x0f, 0xac];

/// A suite selector as nl80211 wants it: the OUI in the top three bytes and
/// the suite type in the low byte, so 00-0F-AC:4 is `0x000fac04`. This is the
/// kernel's `SUITE()` macro.
pub const fn suite(oui: [u8; 3], suite_type: u8) -> u32 {
    u32::from_be_bytes([oui[0], oui[1], oui[2], suite_type])
}

const fn ieee(suite_type: u8) -> u32 {
    suite(OUI_IEEE, suite_type)
}

pub const WLAN_CIPHER_SUITE_USE_GROUP: u32 = ieee(0);
pub const WLAN_CIPHER_SUITE_WEP40: u32 = ieee(1);
pub const WLAN_CIPHER_SUITE_TKIP: u32 = ieee(2);
pub const WLAN_CIPHER_SUITE_CCMP: u32 = ieee(4);
pub const WLAN_CIPHER_SUITE_WEP104: u32 = ieee(5);
pub const WLAN_CIPHER_SUITE_AES_CMAC: u32 = ieee(6);
pub const WLAN_CIPHER_SUITE_GCMP: u32 = ieee(8);
pub const WLAN_CIPHER_SUITE_GCMP_256: u32 = ieee(9);
pub const WLAN_CIPHER_SUITE_CCMP_256: u32 = ieee(10);

pub const WLAN_AKM_SUITE_8021X: u32 = ieee(1);
pub const WLAN_AKM_SUITE_PSK: u32 = ieee(2);
pub const WLAN_AKM_SUITE_FT_8021X: u32 = ieee(3);
pub const WLAN_AKM_SUITE_FT_PSK: u32 = ieee(4);
pub const WLAN_AKM_SUITE_8021X_SHA256: u32 = ieee(5);
pub const WLAN_AKM_SUITE_PSK_SHA256: u32 = ieee(6);
pub const WLAN_AKM_SUITE_SAE: u32 = ieee(8);
pub const WLAN_AKM_SUITE_FT_OVER_SAE: u32 = ieee(9);
pub const WLAN_AKM_SUITE_8021X_SUITE_B_192: u32 = ieee(12);
pub const WLAN_AKM_SUITE_OWE: u32 = ieee(18);

/// The suite selector nl80211 expects for a cipher `caw-80211` parsed out of
/// an RSN element.
///
/// The round trip matters: what caw asks the kernel to negotiate has to match
/// what the AP advertised, and the 4-way handshake MIC covers the element that
/// said so. `None` for `UseGroup`, which is not a cipher a station can request.
pub fn cipher_suite(cipher: caw_80211::Cipher) -> Option<u32> {
    use caw_80211::Cipher;
    Some(match cipher {
        Cipher::UseGroup => return None,
        Cipher::Wep40 => WLAN_CIPHER_SUITE_WEP40,
        Cipher::Tkip => WLAN_CIPHER_SUITE_TKIP,
        Cipher::Ccmp128 => WLAN_CIPHER_SUITE_CCMP,
        Cipher::Wep104 => WLAN_CIPHER_SUITE_WEP104,
        Cipher::BipCmac128 => WLAN_CIPHER_SUITE_AES_CMAC,
        Cipher::Gcmp128 => WLAN_CIPHER_SUITE_GCMP,
        Cipher::Gcmp256 => WLAN_CIPHER_SUITE_GCMP_256,
        Cipher::Ccmp256 => WLAN_CIPHER_SUITE_CCMP_256,
        // A vendor cipher keeps its own OUI; passing it through lets the
        // kernel reject it rather than having caw guess it away.
        Cipher::Unknown(sel) => u32::from_be_bytes(sel),
    })
}

/// The suite selector nl80211 expects for an AKM `caw-80211` parsed out of an
/// RSN element. See [`cipher_suite`].
pub fn akm_suite(akm: caw_80211::Akm) -> u32 {
    use caw_80211::Akm;
    match akm {
        Akm::Psk => WLAN_AKM_SUITE_PSK,
        Akm::PskSha256 => WLAN_AKM_SUITE_PSK_SHA256,
        Akm::Sae => WLAN_AKM_SUITE_SAE,
        Akm::Dot1x => WLAN_AKM_SUITE_8021X,
        Akm::Dot1xSha256 => WLAN_AKM_SUITE_8021X_SHA256,
        Akm::Owe => WLAN_AKM_SUITE_OWE,
        Akm::FtPsk => WLAN_AKM_SUITE_FT_PSK,
        Akm::FtSae => WLAN_AKM_SUITE_FT_OVER_SAE,
        Akm::FtDot1x => WLAN_AKM_SUITE_FT_8021X,
        Akm::Dot1xSuiteB192 => WLAN_AKM_SUITE_8021X_SUITE_B_192,
        Akm::Unknown(sel) => u32::from_be_bytes(sel),
    }
}
