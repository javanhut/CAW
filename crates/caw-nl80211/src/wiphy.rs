//! PHYs and interfaces: what radios exist, and what they can do themselves.

use caw_netlink::Message;

use crate::attr::{Attrs, mac_of};
use crate::consts::*;

/// A wireless PHY and its capabilities.
pub struct Wiphy {
    pub index: u32,
    pub name: String,
    pub supports_ap: bool,
    /// `NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK`: the device can offload the
    /// handshake, letting us hand the PSK to the kernel instead of running it.
    pub offloads_4way_psk: bool,
    /// The same for 802.1X, where the kernel is given the PMK the EAP exchange
    /// produced rather than the PSK.
    pub offloads_4way_1x: bool,
    pub offloads_sae: bool,
}

/// The `NL80211_ATTR_EXT_FEATURES` bitmap.
///
/// A byte array indexed by feature number, least-significant bit of byte zero
/// first: feature 15 is bit 7 of byte 1, feature 16 is bit 0 of byte 2. Get the
/// indexing wrong and caw silently misreads whether the device will run the
/// 4-way handshake for it, which fails much later and looks like a driver bug.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ExtFeatures(Vec<u8>);

impl ExtFeatures {
    pub fn new(bitmap: &[u8]) -> Self {
        Self(bitmap.to_vec())
    }

    pub fn has(&self, index: u32) -> bool {
        let byte = (index / 8) as usize;
        // A kernel older than the feature simply sends a shorter array, so a
        // read past the end is "not supported", not an error.
        self.0
            .get(byte)
            .is_some_and(|b| b & (1 << (index % 8)) != 0)
    }
}

/// One `NL80211_CMD_NEW_WIPHY` message.
///
/// Under a split dump the kernel describes a single wiphy across several
/// messages, each repeating the wiphy index, so a chunk carries only what its
/// own message said and is merged into the accumulating [`Wiphy`].
pub(crate) struct WiphyChunk {
    pub index: u32,
    pub name: Option<String>,
    pub supports_ap: bool,
    pub features: Option<ExtFeatures>,
}

impl WiphyChunk {
    pub(crate) fn parse(msg: &Message<'_>) -> Option<Self> {
        let mut chunk = Self {
            index: u32::MAX,
            name: None,
            supports_ap: false,
            features: None,
        };
        let mut seen_index = false;

        for attr in Attrs::of_body(msg.payload) {
            match attr.kind {
                NL80211_ATTR_WIPHY => {
                    chunk.index = attr.u32()?;
                    seen_index = true;
                }
                NL80211_ATTR_WIPHY_NAME => chunk.name = attr.str().map(str::to_owned),
                // A nest of flag attributes whose *types* are the iftypes.
                NL80211_ATTR_SUPPORTED_IFTYPES => {
                    chunk.supports_ap =
                        Attrs::new(attr.payload).any(|t| u32::from(t.kind) == NL80211_IFTYPE_AP);
                }
                NL80211_ATTR_EXT_FEATURES => {
                    chunk.features = Some(ExtFeatures::new(attr.payload));
                }
                _ => {}
            }
        }
        seen_index.then_some(chunk)
    }

    pub(crate) fn merge_into(self, wiphy: &mut Wiphy) {
        if let Some(name) = self.name {
            wiphy.name = name;
        }
        // Never clear a capability another chunk established: only one message
        // of a split dump carries any given attribute.
        wiphy.supports_ap |= self.supports_ap;
        if let Some(f) = self.features {
            wiphy.offloads_4way_psk |= f.has(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK);
            wiphy.offloads_4way_1x |= f.has(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X);
            wiphy.offloads_sae |= f.has(NL80211_EXT_FEATURE_SAE_OFFLOAD);
        }
    }

    pub(crate) fn into_wiphy(self) -> Wiphy {
        let mut wiphy = Wiphy {
            index: self.index,
            name: String::new(),
            supports_ap: false,
            offloads_4way_psk: false,
            offloads_4way_1x: false,
            offloads_sae: false,
        };
        self.merge_into(&mut wiphy);
        wiphy
    }
}

/// What a wireless interface is currently configured to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IfType {
    Unspecified,
    AdHoc,
    Station,
    Ap,
    Monitor,
    MeshPoint,
    P2pClient,
    P2pGo,
    P2pDevice,
    /// A mode caw has no use for; kept as its raw value so `caw port info` can
    /// still say something truthful about it.
    Other(u32),
}

impl IfType {
    pub fn from_raw(v: u32) -> Self {
        match v {
            NL80211_IFTYPE_UNSPECIFIED => Self::Unspecified,
            NL80211_IFTYPE_ADHOC => Self::AdHoc,
            NL80211_IFTYPE_STATION => Self::Station,
            NL80211_IFTYPE_AP => Self::Ap,
            NL80211_IFTYPE_MONITOR => Self::Monitor,
            NL80211_IFTYPE_MESH_POINT => Self::MeshPoint,
            NL80211_IFTYPE_P2P_CLIENT => Self::P2pClient,
            NL80211_IFTYPE_P2P_GO => Self::P2pGo,
            NL80211_IFTYPE_P2P_DEVICE => Self::P2pDevice,
            other => Self::Other(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::AdHoc => "ad-hoc",
            Self::Station => "managed",
            Self::Ap => "AP",
            Self::Monitor => "monitor",
            Self::MeshPoint => "mesh",
            Self::P2pClient => "P2P-client",
            Self::P2pGo => "P2P-GO",
            Self::P2pDevice => "P2P-device",
            Self::Other(_) => "other",
        }
    }
}

impl std::fmt::Display for IfType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A wireless interface: one netdev on one [`Wiphy`].
pub struct Interface {
    pub ifindex: u32,
    /// The PHY this interface runs on. Several interfaces can share one radio,
    /// which is why scanning and connecting are addressed by ifindex but
    /// capabilities are a property of the wiphy.
    pub wiphy: u32,
    pub name: String,
    pub iftype: IfType,
    pub mac: Option<[u8; 6]>,
}

impl Interface {
    pub(crate) fn parse(msg: &Message<'_>) -> Option<Self> {
        let mut iface = Self {
            ifindex: 0,
            wiphy: 0,
            name: String::new(),
            iftype: IfType::Unspecified,
            mac: None,
        };
        let mut seen_ifindex = false;

        for attr in Attrs::of_body(msg.payload) {
            match attr.kind {
                NL80211_ATTR_IFINDEX => {
                    iface.ifindex = attr.u32()?;
                    seen_ifindex = true;
                }
                NL80211_ATTR_WIPHY => iface.wiphy = attr.u32().unwrap_or(0),
                NL80211_ATTR_IFNAME => iface.name = attr.str().unwrap_or_default().to_owned(),
                NL80211_ATTR_IFTYPE => iface.iftype = IfType::from_raw(attr.u32().unwrap_or(0)),
                NL80211_ATTR_MAC => iface.mac = mac_of(&attr),
                _ => {}
            }
        }
        // A P2P device has a wdev but no netdev, so it has no ifindex and
        // nothing in caw can address it.
        seen_ifindex.then_some(iface)
    }
}
