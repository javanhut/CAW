//! IEEE 802.11 frame and information-element parsing.
//!
//! Shared by the scan path (decoding beacons and probe responses) and the
//! authentication path: the RSN IE is not just informational, it is fed into
//! the 4-way handshake and covered by the MIC, so both layers need the same
//! parser and the same byte-exact re-encoding.
//!
//! Nothing here does I/O or keeps state. It consumes a frame body and returns
//! values, so the whole crate is testable on any host without a radio.
#![forbid(unsafe_code)]

use std::fmt;

// Element IDs used below. The full registry is large; these are the ones that
// decide what a network is called and how to join it.
/// Service Set Identifier.
pub const EID_SSID: u8 = 0;
/// DS Parameter Set, one byte: the primary channel.
pub const EID_DS_PARAMS: u8 = 3;
/// Robust Security Network element (WPA2 and later).
pub const EID_RSN: u8 = 48;
/// Vendor-specific; the payload opens with an OUI that says whose it is.
pub const EID_VENDOR: u8 = 221;

/// 00-0F-AC, the IEEE 802.11 OUI that prefixes every standard suite selector.
const OUI_IEEE: [u8; 3] = [0x00, 0x0f, 0xac];
/// 00-50-F2, the Microsoft OUI. Carries the legacy WPA1 element, and prefixes
/// the suite selectors inside it.
const OUI_MICROSOFT: [u8; 3] = [0x00, 0x50, 0xf2];
/// Vendor element subtype 1 under [`OUI_MICROSOFT`] is WPA1. Subtypes 2 and 4
/// are WMM and WPS, which are not security elements and must not be mistaken
/// for one.
const WPA1_VENDOR_TYPE: u8 = 1;

/// RSN capabilities bit 6: the AP can protect management frames (802.11w).
const RSN_CAP_MFPC: u16 = 1 << 6;
/// RSN capabilities bit 7: the AP demands it, and will refuse a station that
/// associates without it.
const RSN_CAP_MFPR: u16 = 1 << 7;

/// A suite selector: three OUI bytes then a one-byte suite type.
pub type Selector = [u8; 4];

/// Cipher suites from the RSN IE.
///
/// Unrecognised selectors are kept verbatim rather than dropped: a vendor
/// cipher must still round-trip into the display and must not make an
/// otherwise valid element look empty.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cipher {
    /// Only legal in a pairwise list, and means "no pairwise key, use the
    /// group key" — a WEP-era arrangement.
    UseGroup,
    Wep40,
    Tkip,
    Ccmp128,
    Wep104,
    /// Group management cipher for 802.11w-protected management frames.
    BipCmac128,
    Gcmp128,
    Gcmp256,
    Ccmp256,
    Unknown(Selector),
}

impl Cipher {
    fn from_selector(sel: Selector) -> Self {
        // WPA1 numbers its ciphers the same way under the Microsoft OUI, so one
        // table serves both elements.
        if sel[..3] != OUI_IEEE && sel[..3] != OUI_MICROSOFT {
            return Self::Unknown(sel);
        }
        match sel[3] {
            0 => Self::UseGroup,
            1 => Self::Wep40,
            2 => Self::Tkip,
            4 => Self::Ccmp128,
            5 => Self::Wep104,
            6 => Self::BipCmac128,
            8 => Self::Gcmp128,
            9 => Self::Gcmp256,
            10 => Self::Ccmp256,
            _ => Self::Unknown(sel),
        }
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UseGroup => f.write_str("use-group"),
            Self::Wep40 => f.write_str("WEP-40"),
            Self::Tkip => f.write_str("TKIP"),
            Self::Ccmp128 => f.write_str("CCMP-128"),
            Self::Wep104 => f.write_str("WEP-104"),
            Self::BipCmac128 => f.write_str("BIP-CMAC-128"),
            Self::Gcmp128 => f.write_str("GCMP-128"),
            Self::Gcmp256 => f.write_str("GCMP-256"),
            Self::Ccmp256 => f.write_str("CCMP-256"),
            Self::Unknown(s) => write!(f, "{:02x}-{:02x}-{:02x}:{}", s[0], s[1], s[2], s[3]),
        }
    }
}

/// Authentication and key-management suite, as advertised in the RSN IE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Akm {
    /// WPA2-Personal.
    Psk,
    /// WPA2-Personal with SHA-256 KDF.
    PskSha256,
    /// WPA3-Personal.
    Sae,
    /// WPA2-Enterprise.
    Dot1x,
    /// WPA3-Enterprise.
    Dot1xSha256,
    /// Opportunistic Wireless Encryption.
    Owe,
    /// 802.11r fast transition. Present alongside its non-FT sibling on nearly
    /// every roaming-capable AP, and decoded because an AP that advertises
    /// *only* the FT variant would otherwise look like it had no AKM at all.
    FtPsk,
    FtSae,
    FtDot1x,
    /// WPA3-Enterprise Suite B, 192-bit mode.
    Dot1xSuiteB192,
    Unknown(Selector),
}

impl Akm {
    fn from_selector(sel: Selector) -> Self {
        if sel[..3] != OUI_IEEE && sel[..3] != OUI_MICROSOFT {
            return Self::Unknown(sel);
        }
        match sel[3] {
            1 => Self::Dot1x,
            2 => Self::Psk,
            3 => Self::FtDot1x,
            4 => Self::FtPsk,
            5 => Self::Dot1xSha256,
            6 => Self::PskSha256,
            8 => Self::Sae,
            9 => Self::FtSae,
            12 => Self::Dot1xSuiteB192,
            18 => Self::Owe,
            _ => Self::Unknown(sel),
        }
    }

    /// Authenticates with a pre-shared key, i.e. WPA2-Personal.
    pub fn is_psk(self) -> bool {
        matches!(self, Self::Psk | Self::PskSha256 | Self::FtPsk)
    }

    /// Authenticates with SAE, i.e. WPA3-Personal.
    pub fn is_sae(self) -> bool {
        matches!(self, Self::Sae | Self::FtSae)
    }

    /// Authenticates with 802.1X, so joining needs EAP credentials rather than
    /// a passphrase.
    pub fn is_enterprise(self) -> bool {
        matches!(
            self,
            Self::Dot1x | Self::Dot1xSha256 | Self::FtDot1x | Self::Dot1xSuiteB192
        )
    }
}

impl fmt::Display for Akm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Psk => f.write_str("PSK"),
            Self::PskSha256 => f.write_str("PSK-SHA256"),
            Self::Sae => f.write_str("SAE"),
            Self::Dot1x => f.write_str("802.1X"),
            Self::Dot1xSha256 => f.write_str("802.1X-SHA256"),
            Self::Owe => f.write_str("OWE"),
            Self::FtPsk => f.write_str("FT-PSK"),
            Self::FtSae => f.write_str("FT-SAE"),
            Self::FtDot1x => f.write_str("FT-802.1X"),
            Self::Dot1xSuiteB192 => f.write_str("802.1X-SuiteB-192"),
            Self::Unknown(s) => write!(f, "{:02x}-{:02x}-{:02x}:{}", s[0], s[1], s[2], s[3]),
        }
    }
}

/// What a network requires, distilled from its RSN IE for display and policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Security {
    Open,
    Wep,
    /// The original WPA. Broken, but naming it beats showing it as open.
    Wpa1Personal,
    Wpa1Enterprise,
    Wpa2Personal,
    Wpa3Personal,
    /// WPA3 transition mode: accepts both SAE and PSK.
    Wpa2Wpa3Personal,
    Wpa2Enterprise,
    Wpa3Enterprise,
    Owe,
}

impl Security {
    /// Classify a network from what its beacon advertised.
    ///
    /// `privacy` is the Privacy bit of the capability field, which is not an
    /// element — nl80211 reports it separately. Without an RSN or WPA element
    /// it is the only evidence that a network is WEP rather than open.
    pub fn classify(rsn: Option<&RsnIe>, wpa: Option<&WpaIe>, privacy: bool) -> Self {
        // RSN wins over a WPA1 element when both are present: a mixed-mode AP
        // advertises both, and we would always join with RSN.
        if let Some(rsn) = rsn
            && let Some(security) = Self::from_akms(&rsn.akms, rsn.mfp_required)
        {
            return security;
        }
        if let Some(wpa) = wpa {
            return if wpa.akms.iter().any(|a| a.is_enterprise()) {
                Self::Wpa1Enterprise
            } else {
                Self::Wpa1Personal
            };
        }
        if privacy { Self::Wep } else { Self::Open }
    }

    /// `None` when no AKM in the list is one we recognise, which leaves the
    /// caller to fall back rather than guess.
    fn from_akms(akms: &[Akm], mfp_required: bool) -> Option<Self> {
        let sae = akms.iter().any(|a| a.is_sae());
        let psk = akms.iter().any(|a| a.is_psk());
        let enterprise = akms.iter().any(|a| a.is_enterprise());
        let owe = akms.contains(&Akm::Owe);

        if sae && psk {
            Some(Self::Wpa2Wpa3Personal)
        } else if sae {
            Some(Self::Wpa3Personal)
        } else if owe {
            Some(Self::Owe)
        } else if enterprise {
            // WPA3-Enterprise is WPA2-Enterprise plus mandatory management
            // frame protection; the AKM alone does not distinguish them. Suite
            // B is WPA3-only by definition.
            if mfp_required || akms.contains(&Akm::Dot1xSuiteB192) {
                Some(Self::Wpa3Enterprise)
            } else {
                Some(Self::Wpa2Enterprise)
            }
        } else if psk {
            Some(Self::Wpa2Personal)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Wep => "WEP",
            Self::Wpa1Personal => "WPA1-Personal",
            Self::Wpa1Enterprise => "WPA1-Enterprise",
            Self::Wpa2Personal => "WPA2-Personal",
            Self::Wpa3Personal => "WPA3-Personal",
            Self::Wpa2Wpa3Personal => "WPA2/WPA3-Personal",
            Self::Wpa2Enterprise => "WPA2-Enterprise",
            Self::Wpa3Enterprise => "WPA3-Enterprise",
            Self::Owe => "OWE",
        }
    }

    /// Joining needs no credentials at all. OWE encrypts without them, so it
    /// counts here even though it is not an open network on the air.
    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Owe)
    }
}

impl fmt::Display for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An SSID as it came off the air: bytes, not text.
///
/// The standard imposes no character set, so an SSID may be non-UTF8 or hold
/// control characters. Keeping the raw bytes matters beyond display, because
/// the PSK derivation hashes them exactly as received.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct Ssid(pub Vec<u8>);

impl Ssid {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// An AP hiding its name sends a zero-length SSID element, or one padded
    /// with NULs to the real length. Neither means the name is empty.
    pub fn is_hidden(&self) -> bool {
        self.0.is_empty() || self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Display for Ssid {
    /// Lossy on purpose: this is for a terminal, and an SSID that is invalid
    /// UTF-8 or full of control bytes must not corrupt the scan list. Use
    /// [`Ssid::as_bytes`] anywhere the exact bytes matter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_hidden() {
            return f.write_str("<hidden>");
        }
        for c in String::from_utf8_lossy(&self.0).chars() {
            if c.is_control() {
                write!(f, "{}", c.escape_debug())?;
            } else {
                f.write_str(c.encode_utf8(&mut [0u8; 4]))?;
            }
        }
        Ok(())
    }
}

/// One information element.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Element<'a> {
    pub id: u8,
    /// The element body, without the two-byte header.
    pub payload: &'a [u8],
    /// The element including its header, borrowed from the frame. The 4-way
    /// handshake compares the RSN element byte for byte against the copy in
    /// message 3, so that path takes these bytes rather than re-encoding.
    pub raw: &'a [u8],
}

/// Walks the information elements in a beacon or probe response body.
pub struct Ies<'a> {
    rest: &'a [u8],
}

impl<'a> Ies<'a> {
    /// `body` is the element sequence: for a beacon, everything after the
    /// timestamp, beacon interval and capability field. nl80211 hands over
    /// exactly this in `NL80211_BSS_INFORMATION_ELEMENTS`.
    pub fn new(body: &'a [u8]) -> Self {
        Self { rest: body }
    }
}

impl<'a> Iterator for Ies<'a> {
    type Item = Element<'a>;

    fn next(&mut self) -> Option<Element<'a>> {
        // A capture can end mid-element — a short read, a radio that clipped
        // the frame. There is no way to resynchronise past a length that lies,
        // so stop; never panic and never loop.
        let (&id, &len) = (self.rest.first()?, self.rest.get(1)?);
        let total = 2 + len as usize;
        if self.rest.len() < total {
            self.rest = &[];
            return None;
        }
        let (raw, tail) = self.rest.split_at(total);
        self.rest = tail;
        Some(Element {
            id,
            payload: &raw[2..],
            raw,
        })
    }
}

/// The parsed contents of an RSN information element.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RsnIe {
    /// Always 1; no other version has ever been defined.
    pub version: u16,
    pub group_cipher: Cipher,
    pub pairwise_ciphers: Vec<Cipher>,
    pub akms: Vec<Akm>,
    /// The capabilities field verbatim, since it also carries pre-auth and the
    /// replay counter counts that policy may want later.
    pub capabilities: u16,
    /// 802.11w management frame protection.
    pub mfp_capable: bool,
    pub mfp_required: bool,
    /// Present only when the AP protects management frames.
    pub group_mgmt_cipher: Option<Cipher>,
    /// The element exactly as received; the handshake MIC covers these bytes.
    pub raw: Vec<u8>,
}

impl RsnIe {
    /// Parse from the whole element, header included, as [`Element::raw`]
    /// gives it.
    pub fn parse(element: &[u8]) -> Result<Self, Error> {
        let payload = match element {
            [EID_RSN, len, rest @ ..] if rest.len() >= *len as usize => &rest[..*len as usize],
            _ => return Err(Error::Truncated),
        };
        let mut ie = Self::parse_body(payload)?;
        ie.raw = element[..2 + payload.len()].to_vec();
        Ok(ie)
    }

    /// Everything after the version is optional. 802.11 lets an AP stop the
    /// element early and have the defaults apply, so a short body is normal
    /// rather than an error — and a body that overruns its own counts is read
    /// as far as it goes, because a network worth listing is worth listing
    /// with whatever it did say.
    fn parse_body(body: &[u8]) -> Result<Self, Error> {
        let mut cur = Cursor { rest: body };
        let version = cur.u16le().ok_or(Error::Truncated)?;
        if version != 1 {
            // The layout after the version is defined only for version 1, so
            // reading on would be invention.
            return Err(Error::Malformed);
        }

        let group_cipher = cur
            .selector()
            .map_or(Cipher::Ccmp128, Cipher::from_selector);
        let pairwise_ciphers = match cur.suite_list() {
            Some(list) => list.into_iter().map(Cipher::from_selector).collect(),
            None => vec![Cipher::Ccmp128],
        };
        let akms = match cur.suite_list() {
            Some(list) => list.into_iter().map(Akm::from_selector).collect(),
            None => vec![Akm::Dot1x],
        };
        let capabilities = cur.u16le().unwrap_or(0);

        // PMKIDs sit between the capabilities and the group management cipher.
        // We do not cache them, but they must be stepped over to reach it.
        let pmkids = cur.u16le().unwrap_or(0) as usize;
        let group_mgmt_cipher = cur
            .skip(pmkids * 16)
            .and_then(|()| cur.selector())
            .map(Cipher::from_selector);

        Ok(Self {
            version,
            group_cipher,
            pairwise_ciphers,
            akms,
            capabilities,
            mfp_capable: capabilities & RSN_CAP_MFPC != 0,
            mfp_required: capabilities & RSN_CAP_MFPR != 0,
            group_mgmt_cipher,
            raw: Vec::new(),
        })
    }
}

/// The legacy WPA1 vendor element (221, OUI 00-50-F2, type 1).
///
/// Parsed so that a WPA1-only network is named as such instead of appearing
/// open, which is what happens if only element 48 is understood.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WpaIe {
    pub version: u16,
    pub group_cipher: Cipher,
    pub pairwise_ciphers: Vec<Cipher>,
    pub akms: Vec<Akm>,
    /// The element exactly as received, header and OUI included.
    pub raw: Vec<u8>,
}

impl WpaIe {
    /// Parse from the whole element, header included. Returns
    /// [`Error::Malformed`] for a vendor element belonging to someone else, or
    /// to another Microsoft subtype such as WMM or WPS.
    pub fn parse(element: &[u8]) -> Result<Self, Error> {
        let payload = match element {
            [EID_VENDOR, len, rest @ ..] if rest.len() >= *len as usize => &rest[..*len as usize],
            _ => return Err(Error::Truncated),
        };
        let body = match payload {
            [a, b, c, WPA1_VENDOR_TYPE, rest @ ..] if [*a, *b, *c] == OUI_MICROSOFT => rest,
            _ => return Err(Error::Malformed),
        };

        let mut cur = Cursor { rest: body };
        let version = cur.u16le().ok_or(Error::Truncated)?;
        if version != 1 {
            return Err(Error::Malformed);
        }
        // WPA1 predates CCMP, so its defaults are TKIP throughout.
        let group_cipher = cur.selector().map_or(Cipher::Tkip, Cipher::from_selector);
        let pairwise_ciphers = match cur.suite_list() {
            Some(list) => list.into_iter().map(Cipher::from_selector).collect(),
            None => vec![Cipher::Tkip],
        };
        let akms = match cur.suite_list() {
            Some(list) => list.into_iter().map(Akm::from_selector).collect(),
            None => vec![Akm::Dot1x],
        };

        Ok(Self {
            version,
            group_cipher,
            pairwise_ciphers,
            akms,
            raw: element[..2 + payload.len()].to_vec(),
        })
    }
}

/// Everything caw takes from a beacon or probe response.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct BeaconIes {
    pub ssid: Option<Ssid>,
    /// From the DS Parameter Set. Absent on 5 GHz and 6 GHz, where the channel
    /// comes from the frequency nl80211 reports instead.
    pub channel: Option<u8>,
    pub rsn: Option<RsnIe>,
    pub wpa: Option<WpaIe>,
}

impl BeaconIes {
    /// A malformed security element is dropped rather than failing the whole
    /// frame: the rest of the beacon is still worth showing, and a network
    /// whose RSN element we cannot read is one we could not have joined.
    pub fn parse(body: &[u8]) -> Self {
        let mut out = Self::default();
        for el in Ies::new(body) {
            // First occurrence wins. A duplicate element is a malformed beacon,
            // and taking the later one would let a padded frame overwrite good
            // data.
            match el.id {
                EID_SSID if out.ssid.is_none() => out.ssid = Some(Ssid(el.payload.to_vec())),
                EID_DS_PARAMS if out.channel.is_none() => {
                    out.channel = el.payload.first().copied();
                }
                EID_RSN if out.rsn.is_none() => out.rsn = RsnIe::parse(el.raw).ok(),
                EID_VENDOR if out.wpa.is_none() => out.wpa = WpaIe::parse(el.raw).ok(),
                _ => {}
            }
        }
        out
    }

    /// `privacy` is the Privacy bit from the capability field; see
    /// [`Security::classify`].
    pub fn security(&self, privacy: bool) -> Security {
        Security::classify(self.rsn.as_ref(), self.wpa.as_ref(), privacy)
    }
}

/// Reads the fixed-layout fields of an RSN or WPA element.
struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.rest.len() < n {
            return None;
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Some(head)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    /// Suite element counts and the RSN version are little-endian, unlike
    /// netlink's native-endian encoding elsewhere in caw.
    fn u16le(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn selector(&mut self) -> Option<Selector> {
        self.take(4).map(|b| [b[0], b[1], b[2], b[3]])
    }

    /// A 16-bit count followed by that many selectors, truncated to what the
    /// element actually holds.
    fn suite_list(&mut self) -> Option<Vec<Selector>> {
        let count = self.u16le()?;
        let mut out = Vec::with_capacity(count.min(16) as usize);
        for _ in 0..count {
            match self.selector() {
                Some(sel) => out.push(sel),
                None => break,
            }
        }
        Some(out)
    }
}

#[derive(Debug)]
pub enum Error {
    /// The element ended before a mandatory field.
    Truncated,
    /// The element is not the one claimed, or declares a version whose layout
    /// is undefined.
    Malformed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated 802.11 element"),
            Self::Malformed => f.write_str("malformed 802.11 element"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    /// WPA2-PSK: CCMP group and pairwise, one PSK AKM, no MFP.
    const WPA2_PSK: [u8; 22] = [
        0x30, 0x14, // element 48, 20 bytes
        0x01, 0x00, // version 1
        0x00, 0x0f, 0xac, 0x04, // group: CCMP-128
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // pairwise: CCMP-128
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, // AKM: PSK
        0x00, 0x00, // capabilities
    ];

    /// WPA3-Personal: SAE only, management frame protection required.
    const WPA3_SAE: [u8; 22] = [
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
        0x00, 0x00, 0x0f, 0xac, 0x08, // AKM: SAE
        0xc0, 0x00, // MFPC | MFPR
    ];

    /// WPA3 transition mode: both SAE and PSK, MFP capable but not required —
    /// it cannot be, or the WPA2 stations it exists for could not associate.
    const WPA2_WPA3: [u8; 26] = [
        0x30, 0x18, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x02,
        0x00, // two AKMs
        0x00, 0x0f, 0xac, 0x02, // PSK
        0x00, 0x0f, 0xac, 0x08, // SAE
        0x40, 0x00, // MFPC only
    ];

    /// WPA2-Enterprise: 802.1X, no MFP.
    const WPA2_ENTERPRISE: [u8; 22] = [
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
        0x00, 0x00, 0x0f, 0xac, 0x01, // AKM: 802.1X
        0x00, 0x00,
    ];

    /// Legacy WPA1: TKIP throughout, PSK, under the Microsoft OUI.
    const WPA1_PSK: [u8; 24] = [
        0xdd, 0x16, // element 221, 22 bytes
        0x00, 0x50, 0xf2, 0x01, // Microsoft OUI, WPA subtype
        0x01, 0x00, // version 1
        0x00, 0x50, 0xf2, 0x02, // group: TKIP
        0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, // pairwise: TKIP
        0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, // AKM: PSK
    ];

    fn rsn_of(bytes: &[u8]) -> RsnIe {
        RsnIe::parse(bytes).expect("valid RSN element")
    }

    fn security_of(bytes: &[u8]) -> Security {
        BeaconIes::parse(bytes).security(true)
    }

    #[test]
    fn walks_elements() {
        // SSID "caw", DS parameter set channel 6.
        let body = [0x00, 0x03, b'c', b'a', b'w', 0x03, 0x01, 0x06];
        let els: Vec<_> = Ies::new(&body).map(|e| (e.id, e.payload)).collect();
        assert_eq!(els, vec![(0u8, &b"caw"[..]), (3u8, &[6u8][..])]);
    }

    #[test]
    fn truncated_element_stops_iteration() {
        // The element claims 20 bytes of payload and supplies 2.
        let body = [0x30, 0x14, 0x01, 0x00];
        assert_eq!(Ies::new(&body).count(), 0);

        // A good element followed by a clipped one yields only the good one.
        let mut body = vec![0x00, 0x03, b'c', b'a', b'w'];
        body.extend_from_slice(&[0x30, 0x14, 0x01, 0x00]);
        let els: Vec<_> = Ies::new(&body).collect();
        assert_eq!(els.len(), 1);
        assert_eq!(els[0].id, EID_SSID);

        // And a lone dangling id byte is not a half element.
        assert_eq!(Ies::new(&[0x30]).count(), 0);
    }

    #[test]
    fn truncated_rsn_classifies_without_panicking() {
        let body = [0x30, 0x14, 0x01, 0x00];
        let info = BeaconIes::parse(&body);
        assert!(info.rsn.is_none());
        // Privacy was set, so it is an encrypted network we cannot identify —
        // WEP is the honest floor, and it is not Open.
        assert_eq!(info.security(true), Security::Wep);
        assert_eq!(info.security(false), Security::Open);
    }

    #[test]
    fn hidden_ssid() {
        let info = BeaconIes::parse(&[0x00, 0x00]);
        assert!(info.ssid.as_ref().unwrap().is_hidden());
        assert_eq!(info.ssid.unwrap().to_string(), "<hidden>");

        // NUL-padded to the real length is the other way APs hide.
        let info = BeaconIes::parse(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
        assert!(info.ssid.unwrap().is_hidden());
    }

    #[test]
    fn ssid_is_bytes_not_a_string() {
        // Invalid UTF-8 must survive parsing intact; PSK derivation hashes it.
        let body = [0x00, 0x03, 0xff, 0xfe, 0x41];
        let ssid = BeaconIes::parse(&body).ssid.unwrap();
        assert_eq!(ssid.as_bytes(), &[0xff, 0xfe, 0x41]);
        assert!(!ssid.is_hidden());
        // Display is lossy, and must not emit raw control bytes.
        assert!(!Ssid(vec![b'a', 0x07]).to_string().contains('\x07'));
    }

    #[test]
    fn ds_param_gives_channel() {
        assert_eq!(BeaconIes::parse(&[0x03, 0x01, 0x0b]).channel, Some(11));
        // Absent on 5 GHz beacons.
        assert_eq!(BeaconIes::parse(&[0x00, 0x00]).channel, None);
    }

    #[test]
    fn wpa2_psk_is_parsed_and_classified() {
        let rsn = rsn_of(&WPA2_PSK);
        assert_eq!(rsn.version, 1);
        assert_eq!(rsn.group_cipher, Cipher::Ccmp128);
        assert_eq!(rsn.pairwise_ciphers, vec![Cipher::Ccmp128]);
        assert_eq!(rsn.akms, vec![Akm::Psk]);
        assert!(!rsn.mfp_capable);
        assert!(!rsn.mfp_required);
        assert_eq!(security_of(&WPA2_PSK), Security::Wpa2Personal);
    }

    #[test]
    fn wpa3_sae_requires_mfp() {
        let rsn = rsn_of(&WPA3_SAE);
        assert_eq!(rsn.akms, vec![Akm::Sae]);
        assert!(rsn.mfp_capable);
        assert!(rsn.mfp_required);
        assert_eq!(security_of(&WPA3_SAE), Security::Wpa3Personal);
    }

    #[test]
    fn transition_mode_lists_both_akms() {
        let rsn = rsn_of(&WPA2_WPA3);
        assert_eq!(rsn.akms, vec![Akm::Psk, Akm::Sae]);
        assert!(rsn.mfp_capable);
        assert!(!rsn.mfp_required);
        assert_eq!(security_of(&WPA2_WPA3), Security::Wpa2Wpa3Personal);
    }

    #[test]
    fn enterprise_splits_on_mfp() {
        assert_eq!(security_of(&WPA2_ENTERPRISE), Security::Wpa2Enterprise);

        let mut wpa3 = WPA2_ENTERPRISE;
        wpa3[20] = 0xc0; // capabilities: MFPC | MFPR
        assert_eq!(security_of(&wpa3), Security::Wpa3Enterprise);

        // Suite B 192-bit is WPA3-only whatever the capabilities say.
        let mut suite_b = WPA2_ENTERPRISE;
        suite_b[19] = 12;
        assert_eq!(security_of(&suite_b), Security::Wpa3Enterprise);
    }

    #[test]
    fn owe_is_not_open() {
        let mut owe = WPA3_SAE;
        owe[19] = 18; // AKM: OWE
        assert_eq!(security_of(&owe), Security::Owe);
        assert!(Security::Owe.is_open());
    }

    #[test]
    fn wpa1_only_network_is_not_shown_as_open() {
        let info = BeaconIes::parse(&WPA1_PSK);
        let wpa = info.wpa.as_ref().expect("WPA1 element");
        assert_eq!(wpa.group_cipher, Cipher::Tkip);
        assert_eq!(wpa.pairwise_ciphers, vec![Cipher::Tkip]);
        assert_eq!(wpa.akms, vec![Akm::Psk]);
        assert_eq!(info.security(true), Security::Wpa1Personal);

        let mut enterprise = WPA1_PSK;
        enterprise[23] = 1; // AKM: 802.1X
        assert_eq!(security_of(&enterprise), Security::Wpa1Enterprise);
    }

    #[test]
    fn other_vendor_elements_are_not_wpa1() {
        // WMM (Microsoft OUI, subtype 2) must not be read as a security element.
        let wmm = [0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00];
        let info = BeaconIes::parse(&wmm);
        assert!(info.wpa.is_none());
        assert_eq!(info.security(false), Security::Open);
    }

    #[test]
    fn rsn_wins_over_a_stale_wpa1_element() {
        // A mixed-mode AP beacons both; we would join with RSN.
        let mut body = WPA1_PSK.to_vec();
        body.extend_from_slice(&WPA2_PSK);
        let info = BeaconIes::parse(&body);
        assert!(info.wpa.is_some());
        assert_eq!(info.security(true), Security::Wpa2Personal);
    }

    #[test]
    fn raw_is_the_element_verbatim() {
        // The 4-way handshake compares these bytes against message 3's key
        // data, so trailing elements must not bleed in and nothing may be
        // re-encoded.
        let mut body = vec![0x00, 0x03, b'c', b'a', b'w'];
        body.extend_from_slice(&WPA2_PSK);
        body.extend_from_slice(&[0x03, 0x01, 0x06]);

        let rsn = BeaconIes::parse(&body).rsn.unwrap();
        assert_eq!(rsn.raw, WPA2_PSK);
    }

    #[test]
    fn missing_tail_fields_take_their_defaults() {
        // Version and group cipher only: 802.11 says the rest defaults to CCMP
        // pairwise and 802.1X.
        let ie = [0x30, 0x06, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04];
        let rsn = rsn_of(&ie);
        assert_eq!(rsn.pairwise_ciphers, vec![Cipher::Ccmp128]);
        assert_eq!(rsn.akms, vec![Akm::Dot1x]);
        assert_eq!(rsn.capabilities, 0);
        assert_eq!(security_of(&ie), Security::Wpa2Enterprise);
    }

    #[test]
    fn suite_count_that_overruns_the_element_is_clamped() {
        // Claims four pairwise ciphers, carries one. Reading past the element
        // would be a buffer overrun in C; here it must simply stop.
        let ie = [
            0x30, 0x0c, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x04, 0x00, 0x00, 0x0f, 0xac, 0x04,
        ];
        let rsn = rsn_of(&ie);
        assert_eq!(rsn.pairwise_ciphers, vec![Cipher::Ccmp128]);
        assert_eq!(rsn.akms, vec![Akm::Dot1x]);
    }

    #[test]
    fn unknown_suites_are_kept_not_dropped() {
        let mut ie = WPA2_PSK;
        ie[16..20].copy_from_slice(&[0x00, 0x40, 0x96, 0x00]); // a vendor AKM
        let rsn = rsn_of(&ie);
        assert_eq!(rsn.akms, vec![Akm::Unknown([0x00, 0x40, 0x96, 0x00])]);
        // No AKM we can use, and privacy is on, so it is not open.
        assert_eq!(security_of(&ie), Security::Wep);
    }

    #[test]
    fn group_management_cipher_follows_the_pmkid_list() {
        let mut ie = vec![
            0x30, 0x2a, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
            0x01, 0x00, 0x00, 0x0f, 0xac, 0x08, 0xc0, 0x00, 0x01, 0x00, // one PMKID
        ];
        ie.extend_from_slice(&[0xaa; 16]);
        ie.extend_from_slice(&[0x00, 0x0f, 0xac, 0x06]); // BIP-CMAC-128

        let rsn = rsn_of(&ie);
        assert_eq!(rsn.group_mgmt_cipher, Some(Cipher::BipCmac128));
        assert_eq!(rsn.raw, ie);
    }

    #[test]
    fn unsupported_rsn_version_is_rejected() {
        let mut ie = WPA2_PSK;
        ie[2] = 2;
        assert!(matches!(RsnIe::parse(&ie), Err(Error::Malformed)));
    }
}
