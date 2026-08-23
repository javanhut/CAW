//! IEEE 802.11 frame and information-element parsing.
//!
//! Shared by the scan path (decoding beacons and probe responses) and the
//! authentication path: the RSN IE is not just informational, it is fed into
//! the 4-way handshake and covered by the MIC, so both layers need the same
//! parser and the same byte-exact re-encoding.
#![forbid(unsafe_code)]

/// Cipher suites from the RSN IE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cipher {
    Wep40,
    Tkip,
    Ccmp128,
    Gcmp256,
    BipCmac128,
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
}

/// What a network requires, distilled from its RSN IE for display and policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Security {
    Open,
    Wep,
    Wpa2Personal,
    Wpa3Personal,
    /// WPA3 transition mode: accepts both SAE and PSK.
    Wpa2Wpa3Personal,
    Wpa2Enterprise,
    Wpa3Enterprise,
    Owe,
}

/// The parsed contents of an RSN information element.
pub struct RsnIe {
    pub group_cipher: Cipher,
    pub pairwise_ciphers: Vec<Cipher>,
    pub akms: Vec<Akm>,
    /// 802.11w management frame protection.
    pub mfp_capable: bool,
    pub mfp_required: bool,
    /// The element exactly as received; the handshake MIC covers these bytes.
    pub raw: Vec<u8>,
}

/// Walks the information elements in a beacon or probe response body.
pub struct Ies<'a> {
    _rest: &'a [u8],
}

#[derive(Debug)]
pub enum Error {
    Truncated,
    Malformed,
}
