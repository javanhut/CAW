//! The RSN element the station puts in its association request.
//!
//! `caw-80211` parses the AP's element; this builds ours. They are not the
//! same element: the AP advertises everything it will accept, and the station
//! answers with the single pairwise cipher and single AKM it chose. Those
//! bytes then have to be repeated verbatim in message 2 of the 4-way
//! handshake, where the MIC covers them — so this is wire format, not a
//! summary, and it is built once and carried through.

use caw_80211::{Akm, Cipher};

/// Element id 48.
const EID_RSN: u8 = 48;
/// The only version ever defined.
const VERSION: u16 = 1;
/// RSN capabilities bit 6: this station can protect management frames.
const CAP_MFPC: u16 = 1 << 6;
/// Bit 7: and will not associate without it.
const CAP_MFPR: u16 = 1 << 7;

/// The suites and capabilities the station is asking for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StationRsn {
    /// Echoed from the AP: the group key is the AP's to choose.
    pub group: Cipher,
    pub pairwise: Cipher,
    pub akm: Akm,
    pub mfp_capable: bool,
    pub mfp_required: bool,
    /// Names the PMK an SAE exchange just derived, so the AP knows which of
    /// its cached keys the 4-way handshake will use.
    pub pmkid: Option<[u8; 16]>,
    /// Only meaningful with management frame protection on.
    pub group_mgmt: Option<Cipher>,
}

impl StationRsn {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![EID_RSN, 0];
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&cipher_selector(self.group));
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&cipher_selector(self.pairwise));
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&akm_selector(self.akm));

        let mut capabilities = 0u16;
        if self.mfp_capable {
            capabilities |= CAP_MFPC;
        }
        if self.mfp_required {
            capabilities |= CAP_MFPR;
        }
        out.extend_from_slice(&capabilities.to_le_bytes());

        // The PMKID count is a positional field: the group management cipher
        // follows it, so an element carrying one has to carry the count even
        // when it is zero.
        if self.pmkid.is_some() || self.group_mgmt.is_some() {
            out.extend_from_slice(&u16::from(self.pmkid.is_some()).to_le_bytes());
            if let Some(pmkid) = self.pmkid {
                out.extend_from_slice(&pmkid);
            }
            if let Some(cipher) = self.group_mgmt {
                out.extend_from_slice(&cipher_selector(cipher));
            }
        }

        let len = out.len() - 2;
        out[1] = u8::try_from(len).expect("a station's RSN element is at most 40 octets");
        out
    }
}

/// The four selector octets as they appear in the element: OUI then type.
///
/// `caw-nl80211` already holds the table, in the packed form the kernel wants,
/// and the two encodings are the same four bytes in the same order.
fn cipher_selector(cipher: Cipher) -> [u8; 4] {
    // `cipher_suite` declines `UseGroup` because a station cannot ask nl80211
    // to negotiate it. The element still has a selector for it, and a pairwise
    // list of "use the group key" is legal, if archaic.
    caw_nl80211::cipher_suite(cipher)
        .unwrap_or(caw_nl80211::WLAN_CIPHER_SUITE_USE_GROUP)
        .to_be_bytes()
}

fn akm_selector(akm: Akm) -> [u8; 4] {
    caw_nl80211::akm_suite(akm).to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use caw_80211::RsnIe;

    fn psk() -> StationRsn {
        StationRsn {
            group: Cipher::Ccmp128,
            pairwise: Cipher::Ccmp128,
            akm: Akm::Psk,
            mfp_capable: false,
            mfp_required: false,
            pmkid: None,
            group_mgmt: None,
        }
    }

    /// The WPA2-Personal element as it appears on the air, asserted verbatim
    /// because the handshake MIC covers exactly these bytes. It is the same
    /// element `caw-eapol`'s handshake tests script an authenticator with.
    #[test]
    fn wpa2_psk_element_is_wire_exact() {
        assert_eq!(
            psk().encode(),
            [
                0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
                0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
            ]
        );
    }

    /// WPA3 needs management frame protection, and names its PMK.
    #[test]
    fn sae_element_carries_mfp_and_the_pmkid() {
        let element = StationRsn {
            akm: Akm::Sae,
            mfp_capable: true,
            mfp_required: true,
            pmkid: Some([0xab; 16]),
            group_mgmt: Some(Cipher::BipCmac128),
            ..psk()
        }
        .encode();

        let parsed = RsnIe::parse(&element).expect("our own element parses");
        assert_eq!(parsed.akms, vec![Akm::Sae]);
        assert_eq!(parsed.pairwise_ciphers, vec![Cipher::Ccmp128]);
        assert!(parsed.mfp_capable && parsed.mfp_required);
        assert_eq!(parsed.group_mgmt_cipher, Some(Cipher::BipCmac128));
        assert_eq!(parsed.raw, element, "the element round-trips verbatim");
    }

    /// Everything caw builds has to survive the parser the handshake compares
    /// against, whatever combination of optional fields it ends up with.
    #[test]
    fn every_shape_parses_back() {
        for (pmkid, group_mgmt) in [
            (None, None),
            (Some([1u8; 16]), None),
            (None, Some(Cipher::BipCmac128)),
            (Some([1u8; 16]), Some(Cipher::BipCmac128)),
        ] {
            let element = StationRsn {
                pmkid,
                group_mgmt,
                ..psk()
            }
            .encode();
            let parsed = RsnIe::parse(&element).expect("parses");
            assert_eq!(parsed.group_mgmt_cipher, group_mgmt);
            assert_eq!(usize::from(element[1]), element.len() - 2);
        }
    }
}
