//! The EAPOL-Key MIC: what proves both ends hold the same PMK.
//!
//! The algorithm is named by the Key Descriptor Version field of the frame
//! itself rather than inferred from the AKM, so it is a parameter here: an AP
//! may negotiate a SHA-256 AKM and still send version 2 descriptors, and a
//! supplicant that assumed otherwise would reject a legitimate handshake.

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::Error;

/// Width of the MIC field. Both supported algorithms produce exactly this much
/// — HMAC-SHA1 by truncation, AES-CMAC natively.
pub const MIC_LEN: usize = 16;

/// The MIC and key-wrap pairing named by the low 3 bits of Key Information.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyDescriptorVersion {
    /// Version 2: HMAC-SHA1-128 MIC with AES key wrap. WPA2 with CCMP.
    HmacSha1 = 2,
    /// Version 3: AES-128-CMAC MIC with AES key wrap. Negotiated by the
    /// SHA-256 AKMs and required by SAE.
    AesCmac = 3,
}

impl KeyDescriptorVersion {
    /// Decode the Key Descriptor Version subfield.
    ///
    /// Version 1 (HMAC-MD5 MIC, RC4-wrapped key data) exists only to carry
    /// TKIP, which caw never negotiates, so it is rejected rather than
    /// implemented.
    pub fn from_key_info(key_info: u16) -> Result<Self, Error> {
        match key_info & 0x0007 {
            2 => Ok(Self::HmacSha1),
            3 => Ok(Self::AesCmac),
            _ => Err(Error::UnsupportedVersion),
        }
    }

    /// The subfield value, for building a frame.
    pub fn bits(self) -> u16 {
        self as u16
    }
}

/// Compute the MIC over an EAPOL-Key frame with the KCK.
///
/// `frame` is the whole frame, from the EAPOL protocol-version octet through
/// the end of the key data. The MIC covers the field it will occupy, so the
/// caller zeroes those 16 bytes first and writes the result back afterwards.
pub fn compute_mic(kck: &[u8; 16], version: KeyDescriptorVersion, frame: &[u8]) -> [u8; MIC_LEN] {
    let mut mic = [0u8; MIC_LEN];
    match version {
        KeyDescriptorVersion::HmacSha1 => mic.copy_from_slice(&hmac_sha1(kck, frame)[..MIC_LEN]),
        KeyDescriptorVersion::AesCmac => {
            let mut mac = Cmac::<Aes128>::new_from_slice(kck).expect("KCK is one AES-128 key");
            mac.update(frame);
            mic.copy_from_slice(&mac.finalize().into_bytes());
        }
    }
    mic
}

/// Check a received MIC in constant time.
///
/// A short-circuiting compare would leak how many leading bytes of a guess were
/// right, which is enough to forge a MIC one byte at a time.
pub fn verify_mic(
    kck: &[u8; 16],
    version: KeyDescriptorVersion,
    frame: &[u8],
    mic: &[u8],
) -> Result<(), Error> {
    if mic.len() != MIC_LEN {
        return Err(Error::Malformed);
    }
    let want = compute_mic(kck, version, frame);
    if want[..].ct_eq(mic).into() {
        Ok(())
    } else {
        Err(Error::MicMismatch)
    }
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(msg);
    let mut out = [0u8; 20];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// RFC 4493 § 4, AES-CMAC with the RFC 3602 key. Its 128-bit key is exactly
    /// a KCK, so these run through [`compute_mic`] unmodified.
    #[test]
    fn rfc4493_cmac_vectors() {
        let kck: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
        let cases = [
            ("", "bb1d6929e95937287fa37d129b756746"),
            (
                "6bc1bee22e409f96e93d7e117393172a",
                "070a16b46b4d4144f79bdd9dd04a287c",
            ),
            (
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                 30c81c46a35ce411",
                "dfa66747de9ae63030ca32611497c827",
            ),
            (
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                 30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "51f0bebf7e3b9d92fc49741779363cfe",
            ),
        ];
        for (msg, tag) in cases {
            let msg = hex(msg);
            assert_eq!(
                compute_mic(&kck, KeyDescriptorVersion::AesCmac, &msg)[..],
                hex(tag)[..],
                "message of {} bytes",
                msg.len()
            );
        }
    }

    /// RFC 2202 § 3, HMAC-SHA1. Version 2 truncates this to 128 bits.
    #[test]
    fn rfc2202_hmac_sha1_vectors() {
        assert_eq!(
            hmac_sha1(&[0x0b; 20], b"Hi There")[..],
            hex("b617318655057264e28bc0b6fb378c8ef146be00")[..]
        );
        assert_eq!(
            hmac_sha1(b"Jefe", b"what do ya want for nothing?")[..],
            hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")[..]
        );
        assert_eq!(
            hmac_sha1(&[0x0c; 20], b"Test With Truncation")[..],
            hex("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04")[..]
        );
    }

    #[test]
    fn version_2_is_the_hmac_truncated_to_16_bytes() {
        let kck = [0x0c; 16];
        let frame = b"Test With Truncation";
        assert_eq!(
            compute_mic(&kck, KeyDescriptorVersion::HmacSha1, frame)[..],
            hmac_sha1(&kck, frame)[..MIC_LEN]
        );
    }

    #[test]
    fn verify_accepts_only_the_right_mic() {
        let kck = [0x42; 16];
        let frame = b"EAPOL-Key frame with a zeroed MIC field";
        for version in [
            KeyDescriptorVersion::HmacSha1,
            KeyDescriptorVersion::AesCmac,
        ] {
            let mut mic = compute_mic(&kck, version, frame);
            assert!(verify_mic(&kck, version, frame, &mic).is_ok());

            mic[15] ^= 1;
            assert!(matches!(
                verify_mic(&kck, version, frame, &mic),
                Err(Error::MicMismatch)
            ));
            assert!(matches!(
                verify_mic(&kck, version, frame, &mic[..8]),
                Err(Error::Malformed)
            ));
        }
    }

    /// The two algorithms must not be interchangeable, or a version mix-up
    /// would go unnoticed until it mattered.
    #[test]
    fn versions_disagree() {
        let kck = [0x42; 16];
        assert_ne!(
            compute_mic(&kck, KeyDescriptorVersion::HmacSha1, b"frame"),
            compute_mic(&kck, KeyDescriptorVersion::AesCmac, b"frame")
        );
    }

    #[test]
    fn decodes_the_version_subfield() {
        // Key Information with other bits set: only the low three count.
        assert_eq!(
            KeyDescriptorVersion::from_key_info(0x13cb).unwrap(),
            KeyDescriptorVersion::AesCmac
        );
        assert_eq!(
            KeyDescriptorVersion::from_key_info(0x008a).unwrap(),
            KeyDescriptorVersion::HmacSha1
        );
        assert_eq!(KeyDescriptorVersion::AesCmac.bits(), 3);
        // Version 1 is TKIP's, and 0 and 4..7 are not assigned.
        for bits in [0, 1, 4, 5, 6, 7] {
            assert!(matches!(
                KeyDescriptorVersion::from_key_info(bits),
                Err(Error::UnsupportedVersion)
            ));
        }
    }
}
