//! Key derivation: the pairwise key hierarchy and the two pseudo-random
//! functions 802.11 builds it from.
//!
//! Which function applies is decided by the negotiated AKM, not by the cipher.
//! The original suites use the HMAC-SHA1 PRF; everything from the SHA-256 AKMs
//! onward uses the KDF of 802.11-2012 11.6.1.7.2. Choosing wrong produces a
//! key that looks perfectly well formed and fails only at the handshake MIC,
//! several messages later, so the mapping lives in exactly one place here.

use caw_80211::Akm;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Pmk, Ptk};

/// Hashed verbatim into every PTK, so the exact spelling is wire format.
const PTK_LABEL: &str = "Pairwise key expansion";

/// KCK(16) || KEK(16) || TK(16), the CCMP-128 hierarchy. TKIP would want 512
/// bits here; caw does not join TKIP networks.
const PTK_LEN: usize = 48;

/// IEEE 802.11 PRF-*n*, the HMAC-SHA1 construction of 802.11-2016 12.7.1.2.
///
/// `n` is `out.len() * 8`: PRF-384 fills a CCMP PTK, PRF-512 a TKIP one. Blocks
/// are 20 bytes and the last is truncated, so any length is legal.
pub fn prf_sha1(key: &[u8], label: &str, data: &[u8], out: &mut [u8]) {
    debug_assert!(out.len() <= 20 * 256, "block counter is a single octet");
    for (i, block) in out.chunks_mut(20).enumerate() {
        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes a key of any length");
        mac.update(label.as_bytes());
        // The zero octet keeps a label from running into the data behind it, so
        // no two (label, data) pairs can present the same bytes to the hash.
        mac.update(&[0]);
        mac.update(data);
        mac.update(&[i as u8]);
        let full = mac.finalize().into_bytes();
        block.copy_from_slice(&full[..block.len()]);
    }
}

/// The KDF of IEEE 802.11-2012 11.6.1.7.2, built on HMAC-SHA256.
///
/// Not [`prf_sha1`] with the hash swapped: the counter is prepended rather than
/// appended and starts at one, the label is not terminated, and the requested
/// length is appended — in *bits*, and little-endian, as is the counter.
pub fn kdf_sha256(key: &[u8], label: &str, data: &[u8], out: &mut [u8]) {
    let bits = u16::try_from(out.len() * 8).expect("KDF length field is 16 bits");
    for (i, block) in out.chunks_mut(32).enumerate() {
        let counter = i as u16 + 1;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
        mac.update(&counter.to_le_bytes());
        mac.update(label.as_bytes());
        mac.update(data);
        mac.update(&bits.to_le_bytes());
        let full = mac.finalize().into_bytes();
        block.copy_from_slice(&full[..block.len()]);
    }
}

/// Derives the PTK from a PMK and the two nonces. The KDF and MIC algorithm
/// both depend on the negotiated AKM, which is why it is threaded through.
///
/// `aa` is the authenticator's address (the BSSID) and `spa` the supplicant's.
pub fn derive_ptk(
    pmk: &Pmk,
    akm: Akm,
    aa: [u8; 6],
    spa: [u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> Result<Ptk, Error> {
    let hash = ptk_hash(akm)?;

    // Both ends must reach the same key without agreeing who is who, so each
    // pair goes in sorted. The ordering is the bytewise one a memcmp gives.
    let (addr_lo, addr_hi) = if aa < spa { (aa, spa) } else { (spa, aa) };
    let (nonce_lo, nonce_hi) = if anonce < snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };

    let mut data = [0u8; 76];
    data[..6].copy_from_slice(&addr_lo);
    data[6..12].copy_from_slice(&addr_hi);
    data[12..44].copy_from_slice(nonce_lo);
    data[44..76].copy_from_slice(nonce_hi);

    let mut ptk = Zeroizing::new([0u8; PTK_LEN]);
    match hash {
        PtkHash::Sha1 => prf_sha1(&pmk.0, PTK_LABEL, &data, &mut ptk[..]),
        PtkHash::Sha256 => kdf_sha256(&pmk.0, PTK_LABEL, &data, &mut ptk[..]),
    }

    // The three keys are a straight split of the output, in this order.
    Ok(Ptk {
        kck: ptk[..16].try_into().expect("16 of 48 bytes"),
        kek: ptk[16..32].try_into().expect("16 of 48 bytes"),
        tk: ptk[32..48].try_into().expect("16 of 48 bytes"),
    })
}

/// Which pseudo-random function an AKM selects for the pairwise hierarchy.
enum PtkHash {
    Sha1,
    Sha256,
}

fn ptk_hash(akm: Akm) -> Result<PtkHash, Error> {
    match akm {
        // Suites 1 and 2, the pair WPA2 shipped with.
        Akm::Dot1x | Akm::Psk => Ok(PtkHash::Sha1),
        Akm::Dot1xSha256 | Akm::PskSha256 | Akm::Sae | Akm::Owe => Ok(PtkHash::Sha256),
        // The rest need a hierarchy this function does not implement: the fast
        // transition suites derive the PTK from PMK-R1 rather than the PMK, and
        // Suite B 192 runs on SHA-384 with keys wider than `Ptk` holds.
        _ => Err(Error::UnsupportedAkm),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    const AA: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
    const SPA: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x02, 0x00];

    fn pmk() -> Pmk {
        Pmk(
            hex("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")
                .try_into()
                .unwrap(),
        )
    }

    /// IEEE 802.11i-2004 Annex H.4.1, "PRF-192" test vectors.
    #[test]
    fn ieee_80211i_prf_vectors() {
        let mut out = [0u8; 24];

        prf_sha1(&[0x0b; 20], "prefix", b"Hi There", &mut out);
        assert_eq!(
            out[..],
            hex("bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606")[..]
        );

        prf_sha1(b"Jefe", "prefix", b"what do ya want for nothing?", &mut out);
        assert_eq!(
            out[..],
            hex("51f4de5b33f249adf81aeb713a3c20f4fe631446fabdfa58")[..]
        );

        prf_sha1(&[0xaa; 20], "prefix", &[0xdd; 50], &mut out);
        assert_eq!(
            out[..],
            hex("e1ac546ec4cb636f9976487be5c86be17a0252ca5d8d8df1")[..]
        );
    }

    /// Each 32-byte block is one HMAC over counter || label || data || length,
    /// with the counter starting at one and both integers little-endian.
    #[test]
    fn kdf_sha256_block_layout() {
        let mut out = [0u8; 48];
        kdf_sha256(b"key", "label", b"data", &mut out);

        for (i, block) in out.chunks(32).enumerate() {
            let mut mac = Hmac::<Sha256>::new_from_slice(b"key").unwrap();
            mac.update(&(i as u16 + 1).to_le_bytes());
            mac.update(b"label");
            mac.update(b"data");
            mac.update(&384u16.to_le_bytes());
            let want = mac.finalize().into_bytes();
            assert_eq!(block, &want[..block.len()]);
        }
    }

    /// The requested length is hashed in, so a prefix of a longer output is not
    /// the same as a shorter one. Getting this wrong would silently weaken any
    /// caller that asked for a truncated key.
    #[test]
    fn kdf_sha256_binds_its_length() {
        let mut short = [0u8; 16];
        let mut long = [0u8; 32];
        kdf_sha256(b"key", "label", b"data", &mut short);
        kdf_sha256(b"key", "label", b"data", &mut long);
        assert_ne!(short[..], long[..16]);
    }

    /// The sort is what lets the AP and the station agree, so passing the pairs
    /// the other way round must land on the same key.
    #[test]
    fn ptk_is_independent_of_argument_order() {
        let (anonce, snonce) = ([0x33u8; 32], [0x11u8; 32]);
        let a = derive_ptk(&pmk(), Akm::Psk, AA, SPA, &anonce, &snonce).unwrap();
        let b = derive_ptk(&pmk(), Akm::Psk, SPA, AA, &snonce, &anonce).unwrap();
        assert_eq!(a.kck, b.kck);
        assert_eq!(a.kek, b.kek);
        assert_eq!(a.tk, b.tk);
    }

    /// The sorted concatenation and the KCK/KEK/TK split, spelled out.
    #[test]
    fn ptk_layout_matches_the_standard() {
        let (anonce, snonce) = ([0x33u8; 32], [0x11u8; 32]);
        let ptk = derive_ptk(&pmk(), Akm::Psk, AA, SPA, &anonce, &snonce).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&AA); // AA < SPA here
        data.extend_from_slice(&SPA);
        data.extend_from_slice(&snonce); // SNonce < ANonce here
        data.extend_from_slice(&anonce);
        let mut want = [0u8; 48];
        prf_sha1(&pmk().0, "Pairwise key expansion", &data, &mut want);

        assert_eq!(ptk.kck[..], want[..16]);
        assert_eq!(ptk.kek[..], want[16..32]);
        assert_eq!(ptk.tk[..], want[32..48]);
    }

    #[test]
    fn sha256_akms_derive_a_different_key() {
        let (anonce, snonce) = ([0x33u8; 32], [0x11u8; 32]);
        let sha1 = derive_ptk(&pmk(), Akm::Psk, AA, SPA, &anonce, &snonce).unwrap();
        let sha256 = derive_ptk(&pmk(), Akm::PskSha256, AA, SPA, &anonce, &snonce).unwrap();
        assert_ne!(sha1.kck, sha256.kck);

        let sae = derive_ptk(&pmk(), Akm::Sae, AA, SPA, &anonce, &snonce).unwrap();
        assert_eq!(sha256.kck, sae.kck);
    }

    #[test]
    fn rejects_akms_with_another_hierarchy() {
        let nonce = [0u8; 32];
        for akm in [Akm::FtPsk, Akm::FtSae, Akm::Dot1xSuiteB192] {
            assert!(matches!(
                derive_ptk(&pmk(), akm, AA, SPA, &nonce, &nonce),
                Err(Error::UnsupportedAkm)
            ));
        }
    }
}
