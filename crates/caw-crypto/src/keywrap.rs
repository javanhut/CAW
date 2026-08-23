//! AES Key Wrap: how a group key crosses the air.
//!
//! Message 3 of the 4-way handshake and every group rekey carry the GTK inside
//! the Key Data field, wrapped under the KEK. Only unwrapping is implemented —
//! a station receives group keys and never issues them.

use aes_kw::{KeyInit, KwAes128};
use zeroize::Zeroizing;

use crate::Error;

/// The wrap's integrity check value occupies one semiblock (RFC 3394 § 2.2.3.1).
const ICV_LEN: usize = 8;

/// Unwrap an EAPOL-Key Key Data field with the KEK, per RFC 3394.
///
/// The check value is what stands between a station and an attacker-supplied
/// group key, so a failure here ends the handshake; it is not worth retrying,
/// because the only causes are a wrong PMK or a modified frame.
///
/// The plaintext is 8 bytes shorter than `wrapped` and comes back zeroizing:
/// it holds the GTK, in a GTK KDE alongside whatever else the AP sent.
pub fn unwrap_key_data(kek: &[u8; 16], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Two semiblocks in, one of which is the check value; anything shorter or
    // unaligned cannot have come out of the wrap.
    if wrapped.len() < 2 * ICV_LEN || !wrapped.len().is_multiple_of(ICV_LEN) {
        return Err(Error::Malformed);
    }

    let kw = KwAes128::new_from_slice(kek).expect("KEK is one AES-128 key");
    let mut out = Zeroizing::new(vec![0u8; wrapped.len() - ICV_LEN]);
    kw.unwrap_key(wrapped, &mut out[..])
        .map_err(|_| Error::KeyUnwrapFailed)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// RFC 3394 § 4.1: wrapping 128 bits of key data with a 128-bit KEK, which
    /// is the WPA2 case — a CCMP GTK under a 16-byte KEK.
    #[test]
    fn rfc3394_128_bit_kek() {
        let kek: [u8; 16] = hex("000102030405060708090A0B0C0D0E0F").try_into().unwrap();
        let wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        assert_eq!(
            unwrap_key_data(&kek, &wrapped).unwrap()[..],
            hex("00112233445566778899AABBCCDDEEFF")[..]
        );
    }

    #[test]
    fn rejects_a_tampered_check_value() {
        let kek: [u8; 16] = hex("000102030405060708090A0B0C0D0E0F").try_into().unwrap();
        let mut wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        wrapped[0] ^= 1;
        assert!(matches!(
            unwrap_key_data(&kek, &wrapped),
            Err(Error::KeyUnwrapFailed)
        ));
    }

    #[test]
    fn rejects_the_wrong_kek() {
        let wrapped = hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        assert!(matches!(
            unwrap_key_data(&[0xff; 16], &wrapped),
            Err(Error::KeyUnwrapFailed)
        ));
    }

    #[test]
    fn rejects_lengths_the_wrap_cannot_produce() {
        for len in [0, 8, 17, 23] {
            assert!(matches!(
                unwrap_key_data(&[0; 16], &vec![0u8; len]),
                Err(Error::Malformed)
            ));
        }
    }

    /// A real Key Data field is longer than one semiblock pair: a GTK KDE is
    /// 8 bytes of header plus a 16-byte key, padded out to 32.
    #[test]
    fn round_trips_a_gtk_sized_payload() {
        let kek = [0x5a; 16];
        let key_data: Vec<u8> = (0..32u8).collect();
        let mut buf = [0u8; 40];
        let wrapped = KwAes128::new_from_slice(&kek)
            .unwrap()
            .wrap_key(&key_data, &mut buf)
            .unwrap();
        assert_eq!(unwrap_key_data(&kek, wrapped).unwrap()[..], key_data[..]);
    }
}
