//! The EAPOL-Key descriptor, IEEE 802.11-2016 12.7.2, and the Key Data field
//! it carries.
//!
//! Every field is big-endian and fixed-position, so the layout is written once
//! as offsets and shared by the parser and the builder. A single offset off by
//! one does not show up as a parse failure: it shows up as a MIC mismatch two
//! messages later, which on the wire is indistinguishable from a wrong
//! passphrase. That is worth spelling out rather than counting by hand.

use caw_crypto::{KeyDescriptorVersion, MIC_LEN, compute_mic};
use zeroize::Zeroizing;

use crate::{EAPOL_HDR_LEN, Error, PacketType};

/// Descriptor type 2: the RSN key descriptor, used by WPA2 and WPA3.
///
/// Type 254 is WPA1's vendor descriptor. caw does not join TKIP networks, so
/// it is rejected rather than parsed — accepting it would mean implementing
/// the RC4 key wrap and MD5 MIC that go with it.
pub const DESCRIPTOR_TYPE_RSN: u8 = 2;

// Offsets within the EAPOL-Key body, i.e. from the Key Descriptor Type octet.
const OFF_KEY_INFO: usize = 1;
const OFF_KEY_LENGTH: usize = 3;
const OFF_REPLAY_COUNTER: usize = 5;
const OFF_KEY_NONCE: usize = 13;
const OFF_KEY_IV: usize = 45;
const OFF_KEY_RSC: usize = 61;
// 69..77 is reserved; WPA1 used it for a key id and RSN leaves it zero.
const OFF_KEY_MIC: usize = 77;
const OFF_KEY_DATA_LEN: usize = 93;

/// Size of an EAPOL-Key body with an empty Key Data field.
pub const BODY_MIN: usize = 95;

/// Where the Key MIC sits in a complete EAPOL frame, EAPOL header included.
/// The MIC is computed over the frame with these 16 bytes zeroed.
pub const MIC_OFFSET: usize = EAPOL_HDR_LEN + OFF_KEY_MIC;

/// The Key Information bitfield.
///
/// Bit positions are given as masks rather than a bitflags-style enum because
/// the low three bits are not a flag at all — they are the Key Descriptor
/// Version, which selects the MIC algorithm.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyInfo(pub u16);

impl KeyInfo {
    /// Set on a pairwise key, clear on a group key.
    pub const PAIRWISE: u16 = 1 << 3;
    /// Install the pairwise key once this exchange completes.
    pub const INSTALL: u16 = 1 << 6;
    /// The sender expects a reply. Only the authenticator ever sets it, which
    /// is what tells a supplicant's own frames apart from an AP's.
    pub const ACK: u16 = 1 << 7;
    /// The Key MIC field is populated.
    pub const MIC: u16 = 1 << 8;
    /// The pairwise key is already established, so this frame is protected.
    pub const SECURE: u16 = 1 << 9;
    /// The sender is reporting a MIC failure (with `REQUEST`).
    pub const ERROR: u16 = 1 << 10;
    /// Supplicant-initiated request; never sent by an authenticator.
    pub const REQUEST: u16 = 1 << 11;
    /// The Key Data field is wrapped under the KEK.
    pub const ENCRYPTED: u16 = 1 << 12;

    /// Which MIC and key-wrap pairing this frame uses.
    pub fn version(self) -> Result<KeyDescriptorVersion, Error> {
        Ok(KeyDescriptorVersion::from_key_info(self.0)?)
    }

    pub fn pairwise(self) -> bool {
        self.0 & Self::PAIRWISE != 0
    }
    pub fn install(self) -> bool {
        self.0 & Self::INSTALL != 0
    }
    pub fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }
    pub fn mic(self) -> bool {
        self.0 & Self::MIC != 0
    }
    pub fn secure(self) -> bool {
        self.0 & Self::SECURE != 0
    }
    pub fn error(self) -> bool {
        self.0 & Self::ERROR != 0
    }
    pub fn request(self) -> bool {
        self.0 & Self::REQUEST != 0
    }
    pub fn encrypted(self) -> bool {
        self.0 & Self::ENCRYPTED != 0
    }
}

/// One EAPOL-Key frame. Borrows its Key Data from the buffer it was parsed
/// from, or from whatever the builder is about to encode.
pub struct KeyFrame<'a> {
    pub descriptor_type: u8,
    pub key_info: KeyInfo,
    /// Length of the temporal key the descriptor refers to: 16 for CCMP.
    pub key_length: u16,
    pub replay_counter: u64,
    /// ANonce from the authenticator, SNonce from the supplicant.
    pub key_nonce: [u8; 32],
    /// Unused by RSN; kept because it is inside the MIC.
    pub key_iv: [u8; 16],
    /// Starting receive sequence counter for the group key.
    pub key_rsc: [u8; 8],
    pub key_mic: [u8; MIC_LEN],
    pub key_data: &'a [u8],
}

impl<'a> KeyFrame<'a> {
    /// Parse an EAPOL-Key body — everything after the 4-byte EAPOL header.
    pub fn parse(body: &'a [u8]) -> Result<Self, Error> {
        if body.len() < BODY_MIN {
            return Err(Error::Malformed);
        }
        let key_data_len = be16(&body[OFF_KEY_DATA_LEN..]) as usize;
        let key_data = body
            .get(BODY_MIN..BODY_MIN + key_data_len)
            .ok_or(Error::Malformed)?;

        Ok(Self {
            descriptor_type: body[0],
            key_info: KeyInfo(be16(&body[OFF_KEY_INFO..])),
            key_length: be16(&body[OFF_KEY_LENGTH..]),
            replay_counter: u64::from_be_bytes(
                body[OFF_REPLAY_COUNTER..OFF_REPLAY_COUNTER + 8]
                    .try_into()
                    .expect("8 of 95 bytes"),
            ),
            key_nonce: body[OFF_KEY_NONCE..OFF_KEY_NONCE + 32]
                .try_into()
                .expect("32 of 95 bytes"),
            key_iv: body[OFF_KEY_IV..OFF_KEY_IV + 16]
                .try_into()
                .expect("16 of 95 bytes"),
            key_rsc: body[OFF_KEY_RSC..OFF_KEY_RSC + 8]
                .try_into()
                .expect("8 of 95 bytes"),
            key_mic: body[OFF_KEY_MIC..OFF_KEY_MIC + MIC_LEN]
                .try_into()
                .expect("16 of 95 bytes"),
            key_data,
        })
    }

    /// Encode as a complete EAPOL frame, header included, with the Key MIC
    /// field exactly as this struct holds it.
    pub fn encode(&self, protocol_version: u8) -> Vec<u8> {
        let body_len = u16::try_from(BODY_MIN + self.key_data.len())
            .expect("key data is at most a few hundred bytes");
        let mut buf = Vec::with_capacity(EAPOL_HDR_LEN + body_len as usize);

        buf.push(protocol_version);
        buf.push(PacketType::Key as u8);
        buf.extend_from_slice(&body_len.to_be_bytes());

        buf.push(self.descriptor_type);
        buf.extend_from_slice(&self.key_info.0.to_be_bytes());
        buf.extend_from_slice(&self.key_length.to_be_bytes());
        buf.extend_from_slice(&self.replay_counter.to_be_bytes());
        buf.extend_from_slice(&self.key_nonce);
        buf.extend_from_slice(&self.key_iv);
        buf.extend_from_slice(&self.key_rsc);
        buf.extend_from_slice(&[0u8; 8]); // reserved
        buf.extend_from_slice(&self.key_mic);
        buf.extend_from_slice(&(self.key_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.key_data);
        buf
    }

    /// Encode and fill in the Key MIC over the finished frame.
    ///
    /// The MIC covers the field it will occupy, so the field is zeroed here
    /// rather than trusting the caller to have left it clear.
    pub fn encode_signed(
        &self,
        protocol_version: u8,
        kck: &[u8; 16],
        version: KeyDescriptorVersion,
    ) -> Vec<u8> {
        let mut frame = self.encode(protocol_version);
        frame[MIC_OFFSET..MIC_OFFSET + MIC_LEN].fill(0);
        let mic = compute_mic(kck, version, &frame);
        frame[MIC_OFFSET..MIC_OFFSET + MIC_LEN].copy_from_slice(&mic);
        frame
    }
}

/// Check the Key MIC of a received frame.
///
/// `frame` is the complete EAPOL frame trimmed to its declared body length —
/// what [`Eapol::raw`](crate::Eapol::raw) yields. An AP that pads the Ethernet
/// payload does not extend the MIC input, so trimming first is not cosmetic.
pub fn verify_frame_mic(
    frame: &[u8],
    kck: &[u8; 16],
    version: KeyDescriptorVersion,
    mic: &[u8; MIC_LEN],
) -> Result<(), Error> {
    if frame.len() < MIC_OFFSET + MIC_LEN {
        return Err(Error::Malformed);
    }
    let mut zeroed = frame.to_vec();
    zeroed[MIC_OFFSET..MIC_OFFSET + MIC_LEN].fill(0);
    Ok(caw_crypto::verify_mic(kck, version, &zeroed, mic)?)
}

/// A group temporal key and the index the authenticator assigned it.
pub struct Gtk {
    pub key: Zeroizing<Vec<u8>>,
    pub index: u8,
}

/// 00-0F-AC, the IEEE OUI that prefixes the standard KDEs.
const OUI_IEEE: [u8; 3] = [0x00, 0x0f, 0xac];
/// KDE data type 1 under [`OUI_IEEE`]: the GTK.
const KDE_GTK: u8 = 1;
/// Element id 221, which a KDE borrows to look like a vendor IE.
const EID_VENDOR: u8 = 221;
/// Element id 48, the RSN element. It appears in Key Data as a plain element,
/// not wrapped in a KDE.
const EID_RSN: u8 = 48;

/// One element of a decrypted Key Data field: either a KDE or a bare IE.
pub enum KeyDataItem<'a> {
    Kde {
        oui: [u8; 3],
        data_type: u8,
        data: &'a [u8],
    },
    /// The element including its two-byte header, because the RSN element has
    /// to be compared byte-for-byte against the one from the beacon.
    Ie { id: u8, raw: &'a [u8] },
}

/// Walks a decrypted Key Data field.
pub struct KeyDataItems<'a> {
    rest: &'a [u8],
}

/// Iterate the elements of a decrypted Key Data field.
pub fn key_data_items(data: &[u8]) -> KeyDataItems<'_> {
    KeyDataItems { rest: data }
}

impl<'a> Iterator for KeyDataItems<'a> {
    type Item = KeyDataItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&id, &len) = match self.rest {
            [id, len, ..] => (id, len),
            _ => return None,
        };
        // The AES key wrap needs a multiple of 8 octets, so the authenticator
        // pads with a 0xDD octet followed by zeros. Those zeros read as a
        // zero-length element, which is also the only way an element here can
        // be empty — so a zero length ends the field either way.
        if len == 0 {
            return None;
        }
        let element = self.rest.get(..2 + len as usize)?;
        self.rest = &self.rest[element.len()..];

        let payload = &element[2..];
        Some(match (id, payload) {
            (EID_VENDOR, [a, b, c, data_type, data @ ..]) => KeyDataItem::Kde {
                oui: [*a, *b, *c],
                data_type: *data_type,
                data,
            },
            _ => KeyDataItem::Ie { id, raw: element },
        })
    }
}

/// Extract the GTK from a decrypted Key Data field.
///
/// The KDE body is a flags octet — key index in bits 0-1, Tx in bit 2 — then a
/// reserved octet, then the key itself.
pub fn gtk_kde(key_data: &[u8]) -> Result<Gtk, Error> {
    for item in key_data_items(key_data) {
        if let KeyDataItem::Kde {
            oui: OUI_IEEE,
            data_type: KDE_GTK,
            data,
        } = item
        {
            let [flags, _reserved, key @ ..] = data else {
                return Err(Error::Malformed);
            };
            // 16 for CCMP-128 and GCMP-128, 32 for GCMP-256. Any other length
            // is either a cipher caw did not negotiate or a mangled frame, and
            // installing a key of the wrong size is not a recoverable state.
            if key.len() != 16 && key.len() != 32 {
                return Err(Error::Malformed);
            }
            return Ok(Gtk {
                key: Zeroizing::new(key.to_vec()),
                index: flags & 0x03,
            });
        }
    }
    Err(Error::GtkMissing)
}

/// The first RSN element in a decrypted Key Data field, header included.
pub fn rsn_element(key_data: &[u8]) -> Option<&[u8]> {
    key_data_items(key_data).find_map(|item| match item {
        KeyDataItem::Ie { id: EID_RSN, raw } => Some(raw),
        _ => None,
    })
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
