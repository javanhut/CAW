//! Getting the MSK out of a finished TLS session.
//!
//! This is the whole point of the TLS handshake as far as WiFi is concerned.
//! The certificates prove who the RADIUS server is; the exported key material
//! is what the AP is separately told over RADIUS, and what the 4-way handshake
//! then proves the AP actually holds.
//!
//! # Two exports, because TLS 1.3 removed the first one
//!
//! Under TLS 1.2 the methods each named a label and reached into the TLS PRF
//! directly. RFC 5705 later standardised that as the exporter interface, and
//! the two agree exactly: an exporter run with the method's own label and no
//! context is `PRF(master_secret, label, client_random || server_random)`,
//! byte for byte what RFC 5216 §2.3 and RFC 5281 §8 specify.
//!
//! TLS 1.3 has no master secret and no PRF, so RFC 9190 respecified the
//! export: one label for every TLS-based EAP method, with the method's own
//! type code as the exporter *context* to keep EAP-TLS, PEAP and TTLS from
//! deriving the same key from the same session. It also asks for 128 octets —
//! MSK then EMSK — where TLS 1.2 derived them from separate exports.
//!
//! Getting this wrong is invisible until the 4-way handshake, where it is
//! indistinguishable from a wrong password.

use rustls::{ClientConnection, ProtocolVersion};
use zeroize::Zeroizing;

use crate::Error;

/// RFC 5216 §2.3. Also PEAPv0's, which inherited it.
pub const TLS12_LABEL_EAP_TLS: &[u8] = b"client EAP encryption";
/// RFC 5281 §8.
pub const TLS12_LABEL_TTLS: &[u8] = b"ttls keying material";
/// RFC 9190 §2.3, for every TLS-based method.
pub const TLS13_LABEL: &[u8] = b"EXPORTER_EAP_TLS_Key_Material";

/// MSK length. The AP only uses the first half, but the export is one
/// operation and truncating it early yields different bytes.
pub const MSK_LEN: usize = 64;

/// Export the MSK from a completed handshake.
///
/// `method_type` is the EAP type code — 13, 21 or 25 — and is the exporter
/// context under TLS 1.3. `tls12_label` is the method's own RFC-assigned
/// label, unused under TLS 1.3.
pub fn export_msk(
    conn: &ClientConnection,
    method_type: u8,
    tls12_label: &[u8],
) -> Result<[u8; MSK_LEN], Error> {
    let mut msk = [0u8; MSK_LEN];
    match conn.protocol_version() {
        Some(ProtocolVersion::TLSv1_3) => {
            // RFC 9190 exports MSK||EMSK in one call. 802.11 wants only the
            // MSK, but asking for 64 octets would produce a *different* 64.
            let material = Zeroizing::new(conn.export_keying_material(
                [0u8; 2 * MSK_LEN],
                TLS13_LABEL,
                Some(&[method_type]),
            )?);
            msk.copy_from_slice(&material[..MSK_LEN]);
        }
        Some(_) => {
            msk = conn.export_keying_material(msk, tls12_label, None)?;
        }
        // Reachable only if the handshake has not finished, which every caller
        // here checks first — but a silent zero MSK would be catastrophic.
        None => return Err(Error::UnexpectedMessage),
    }
    Ok(msk)
}
