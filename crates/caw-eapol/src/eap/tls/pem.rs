//! PEM decoding for the configured CA bundle and client certificate.
//!
//! Forty lines rather than a dependency, because that is genuinely all it is:
//! find the labelled block, drop the whitespace, decode base64. The alternative
//! is a crate whose only job is those forty lines, and this crate already
//! carries more dependencies than it would like.
//!
//! Nothing here validates the DER it produces. That is `rustls`'s and
//! `webpki`'s job, and doing it twice in two parsers is how a certificate ends
//! up meaning two different things.

use crate::Error;

/// A PEM block's contents, one entry per matching label.
///
/// `label` is the text between the dashes, e.g. `CERTIFICATE`.
pub fn blocks(pem: &[u8], label: &str) -> Result<Vec<Vec<u8>>, Error> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let text = std::str::from_utf8(pem)
        .map_err(|_| Error::CertificateStore("PEM is not valid UTF-8".into()))?;

    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let body = &rest[start + begin.len()..];
        let stop = body
            .find(&end)
            .ok_or_else(|| Error::CertificateStore(format!("unterminated {label} block")))?;
        out.push(base64_decode(&body[..stop])?);
        rest = &body[stop + end.len()..];
    }
    Ok(out)
}

/// Every certificate in a PEM bundle, in file order.
///
/// A CA bundle is usually several concatenated certificates and all of them
/// are trust anchors, so this returns the lot rather than the first.
pub fn certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let certs = blocks(pem, "CERTIFICATE")?;
    if certs.is_empty() {
        return Err(Error::CertificateStore(
            "no CERTIFICATE block in the PEM input".into(),
        ));
    }
    Ok(certs)
}

/// Standard base64 with `=` padding, ignoring the line breaks PEM wraps at.
fn base64_decode(s: &str) -> Result<Vec<u8>, Error> {
    fn sextet(c: u8) -> Option<u8> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }

    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    // Accumulate sextets into a 24-bit group and spill three octets per group.
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut padding = 0usize;
    for &c in s.as_bytes() {
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'=' => {
                padding += 1;
                continue;
            }
            _ => {}
        }
        if padding > 0 {
            return Err(Error::CertificateStore("base64 data after padding".into()));
        }
        let v = sextet(c).ok_or_else(|| Error::CertificateStore("invalid base64".into()))?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits == 24 {
            out.extend_from_slice(&acc.to_be_bytes()[1..]);
            acc = 0;
            bits = 0;
        }
    }
    // A trailing group of 12 or 18 bits carries one or two whole octets; the
    // leftover 4 or 2 bits are padding and must be zero.
    match bits {
        0 => {}
        12 => out.push((acc >> 4) as u8),
        18 => {
            out.push((acc >> 10) as u8);
            out.push((acc >> 2) as u8);
        }
        _ => return Err(Error::CertificateStore("truncated base64".into())),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: &str = "\
-----BEGIN CERTIFICATE-----
TWFu
-----END CERTIFICATE-----
";

    #[test]
    fn decodes_a_block() {
        assert_eq!(certificates(ONE.as_bytes()).unwrap(), vec![b"Man".to_vec()]);
    }

    /// A CA bundle is normally several concatenated certificates, and dropping
    /// all but the first would fail against a two-tier PKI in a way that looks
    /// like a bad server certificate.
    #[test]
    fn decodes_every_block_in_a_bundle() {
        let bundle = format!("{ONE}some noise between blocks\n{ONE}");
        assert_eq!(certificates(bundle.as_bytes()).unwrap().len(), 2);
    }

    #[test]
    fn handles_every_padding_length() {
        // RFC 4648 §10.
        for (encoded, decoded) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(
                base64_decode(encoded).unwrap(),
                decoded.as_bytes(),
                "{encoded}"
            );
        }
    }

    #[test]
    fn ignores_the_line_wrapping_pem_adds() {
        assert_eq!(base64_decode("Zm9v\n  Ym\tFy\r\n").unwrap(), b"foobar");
    }

    #[test]
    fn rejects_junk() {
        assert!(base64_decode("Zm9*").is_err());
        assert!(base64_decode("Zg==Zg==").is_err());
        assert!(base64_decode("Z").is_err());
    }

    #[test]
    fn rejects_an_unterminated_block() {
        assert!(blocks(b"-----BEGIN CERTIFICATE-----\nTWFu\n", "CERTIFICATE").is_err());
    }

    /// An empty CA file must not silently become an empty trust store, which
    /// would then be indistinguishable from validation being switched off.
    #[test]
    fn rejects_a_pem_file_with_no_certificate_in_it() {
        assert!(certificates(b"# nothing here\n").is_err());
    }
}
