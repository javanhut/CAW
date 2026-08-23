//! EAP-MSCHAPv2 (RFC 2759, draft-kamath-pppext-eap-mschapv2): PEAP's inner
//! method, and the one nearly every Windows-domain WiFi network uses.
//!
//! # It is broken, and that is the point of the tunnel
//!
//! MSCHAPv2's response is three single-DES encryptions under a 16-byte MD4
//! hash of the password, split into 7+7+2 bytes. The last DES key is two bytes
//! of key material and five zeros, so a captured challenge/response pair is
//! recoverable with a single DES exhaustion — hours, on rented hardware, in
//! 2012 and considerably less now.
//!
//! caw implements it anyway because that is what the deployed networks speak,
//! and it is safe *only* because PEAP never lets it near the air: the exchange
//! happens inside a TLS tunnel whose server certificate has already been
//! validated. That dependency runs the other way too — this method is the
//! reason
//! [`danger_accept_any_server_certificate`](super::tls::TlsConfig::danger_accept_any_server_certificate)
//! is spelled the way it is. Without a validated tunnel, MSCHAPv2 hands an
//! offline-crackable password verifier to whoever answered.
//!
//! # What it buys back
//!
//! Mutual authentication. The server's Success message carries an
//! authenticator response that only something knowing the password hash can
//! compute, and [`Mschapv2`] checks it before reporting success. A tunnel
//! endpoint that terminated TLS but does not know the password cannot get
//! past that step.
//!
//! # Sans-IO
//!
//! The peer challenge is the one input that cannot be derived, so it enters
//! through [`Mschapv2::with_peer_challenge`]; [`Mschapv2::new`] is the thin
//! shell that draws it from `getrandom`.

use des::Des;
use des::cipher::{BlockCipherEncrypt, KeyInit};
use md4::Md4;
use sha1::Sha1;
use sha1::digest::Digest;
use zeroize::{Zeroize, Zeroizing};

use super::packet::eap_type;
use crate::{EapMethod, Error};

/// MSCHAPv2 operation codes.
const OP_CHALLENGE: u8 = 1;
const OP_RESPONSE: u8 = 2;
const OP_SUCCESS: u8 = 3;
const OP_FAILURE: u8 = 4;

/// OpCode, MS-CHAPv2-ID, MS-Length.
const MS_HDR_LEN: usize = 4;

/// PeerChallenge(16) || Reserved(8) || NT-Response(24) || Flags(1).
const RESPONSE_LEN: usize = 49;

/// RFC 2759 §8.7, hashed verbatim, so the exact spelling is wire format.
const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

/// `NtPasswordHash`, RFC 2759 §8.3: MD4 of the password in UTF-16LE.
///
/// No salt and no iteration count — this is a raw hash of the password, which
/// is why it is also a password-equivalent secret.
pub fn nt_password_hash(password: &str) -> Zeroizing<[u8; 16]> {
    let mut utf16 = Zeroizing::new(Vec::with_capacity(password.len() * 2));
    for unit in password.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&Md4::digest(&utf16[..]));
    out
}

/// `HashNtPasswordHash`, RFC 2759 §8.4.
pub fn hash_nt_password_hash(hash: &[u8; 16]) -> Zeroizing<[u8; 16]> {
    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&Md4::digest(hash));
    out
}

/// `ChallengeHash`, RFC 2759 §8.2.
///
/// Folding both challenges and the username into eight octets is what stops a
/// peer from choosing a challenge that replays an earlier response.
pub fn challenge_hash(
    peer_challenge: &[u8; 16],
    authenticator_challenge: &[u8; 16],
    username: &[u8],
) -> [u8; 8] {
    let mut sha = Sha1::new();
    sha.update(peer_challenge);
    sha.update(authenticator_challenge);
    sha.update(username);
    let digest = sha.finalize();
    digest[..8].try_into().expect("SHA-1 is 20 octets")
}

/// `ChallengeResponse`, RFC 2759 §8.5: three DES encryptions of the challenge
/// under the password hash, zero-padded to 21 octets.
///
/// The padding is the flaw. The third key is `hash[14..16]` followed by five
/// zero octets, so its 16 bits of entropy fall to a lookup table and the other
/// two DES keys follow from the recovered hash.
pub fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut padded = Zeroizing::new([0u8; 21]);
    padded[..16].copy_from_slice(password_hash);

    let mut out = [0u8; 24];
    for (i, block) in out.chunks_mut(8).enumerate() {
        let key: [u8; 7] = padded[i * 7..i * 7 + 7].try_into().expect("21 = 3 * 7");
        block.copy_from_slice(&des_encrypt(&key, challenge));
    }
    out
}

/// `GenerateNTResponse`, RFC 2759 §8.1.
pub fn generate_nt_response(
    authenticator_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    username: &[u8],
    password: &str,
) -> [u8; 24] {
    let challenge = challenge_hash(peer_challenge, authenticator_challenge, username);
    challenge_response(&challenge, &nt_password_hash(password))
}

/// `GenerateAuthenticatorResponse`, RFC 2759 §8.7, as the ASCII `S=...` the
/// server sends.
///
/// This is the half of MSCHAPv2 worth having: only something holding the
/// password hash can produce it, so checking it authenticates the far end of
/// the tunnel and not merely the tunnel.
pub fn generate_authenticator_response(
    password: &str,
    nt_response: &[u8; 24],
    peer_challenge: &[u8; 16],
    authenticator_challenge: &[u8; 16],
    username: &[u8],
) -> [u8; 42] {
    let password_hash = nt_password_hash(password);
    let password_hash_hash = hash_nt_password_hash(&password_hash);

    let mut sha = Sha1::new();
    sha.update(&password_hash_hash[..]);
    sha.update(nt_response);
    sha.update(MAGIC1);
    let digest = sha.finalize();

    let challenge = challenge_hash(peer_challenge, authenticator_challenge, username);
    let mut sha = Sha1::new();
    sha.update(digest);
    sha.update(challenge);
    sha.update(MAGIC2);
    let digest = sha.finalize();

    let mut out = [0u8; 42];
    out[0] = b'S';
    out[1] = b'=';
    for (i, byte) in digest.iter().enumerate() {
        out[2 + i * 2] = HEX[(byte >> 4) as usize];
        out[3 + i * 2] = HEX[(byte & 0x0f) as usize];
    }
    out
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Expand a 7-octet DES key into the 8 octets the cipher takes.
///
/// DES keys are 56 bits carried in 64: every eighth bit is parity and is
/// ignored. This is the shift that inserts the gaps.
fn expand_des_key(key: &[u8; 7]) -> [u8; 8] {
    [
        key[0] & 0xfe,
        (key[0] << 7) | (key[1] >> 1),
        (key[1] << 6) | (key[2] >> 2),
        (key[2] << 5) | (key[3] >> 3),
        (key[3] << 4) | (key[4] >> 4),
        (key[4] << 3) | (key[5] >> 5),
        (key[5] << 2) | (key[6] >> 6),
        key[6] << 1,
    ]
}

fn des_encrypt(key: &[u8; 7], plaintext: &[u8; 8]) -> [u8; 8] {
    let mut expanded = Zeroizing::new(expand_des_key(key));
    let cipher = Des::new_from_slice(&expanded[..]).expect("DES takes exactly 8 octets");
    expanded.zeroize();

    let mut block = des::cipher::Block::<Des>::default();
    block.copy_from_slice(plaintext);
    cipher.encrypt_block(&mut block);

    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    out
}

/// Compare without an early exit. The authenticator response is not secret,
/// but a comparison that stops at the first wrong octet is a free oracle and
/// there is no reason to hand one out.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    AwaitingChallenge,
    AwaitingSuccess,
    /// The server proved it knows the password hash.
    Authenticated,
}

/// EAP-MSCHAPv2, type 26. Driven by [`Peap`](super::peap::Peap) inside the
/// tunnel; never run on its own, because on its own it authenticates nothing
/// an attacker cannot capture.
pub struct Mschapv2 {
    username: String,
    password: Zeroizing<String>,
    peer_challenge: [u8; 16],
    /// What the server's Success must carry, computed when the response is
    /// built. Holding it is what turns MSCHAPv2 from one-way to mutual.
    expected_response: Option<[u8; 42]>,
    state: State,
}

impl Mschapv2 {
    /// Draw the peer challenge from `getrandom`.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Result<Self, Error> {
        let nonce = crate::random_nonce()?;
        let mut peer_challenge = [0u8; 16];
        peer_challenge.copy_from_slice(&nonce[..16]);
        Ok(Self::with_peer_challenge(
            username,
            password,
            peer_challenge,
        ))
    }

    /// The sans-IO constructor: every input explicit, nothing drawn from the
    /// environment.
    pub fn with_peer_challenge(
        username: impl Into<String>,
        password: impl Into<String>,
        peer_challenge: [u8; 16],
    ) -> Self {
        Self {
            username: username.into(),
            password: Zeroizing::new(password.into()),
            peer_challenge,
            expected_response: None,
            state: State::AwaitingChallenge,
        }
    }

    /// True once the server's authenticator response has been verified.
    pub fn authenticated(&self) -> bool {
        self.state == State::Authenticated
    }

    fn on_challenge(&mut self, ms_id: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
        let [value_size, rest @ ..] = body else {
            return Err(Error::Malformed);
        };
        if *value_size as usize != 16 {
            return Err(Error::Malformed);
        }
        let authenticator_challenge: [u8; 16] = rest
            .get(..16)
            .ok_or(Error::Malformed)?
            .try_into()
            .expect("16 of 16");

        let nt_response = generate_nt_response(
            &authenticator_challenge,
            &self.peer_challenge,
            self.username.as_bytes(),
            &self.password,
        );
        self.expected_response = Some(generate_authenticator_response(
            &self.password,
            &nt_response,
            &self.peer_challenge,
            &authenticator_challenge,
            self.username.as_bytes(),
        ));

        let mut value = Vec::with_capacity(RESPONSE_LEN);
        value.extend_from_slice(&self.peer_challenge);
        value.extend_from_slice(&[0u8; 8]); // reserved
        value.extend_from_slice(&nt_response);
        value.push(0); // Flags: the deprecated LM response is not offered

        let mut body = Vec::with_capacity(1 + RESPONSE_LEN + self.username.len());
        body.push(RESPONSE_LEN as u8);
        body.extend_from_slice(&value);
        body.extend_from_slice(self.username.as_bytes());

        self.state = State::AwaitingSuccess;
        Ok(message(OP_RESPONSE, ms_id, &body))
    }

    fn on_success(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let expected = self.expected_response.ok_or(Error::UnexpectedMessage)?;
        // "S=<40 hex digits>" then optionally " M=<text>". The field is found
        // by prefix rather than by offset because servers differ on what, if
        // anything, precedes it.
        let found = message
            .windows(expected.len())
            .find(|w| w.starts_with(b"S="))
            .ok_or(Error::Rejected)?;
        if !constant_time_eq(found, &expected) {
            // The far end terminated TLS but cannot compute the authenticator
            // response, so it does not know the password. That is precisely
            // the case mutual authentication exists to catch.
            return Err(Error::Rejected);
        }
        self.state = State::Authenticated;
        // A bare Success opcode, with none of the header: the peer's
        // acknowledgement is defined as a single octet.
        Ok(vec![OP_SUCCESS])
    }
}

/// Frame an MSCHAPv2 message. MS-Length covers this header and the body — the
/// EAP header and Type octet are the five octets it excludes.
fn message(op_code: u8, ms_id: u8, body: &[u8]) -> Vec<u8> {
    let len = u16::try_from(MS_HDR_LEN + body.len()).expect("an MSCHAPv2 message is small");
    let mut out = Vec::with_capacity(len as usize);
    out.push(op_code);
    out.push(ms_id);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    out
}

impl EapMethod for Mschapv2 {
    fn type_code(&self) -> u8 {
        eap_type::MSCHAPV2
    }

    fn on_request(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let [op_code, ms_id, hi, lo, rest @ ..] = data else {
            return Err(Error::Malformed);
        };
        // MS-Length is redundant with the EAP length and servers disagree on
        // the padding after it, so it bounds the body rather than defining it.
        let declared = u16::from_be_bytes([*hi, *lo]) as usize;
        let body_len = declared.saturating_sub(MS_HDR_LEN).min(rest.len());
        let body = &rest[..body_len];

        match (*op_code, self.state) {
            (OP_CHALLENGE, State::AwaitingChallenge) => Ok(Some(self.on_challenge(*ms_id, body)?)),
            (OP_SUCCESS, State::AwaitingSuccess) => Ok(Some(self.on_success(body)?)),
            (OP_FAILURE, _) => Err(Error::Rejected),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    /// MSCHAPv2's own MPPE keys are not used: PEAP takes the MSK from the TLS
    /// tunnel, which is the only key material in the exchange an attacker
    /// cannot grind offline.
    fn msk(&self) -> Option<[u8; 64]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2759 §9.2, the worked example in full. Every intermediate value is
    // checked, because a wrong one only shows up as a rejected login.
    const PASSWORD: &str = "clientPass";
    const USERNAME: &[u8] = b"User";
    const AUTH_CHALLENGE: [u8; 16] = [
        0x5b, 0x5d, 0x7c, 0x7d, 0x7b, 0x3f, 0x2f, 0x3e, 0x3c, 0x2c, 0x60, 0x21, 0x32, 0x26, 0x26,
        0x28,
    ];
    const PEER_CHALLENGE: [u8; 16] = [
        0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29, 0x5f, 0x2b, 0x3a, 0x33, 0x7c,
        0x7e,
    ];
    const CHALLENGE: [u8; 8] = [0xd0, 0x2e, 0x43, 0x86, 0xbc, 0xe9, 0x12, 0x26];
    const PASSWORD_HASH: [u8; 16] = [
        0x44, 0xeb, 0xba, 0x8d, 0x53, 0x12, 0xb8, 0xd6, 0x11, 0x47, 0x44, 0x11, 0xf5, 0x69, 0x89,
        0xae,
    ];
    const PASSWORD_HASH_HASH: [u8; 16] = [
        0x41, 0xc0, 0x0c, 0x58, 0x4b, 0xd2, 0xd9, 0x1c, 0x40, 0x17, 0xa2, 0xa1, 0x2f, 0xa5, 0x9f,
        0x3f,
    ];
    const NT_RESPONSE: [u8; 24] = [
        0x82, 0x30, 0x9e, 0xcd, 0x8d, 0x70, 0x8b, 0x5e, 0xa0, 0x8f, 0xaa, 0x39, 0x81, 0xcd, 0x83,
        0x54, 0x42, 0x33, 0x11, 0x4a, 0x3d, 0x85, 0xd6, 0xdf,
    ];
    const AUTHENTICATOR_RESPONSE: &[u8] = b"S=407A5589115FD0D6209F510FE9C04566932CDA56";

    #[test]
    fn rfc2759_nt_password_hash() {
        assert_eq!(nt_password_hash(PASSWORD)[..], PASSWORD_HASH);
    }

    #[test]
    fn rfc2759_hash_nt_password_hash() {
        assert_eq!(
            hash_nt_password_hash(&PASSWORD_HASH)[..],
            PASSWORD_HASH_HASH
        );
    }

    #[test]
    fn rfc2759_challenge_hash() {
        assert_eq!(
            challenge_hash(&PEER_CHALLENGE, &AUTH_CHALLENGE, USERNAME),
            CHALLENGE
        );
    }

    /// The DES chain, which is where an off-by-one in the key expansion hides.
    #[test]
    fn rfc2759_challenge_response() {
        assert_eq!(challenge_response(&CHALLENGE, &PASSWORD_HASH), NT_RESPONSE);
    }

    #[test]
    fn rfc2759_nt_response() {
        assert_eq!(
            generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USERNAME, PASSWORD),
            NT_RESPONSE
        );
    }

    #[test]
    fn rfc2759_authenticator_response() {
        assert_eq!(
            generate_authenticator_response(
                PASSWORD,
                &NT_RESPONSE,
                &PEER_CHALLENGE,
                &AUTH_CHALLENGE,
                USERNAME
            ),
            AUTHENTICATOR_RESPONSE
        );
    }

    fn challenge_packet() -> Vec<u8> {
        let mut body = vec![16];
        body.extend_from_slice(&AUTH_CHALLENGE);
        body.extend_from_slice(b"radius.example.net");
        message(OP_CHALLENGE, 7, &body)
    }

    fn peer() -> Mschapv2 {
        Mschapv2::with_peer_challenge("User", PASSWORD, PEER_CHALLENGE)
    }

    #[test]
    fn answers_a_challenge_with_the_rfc_response() {
        let mut m = peer();
        let reply = m.on_request(&challenge_packet()).unwrap().unwrap();
        assert_eq!(reply[0], OP_RESPONSE);
        assert_eq!(reply[1], 7, "the server's MSCHAPv2 id is echoed");
        assert_eq!(
            u16::from_be_bytes([reply[2], reply[3]]) as usize,
            reply.len()
        );
        assert_eq!(reply[4], RESPONSE_LEN as u8);
        assert_eq!(&reply[5..21], PEER_CHALLENGE);
        assert_eq!(&reply[21..29], [0u8; 8], "the reserved field is zero");
        assert_eq!(&reply[29..53], NT_RESPONSE);
        assert_eq!(reply[53], 0, "the LM response is not offered");
        assert_eq!(&reply[54..], b"User");
    }

    #[test]
    fn verifies_the_servers_authenticator_response() {
        let mut m = peer();
        m.on_request(&challenge_packet()).unwrap();

        let mut body = AUTHENTICATOR_RESPONSE.to_vec();
        body.extend_from_slice(b" M=Welcome");
        let success = message(OP_SUCCESS, 8, &body);

        assert_eq!(m.on_request(&success).unwrap().unwrap(), vec![OP_SUCCESS]);
        assert!(m.authenticated());
    }

    /// A tunnel endpoint that terminated TLS but does not know the password
    /// cannot produce this value. Accepting it anyway would throw away the
    /// only mutual authentication MSCHAPv2 offers.
    #[test]
    fn rejects_a_wrong_authenticator_response() {
        let mut m = peer();
        m.on_request(&challenge_packet()).unwrap();

        let mut wrong = AUTHENTICATOR_RESPONSE.to_vec();
        *wrong.last_mut().unwrap() = b'0';
        assert!(matches!(
            m.on_request(&message(OP_SUCCESS, 8, &wrong)),
            Err(Error::Rejected)
        ));
        assert!(!m.authenticated());
    }

    #[test]
    fn rejects_a_success_with_no_authenticator_response_at_all() {
        let mut m = peer();
        m.on_request(&challenge_packet()).unwrap();
        assert!(matches!(
            m.on_request(&message(OP_SUCCESS, 8, b"M=Welcome")),
            Err(Error::Rejected)
        ));
    }

    #[test]
    fn a_failure_ends_the_exchange() {
        let mut m = peer();
        assert!(matches!(
            m.on_request(&message(OP_FAILURE, 1, b"E=691 R=0 C=... V=3")),
            Err(Error::Rejected)
        ));
    }

    /// A Success before a Challenge has nothing to check itself against.
    #[test]
    fn rejects_a_success_that_arrives_first() {
        let mut m = peer();
        assert!(matches!(
            m.on_request(&message(OP_SUCCESS, 1, AUTHENTICATOR_RESPONSE)),
            Err(Error::UnexpectedMessage)
        ));
    }

    #[test]
    fn rejects_a_truncated_challenge() {
        let mut m = peer();
        let mut body = vec![16];
        body.extend_from_slice(&AUTH_CHALLENGE[..8]);
        assert!(m.on_request(&message(OP_CHALLENGE, 1, &body)).is_err());
    }

    #[test]
    fn a_non_ascii_password_is_hashed_as_utf16le() {
        // MD4 over UTF-16LE, not over UTF-8: the two differ for anything
        // outside ASCII, and the difference is a login that never works.
        assert_ne!(nt_password_hash("é")[..], nt_password_hash("e")[..]);
        assert_eq!(nt_password_hash("é")[..], Md4::digest([0xe9, 0x00])[..]);
    }
}
