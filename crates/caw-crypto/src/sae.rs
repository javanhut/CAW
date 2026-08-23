//! WPA3-Personal: SAE, the Dragonfly exchange of IEEE 802.11-2020 12.4.
//!
//! # What it buys over WPA2-PSK
//!
//! A WPA2 PMK is a deterministic function of the passphrase, so a captured
//! 4-way handshake can be attacked offline for as long as the attacker likes.
//! SAE replaces that with a balanced PAKE: both ends prove they know the
//! password without either putting anything password-derived on the air that
//! can be tested offline. Each exchange also produces a fresh PMK, so
//! recording traffic today and learning the password tomorrow does not decrypt
//! it.
//!
//! # Hash-to-Element, and why hunting-and-pecking is absent
//!
//! Dragonfly needs to turn the password into a curve point (the PWE). The
//! original method — "hunting and pecking" — loops, hashing a counter until it
//! lands on a valid x-coordinate. The number of iterations depends on the
//! password, and the loop's timing and cache footprint leak it. That is the
//! Dragonblood family of attacks (CVE-2019-9494 and relatives), which turned
//! SAE back into an offline-dictionary problem.
//!
//! Hash-to-Element (802.11-2020 12.4.4.3.3, the SSWU map of RFC 9380) has no
//! loop: it is a fixed sequence of field operations, so its cost is the same
//! for every password. caw implements H2E only. An access point that offers
//! only hunting-and-pecking is refused rather than joined by a method known to
//! leak the password — WPA3 has mandated H2E for new deployments since WPA3
//! Specification v3.0.
//!
//! # Frames
//!
//! [`Step::Send`] carries an 802.11 authentication frame *body*: the
//! Authentication Algorithm Number, the transaction sequence number, the
//! status code, and then the SAE fields. A caller feeding
//! `NL80211_ATTR_AUTH_DATA` skips the first two octets, which is where that
//! attribute is defined to begin; a caller writing a full management frame
//! prepends the 802.11 header.
//!
//! # Group 19 only
//!
//! NIST P-256 is the only group WPA3-Personal requires, and the only one every
//! shipping access point supports. Groups 20 and 21 (P-384, P-521) are a
//! parameter change away; the finite-field groups are deprecated precisely
//! because Dragonblood hit them hardest.
//!
//! # Sans-IO
//!
//! Nothing here reads a clock or a socket. Randomness — the one thing a PAKE
//! cannot derive from its inputs — enters through [`SaeProvider::with_seed`];
//! [`SaeProvider::new`] is the thin shell that fills a seed from `getrandom`.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::array::Array;
use p256::elliptic_curve::bigint::{ArrayEncoding, NonZero, U256};
use p256::elliptic_curve::consts::U48;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::{Curve, Group, PrimeField};
use p256::hash2curve::MapToCurve;
use p256::{AffinePoint, FieldBytes, NistP256, ProjectivePoint, Scalar};
use sha2::Sha256;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::{AuthContext, AuthStage, Error, Pmk, PmkProvider, Step, kdf_sha256};

/// Authentication Algorithm Number for SAE (802.11-2020 9.4.1.1).
const AUTH_ALG_SAE: u16 = 3;
// Transaction sequence numbers: SAE is two exchanges, commit then confirm.
const SEQ_COMMIT: u16 = 1;
const SEQ_CONFIRM: u16 = 2;

// Status codes. SAE gives two of them a meaning they have nowhere else.
const STATUS_SUCCESS: u16 = 0;
/// The AP is under load and wants the commit echoed with its token before it
/// will spend a scalar multiplication on us.
const STATUS_ANTI_CLOGGING: u16 = 76;
/// "I derived the PWE with hash-to-element." Carried in a *commit*, where a
/// status code otherwise has nothing to report, which is how H2E is negotiated
/// without a new field.
const STATUS_H2E: u16 = 126;

/// Finite Cyclic Group 19: NIST P-256.
const GROUP_P256: u16 = 19;

/// Element ID 255: the element carries its real ID in the next octet.
const EID_EXTENSION: u8 = 255;
/// Element ID Extension 93: Anti-Clogging Token Container.
const EID_EXT_ANTI_CLOGGING: u8 = 93;

/// olen(r) — a scalar on the wire, big-endian, zero-padded to the order.
const SCALAR_LEN: usize = 32;
/// Two olen(p) coordinates, x then y. No SEC1 tag octet: 802.11 fixed the
/// length instead.
const ELEMENT_LEN: usize = 64;
/// SHA-256 is the hash for every group whose prime is 256 bits or less
/// (802.11-2020 12.4.2), so the confirm and the KCK are both 32 bytes.
const HASH_LEN: usize = 32;

/// len = olen(p) + ceil(olen(p)/2), the wide value H2E reduces modulo p. The
/// extra half-length is what makes the reduction's bias negligible instead of
/// something an attacker could distinguish.
const PWD_VALUE_LEN: usize = 48;

/// Seed length: two secret scalars, each drawn by wide reduction.
pub const SEED_LEN: usize = 2 * PWD_VALUE_LEN;

/// dot11RSNASAESync: how many times a frame is retransmitted before the
/// exchange is abandoned.
const SYNC_MAX: u8 = 5;

/// The field element type the SSWU map consumes. p256 does not name it in its
/// public API, so it is reached through the trait.
type FieldElement = <NistP256 as MapToCurve>::FieldElement;

/// WPA3-Personal. Runs before association, over authentication frames.
///
/// One instance is one exchange with one AP. A retry against the same AP needs
/// a new instance: reusing `rand` across exchanges would defeat the point of
/// deriving a fresh PMK each time.
pub struct SaeProvider {
    password: Zeroizing<String>,
    seed: Zeroizing<[u8; SEED_LEN]>,
    state: State,
    /// The bytes of the last frame handed to the caller, kept so a timeout can
    /// retransmit them unchanged. SAE forbids re-deriving the commit on a
    /// retry — a second scalar over the same PWE hands an observer two
    /// equations in the same secrets.
    last_sent: Vec<u8>,
    sync: u8,
    send_confirm: u16,
    /// Echoed back in the commit when the AP demands one.
    token: Option<Vec<u8>>,
    /// Kept on the provider rather than in [`State`] because the caller needs
    /// it after the exchange has finished, to name the PMK in the RSN IE of
    /// the association request.
    pmkid: Option<[u8; 16]>,
}

/// Where the exchange has got to. Each variant carries exactly the material
/// that exists at that point, so there is no state in which a field is present
/// but meaningless.
enum State {
    /// Before [`PmkProvider::start`].
    Idle,
    /// Our commit is out; waiting for the peer's.
    Committed(Box<Commit>),
    /// Both commits are in and our confirm is out; waiting for the peer's.
    Confirmed(Box<Session>),
    /// The peer's confirm verified. The PMK has been handed over.
    Accepted,
    /// An error ended the exchange. There is no resuming it: SAE's security
    /// rests on one `rand` per exchange, so a retry is a new instance.
    Failed,
}

/// Our half of the commit exchange.
struct Commit {
    /// The private scalar. `commit-scalar` is `rand + mask`, and the element
    /// is `-mask * PWE`, so a peer who sees both learns the sum and the
    /// product but neither term: that split is what keeps the exchange from
    /// being a plain Diffie-Hellman over a password-derived generator.
    ///
    /// p256's `Scalar` implements no `Zeroize`, so this cannot be wiped on
    /// drop the way the byte-array secrets in this crate are.
    rand: Scalar,
    scalar: Scalar,
    pwe: ProjectivePoint,
    scalar_bytes: [u8; SCALAR_LEN],
    element_bytes: [u8; ELEMENT_LEN],
}

/// Everything derived once the peer's commit has been checked.
struct Session {
    peer_scalar_bytes: [u8; SCALAR_LEN],
    peer_element_bytes: [u8; ELEMENT_LEN],
    own_scalar_bytes: [u8; SCALAR_LEN],
    own_element_bytes: [u8; ELEMENT_LEN],
    kck: Zeroizing<[u8; HASH_LEN]>,
    pmk: [u8; 32],
}

impl SaeProvider {
    /// Build a provider whose secret scalars come from `seed`.
    ///
    /// The state machine takes its randomness as an input rather than reaching
    /// for the OS itself, which is what keeps it sans-IO and lets a test drive
    /// two instances against each other reproducibly. Production callers want
    /// [`SaeProvider::new`].
    ///
    /// `seed` must be uniform random and must never be reused.
    pub fn with_seed(password: impl Into<String>, seed: &[u8; SEED_LEN]) -> Self {
        Self {
            password: Zeroizing::new(password.into()),
            seed: Zeroizing::new(*seed),
            state: State::Idle,
            last_sent: Vec::new(),
            sync: 0,
            send_confirm: 0,
            token: None,
            pmkid: None,
        }
    }

    /// Build a provider seeded from `getrandom`.
    ///
    /// The `expect` is sound rather than optimistic: on Linux, `getrandom`
    /// with no flags blocks until the pool is initialised and never returns
    /// short for a buffer this small, leaving only `EFAULT` and `EINVAL` —
    /// impossible for a stack buffer and zero flags.
    #[cfg(target_os = "linux")]
    pub fn new(password: impl Into<String>) -> Self {
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        let mut filled = 0;
        while filled < SEED_LEN {
            filled +=
                rustix::rand::getrandom(&mut seed[filled..], rustix::rand::GetRandomFlags::empty())
                    .expect("getrandom fails only on a bad buffer or bad flags");
        }
        Self::with_seed(password, &seed)
    }

    /// The PMKID for the derived PMK, once the commit exchange has completed.
    ///
    /// The 4-way handshake needs it to name this PMK in the RSN IE of the
    /// association request, so it is exposed separately from [`Step::Done`].
    pub fn pmkid(&self) -> Option<[u8; 16]> {
        self.pmkid
    }

    /// Build (or rebuild, after an anti-clogging token) the commit frame.
    fn commit_frame(&self, commit: &Commit) -> Vec<u8> {
        let mut frame = auth_header(SEQ_COMMIT, STATUS_H2E);
        frame.extend_from_slice(&GROUP_P256.to_le_bytes());
        frame.extend_from_slice(&commit.scalar_bytes);
        frame.extend_from_slice(&commit.element_bytes);
        if let Some(token) = &self.token {
            // With H2E the token travels in an element after the fixed fields,
            // not as a bare field, because H2E added a Rejected Groups element
            // there and a bare token would be ambiguous with it.
            frame.push(EID_EXTENSION);
            frame
                .push(u8::try_from(token.len() + 1).expect("a parsed token is at most 254 octets"));
            frame.push(EID_EXT_ANTI_CLOGGING);
            frame.extend_from_slice(token);
        }
        frame
    }

    /// The peer's commit: validate it, derive the shared secret, and answer
    /// with our confirm.
    fn on_commit(&mut self, commit: Commit, body: &[u8]) -> Result<Step, Error> {
        let (peer_scalar_bytes, peer_element_bytes) = parse_commit(body)?;

        // Both operands have already crossed the air, so an ordinary compare
        // leaks nothing here.
        //
        // A peer that echoes our own commit back at us knows no password: it
        // is either an attacker hoping we will confirm against ourselves, or
        // our own frame looped back. 802.11 has the mesh case discard this
        // silently; a station talking to an AP has nothing to wait for, so it
        // fails.
        if peer_scalar_bytes == commit.scalar_bytes && peer_element_bytes == commit.element_bytes {
            return Err(Error::AuthFailed);
        }

        let peer_scalar = decode_scalar(&peer_scalar_bytes)?;
        let peer_element = decode_element(&peer_element_bytes)?;

        // K = rand * (peer-scalar * PWE + PEER-ELEMENT). The peer's element
        // cancels the mask it hid its own `rand` behind, leaving a point only
        // someone who knows the password can reach.
        let k_point = (commit.pwe * peer_scalar + peer_element) * commit.rand;
        // The identity means the peer chose its element to cancel the rest of
        // the expression — a small-subgroup-style attempt that would fix K to
        // a value it knows.
        if bool::from(k_point.is_identity()) {
            return Err(Error::AuthFailed);
        }
        let k = Zeroizing::new(x_coordinate(&k_point));

        let keyseed = Zeroizing::new(hmac_sha256(&[0u8; HASH_LEN], &[&k[..]]));

        // context = (commit-scalar + peer-commit-scalar) mod r, big-endian and
        // padded to the order. Scalar addition already reduces.
        let context = (commit.scalar + peer_scalar).to_bytes();

        let mut keys = Zeroizing::new([0u8; HASH_LEN + 32]);
        kdf_sha256(&keyseed[..], "SAE KCK and PMK", &context, &mut keys[..]);

        let mut kck = Zeroizing::new([0u8; HASH_LEN]);
        kck.copy_from_slice(&keys[..HASH_LEN]);
        let mut pmk = [0u8; 32];
        pmk.copy_from_slice(&keys[HASH_LEN..]);
        // PMKID = L(context, 0, 128): the leading 128 bits of the same value
        // the keys are derived over.
        let mut pmkid = [0u8; 16];
        pmkid.copy_from_slice(&context[..16]);
        self.pmkid = Some(pmkid);

        let session = Session {
            peer_scalar_bytes,
            peer_element_bytes,
            own_scalar_bytes: commit.scalar_bytes,
            own_element_bytes: commit.element_bytes,
            kck,
            pmk,
        };

        let frame = self.confirm_frame(&session);
        self.state = State::Confirmed(Box::new(session));
        self.last_sent = frame.clone();
        self.sync = 0;
        Ok(Step::Send(frame))
    }

    /// Our confirm, over both commits in our-first order.
    fn confirm_frame(&mut self, session: &Session) -> Vec<u8> {
        // The counter starts at one and rises with every confirm we send, so a
        // replayed confirm cannot be mistaken for a fresh one.
        self.send_confirm = self.send_confirm.saturating_add(1);
        let sc = self.send_confirm.to_le_bytes();
        let confirm = confirm_hash(
            &session.kck,
            &sc,
            &session.own_scalar_bytes,
            &session.own_element_bytes,
            &session.peer_scalar_bytes,
            &session.peer_element_bytes,
        );

        let mut frame = auth_header(SEQ_CONFIRM, STATUS_SUCCESS);
        frame.extend_from_slice(&sc);
        frame.extend_from_slice(&confirm);
        frame
    }

    /// The peer's confirm: the only proof that it knows the password.
    fn on_confirm(&mut self, session: Session, body: &[u8]) -> Result<Step, Error> {
        if body.len() < 2 + HASH_LEN {
            return Err(Error::Malformed);
        }
        let peer_sc = &body[..2];
        let verifier = confirm_hash(
            &session.kck,
            peer_sc,
            &session.peer_scalar_bytes,
            &session.peer_element_bytes,
            &session.own_scalar_bytes,
            &session.own_element_bytes,
        );

        // Constant-time, because a comparison that stops at the first wrong
        // byte tells an attacker how much of a guessed confirm was right, and
        // a confirm can then be built a byte at a time.
        if !bool::from(verifier.ct_eq(&body[2..2 + HASH_LEN])) {
            return Err(Error::AuthFailed);
        }

        let pmk = Pmk(session.pmk);
        self.state = State::Accepted;
        self.last_sent.clear();
        Ok(Step::Done(pmk))
    }

    /// An AP under load answers the first commit with a token instead of a
    /// commit. Echoing it proves we are at a real address before the AP spends
    /// a scalar multiplication on us.
    fn on_token_request(&mut self, commit: Commit, body: &[u8]) -> Result<Step, Error> {
        let token = parse_token(body)?;
        // Same scalar, same element: only the token is new. A fresh commit
        // here would leak a second equation in `rand` and `mask`.
        self.token = Some(token);
        let frame = self.commit_frame(&commit);
        self.state = State::Committed(Box::new(commit));
        self.last_sent = frame.clone();
        self.sync = 0;
        Ok(Step::Send(frame))
    }
}

impl PmkProvider for SaeProvider {
    fn stage(&self) -> AuthStage {
        AuthStage::PreAssoc
    }

    fn start(&mut self, ctx: &AuthContext<'_>) -> Result<Step, Error> {
        if !matches!(self.state, State::Idle) {
            return Err(Error::Protocol);
        }
        // FT-SAE authenticates identically but feeds PMK-R0 rather than the
        // PMK to a different key hierarchy, which this crate does not derive.
        if ctx.akm != caw_80211::Akm::Sae {
            return Err(Error::UnsupportedAkm);
        }

        let pt = password_token(ctx.ssid, &self.password);
        let pwe = password_element(&pt, ctx.own_mac, ctx.bssid);

        let (rand, mask) = commit_scalars(&self.seed);
        // The seed is the private key of this exchange in another form, and
        // nothing needs it again: a retry is a new instance with a new seed.
        self.seed.zeroize();
        let scalar = rand + mask;
        // COMMIT-ELEMENT = inverse(mask * PWE): the mask is sent hidden in a
        // point so that only the sum of the two secrets is public.
        let element = -(pwe * mask);

        let commit = Commit {
            rand,
            scalar,
            pwe,
            scalar_bytes: scalar.to_bytes().into(),
            element_bytes: encode_element(&element),
        };

        let frame = self.commit_frame(&commit);
        self.state = State::Committed(Box::new(commit));
        self.last_sent = frame.clone();
        self.sync = 0;
        Ok(Step::Send(frame))
    }

    fn on_frame(&mut self, _ctx: &AuthContext<'_>, frame: &[u8]) -> Result<Step, Error> {
        let auth = parse_auth(frame)?;

        // Anything but success, the H2E marker or a token request is the AP
        // refusing us: an unsupported group, an unknown password identifier,
        // or a plain rejection. None is retryable with what we hold.
        match (auth.seq, auth.status) {
            (SEQ_COMMIT, STATUS_H2E | STATUS_ANTI_CLOGGING) => {}
            // An AP that answers an H2E commit with status 0 derived its PWE
            // by hunting and pecking. Its PWE is not ours, so continuing would
            // fail at the confirm anyway — but it is refused explicitly,
            // because the failure means "this AP is too old for a safe SAE"
            // and not "wrong password".
            (SEQ_COMMIT, STATUS_SUCCESS) => return Err(Error::AuthFailed),
            (SEQ_CONFIRM, STATUS_SUCCESS) => {}
            _ => return Err(Error::AuthFailed),
        }

        // Take the state so its payload can be moved into the next one. Every
        // path below either transitions or puts back what it took; an error
        // leaves `Failed` behind, which is what an abandoned exchange is.
        match (std::mem::replace(&mut self.state, State::Failed), auth.seq) {
            (State::Committed(commit), SEQ_COMMIT) => {
                if auth.status == STATUS_ANTI_CLOGGING {
                    self.on_token_request(*commit, auth.body)
                } else {
                    self.on_commit(*commit, auth.body)
                }
            }
            (State::Confirmed(session), SEQ_CONFIRM) => self.on_confirm(*session, auth.body),

            // A confirm before we have a commit, or a second commit once we
            // have confirmed, is dropped rather than treated as an error: on
            // an open medium anyone can inject one, and turning an injected
            // frame into a failure would hand an attacker a way to break every
            // association attempt.
            (state @ State::Committed(_), _) | (state @ State::Confirmed(_), _) => {
                self.state = state;
                Ok(Step::Wait)
            }
            (State::Accepted, _) => {
                self.state = State::Accepted;
                Ok(Step::Wait)
            }
            // A caller bug rather than a peer's, so the exchange is left as
            // it was: it has not started yet.
            (State::Idle, _) => {
                self.state = State::Idle;
                Err(Error::Protocol)
            }
            (State::Failed, _) => Err(Error::AuthFailed),
        }
    }

    fn on_timeout(&mut self, _ctx: &AuthContext<'_>) -> Result<Step, Error> {
        match self.state {
            State::Committed(_) | State::Confirmed(_) => {
                self.sync += 1;
                if self.sync > SYNC_MAX {
                    return Err(Error::AuthFailed);
                }
                // Byte-identical to the first transmission: see `last_sent`.
                Ok(Step::Send(self.last_sent.clone()))
            }
            State::Accepted => Ok(Step::Wait),
            State::Failed => Err(Error::AuthFailed),
            State::Idle => Err(Error::Protocol),
        }
    }
}

/// PT — the password token of 802.11-2020 12.4.4.3.3.
///
/// It depends only on the SSID and the password, not on either MAC address,
/// which is what lets an implementation compute it once per profile instead of
/// once per association. caw does not cache it yet.
fn password_token(ssid: &[u8], password: &str) -> ProjectivePoint {
    // pwd-seed = HKDF-Extract(ssid, password). The SSID is the salt, so the
    // same password on two networks gives two unrelated points.
    let hk = Hkdf::<Sha256>::new(Some(ssid), password.as_bytes());
    // One SSWU output is not uniform over the group — its image is roughly
    // half the curve — so RFC 9380's random-oracle construction sums two
    // independent maps, and 802.11 inherits that.
    map_to_point(&hk, "SAE Hash to Element u1 P1") + map_to_point(&hk, "SAE Hash to Element u2 P2")
}

/// One `u = pwd-value mod p; P = SSWU(u)` step.
fn map_to_point(hk: &Hkdf<Sha256>, label: &str) -> ProjectivePoint {
    let mut pwd_value = Zeroizing::new([0u8; PWD_VALUE_LEN]);
    hk.expand(label.as_bytes(), &mut pwd_value[..])
        .expect("48 octets is well under HKDF's 255-block ceiling");
    let wide = Array::<u8, U48>::try_from(&pwd_value[..]).expect("PWD_VALUE_LEN is 48");
    let u = <FieldElement as Reduce<Array<u8, U48>>>::reduce(&wide);
    <NistP256 as MapToCurve>::map_to_curve(u)
}

/// PWE = scalar-op(val, PT), where val binds the point to this pair of MAC
/// addresses.
///
/// Without that binding, PT would be the same point for every station on the
/// network, and one station's exchange would replay against another's.
fn password_element(pt: &ProjectivePoint, own: [u8; 6], peer: [u8; 6]) -> ProjectivePoint {
    // MAX then MIN, so both ends compute the same value without agreeing who
    // is who. The comparison is the bytewise one, as in 802.11-2020 12.4.4.3.3.
    let (hi, lo) = if own > peer { (own, peer) } else { (peer, own) };
    let val = hmac_sha256(&[0u8; HASH_LEN], &[&hi, &lo]);

    // val = val mod (r - 1) + 1, landing in [1, r-1] so the multiplication
    // cannot annihilate PT. r-1 is not the scalar modulus, so this is integer
    // arithmetic, not field arithmetic. The MAC addresses are public, so a
    // variable-time reduction leaks nothing.
    let order = NistP256::ORDER.get();
    let modulus =
        NonZero::new(order.wrapping_sub(&U256::ONE)).expect("the group order exceeds one");
    let reduced = U256::from_be_byte_array(val.into()).rem_vartime(&modulus);
    let val = Option::<Scalar>::from(Scalar::from_repr(
        reduced.wrapping_add(&U256::ONE).to_be_byte_array(),
    ))
    .expect("a value in [1, r-1] is a scalar");

    *pt * val
}

/// `rand` and `mask`, the two secrets behind one commit.
///
/// Each is a wide reduction of 48 seed octets rather than a rejection-sampling
/// loop: the loop would run a password-independent but *seed*-dependent number
/// of times, and constant time is cheap enough here that there is no reason to
/// argue about whether that matters.
fn commit_scalars(seed: &[u8; SEED_LEN]) -> (Scalar, Scalar) {
    let scalar_from = |bytes: &[u8]| {
        let wide = Array::<u8, U48>::try_from(bytes).expect("half a seed is 48 octets");
        let s = <Scalar as Reduce<Array<u8, U48>>>::reduce(&wide);
        // 802.11-2020 12.4.5.2 wants 1 < rand, mask < r. A wide reduction
        // lands on 0 or 1 with probability about 2^-254, so this is defence in
        // depth — but it is a constant-time select, because a branch on the
        // value of a secret scalar is the shape of leak Dragonblood taught us
        // to avoid.
        let degenerate = s.ct_eq(&Scalar::ZERO) | s.ct_eq(&Scalar::ONE);
        Scalar::conditional_select(&s, &Scalar::from(2u64), degenerate)
    };
    (
        scalar_from(&seed[..PWD_VALUE_LEN]),
        scalar_from(&seed[PWD_VALUE_LEN..]),
    )
}

/// CN(key, X, Y, Z, ...) = HMAC-SHA256(key, D2OS(X) || D2OS(Y) || ...).
///
/// The two ends hash the same five values in opposite orders, so a confirm
/// cannot be reflected back as a valid verifier.
fn confirm_hash(
    kck: &[u8; HASH_LEN],
    send_confirm: &[u8],
    scalar1: &[u8; SCALAR_LEN],
    element1: &[u8; ELEMENT_LEN],
    scalar2: &[u8; SCALAR_LEN],
    element2: &[u8; ELEMENT_LEN],
) -> [u8; HASH_LEN] {
    hmac_sha256(kck, &[send_confirm, scalar1, element1, scalar2, element2])
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    for part in parts {
        mac.update(part);
    }
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// x || y, big-endian, with no SEC1 tag octet — the 802.11 element encoding.
fn encode_element(point: &ProjectivePoint) -> [u8; ELEMENT_LEN] {
    let encoded = point.to_affine().to_sec1_point(false);
    let mut out = [0u8; ELEMENT_LEN];
    // Only the identity encodes without coordinates, and no element in this
    // exchange is the identity: ours is a mask times a generator-like point,
    // and the peer's is rejected on arrival if it is.
    out[..32].copy_from_slice(encoded.x().expect("an element is never the identity"));
    out[32..].copy_from_slice(encoded.y().expect("an uncompressed point carries y"));
    out
}

/// Decode a peer element and apply the three checks of 802.11-2020 12.4.5.4.
///
/// Coordinates below the prime and the curve equation are both checked by the
/// SEC1 decoder; the identity is checked here. P-256 has cofactor one, so
/// membership of the prime-order group needs nothing further — on a curve with
/// a cofactor this would also need a subgroup check.
fn decode_element(bytes: &[u8; ELEMENT_LEN]) -> Result<ProjectivePoint, Error> {
    let mut sec1 = [0u8; 1 + ELEMENT_LEN];
    sec1[0] = 0x04; // uncompressed
    sec1[1..].copy_from_slice(bytes);
    let affine = AffinePoint::from_sec1_bytes(&sec1).map_err(|_| Error::AuthFailed)?;
    let point = ProjectivePoint::from(affine);
    if bool::from(point.is_identity()) {
        return Err(Error::AuthFailed);
    }
    Ok(point)
}

/// Decode a peer scalar, which must satisfy 1 < scalar < r.
///
/// Zero and one are excluded because either would let the peer choose K
/// without knowing the password.
fn decode_scalar(bytes: &[u8; SCALAR_LEN]) -> Result<Scalar, Error> {
    let repr = FieldBytes::from(*bytes);
    let scalar = Option::<Scalar>::from(Scalar::from_repr(repr)).ok_or(Error::AuthFailed)?;
    if bool::from(scalar.ct_eq(&Scalar::ZERO) | scalar.ct_eq(&Scalar::ONE)) {
        return Err(Error::AuthFailed);
    }
    Ok(scalar)
}

/// x-coordinate of K, which is the shared secret proper.
fn x_coordinate(point: &ProjectivePoint) -> [u8; 32] {
    let encoded = point.to_affine().to_sec1_point(false);
    let mut out = [0u8; 32];
    out.copy_from_slice(
        encoded
            .x()
            .expect("K is checked against the identity first"),
    );
    out
}

/// The fixed fields every authentication frame body starts with.
fn auth_header(seq: u16, status: u16) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6 + 2 + SCALAR_LEN + ELEMENT_LEN);
    frame.extend_from_slice(&AUTH_ALG_SAE.to_le_bytes());
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&status.to_le_bytes());
    frame
}

struct AuthFrame<'a> {
    seq: u16,
    status: u16,
    /// Everything after the fixed authentication fields.
    body: &'a [u8],
}

fn parse_auth(frame: &[u8]) -> Result<AuthFrame<'_>, Error> {
    if frame.len() < 6 {
        return Err(Error::Malformed);
    }
    if le16(&frame[0..2]) != AUTH_ALG_SAE {
        return Err(Error::Malformed);
    }
    Ok(AuthFrame {
        seq: le16(&frame[2..4]),
        status: le16(&frame[4..6]),
        body: &frame[6..],
    })
}

/// Group, scalar and element out of a commit body.
///
/// Trailing elements — a password identifier, rejected groups, a token
/// container — are ignored: caw offers one group and no identifier, so nothing
/// it can say there changes the outcome.
fn parse_commit(body: &[u8]) -> Result<([u8; SCALAR_LEN], [u8; ELEMENT_LEN]), Error> {
    const FIXED: usize = 2 + SCALAR_LEN + ELEMENT_LEN;
    if body.len() < FIXED {
        return Err(Error::Malformed);
    }
    // A different group means the AP ignored what we offered; its scalar and
    // element would be the wrong size to interpret.
    if le16(&body[0..2]) != GROUP_P256 {
        return Err(Error::AuthFailed);
    }
    let scalar = body[2..2 + SCALAR_LEN].try_into().expect("32 of 98 octets");
    let element = body[2 + SCALAR_LEN..FIXED]
        .try_into()
        .expect("64 of 98 octets");
    Ok((scalar, element))
}

/// The token out of a token request: group, then an Anti-Clogging Token
/// Container element.
fn parse_token(body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() < 2 + 3 {
        return Err(Error::Malformed);
    }
    let element = &body[2..];
    let len = element[1] as usize;
    if element[0] != EID_EXTENSION || len == 0 || len > element.len() - 2 {
        return Err(Error::Malformed);
    }
    if element[2] != EID_EXT_ANTI_CLOGGING {
        return Err(Error::Malformed);
    }
    Ok(element[3..2 + len].to_vec())
}

fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    const SSID: &[u8] = b"caw-test";
    const STA: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const AP: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

    /// The order r of P-256, which a peer scalar must stay below.
    const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    fn ctx(own: [u8; 6], peer: [u8; 6]) -> AuthContext<'static> {
        AuthContext {
            ssid: SSID,
            bssid: peer,
            own_mac: own,
            akm: caw_80211::Akm::Sae,
        }
    }

    /// Distinct halves, so `rand` and `mask` are not the same scalar.
    fn seed(tag: u8) -> [u8; SEED_LEN] {
        let mut seed = [0u8; SEED_LEN];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(tag);
        }
        seed
    }

    fn sent(step: Step) -> Vec<u8> {
        match step {
            Step::Send(frame) => frame,
            _ => panic!("expected a frame to send"),
        }
    }

    fn pmk(step: Step) -> [u8; 32] {
        match step {
            Step::Done(pmk) => pmk.0,
            _ => panic!("expected a PMK"),
        }
    }

    /// SSWU applied to a published `u`, which is already reduced modulo p and
    /// so survives the wide reduction unchanged.
    fn sswu(u: &str) -> ProjectivePoint {
        let mut wide = [0u8; PWD_VALUE_LEN];
        wide[PWD_VALUE_LEN - 32..].copy_from_slice(&hex(u));
        let wide = Array::<u8, U48>::try_from(&wide[..]).unwrap();
        <NistP256 as MapToCurve>::map_to_curve(<FieldElement as Reduce<Array<u8, U48>>>::reduce(
            &wide,
        ))
    }

    /// RFC 9380 Appendix J.1.1, `P256_XMD:SHA-256_SSWU_RO_`.
    ///
    /// H2E is exactly this map — 802.11-2020 12.4.4.3.3 feeds it HKDF output
    /// instead of `expand_message_xmd`, but `SSWU(u)` and the addition of the
    /// two points are shared, and they are the part that has to be right.
    #[test]
    fn rfc9380_sswu_vectors() {
        let cases = [
            (
                "ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009",
                "8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a",
                "ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5",
                "dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1",
                "51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5",
                "b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac",
                "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
                "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
            ),
            (
                "afe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1",
                "379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0",
                "5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c58cb48",
                "7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301b191d93ecf",
                "019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee3875f",
                "589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee4252715446e",
                "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
                "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
            ),
            (
                "0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c",
                "b68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb",
                "a17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2",
                "4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3c9c2e",
                "7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66",
                "b765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f96e6f9",
                "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
                "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
            ),
        ];

        for (u0, u1, q0x, q0y, q1x, q1y, px, py) in cases {
            let q0 = sswu(u0);
            let q1 = sswu(u1);
            assert_eq!(encode_element(&q0)[..], [hex(q0x), hex(q0y)].concat()[..]);
            assert_eq!(encode_element(&q1)[..], [hex(q1x), hex(q1y)].concat()[..]);
            // P-256 has cofactor one, so clear_cofactor is the identity and
            // the published P is just the sum.
            assert_eq!(
                encode_element(&(q0 + q1))[..],
                [hex(px), hex(py)].concat()[..]
            );
        }
    }

    /// Two instances of the exchange, run against each other. Both must reach
    /// the same PMK and the same PMKID from the same password.
    #[test]
    fn both_ends_derive_the_same_pmk() {
        let (ctx_a, ctx_b) = (ctx(STA, AP), ctx(AP, STA));
        let mut a = SaeProvider::with_seed("correct horse", &seed(1));
        let mut b = SaeProvider::with_seed("correct horse", &seed(2));

        let commit_a = sent(a.start(&ctx_a).unwrap());
        let commit_b = sent(b.start(&ctx_b).unwrap());
        let confirm_a = sent(a.on_frame(&ctx_a, &commit_b).unwrap());
        let confirm_b = sent(b.on_frame(&ctx_b, &commit_a).unwrap());

        let pmk_a = pmk(a.on_frame(&ctx_a, &confirm_b).unwrap());
        let pmk_b = pmk(b.on_frame(&ctx_b, &confirm_a).unwrap());

        assert_eq!(pmk_a, pmk_b);
        assert_eq!(a.pmkid(), b.pmkid());
        assert!(a.pmkid().is_some());
        // Two different seeds must not produce the same secret twice.
        assert_ne!(commit_a, commit_b);
    }

    /// The whole point: a different password is caught, and it is caught at
    /// the confirm rather than by anything either side can test offline.
    #[test]
    fn a_different_password_fails_at_the_confirm() {
        let (ctx_a, ctx_b) = (ctx(STA, AP), ctx(AP, STA));
        let mut a = SaeProvider::with_seed("correct horse", &seed(1));
        let mut b = SaeProvider::with_seed("battery staple", &seed(2));

        let commit_a = sent(a.start(&ctx_a).unwrap());
        let commit_b = sent(b.start(&ctx_b).unwrap());
        // The commits themselves are still well formed: nothing in them can be
        // checked against the password.
        let confirm_a = sent(a.on_frame(&ctx_a, &commit_b).unwrap());
        let confirm_b = sent(b.on_frame(&ctx_b, &commit_a).unwrap());

        assert!(matches!(
            a.on_frame(&ctx_a, &confirm_b),
            Err(Error::AuthFailed)
        ));
        assert!(matches!(
            b.on_frame(&ctx_b, &confirm_a),
            Err(Error::AuthFailed)
        ));
    }

    /// The PMK must depend on every input that names the network or the pair
    /// of stations, or a captured exchange would replay somewhere else.
    #[test]
    fn the_pmk_is_bound_to_ssid_and_addresses() {
        let run = |ssid: &'static [u8], sta: [u8; 6], ap: [u8; 6]| {
            let ctx_a = AuthContext {
                ssid,
                bssid: ap,
                own_mac: sta,
                akm: caw_80211::Akm::Sae,
            };
            let ctx_b = AuthContext {
                ssid,
                bssid: sta,
                own_mac: ap,
                akm: caw_80211::Akm::Sae,
            };
            let mut a = SaeProvider::with_seed("pw", &seed(1));
            let mut b = SaeProvider::with_seed("pw", &seed(2));
            let commit_a = sent(a.start(&ctx_a).unwrap());
            let commit_b = sent(b.start(&ctx_b).unwrap());
            let confirm_b = sent(b.on_frame(&ctx_b, &commit_a).unwrap());
            let _ = a.on_frame(&ctx_a, &commit_b).unwrap();
            pmk(a.on_frame(&ctx_a, &confirm_b).unwrap())
        };

        let base = run(SSID, STA, AP);
        assert_ne!(base, run(b"other-ssid", STA, AP));
        assert_ne!(base, run(SSID, STA, [0x02, 0, 0, 0, 0, 0x03]));
    }

    fn commit_frame(scalar: &[u8], element: &[u8]) -> Vec<u8> {
        let mut frame = auth_header(SEQ_COMMIT, STATUS_H2E);
        frame.extend_from_slice(&GROUP_P256.to_le_bytes());
        frame.extend_from_slice(scalar);
        frame.extend_from_slice(element);
        frame
    }

    /// A committed provider, and a valid element to build peer commits from.
    fn committed() -> (SaeProvider, AuthContext<'static>, Vec<u8>) {
        let ctx_a = ctx(STA, AP);
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        a.start(&ctx_a).unwrap();

        let mut b = SaeProvider::with_seed("pw", &seed(2));
        let commit_b = sent(b.start(&ctx(AP, STA)).unwrap());
        let element = commit_b[8 + SCALAR_LEN..8 + SCALAR_LEN + ELEMENT_LEN].to_vec();
        (a, ctx_a, element)
    }

    /// 802.11-2020 12.4.5.4: a scalar outside (1, r) and an element that is
    /// not a point on the curve are both rejected before anything is derived
    /// from them.
    #[test]
    fn rejects_invalid_peer_commits() {
        let (_, _, good_element) = committed();

        let zero = [0u8; SCALAR_LEN];
        let mut one = [0u8; SCALAR_LEN];
        one[31] = 1;
        let order = hex(ORDER);

        // Scalar 0, scalar 1, and scalar r itself.
        for scalar in [&zero[..], &one[..], &order[..]] {
            let (mut a, ctx_a, _) = committed();
            assert!(matches!(
                a.on_frame(&ctx_a, &commit_frame(scalar, &good_element)),
                Err(Error::AuthFailed)
            ));
        }

        let good_scalar = [0x11u8; SCALAR_LEN];

        // A point not on the curve: flip a bit in x and the equation no longer
        // holds for the y that came with it.
        let mut off_curve = good_element.clone();
        off_curve[0] ^= 1;
        let (mut a, ctx_a, _) = committed();
        assert!(matches!(
            a.on_frame(&ctx_a, &commit_frame(&good_scalar, &off_curve)),
            Err(Error::AuthFailed)
        ));

        // The identity, which has no affine encoding: (0, 0) is not on the
        // curve, so it is refused by the same check.
        let (mut a, ctx_a, _) = committed();
        assert!(matches!(
            a.on_frame(&ctx_a, &commit_frame(&good_scalar, &[0u8; ELEMENT_LEN])),
            Err(Error::AuthFailed)
        ));

        // Coordinates at or above the prime are not field elements.
        let (mut a, ctx_a, _) = committed();
        assert!(matches!(
            a.on_frame(&ctx_a, &commit_frame(&good_scalar, &[0xffu8; ELEMENT_LEN])),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn rejects_truncated_and_foreign_frames() {
        let element = committed().2;

        // Shorter than the fixed authentication fields.
        let (mut a, ctx_a, _) = committed();
        assert!(matches!(
            a.on_frame(&ctx_a, &[3, 0, 1, 0]),
            Err(Error::Malformed)
        ));
        // A different authentication algorithm entirely.
        let (mut a, ctx_a, _) = committed();
        let mut open = commit_frame(&[0x11; SCALAR_LEN], &element);
        open[0] = 0;
        assert!(matches!(a.on_frame(&ctx_a, &open), Err(Error::Malformed)));
        // The right frame, one octet short of a full element.
        let (mut a, ctx_a, _) = committed();
        let short = commit_frame(&[0x11; SCALAR_LEN], &element[..ELEMENT_LEN - 1]);
        assert!(matches!(a.on_frame(&ctx_a, &short), Err(Error::Malformed)));
        // A group we did not offer.
        let (mut a, ctx_a, _) = committed();
        let mut wrong_group = commit_frame(&[0x11; SCALAR_LEN], &element);
        wrong_group[6..8].copy_from_slice(&20u16.to_le_bytes());
        assert!(matches!(
            a.on_frame(&ctx_a, &wrong_group),
            Err(Error::AuthFailed)
        ));
        // A rejected frame ends the exchange rather than leaving it open to
        // the next thing that arrives.
        assert!(matches!(
            a.on_frame(&ctx_a, &commit_frame(&[0x11; SCALAR_LEN], &element)),
            Err(Error::AuthFailed)
        ));
        assert!(matches!(a.on_timeout(&ctx_a), Err(Error::AuthFailed)));
    }

    /// Our own commit, sent back at us. Confirming against it would be
    /// confirming against ourselves.
    #[test]
    fn rejects_a_reflected_commit() {
        let ctx_a = ctx(STA, AP);
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        let commit_a = sent(a.start(&ctx_a).unwrap());
        assert!(matches!(
            a.on_frame(&ctx_a, &commit_a),
            Err(Error::AuthFailed)
        ));
    }

    /// An AP that answers with status 0 derived its PWE by hunting and
    /// pecking, which caw does not implement and will not fall back to.
    #[test]
    fn refuses_an_access_point_without_h2e() {
        let (mut a, ctx_a, element) = committed();
        let mut legacy = commit_frame(&[0x11; SCALAR_LEN], &element);
        legacy[4..6].copy_from_slice(&STATUS_SUCCESS.to_le_bytes());
        assert!(matches!(
            a.on_frame(&ctx_a, &legacy),
            Err(Error::AuthFailed)
        ));
    }

    #[test]
    fn refuses_a_rejection_status() {
        let (mut a, ctx_a, element) = committed();
        let mut refused = commit_frame(&[0x11; SCALAR_LEN], &element);
        // 77: FINITE_CYCLIC_GROUP_NOT_SUPPORTED.
        refused[4..6].copy_from_slice(&77u16.to_le_bytes());
        assert!(matches!(
            a.on_frame(&ctx_a, &refused),
            Err(Error::AuthFailed)
        ));
    }

    /// The commit frame is the fixed authentication fields, the group, the
    /// scalar and the element — 102 octets, and nothing else.
    #[test]
    fn commit_frame_layout() {
        let ctx_a = ctx(STA, AP);
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        let frame = sent(a.start(&ctx_a).unwrap());

        assert_eq!(frame.len(), 6 + 2 + SCALAR_LEN + ELEMENT_LEN);
        assert_eq!(le16(&frame[0..2]), AUTH_ALG_SAE);
        assert_eq!(le16(&frame[2..4]), SEQ_COMMIT);
        assert_eq!(le16(&frame[4..6]), STATUS_H2E);
        assert_eq!(le16(&frame[6..8]), GROUP_P256);
        // The element is a point on the curve, in x || y with no SEC1 tag.
        let element: [u8; ELEMENT_LEN] = frame[8 + SCALAR_LEN..].try_into().unwrap();
        assert!(decode_element(&element).is_ok());
    }

    /// The confirm carries the counter it was hashed with, so the peer can
    /// recompute the same hash.
    #[test]
    fn confirm_frame_layout() {
        let (ctx_a, ctx_b) = (ctx(STA, AP), ctx(AP, STA));
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        let mut b = SaeProvider::with_seed("pw", &seed(2));
        a.start(&ctx_a).unwrap();
        let commit_b = sent(b.start(&ctx_b).unwrap());
        let confirm = sent(a.on_frame(&ctx_a, &commit_b).unwrap());

        assert_eq!(confirm.len(), 6 + 2 + HASH_LEN);
        assert_eq!(le16(&confirm[2..4]), SEQ_CONFIRM);
        assert_eq!(le16(&confirm[4..6]), STATUS_SUCCESS);
        assert_eq!(le16(&confirm[6..8]), 1, "first send-confirm is 1");
    }

    /// A confirm that arrives before the peer's commit, or a commit after we
    /// have already confirmed, is dropped. An injected frame must not be able
    /// to end an exchange.
    #[test]
    fn unexpected_frames_are_ignored() {
        let (ctx_a, ctx_b) = (ctx(STA, AP), ctx(AP, STA));
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        let mut b = SaeProvider::with_seed("pw", &seed(2));
        let commit_a = sent(a.start(&ctx_a).unwrap());
        let commit_b = sent(b.start(&ctx_b).unwrap());
        let confirm_b = sent(b.on_frame(&ctx_b, &commit_a).unwrap());

        // Confirm first: still waiting for the commit.
        assert!(matches!(a.on_frame(&ctx_a, &confirm_b), Ok(Step::Wait)));
        // Now the commit is accepted, and the exchange still completes.
        let _ = sent(a.on_frame(&ctx_a, &commit_b).unwrap());
        // A second commit, after confirming, is ignored rather than restarting.
        assert!(matches!(a.on_frame(&ctx_a, &commit_b), Ok(Step::Wait)));
        let _ = pmk(a.on_frame(&ctx_a, &confirm_b).unwrap());
        // Nothing at all is expected once accepted.
        assert!(matches!(a.on_frame(&ctx_a, &confirm_b), Ok(Step::Wait)));
    }

    /// A timeout retransmits the same octets — a fresh commit would give an
    /// observer a second equation in the same secrets — and eventually gives
    /// up rather than retrying forever.
    #[test]
    fn retransmits_then_gives_up() {
        let ctx_a = ctx(STA, AP);
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        let commit = sent(a.start(&ctx_a).unwrap());

        for _ in 0..SYNC_MAX {
            assert_eq!(sent(a.on_timeout(&ctx_a).unwrap()), commit);
        }
        assert!(matches!(a.on_timeout(&ctx_a), Err(Error::AuthFailed)));
    }

    /// An AP under load answers with a token; the retry carries it back
    /// unchanged, and repeats the same commit.
    #[test]
    fn echoes_an_anti_clogging_token() {
        let ctx_a = ctx(STA, AP);
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        let commit = sent(a.start(&ctx_a).unwrap());

        let token = [0xabu8; 32];
        let mut request = auth_header(SEQ_COMMIT, STATUS_ANTI_CLOGGING);
        request.extend_from_slice(&GROUP_P256.to_le_bytes());
        request.push(EID_EXTENSION);
        request.push(1 + token.len() as u8);
        request.push(EID_EXT_ANTI_CLOGGING);
        request.extend_from_slice(&token);

        let retry = sent(a.on_frame(&ctx_a, &request).unwrap());
        assert_eq!(retry[..commit.len()], commit[..], "same scalar and element");
        assert_eq!(retry[commit.len()..], request[8..], "token echoed verbatim");

        // And the exchange still completes from there.
        let mut b = SaeProvider::with_seed("pw", &seed(2));
        let ctx_b = ctx(AP, STA);
        let commit_b = sent(b.start(&ctx_b).unwrap());
        let confirm_b = sent(b.on_frame(&ctx_b, &retry).unwrap());
        let _ = sent(a.on_frame(&ctx_a, &commit_b).unwrap());
        let _ = pmk(a.on_frame(&ctx_a, &confirm_b).unwrap());
    }

    #[test]
    fn rejects_a_malformed_token_container() {
        let (mut a, ctx_a, _) = committed();
        let mut request = auth_header(SEQ_COMMIT, STATUS_ANTI_CLOGGING);
        request.extend_from_slice(&GROUP_P256.to_le_bytes());
        request.push(EID_EXTENSION);
        request.push(40); // longer than what follows
        request.push(EID_EXT_ANTI_CLOGGING);
        request.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            a.on_frame(&ctx_a, &request),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn is_a_pre_association_provider() {
        let a = SaeProvider::with_seed("pw", &seed(1));
        assert_eq!(a.stage(), AuthStage::PreAssoc);
        assert_eq!(a.pmkid(), None);
    }

    #[test]
    fn rejects_a_non_sae_akm() {
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        let ctx = AuthContext {
            ssid: SSID,
            bssid: AP,
            own_mac: STA,
            akm: caw_80211::Akm::FtSae,
        };
        assert!(matches!(a.start(&ctx), Err(Error::UnsupportedAkm)));
    }

    #[test]
    fn rejects_being_driven_out_of_order() {
        let ctx_a = ctx(STA, AP);
        let mut a = SaeProvider::with_seed("pw", &seed(1));
        assert!(matches!(
            a.on_frame(&ctx_a, &[3, 0, 1, 0, 126, 0]),
            Err(Error::Protocol)
        ));
        assert!(matches!(a.on_timeout(&ctx_a), Err(Error::Protocol)));
        a.start(&ctx_a).unwrap();
        assert!(matches!(a.start(&ctx_a), Err(Error::Protocol)));
    }

    /// The one piece of I/O in the crate: two providers that draw their own
    /// seeds from `getrandom` still reach the same PMK.
    #[cfg(target_os = "linux")]
    #[test]
    fn os_seeded_providers_agree() {
        let (ctx_a, ctx_b) = (ctx(STA, AP), ctx(AP, STA));
        let mut a = SaeProvider::new("pw");
        let mut b = SaeProvider::new("pw");

        let commit_a = sent(a.start(&ctx_a).unwrap());
        let commit_b = sent(b.start(&ctx_b).unwrap());
        let confirm_a = sent(a.on_frame(&ctx_a, &commit_b).unwrap());
        let confirm_b = sent(b.on_frame(&ctx_b, &commit_a).unwrap());

        assert_eq!(
            pmk(a.on_frame(&ctx_a, &confirm_b).unwrap()),
            pmk(b.on_frame(&ctx_b, &confirm_a).unwrap())
        );
        // Two exchanges never share a commit, which is what makes each PMK
        // fresh.
        assert_ne!(commit_a, commit_b);
    }

    /// The password token depends on the SSID and the password; the password
    /// element adds the pair of addresses, and does it symmetrically so both
    /// ends reach the same point.
    #[test]
    fn password_element_is_symmetric_and_bound() {
        let pt = password_token(SSID, "pw");
        assert_ne!(
            encode_element(&pt),
            encode_element(&password_token(SSID, "pw2"))
        );
        assert_ne!(
            encode_element(&pt),
            encode_element(&password_token(b"other", "pw"))
        );

        let sta_side = password_element(&pt, STA, AP);
        let ap_side = password_element(&pt, AP, STA);
        assert_eq!(encode_element(&sta_side), encode_element(&ap_side));

        let other = password_element(&pt, STA, [0x02, 0, 0, 0, 0, 0x03]);
        assert_ne!(encode_element(&sta_side), encode_element(&other));
    }
}
