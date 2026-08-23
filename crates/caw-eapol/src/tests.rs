//! The handshake driven against a scripted authenticator.
//!
//! The authenticator here is deliberately not built out of this crate's
//! builders where it matters: it recomputes the MIC over a literal byte offset
//! and derives its own PTK from the SNonce it reads off message 2. A bug in
//! the frame layout therefore shows up as a MIC mismatch, exactly as it would
//! against a real AP.
//!
//! The PMK is the IEEE 802.11i-2004 Annex H.4.2 vector, so the chain from
//! passphrase to installed key is anchored to published numbers at both ends:
//! caw-crypto checks the PMK, the PTK construction and the MIC algorithms
//! against their standards, and these tests check that this crate composes
//! them into the right frames.

use aes_kw::{KeyInit, KwAes128};
use caw_80211::Akm;
use caw_crypto::{KeyDescriptorVersion, Ptk, compute_mic, derive_pmk, derive_ptk};

use super::*;

const SSID: &[u8] = b"ThisIsASSID";
const PASSPHRASE: &str = "ThisIsAPassword";
const BSSID: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
const OWN_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x02, 0x00];
const ANONCE: [u8; 32] = [0x33; 32];
const SNONCE: [u8; 32] = [0x11; 32];
const GTK: [u8; 16] = [0x5a; 16];
const GTK2: [u8; 16] = [0xa5; 16];

/// Where the Key MIC sits in a complete EAPOL-Key frame. Spelled out rather
/// than imported so the tests do not agree with the parser by construction.
const MIC_AT: usize = 81;

fn hex(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex vector has an odd number of digits"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// WPA2-Personal: CCMP group and pairwise, PSK, no MFP.
fn rsn_ie() -> Vec<u8> {
    hex("30140100000fac040100000fac040100000fac020000")
}

/// The same element with the group cipher downgraded to TKIP — what an
/// attacker rewriting a beacon would hand a station.
fn downgraded_rsn_ie() -> Vec<u8> {
    hex("30140100000fac020100000fac040100000fac020000")
}

fn config() -> Config {
    Config {
        akm: Akm::Psk,
        own_mac: OWN_MAC,
        bssid: BSSID,
        assoc_rsn_ie: rsn_ie(),
        beacon_rsn_ie: rsn_ie(),
    }
}

fn station() -> FourWay {
    FourWay::with_snonce(derive_pmk(PASSPHRASE, SSID), config(), SNONCE)
}

/// Recompute a frame's MIC the way an authenticator does: zero the field, run
/// the algorithm the descriptor version names, compare.
fn mic_of(frame: &[u8], kck: &[u8; 16], version: KeyDescriptorVersion) -> [u8; 16] {
    let mut zeroed = frame.to_vec();
    zeroed[MIC_AT..MIC_AT + 16].fill(0);
    compute_mic(kck, version, &zeroed)
}

fn gtk_kde_bytes(index: u8, gtk: &[u8]) -> Vec<u8> {
    let mut kde = vec![
        0xdd,
        (6 + gtk.len()) as u8,
        0x00,
        0x0f,
        0xac,
        0x01,
        index & 0x03,
        0x00,
    ];
    kde.extend_from_slice(gtk);
    kde
}

/// AES key wrap with the 802.11 padding rule: a 0xDD octet then zeros, up to a
/// multiple of eight and at least sixteen octets.
fn wrap(kek: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut padded = data.to_vec();
    if padded.len() < 16 || !padded.len().is_multiple_of(8) {
        padded.push(0xdd);
        while padded.len() < 16 || !padded.len().is_multiple_of(8) {
            padded.push(0);
        }
    }
    let mut out = vec![0u8; padded.len() + 8];
    let n = KwAes128::new_from_slice(kek)
        .unwrap()
        .wrap_key(&padded, &mut out)
        .unwrap()
        .len();
    out.truncate(n);
    out
}

/// A scripted authenticator: enough of hostapd to exercise the supplicant.
struct Authenticator {
    anonce: [u8; 32],
    counter: u64,
    ptk: Option<Ptk>,
    version: KeyDescriptorVersion,
    gtk: Vec<u8>,
    gtk_index: u8,
}

impl Authenticator {
    fn new() -> Self {
        Self {
            anonce: ANONCE,
            counter: 0,
            ptk: None,
            version: KeyDescriptorVersion::HmacSha1,
            gtk: GTK.to_vec(),
            gtk_index: 1,
        }
    }

    fn kck(&self) -> [u8; 16] {
        self.ptk.as_ref().expect("PTK known after message 2").kck
    }

    fn msg1(&mut self) -> Vec<u8> {
        self.counter += 1;
        KeyFrame {
            descriptor_type: key::DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(self.version.bits() | KeyInfo::PAIRWISE | KeyInfo::ACK),
            key_length: 16,
            replay_counter: self.counter,
            key_nonce: self.anonce,
            key_iv: [0; 16],
            key_rsc: [0; 8],
            key_mic: [0; 16],
            key_data: &[],
        }
        .encode(2)
    }

    /// Check message 2 and learn the PTK from it, as an authenticator does.
    /// Returns the RSN element the station echoed.
    fn recv_msg2(&mut self, frame: &[u8]) -> Vec<u8> {
        let eapol = Eapol::parse(frame).unwrap();
        assert_eq!(eapol.packet_type, PacketType::Key);
        let msg2 = KeyFrame::parse(eapol.body).unwrap();

        assert!(msg2.key_info.pairwise(), "message 2 is a pairwise frame");
        assert!(msg2.key_info.mic(), "message 2 carries a MIC");
        assert!(!msg2.key_info.ack(), "only an authenticator sets Key ACK");
        assert!(!msg2.key_info.secure(), "no key is installed yet");
        assert_eq!(msg2.key_length, 0, "message 2 distributes no key");
        assert_eq!(
            msg2.replay_counter, self.counter,
            "message 2 echoes message 1"
        );

        let ptk = derive_ptk(
            &derive_pmk(PASSPHRASE, SSID),
            Akm::Psk,
            BSSID,
            OWN_MAC,
            &self.anonce,
            &msg2.key_nonce,
        )
        .unwrap();
        assert_eq!(
            msg2.key_mic,
            mic_of(frame, &ptk.kck, self.version),
            "message 2 MIC"
        );

        let ie = msg2.key_data.to_vec();
        self.ptk = Some(ptk);
        ie
    }

    fn msg3(&mut self) -> Vec<u8> {
        self.msg3_with(&rsn_ie(), true)
    }

    fn msg3_with(&mut self, rsn: &[u8], with_gtk: bool) -> Vec<u8> {
        self.counter += 1;
        let mut key_data = rsn.to_vec();
        if with_gtk {
            key_data.extend_from_slice(&gtk_kde_bytes(self.gtk_index, &self.gtk));
        }
        let wrapped = wrap(&self.ptk.as_ref().unwrap().kek, &key_data);
        KeyFrame {
            descriptor_type: key::DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(
                self.version.bits()
                    | KeyInfo::PAIRWISE
                    | KeyInfo::INSTALL
                    | KeyInfo::ACK
                    | KeyInfo::MIC
                    | KeyInfo::SECURE
                    | KeyInfo::ENCRYPTED,
            ),
            key_length: 16,
            replay_counter: self.counter,
            key_nonce: self.anonce,
            key_iv: [0; 16],
            key_rsc: [0; 8],
            key_mic: [0; 16],
            key_data: &wrapped,
        }
        .encode_signed(2, &self.kck(), self.version)
    }

    fn recv_msg4(&self, frame: &[u8]) {
        let eapol = Eapol::parse(frame).unwrap();
        let msg4 = KeyFrame::parse(eapol.body).unwrap();

        assert!(msg4.key_info.pairwise());
        assert!(msg4.key_info.mic());
        assert!(msg4.key_info.secure(), "message 4 is sent protected");
        assert!(!msg4.key_info.ack());
        assert_eq!(msg4.key_data.len(), 0, "message 4 carries no key data");
        assert_eq!(
            msg4.replay_counter, self.counter,
            "message 4 echoes message 3"
        );
        assert_eq!(
            msg4.key_mic,
            mic_of(frame, &self.kck(), self.version),
            "message 4 MIC"
        );
    }

    fn group_msg1(&mut self) -> Vec<u8> {
        self.counter += 1;
        let wrapped = wrap(
            &self.ptk.as_ref().unwrap().kek,
            &gtk_kde_bytes(self.gtk_index, &self.gtk),
        );
        KeyFrame {
            descriptor_type: key::DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(
                self.version.bits()
                    | KeyInfo::ACK
                    | KeyInfo::MIC
                    | KeyInfo::SECURE
                    | KeyInfo::ENCRYPTED,
            ),
            key_length: 16,
            replay_counter: self.counter,
            key_nonce: [0; 32],
            key_iv: [0; 16],
            key_rsc: [0; 8],
            key_mic: [0; 16],
            key_data: &wrapped,
        }
        .encode_signed(2, &self.kck(), self.version)
    }

    fn recv_group_msg2(&self, frame: &[u8]) {
        let eapol = Eapol::parse(frame).unwrap();
        let msg2 = KeyFrame::parse(eapol.body).unwrap();
        assert!(!msg2.key_info.pairwise(), "a group frame clears Key Type");
        assert!(msg2.key_info.mic() && msg2.key_info.secure());
        assert!(!msg2.key_info.ack());
        assert_eq!(msg2.replay_counter, self.counter);
        assert_eq!(msg2.key_mic, mic_of(frame, &self.kck(), self.version));
    }
}

fn sent(actions: &[Action]) -> &[u8] {
    actions
        .iter()
        .find_map(|a| match a {
            Action::Send(f) => Some(&f[..]),
            _ => None,
        })
        .expect("an outgoing frame")
}

fn completed(actions: Vec<Action>) -> Keys {
    actions
        .into_iter()
        .find_map(|a| match a {
            Action::Complete(keys) => Some(keys),
            _ => None,
        })
        .expect("a completed handshake")
}

fn new_gtk(actions: Vec<Action>) -> Gtk {
    actions
        .into_iter()
        .find_map(|a| match a {
            Action::NewGtk(gtk) => Some(gtk),
            _ => None,
        })
        .expect("a rekeyed GTK")
}

/// Run messages 1 through 4, returning the station, the authenticator and the
/// keys the station wants installed.
fn handshake() -> (FourWay, Authenticator, Keys) {
    let mut sta = station();
    let mut ap = Authenticator::new();

    let msg1 = ap.msg1();
    let out = sta.poll(Input::Frame(&msg1)).unwrap();
    let echoed = ap.recv_msg2(sent(&out));
    assert_eq!(
        echoed,
        rsn_ie(),
        "message 2 repeats the association element"
    );

    let msg3 = ap.msg3();
    let out = sta.poll(Input::Frame(&msg3)).unwrap();
    ap.recv_msg4(sent(&out));

    let keys = completed(out);
    (sta, ap, keys)
}

#[test]
fn full_handshake_installs_the_expected_keys() {
    let (_sta, _ap, keys) = handshake();

    // PRF-384(PMK, "Pairwise key expansion", AA || SPA || SNonce || ANonce),
    // computed outside this tree from the standard's own construction. Locked
    // as literals so a change to the address sorting, the label or the
    // KCK/KEK/TK split fails here and not at an access point.
    assert_eq!(
        keys.ptk.kck[..],
        hex("a860d711f4b0c9ee8a5b2b45b92bf26b")[..]
    );
    assert_eq!(
        keys.ptk.kek[..],
        hex("9213f7e28037494a931b486211e312cb")[..]
    );
    assert_eq!(keys.ptk.tk[..], hex("ada452c1219f1ae0678d061cfe731a3e")[..]);

    assert_eq!(keys.gtk.key[..], GTK[..]);
    assert_eq!(keys.gtk.index, 1);
}

#[test]
fn message_two_answers_message_one_and_arms_a_timer() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));
    assert!(out.iter().any(|a| matches!(a, Action::ArmTimer(_))));
}

/// A wrong passphrase produces a different PMK, so it is not detected until
/// message 3's MIC — which is exactly what this looks like on the wire.
#[test]
fn a_wrong_passphrase_fails_the_message_three_mic() {
    let mut sta = FourWay::with_snonce(derive_pmk("not the password", SSID), config(), SNONCE);
    let mut ap = Authenticator::new();

    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    // The authenticator derives from the real PMK, so its MIC will not match.
    let eapol = Eapol::parse(sent(&out)).unwrap();
    let msg2 = KeyFrame::parse(eapol.body).unwrap();
    ap.ptk = Some(
        derive_ptk(
            &derive_pmk(PASSPHRASE, SSID),
            Akm::Psk,
            BSSID,
            OWN_MAC,
            &ANONCE,
            &msg2.key_nonce,
        )
        .unwrap(),
    );

    let msg3 = ap.msg3();
    assert!(matches!(
        sta.poll(Input::Frame(&msg3)),
        Err(Error::Crypto(caw_crypto::Error::MicMismatch))
    ));
}

#[test]
fn a_tampered_message_three_fails_its_mic() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    let mut msg3 = ap.msg3();
    let last = msg3.len() - 1;
    msg3[last] ^= 1;
    assert!(matches!(
        sta.poll(Input::Frame(&msg3)),
        Err(Error::Crypto(caw_crypto::Error::MicMismatch))
    ));
}

#[test]
fn rejects_a_replayed_message_three() {
    let (mut sta, mut ap, _keys) = handshake();
    // The same frame again, counter and all.
    ap.counter -= 1;
    let replay = ap.msg3();
    assert!(matches!(
        sta.poll(Input::Frame(&replay)),
        Err(Error::ReplayedCounter)
    ));
}

#[test]
fn rejects_a_replayed_message_one() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let msg1 = ap.msg1();
    sta.poll(Input::Frame(&msg1)).unwrap();
    assert!(matches!(
        sta.poll(Input::Frame(&msg1)),
        Err(Error::ReplayedCounter)
    ));
}

/// The RSN element in message 3 is covered by a MIC an attacker cannot forge,
/// so comparing it against the beacon is what makes a rewritten beacon fatal
/// instead of effective.
#[test]
fn rejects_an_rsn_element_that_does_not_match_the_beacon() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    let msg3 = ap.msg3_with(&downgraded_rsn_ie(), true);
    assert!(matches!(
        sta.poll(Input::Frame(&msg3)),
        Err(Error::RsnMismatch)
    ));
}

#[test]
fn rejects_a_message_three_with_no_rsn_element() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    let msg3 = ap.msg3_with(&[], true);
    assert!(matches!(
        sta.poll(Input::Frame(&msg3)),
        Err(Error::RsnMissing)
    ));
}

#[test]
fn rejects_a_message_three_with_no_gtk() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    let msg3 = ap.msg3_with(&rsn_ie(), false);
    assert!(matches!(
        sta.poll(Input::Frame(&msg3)),
        Err(Error::GtkMissing)
    ));
}

#[test]
fn rejects_an_anonce_that_changed_between_messages() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    // A MIC computed over the changed nonce with the PTK the station has: the
    // only way to reach the nonce check at all.
    ap.anonce = [0x44; 32];
    let msg3 = ap.msg3();
    assert!(matches!(
        sta.poll(Input::Frame(&msg3)),
        Err(Error::NonceMismatch)
    ));
}

#[test]
fn rejects_unencrypted_key_data_in_message_three() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    ap.counter += 1;
    let mut key_data = rsn_ie();
    key_data.extend_from_slice(&gtk_kde_bytes(1, &GTK));
    let msg3 = KeyFrame {
        descriptor_type: key::DESCRIPTOR_TYPE_RSN,
        key_info: KeyInfo(
            ap.version.bits()
                | KeyInfo::PAIRWISE
                | KeyInfo::INSTALL
                | KeyInfo::ACK
                | KeyInfo::MIC
                | KeyInfo::SECURE,
        ),
        key_length: 16,
        replay_counter: ap.counter,
        key_nonce: ap.anonce,
        key_iv: [0; 16],
        key_rsc: [0; 8],
        key_mic: [0; 16],
        key_data: &key_data,
    }
    .encode_signed(2, &ap.kck(), ap.version);

    assert!(matches!(
        sta.poll(Input::Frame(&msg3)),
        Err(Error::Malformed)
    ));
}

/// Reinstalling a pairwise key resets its packet number and replays the
/// keystream — CVE-2017-13077. A repeated message 3 is answered, never
/// installed twice.
#[test]
fn a_repeated_message_three_is_answered_but_not_reinstalled() {
    let (mut sta, mut ap, _keys) = handshake();

    let msg3 = ap.msg3();
    let out = sta.poll(Input::Frame(&msg3)).unwrap();
    ap.recv_msg4(sent(&out));
    assert!(
        !out.iter().any(|a| matches!(a, Action::Complete(_))),
        "the PTK must not be handed out for a second install"
    );
}

#[test]
fn group_rekey_yields_a_new_gtk() {
    let (mut sta, mut ap, _keys) = handshake();

    ap.gtk = GTK2.to_vec();
    ap.gtk_index = 2;
    let rekey = ap.group_msg1();
    let out = sta.poll(Input::Frame(&rekey)).unwrap();
    ap.recv_group_msg2(sent(&out));

    let gtk = new_gtk(out);
    assert_eq!(gtk.key[..], GTK2[..]);
    assert_eq!(gtk.index, 2);
}

#[test]
fn rejects_a_forged_group_rekey() {
    let (mut sta, mut ap, _keys) = handshake();

    let mut rekey = ap.group_msg1();
    rekey[MIC_AT] ^= 1;
    assert!(matches!(
        sta.poll(Input::Frame(&rekey)),
        Err(Error::Crypto(caw_crypto::Error::MicMismatch))
    ));
}

/// Replaying a rekey is how an attacker forces the GTK back to an old value —
/// CVE-2017-13080. The replay counter stops it before the unwrap.
#[test]
fn rejects_a_replayed_group_rekey() {
    let (mut sta, mut ap, _keys) = handshake();

    let rekey = ap.group_msg1();
    sta.poll(Input::Frame(&rekey)).unwrap();
    ap.counter -= 1;
    let replay = ap.group_msg1();
    assert!(matches!(
        sta.poll(Input::Frame(&replay)),
        Err(Error::ReplayedCounter)
    ));
}

#[test]
fn a_group_rekey_before_the_handshake_is_refused() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    // Give the authenticator a PTK without the station having one.
    ap.ptk = Some(
        derive_ptk(
            &derive_pmk(PASSPHRASE, SSID),
            Akm::Psk,
            BSSID,
            OWN_MAC,
            &ANONCE,
            &SNONCE,
        )
        .unwrap(),
    );
    let rekey = ap.group_msg1();
    assert!(matches!(
        sta.poll(Input::Frame(&rekey)),
        Err(Error::UnexpectedMessage)
    ));
}

#[test]
fn retransmits_message_two_a_bounded_number_of_times() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let first = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    let msg2 = sent(&first).to_vec();

    for _ in 0..RETRY_LIMIT {
        let out = sta.poll(Input::Timeout).unwrap();
        assert_eq!(sent(&out), &msg2[..], "a retransmission is byte-identical");
    }
    assert!(matches!(sta.poll(Input::Timeout), Err(Error::Timeout)));
}

#[test]
fn a_timeout_before_message_one_does_nothing() {
    let mut sta = station();
    assert!(sta.poll(Input::Timeout).unwrap().is_empty());
}

/// An unbound packet socket also delivers the frames this station sent. Only
/// an authenticator sets Key ACK, so the echo is dropped rather than treated
/// as a protocol error.
#[test]
fn ignores_frames_without_key_ack() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    let own_msg2 = sent(&out).to_vec();
    assert!(sta.poll(Input::Frame(&own_msg2)).unwrap().is_empty());
}

#[test]
fn ignores_a_supplicant_request_frame() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    ap.counter += 1;
    let request = KeyFrame {
        descriptor_type: key::DESCRIPTOR_TYPE_RSN,
        key_info: KeyInfo(
            ap.version.bits()
                | KeyInfo::PAIRWISE
                | KeyInfo::ACK
                | KeyInfo::REQUEST
                | KeyInfo::ERROR,
        ),
        key_length: 0,
        replay_counter: ap.counter,
        key_nonce: [0; 32],
        key_iv: [0; 16],
        key_rsc: [0; 8],
        key_mic: [0; 16],
        key_data: &[],
    }
    .encode(2);
    assert!(sta.poll(Input::Frame(&request)).unwrap().is_empty());
}

#[test]
fn ignores_eapol_eap_frames() {
    let mut sta = station();
    let frame = Eapol::encode(2, PacketType::Eap, &[1, 0, 0, 5, 1]);
    assert!(sta.poll(Input::Frame(&frame)).unwrap().is_empty());
}

/// Descriptor version 1 pairs an HMAC-MD5 MIC with an RC4 key wrap, and exists
/// only to carry TKIP.
#[test]
fn rejects_descriptor_version_one() {
    let mut sta = station();
    let msg1 = KeyFrame {
        descriptor_type: key::DESCRIPTOR_TYPE_RSN,
        key_info: KeyInfo(1 | KeyInfo::PAIRWISE | KeyInfo::ACK),
        key_length: 32,
        replay_counter: 1,
        key_nonce: ANONCE,
        key_iv: [0; 16],
        key_rsc: [0; 8],
        key_mic: [0; 16],
        key_data: &[],
    }
    .encode(2);
    assert!(matches!(
        sta.poll(Input::Frame(&msg1)),
        Err(Error::Crypto(caw_crypto::Error::UnsupportedVersion))
    ));
}

#[test]
fn rejects_the_wpa1_key_descriptor() {
    let mut sta = station();
    let msg1 = KeyFrame {
        descriptor_type: 254,
        key_info: KeyInfo(KeyDescriptorVersion::HmacSha1.bits() | KeyInfo::PAIRWISE | KeyInfo::ACK),
        key_length: 32,
        replay_counter: 1,
        key_nonce: ANONCE,
        key_iv: [0; 16],
        key_rsc: [0; 8],
        key_mic: [0; 16],
        key_data: &[],
    }
    .encode(2);
    assert!(matches!(
        sta.poll(Input::Frame(&msg1)),
        Err(Error::UnsupportedDescriptor(254))
    ));
}

/// Once the handshake has aborted, nothing may restart it: the caller's job on
/// error is to deauthenticate, and a caller that ignores the error must not
/// end up half authenticated.
#[test]
fn a_failed_handshake_stays_failed() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    let bad = ap.msg3_with(&downgraded_rsn_ie(), true);
    assert!(sta.poll(Input::Frame(&bad)).is_err());

    let msg1 = ap.msg1();
    assert!(matches!(
        sta.poll(Input::Frame(&msg1)),
        Err(Error::UnexpectedMessage)
    ));
}

/// An AP may pad the Ethernet payload to the 60-octet minimum. The MIC covers
/// only what the EAPOL length field declares, so the padding must not reach it.
#[test]
fn padding_past_the_declared_length_is_not_covered_by_the_mic() {
    let mut sta = station();
    let mut ap = Authenticator::new();

    let mut msg1 = ap.msg1();
    msg1.extend_from_slice(&[0u8; 20]);
    let out = sta.poll(Input::Frame(&msg1)).unwrap();
    ap.recv_msg2(sent(&out));

    let mut msg3 = ap.msg3();
    msg3.extend_from_slice(&[0u8; 20]);
    let out = sta.poll(Input::Frame(&msg3)).unwrap();
    ap.recv_msg4(sent(&out));
}

#[test]
fn an_authenticator_may_retry_message_one() {
    let mut sta = station();
    let mut ap = Authenticator::new();

    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    // A fresh ANonce, as a real retry carries.
    ap.anonce = [0x77; 32];
    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));

    let msg3 = ap.msg3();
    let out = sta.poll(Input::Frame(&msg3)).unwrap();
    ap.recv_msg4(sent(&out));
    completed(out);
}

#[test]
fn eapol_header_round_trips() {
    let frame = Eapol::encode(2, PacketType::Key, &[9, 8, 7]);
    assert_eq!(frame, vec![2, 3, 0, 3, 9, 8, 7]);

    let parsed = Eapol::parse(&frame).unwrap();
    assert_eq!(parsed.version, 2);
    assert_eq!(parsed.packet_type, PacketType::Key);
    assert_eq!(parsed.body, &[9, 8, 7]);
    assert_eq!(parsed.raw, &frame[..]);
}

#[test]
fn eapol_rejects_a_body_shorter_than_its_header_claims() {
    assert!(matches!(
        Eapol::parse(&[2, 3, 0, 8, 1, 2, 3]),
        Err(Error::Malformed)
    ));
    assert!(matches!(Eapol::parse(&[2, 3, 0]), Err(Error::Malformed)));
}

#[test]
fn key_frame_round_trips() {
    let original = KeyFrame {
        descriptor_type: key::DESCRIPTOR_TYPE_RSN,
        key_info: KeyInfo(0x13ca),
        key_length: 16,
        replay_counter: 0x0102_0304_0506_0708,
        key_nonce: [0x21; 32],
        key_iv: [0x22; 16],
        key_rsc: [0x23; 8],
        key_mic: [0x24; 16],
        key_data: &[0xde, 0xad, 0xbe, 0xef],
    };
    let frame = original.encode(2);
    assert_eq!(frame.len(), EAPOL_HDR_LEN + key::BODY_MIN + 4);

    let eapol = Eapol::parse(&frame).unwrap();
    let parsed = KeyFrame::parse(eapol.body).unwrap();
    assert_eq!(parsed.key_info, original.key_info);
    assert_eq!(parsed.key_length, 16);
    assert_eq!(parsed.replay_counter, original.replay_counter);
    assert_eq!(parsed.key_nonce, original.key_nonce);
    assert_eq!(parsed.key_iv, original.key_iv);
    assert_eq!(parsed.key_rsc, original.key_rsc);
    assert_eq!(parsed.key_mic, original.key_mic);
    assert_eq!(parsed.key_data, original.key_data);
}

#[test]
fn the_mic_field_lands_where_the_standard_puts_it() {
    let frame = KeyFrame {
        descriptor_type: key::DESCRIPTOR_TYPE_RSN,
        key_info: KeyInfo(KeyDescriptorVersion::HmacSha1.bits() | KeyInfo::MIC),
        key_length: 0,
        replay_counter: 1,
        key_nonce: [0; 32],
        key_iv: [0; 16],
        key_rsc: [0; 8],
        key_mic: [0; 16],
        key_data: &[],
    }
    .encode_signed(2, &[0x42; 16], KeyDescriptorVersion::HmacSha1);

    assert_eq!(key::MIC_OFFSET, MIC_AT);
    assert_eq!(
        frame[MIC_AT..MIC_AT + 16],
        mic_of(&frame, &[0x42; 16], KeyDescriptorVersion::HmacSha1)[..]
    );
}

#[test]
fn key_frame_rejects_a_truncated_body() {
    assert!(matches!(KeyFrame::parse(&[0u8; 94]), Err(Error::Malformed)));
    // Key Data Length claims more than is there.
    let mut body = [0u8; 95];
    body[93] = 0;
    body[94] = 4;
    assert!(matches!(KeyFrame::parse(&body), Err(Error::Malformed)));
}

#[test]
fn key_data_parsing_stops_at_the_wrap_padding() {
    let mut data = rsn_ie();
    data.extend_from_slice(&gtk_kde_bytes(3, &GTK));
    data.extend_from_slice(&[0xdd, 0x00, 0x00, 0x00]);

    assert_eq!(key::rsn_element(&data), Some(&rsn_ie()[..]));
    let gtk = key::gtk_kde(&data).unwrap();
    assert_eq!(gtk.key[..], GTK[..]);
    assert_eq!(gtk.index, 3);
    assert_eq!(key::key_data_items(&data).count(), 2);
}

#[test]
fn gtk_kde_rejects_a_key_of_the_wrong_length() {
    let short = gtk_kde_bytes(0, &[0u8; 8]);
    assert!(matches!(key::gtk_kde(&short), Err(Error::Malformed)));
    assert!(matches!(key::gtk_kde(&[]), Err(Error::GtkMissing)));
}

#[test]
fn gtk_kde_ignores_other_kdes() {
    // A Key ID KDE (type 8) ahead of the GTK, as an MFP-capable AP sends.
    let mut data = vec![0xdd, 0x06, 0x00, 0x0f, 0xac, 0x08, 0x01, 0x00];
    data.extend_from_slice(&gtk_kde_bytes(2, &GTK));
    let gtk = key::gtk_kde(&data).unwrap();
    assert_eq!(gtk.index, 2);
    assert_eq!(gtk.key[..], GTK[..]);
}

#[test]
fn key_info_decodes_its_flags() {
    let info = KeyInfo(
        KeyDescriptorVersion::AesCmac.bits()
            | KeyInfo::PAIRWISE
            | KeyInfo::INSTALL
            | KeyInfo::ACK
            | KeyInfo::MIC
            | KeyInfo::SECURE
            | KeyInfo::ENCRYPTED,
    );
    assert_eq!(info.version().unwrap(), KeyDescriptorVersion::AesCmac);
    assert!(info.pairwise() && info.install() && info.ack());
    assert!(info.mic() && info.secure() && info.encrypted());
    assert!(!info.error() && !info.request());
}

/// The SHA-256 AKMs negotiate descriptor version 3, whose MIC is AES-CMAC.
/// Mirroring the version off the wire rather than inferring it from the AKM is
/// what makes that work.
#[test]
fn handshake_runs_on_descriptor_version_three() {
    let mut sta = station();
    let mut ap = Authenticator::new();
    ap.version = KeyDescriptorVersion::AesCmac;

    let out = sta.poll(Input::Frame(&ap.msg1())).unwrap();
    ap.recv_msg2(sent(&out));
    let msg3 = ap.msg3();
    let out = sta.poll(Input::Frame(&msg3)).unwrap();
    ap.recv_msg4(sent(&out));
    assert_eq!(completed(out).gtk.key[..], GTK[..]);
}

/// The socket itself. Needs `CAP_NET_RAW` and a Linux kernel, so it stays out
/// of the default run: `cargo test -p caw-eapol -- --ignored` inside the
/// privileged dev container.
#[test]
#[ignore = "needs CAP_NET_RAW"]
fn the_packet_socket_opens() {
    let sock = EapolSocket::open(1).unwrap();
    assert_eq!(sock.ifindex(), 1);
    // Nothing has arrived, so there is no authenticator to answer.
    assert!(matches!(sock.send(&[0; 4]), Err(Error::NoPeer)));
}
