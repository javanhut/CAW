//! The whole lifecycle, driven by feeding [`Input`]s and asserting the
//! [`Action`]s that come back.
//!
//! No socket, no radio, no kernel: that is the point of the sans-IO split, and
//! these tests are the payoff. The access point is a scripted authenticator
//! built out of `caw-eapol`'s frame types but signing its frames over literal
//! byte offsets, so a mistake in what caw sends shows up as a MIC mismatch
//! exactly as it would against hostapd.
//!
//! The passphrase and SSID are the IEEE 802.11i-2004 Annex H.4.2 pair, so the
//! PMK underneath every test below is a published number.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use aes_kw::{KeyInit, KwAes128};
use caw_80211::{Akm, Cipher, RsnIe, Security};
use caw_crypto::{
    KeyDescriptorVersion, PmkProvider, Ptk, SEED_LEN, SaeProvider, compute_mic, derive_pmk,
    derive_ptk,
};
use caw_eapol::{Eapol, KeyFrame, KeyInfo, PacketType, key};
use caw_nl80211::{Bss, ConnectStatus, Event};

use crate::*;

const SSID: &[u8] = b"ThisIsASSID";
const PASSPHRASE: &str = "ThisIsAPassword";
const BSSID: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
const OTHER_BSSID: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x03, 0x00];
const OWN_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x02, 0x00];
const IFINDEX: u32 = 3;
const GTK: [u8; 16] = [0x5a; 16];
const GTK2: [u8; 16] = [0xa5; 16];

/// Where the Key MIC sits in a complete EAPOL-Key frame. Spelled out rather
/// than imported so the authenticator does not agree with caw by construction.
const MIC_AT: usize = 81;

// -- fixtures --------------------------------------------------------------

/// A directory that removes itself, so the profile tests can write real files
/// with real modes without a dependency on `tempfile`.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "caw-core-{}-{unique}",
            rustix::process::getpid().as_raw_nonzero()
        ));
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path.join("profiles"))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().expect("built with a parent"));
    }
}

/// An RSN element as an AP would beacon it: CCMP for both keys, and whichever
/// AKMs the caller wants to offer.
pub(crate) fn rsn_element(akms: &[Akm], mfp_required: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&caw_nl80211::WLAN_CIPHER_SUITE_CCMP.to_be_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&caw_nl80211::WLAN_CIPHER_SUITE_CCMP.to_be_bytes());
    body.extend_from_slice(&(akms.len() as u16).to_le_bytes());
    for akm in akms {
        body.extend_from_slice(&caw_nl80211::akm_suite(*akm).to_be_bytes());
    }
    let capabilities: u16 = if mfp_required { 0xc0 } else { 0 };
    body.extend_from_slice(&capabilities.to_le_bytes());

    let mut element = vec![48u8, body.len() as u8];
    element.extend_from_slice(&body);
    element
}

pub(crate) fn rsn_of(akms: &[Akm], mfp_required: bool) -> RsnIe {
    RsnIe::parse(&rsn_element(akms, mfp_required)).expect("a well-formed element")
}

/// One scan result. The security level decides which AKMs the beacon carries,
/// which is the only thing policy reads it for.
pub(crate) fn bss(bssid: [u8; 6], ssid: &[u8], signal_dbm: i32, security: Security) -> Bss {
    let rsn = match security {
        Security::Wpa2Personal => Some(rsn_of(&[Akm::Psk], false)),
        Security::Wpa3Personal => Some(rsn_of(&[Akm::Sae], true)),
        Security::Wpa2Wpa3Personal => Some(rsn_of(&[Akm::Sae, Akm::Psk], false)),
        Security::Wpa2Enterprise => Some(rsn_of(&[Akm::Dot1x], false)),
        _ => None,
    };
    Bss {
        bssid,
        ssid: ssid.to_vec(),
        freq_mhz: 2437,
        signal_dbm,
        last_seen_ms: 0,
        capability: if rsn.is_some() { 1 << 4 } else { 0 },
        security,
        rsn,
    }
}

fn device() -> Device {
    Device {
        ifindex: IFINDEX,
        mac: OWN_MAC,
        caps: DeviceCaps::default(),
    }
}

fn profile_with(passphrase: &str) -> Profile {
    Profile::new(
        SSID.to_vec(),
        Security::Wpa2Personal,
        Credential::Passphrase(Secret::new(passphrase)),
    )
}

fn lease() -> caw_dhcp::Lease {
    caw_dhcp::Lease {
        addr: "192.168.1.24".parse().expect("a literal address"),
        prefix_len: 24,
        gateway: Some("192.168.1.1".parse().expect("a literal address")),
        dns: Vec::new(),
        server: "192.168.1.1".parse().expect("a literal address"),
        lease_secs: 3600,
        renew_secs: 1800,
        rebind_secs: 3150,
    }
}

// -- action inspection -----------------------------------------------------

/// The shape of an action list, for asserting a sequence. The payloads are
/// checked separately, by the tests that care about them.
fn tags(actions: &[Action]) -> Vec<&'static str> {
    actions
        .iter()
        .map(|action| match action {
            Action::TriggerScan { .. } => "TriggerScan",
            Action::FetchScanResults { .. } => "FetchScanResults",
            Action::Associate(_) => "Associate",
            Action::Disconnect { .. } => "Disconnect",
            Action::SendMgmtFrame(_) => "SendMgmtFrame",
            Action::SendEapol(_) => "SendEapol",
            Action::InstallKeys(_) => "InstallKeys",
            Action::StartDhcp => "StartDhcp",
            Action::ApplyLease(_) => "ApplyLease",
            Action::SetTimer { .. } => "SetTimer",
            Action::ClearTimer { .. } => "ClearTimer",
            Action::RequestSecret { .. } => "RequestSecret",
            Action::SaveProfile(_) => "SaveProfile",
            Action::Notify(_) => "Notify",
            Action::Failed(_) => "Failed",
        })
        .collect()
}

fn eapol_out(actions: &[Action]) -> &[u8] {
    actions
        .iter()
        .find_map(|a| match a {
            Action::SendEapol(frame) => Some(&frame[..]),
            _ => None,
        })
        .expect("an outgoing EAPOL frame")
}

fn mgmt_out(actions: &[Action]) -> &[u8] {
    actions
        .iter()
        .find_map(|a| match a {
            Action::SendMgmtFrame(frame) => Some(&frame[..]),
            _ => None,
        })
        .expect("an outgoing management frame")
}

fn assoc_request(actions: &[Action]) -> &AssocRequest {
    actions
        .iter()
        .find_map(|a| match a {
            Action::Associate(request) => Some(&**request),
            _ => None,
        })
        .expect("an association request")
}

fn key_install(actions: &[Action]) -> &KeyInstall {
    actions
        .iter()
        .find_map(|a| match a {
            Action::InstallKeys(keys) => Some(&**keys),
            _ => None,
        })
        .expect("keys to install")
}

fn failure(actions: &[Action]) -> &Failure {
    actions
        .iter()
        .find_map(|a| match a {
            Action::Failed(failure) => Some(failure),
            _ => None,
        })
        .expect("a reported failure")
}

fn timer(actions: &[Action], wanted: TimerId) -> u64 {
    actions
        .iter()
        .find_map(|a| match a {
            Action::SetTimer { id, millis } if *id == wanted => Some(*millis),
            _ => None,
        })
        .expect("an armed timer")
}

// -- the scripted authenticator --------------------------------------------

/// Recompute a frame's MIC the way an authenticator does: zero the field, run
/// the algorithm the descriptor version names.
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

/// AES key wrap with the 802.11 padding rule.
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
        .expect("a 16-octet KEK")
        .wrap_key(&padded, &mut out)
        .expect("padded to a multiple of eight")
        .len();
    out.truncate(n);
    out
}

/// Enough of hostapd to exercise a supplicant.
struct Authenticator {
    /// Its own address: the PTK is derived over the pair, so a roam to another
    /// BSS is a different key even with the same passphrase.
    bssid: [u8; 6],
    anonce: [u8; 32],
    counter: u64,
    ptk: Option<Ptk>,
    version: KeyDescriptorVersion,
    gtk: Vec<u8>,
    gtk_index: u8,
}

impl Authenticator {
    fn new() -> Self {
        Self::at(BSSID)
    }

    fn at(bssid: [u8; 6]) -> Self {
        Self {
            bssid,
            anonce: [0x33; 32],
            counter: 0,
            ptk: None,
            version: KeyDescriptorVersion::HmacSha1,
            gtk: GTK.to_vec(),
            gtk_index: 1,
        }
    }

    fn kck(&self) -> [u8; 16] {
        self.ptk
            .as_ref()
            .expect("a PTK is known after message 2")
            .kck
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

    /// Learn the PTK from message 2, as an authenticator does, and report
    /// whether its MIC verified. A station with the wrong passphrase produces
    /// a message 2 that does not, which is where a real AP would stop.
    fn recv_msg2(&mut self, frame: &[u8]) -> (Vec<u8>, bool) {
        let eapol = Eapol::parse(frame).expect("a well-formed EAPOL frame");
        assert_eq!(eapol.packet_type, PacketType::Key);
        let msg2 = KeyFrame::parse(eapol.body).expect("a well-formed key frame");

        assert!(msg2.key_info.pairwise(), "message 2 is a pairwise frame");
        assert!(msg2.key_info.mic(), "message 2 carries a MIC");
        assert!(!msg2.key_info.ack(), "only an authenticator sets Key ACK");
        assert_eq!(
            msg2.replay_counter, self.counter,
            "message 2 echoes message 1"
        );

        let ptk = derive_ptk(
            &derive_pmk(PASSPHRASE, SSID),
            Akm::Psk,
            self.bssid,
            OWN_MAC,
            &self.anonce,
            &msg2.key_nonce,
        )
        .expect("a supported AKM");
        let verified = msg2.key_mic == mic_of(frame, &ptk.kck, self.version);

        let echoed = msg2.key_data.to_vec();
        self.ptk = Some(ptk);
        (echoed, verified)
    }

    fn msg3(&mut self) -> Vec<u8> {
        self.counter += 1;
        let mut key_data = rsn_element(&[Akm::Psk], false);
        key_data.extend_from_slice(&gtk_kde_bytes(self.gtk_index, &self.gtk));
        let wrapped = wrap(
            &self.ptk.as_ref().expect("known from message 2").kek,
            &key_data,
        );
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
        let eapol = Eapol::parse(frame).expect("a well-formed EAPOL frame");
        let msg4 = KeyFrame::parse(eapol.body).expect("a well-formed key frame");
        assert!(msg4.key_info.secure(), "message 4 is sent protected");
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
            &self.ptk.as_ref().expect("established").kek,
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
        let eapol = Eapol::parse(frame).expect("a well-formed EAPOL frame");
        let msg2 = KeyFrame::parse(eapol.body).expect("a well-formed key frame");
        assert!(!msg2.key_info.pairwise(), "a group frame clears Key Type");
        assert!(msg2.key_info.mic() && msg2.key_info.secure());
        assert_eq!(msg2.key_mic, mic_of(frame, &self.kck(), self.version));
    }
}

// -- driving the machine ---------------------------------------------------

fn connect(connection: &mut Connection) -> Vec<Action> {
    connection.poll(Input::Command(Command::Connect {
        ssid: SSID.to_vec(),
    }))
}

fn associated() -> Event {
    Event::Connected {
        bssid: Some(BSSID),
        status: ConnectStatus::Success,
    }
}

/// Take a WPA2-PSK connection all the way to `Connected`, asserting the
/// sequence as it goes. The end-to-end test is this function plus its
/// assertions; everything after it starts from here.
fn connected(profiles: Vec<Profile>) -> (Connection, Authenticator) {
    let mut connection = Connection::new(device(), profiles);
    let mut ap = Authenticator::new();

    let out = connect(&mut connection);
    assert_eq!(tags(&out), ["Notify", "TriggerScan", "SetTimer"]);
    assert_eq!(connection.state(), State::Scanning);

    let out = connection.poll(Input::Wireless(Event::ScanComplete {
        wiphy: 0,
        ifindex: IFINDEX,
    }));
    assert_eq!(tags(&out), ["FetchScanResults"]);

    let scan = vec![bss(BSSID, SSID, -50, Security::Wpa2Personal)];
    let out = connection.poll(Input::ScanResults(scan));
    assert_eq!(
        tags(&out),
        ["ClearTimer", "Notify", "Associate", "SetTimer"]
    );
    assert_eq!(connection.state(), State::Associating);

    let out = connection.poll(Input::Wireless(associated()));
    assert_eq!(tags(&out), ["ClearTimer", "Notify"]);
    assert_eq!(connection.state(), State::Handshaking);

    let msg1 = ap.msg1();
    let out = connection.poll(Input::Eapol(msg1));
    assert_eq!(tags(&out), ["SendEapol", "SetTimer"]);
    let (echoed, verified) = ap.recv_msg2(eapol_out(&out));
    assert!(verified, "message 2 MIC");
    assert_eq!(
        echoed,
        StationRsn {
            group: Cipher::Ccmp128,
            pairwise: Cipher::Ccmp128,
            akm: Akm::Psk,
            mfp_capable: false,
            mfp_required: false,
            pmkid: None,
            group_mgmt: None,
        }
        .encode(),
        "message 2 repeats the element the association request carried"
    );

    let msg3 = ap.msg3();
    let out = connection.poll(Input::Eapol(msg3));
    assert_eq!(
        tags(&out),
        [
            "SendEapol",
            "ClearTimer",
            "InstallKeys",
            "Notify",
            "StartDhcp"
        ]
    );
    ap.recv_msg4(eapol_out(&out));
    assert_eq!(connection.state(), State::Configuring);

    let install = key_install(&out);
    let pairwise = install.pairwise.as_ref().expect("a pairwise key");
    assert_eq!(pairwise.peer, BSSID);
    assert_eq!(pairwise.cipher, caw_nl80211::WLAN_CIPHER_SUITE_CCMP);
    assert_eq!(install.group.gtk.key[..], GTK[..]);
    assert_eq!(install.group.gtk.index, 1);

    let out = connection.poll(Input::Lease(LeaseEvent::Acquired(lease())));
    assert!(tags(&out).starts_with(&["ApplyLease", "Notify"]));
    assert_eq!(connection.state(), State::Connected);

    (connection, ap)
}

// -- the tests -------------------------------------------------------------

#[test]
fn a_psk_connection_runs_end_to_end() {
    let (connection, _) = connected(vec![profile_with(PASSPHRASE)]);
    assert_eq!(connection.state(), State::Connected);
    assert_eq!(connection.bssid(), Some(BSSID));
    assert_eq!(connection.security(), Some(Security::Wpa2Personal));
}

/// The association request is what the AP sees; its suites have to be the ones
/// policy chose and its RSN element the one the handshake will echo.
#[test]
fn the_association_request_asks_for_what_policy_chose() {
    let mut connection = Connection::new(device(), vec![profile_with(PASSPHRASE)]);
    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa2Personal,
    )]));

    let request = assoc_request(&out);
    assert_eq!(request.ifindex, IFINDEX);
    assert_eq!(request.ssid, SSID);
    assert_eq!(request.bssid, BSSID);
    assert_eq!(request.auth_type, caw_nl80211::NL80211_AUTHTYPE_OPEN_SYSTEM);
    assert_eq!(request.wpa_versions, caw_nl80211::NL80211_WPA_VERSION_2);
    assert_eq!(request.akms, vec![caw_nl80211::WLAN_AKM_SUITE_PSK]);
    assert_eq!(
        request.pairwise_ciphers,
        vec![caw_nl80211::WLAN_CIPHER_SUITE_CCMP]
    );
    assert_eq!(
        request.group_cipher,
        Some(caw_nl80211::WLAN_CIPHER_SUITE_CCMP)
    );
    assert!(request.offload.is_none(), "this device offloads nothing");
    // An association request with no RSN element is refused with status 40.
    let element = RsnIe::parse(&request.ies).expect("our own element parses");
    assert_eq!(element.akms, vec![Akm::Psk]);
}

/// The failure that matters most. A station that treats a wrong passphrase as
/// a transient error reassociates forever and never says what is wrong.
#[test]
fn a_wrong_passphrase_is_reported_not_retried() {
    let mut connection = Connection::new(device(), vec![profile_with("WrongPassword")]);
    let mut ap = Authenticator::new();

    connect(&mut connection);
    connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa2Personal,
    )]));
    connection.poll(Input::Wireless(associated()));

    let msg1 = ap.msg1();
    let out = connection.poll(Input::Eapol(msg1));
    let (_, verified) = ap.recv_msg2(eapol_out(&out));
    assert!(!verified, "the wrong passphrase derives the wrong PTK");

    // A real AP would stop here; this one answers anyway, which is the case
    // where the station itself has to notice.
    let msg3 = ap.msg3();
    let out = connection.poll(Input::Eapol(msg3));

    assert_eq!(*failure(&out), Failure::WrongCredential);
    assert_eq!(tags(&out), ["Disconnect", "ClearTimer", "Failed"]);
    assert_eq!(connection.state(), State::Idle);
    assert!(
        !tags(&out).contains(&"TriggerScan"),
        "a wrong passphrase must not start another attempt"
    );

    // And nothing further happens on its own.
    assert!(
        connection
            .poll(Input::Timer(TimerId::HandshakeRetry))
            .is_empty()
    );
    assert!(
        connection
            .poll(Input::Timer(TimerId::ReconnectBackoff))
            .is_empty()
    );
}

/// The downgrade defence: an attacker presents an open network under a name
/// the machine knows, hoping it will join and start talking.
#[test]
fn a_weaker_network_under_a_known_name_is_refused() {
    let mut profile = profile_with(PASSPHRASE);
    profile.security = Security::Wpa3Personal;
    profile.min_security = Security::Wpa3Personal;

    let mut connection = Connection::new(device(), vec![profile]);
    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -20,
        Security::Open,
    )]));

    assert_eq!(
        *failure(&out),
        Failure::Downgrade {
            recorded: Security::Wpa3Personal,
            offered: Security::Open,
        }
    );
    assert_eq!(tags(&out), ["ClearTimer", "Failed"]);
    assert_eq!(connection.state(), State::Idle);
}

/// The same defence one step subtler: still WPA, but WPA2 where WPA3 was
/// recorded. A device that cannot run SAE would otherwise take the PSK half of
/// a network an attacker is impersonating.
#[test]
fn a_wpa2_network_under_a_wpa3_name_is_refused() {
    let mut profile = profile_with(PASSPHRASE);
    profile.security = Security::Wpa3Personal;
    profile.min_security = Security::Wpa3Personal;

    let mut connection = Connection::new(device(), vec![profile]);
    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -20,
        Security::Wpa2Personal,
    )]));

    assert_eq!(
        *failure(&out),
        Failure::Downgrade {
            recorded: Security::Wpa3Personal,
            offered: Security::Wpa2Personal,
        }
    );
}

/// A network first joined in transition mode records the weaker half as its
/// floor, so its own PSK side is not refused later.
#[test]
fn a_transition_network_joins_with_sae_and_is_not_refused_later() {
    let profile = Profile::new(
        SSID.to_vec(),
        Security::Wpa2Wpa3Personal,
        Credential::Passphrase(Secret::new(PASSPHRASE)),
    );
    let mut connection = Connection::new(device(), vec![profile]);
    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa2Wpa3Personal,
    )]));

    assert_eq!(
        tags(&out),
        ["ClearTimer", "Notify", "SendMgmtFrame", "SetTimer"]
    );
    assert_eq!(connection.state(), State::Authenticating);
    assert_eq!(connection.security(), Some(Security::Wpa3Personal));
}

/// SAE runs to completion before the association request goes out, and the
/// request names the PMK it derived.
#[test]
fn sae_completes_before_the_association_request() {
    let profile = Profile::new(
        SSID.to_vec(),
        Security::Wpa3Personal,
        Credential::Passphrase(Secret::new(PASSPHRASE)),
    );
    let mut connection = Connection::new(device(), vec![profile]);

    // The peer runs the same state machine with the addresses swapped: SAE is
    // symmetric, so an access point is a station with a different context.
    let mut peer = SaeProvider::with_seed(PASSPHRASE, &[0x5c; SEED_LEN]);
    let peer_context = caw_crypto::AuthContext {
        ssid: SSID,
        bssid: OWN_MAC,
        own_mac: BSSID,
        akm: Akm::Sae,
    };

    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa3Personal,
    )]));
    assert_eq!(connection.state(), State::Authenticating);
    let commit = mgmt_out(&out).to_vec();

    let peer_commit = match peer.start(&peer_context).expect("a commit") {
        caw_crypto::Step::Send(frame) => frame,
        _ => panic!("SAE opens with a commit"),
    };
    let out = connection.poll(Input::Wireless(Event::Frame(peer_commit)));
    assert_eq!(tags(&out), ["SendMgmtFrame", "SetTimer"]);
    assert_eq!(
        connection.state(),
        State::Authenticating,
        "still no association request"
    );

    let peer_confirm = match peer.on_frame(&peer_context, &commit).expect("a confirm") {
        caw_crypto::Step::Send(frame) => frame,
        _ => panic!("a commit is answered with a confirm"),
    };
    let out = connection.poll(Input::Wireless(Event::Frame(peer_confirm)));

    assert_eq!(
        tags(&out),
        ["ClearTimer", "Notify", "Associate", "SetTimer"]
    );
    assert_eq!(connection.state(), State::Associating);
    let request = assoc_request(&out);
    assert_eq!(request.auth_type, caw_nl80211::NL80211_AUTHTYPE_SAE);
    assert_eq!(request.akms, vec![caw_nl80211::WLAN_AKM_SUITE_SAE]);
    assert_eq!(request.mfp, Some(caw_nl80211::NL80211_MFP_REQUIRED));
    let element = RsnIe::parse(&request.ies).expect("our own element parses");
    assert!(
        element.mfp_required,
        "WPA3 requires protected management frames"
    );
    assert!(
        request.ies.len() > 22,
        "the element names the PMK the exchange derived"
    );
}

/// `Connected` is not a resting state: an AP rotates the group key about once
/// an hour, and a station that does not answer is deauthenticated.
#[test]
fn a_group_rekey_installs_only_the_group_key() {
    let (mut connection, mut ap) = connected(vec![profile_with(PASSPHRASE)]);

    ap.gtk = GTK2.to_vec();
    ap.gtk_index = 2;
    let rekey = ap.group_msg1();
    let out = connection.poll(Input::Eapol(rekey));

    assert_eq!(tags(&out), ["SendEapol", "InstallKeys"]);
    ap.recv_group_msg2(eapol_out(&out));

    let install = key_install(&out);
    assert!(
        install.pairwise.is_none(),
        "reinstalling a pairwise key replays the keystream (KRACK)"
    );
    assert_eq!(install.group.gtk.key[..], GTK2[..]);
    assert_eq!(install.group.gtk.index, 2);
    assert_eq!(connection.state(), State::Connected);
}

/// A network that is simply not there yet: back off, and try again for longer
/// each time rather than hammering the radio.
#[test]
fn repeated_failure_backs_off() {
    let mut connection = Connection::new(device(), vec![profile_with(PASSPHRASE)]);
    connect(&mut connection);

    let mut delays = Vec::new();
    for _ in 0..8 {
        let out = connection.poll(Input::ScanResults(Vec::new()));
        assert_eq!(tags(&out), ["ClearTimer", "Notify", "SetTimer"]);
        assert_eq!(connection.state(), State::Reconnecting);
        delays.push(timer(&out, TimerId::ReconnectBackoff));

        let out = connection.poll(Input::Timer(TimerId::ReconnectBackoff));
        assert_eq!(
            tags(&out),
            ["ClearTimer", "Notify", "TriggerScan", "SetTimer"]
        );
        assert_eq!(connection.state(), State::Scanning);
    }

    assert_eq!(&delays[..4], &[1_000, 2_000, 4_000, 8_000]);
    assert!(delays.windows(2).all(|w| w[1] >= w[0]), "{delays:?}");
    assert_eq!(*delays.last().expect("eight attempts"), BACKOFF_MAX_MS);
}

/// A network with no profile is prompted for, and only written down once the
/// passphrase has actually worked.
#[test]
fn an_unknown_network_is_prompted_for_then_saved() {
    let mut connection = Connection::new(device(), Vec::new());
    let mut ap = Authenticator::new();

    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa2Personal,
    )]));
    assert_eq!(tags(&out), ["ClearTimer", "RequestSecret"]);
    assert!(connection.profiles().is_empty(), "nothing saved yet");

    // A person typing is not a scan that failed.
    assert!(
        connection
            .poll(Input::Timer(TimerId::ScanTimeout))
            .is_empty()
    );

    let out = connection.poll(Input::Command(Command::Secret {
        value: Secret::new(PASSPHRASE),
    }));
    assert_eq!(tags(&out), ["Notify", "Associate", "SetTimer"]);

    connection.poll(Input::Wireless(associated()));
    let msg1 = ap.msg1();
    let out = connection.poll(Input::Eapol(msg1));
    assert!(ap.recv_msg2(eapol_out(&out)).1, "message 2 MIC");
    let msg3 = ap.msg3();
    connection.poll(Input::Eapol(msg3));

    let out = connection.poll(Input::Lease(LeaseEvent::Acquired(lease())));
    assert_eq!(tags(&out), ["ApplyLease", "Notify", "SaveProfile"]);

    let saved = connection.profiles().first().expect("a saved profile");
    assert_eq!(saved.ssid, SSID);
    assert_eq!(saved.min_security, Security::Wpa2Personal);
    assert_eq!(
        saved.credential,
        Credential::Passphrase(Secret::new(PASSPHRASE))
    );
}

/// An unknown network that never appears fails outright: there is no profile
/// saying it should be waited for.
#[test]
fn an_unknown_network_that_is_absent_does_not_retry() {
    let mut connection = Connection::new(device(), Vec::new());
    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(Vec::new()));

    assert_eq!(*failure(&out), Failure::NotFound);
    assert_eq!(connection.state(), State::Idle);
}

/// Roaming re-associates without touching the address configuration.
#[test]
fn roaming_keeps_the_lease() {
    let (mut connection, _) = connected(vec![profile_with(PASSPHRASE)]);
    let mut ap = Authenticator::at(OTHER_BSSID);

    let scan = vec![
        bss(BSSID, SSID, -70, Security::Wpa2Personal),
        bss(OTHER_BSSID, SSID, -40, Security::Wpa2Personal),
    ];
    let out = connection.poll(Input::ScanResults(scan));
    // No `ClearTimer`: the handshake disarmed its own retransmit timer when it
    // completed, and `Connected` has nothing else running.
    assert_eq!(tags(&out), ["Notify", "Associate", "SetTimer"]);
    assert_eq!(assoc_request(&out).bssid, OTHER_BSSID);
    assert_eq!(connection.state(), State::Associating);

    connection.poll(Input::Wireless(Event::Connected {
        bssid: Some(OTHER_BSSID),
        status: ConnectStatus::Success,
    }));
    let msg1 = ap.msg1();
    let out = connection.poll(Input::Eapol(msg1));
    assert!(
        ap.recv_msg2(eapol_out(&out)).1,
        "message 2 MIC at the new BSS"
    );
    let msg3 = ap.msg3();
    let out = connection.poll(Input::Eapol(msg3));

    assert_eq!(
        tags(&out),
        ["SendEapol", "ClearTimer", "InstallKeys", "Notify"],
        "a roam does not reconfigure the address"
    );
    assert_eq!(connection.state(), State::Connected);
    assert_eq!(connection.bssid(), Some(OTHER_BSSID));
}

/// A BSS that is only marginally better is not worth an association.
#[test]
fn a_marginal_bss_is_not_roamed_to() {
    let (mut connection, _) = connected(vec![profile_with(PASSPHRASE)]);
    let scan = vec![
        bss(BSSID, SSID, -60, Security::Wpa2Personal),
        bss(OTHER_BSSID, SSID, -57, Security::Wpa2Personal),
    ];
    assert!(connection.poll(Input::ScanResults(scan)).is_empty());
    assert_eq!(connection.bssid(), Some(BSSID));
}

/// Losing the link re-enters the lifecycle at `Reconnecting` rather than
/// reporting a failure, because a profile says this network is wanted.
#[test]
fn a_deauthentication_reconnects() {
    let (mut connection, _) = connected(vec![profile_with(PASSPHRASE)]);
    let out = connection.poll(Input::Wireless(Event::Disconnected {
        reason: 7,
        by_ap: true,
    }));

    assert_eq!(tags(&out), ["Notify", "SetTimer"]);
    assert_eq!(connection.state(), State::Reconnecting);
    assert_eq!(timer(&out, TimerId::ReconnectBackoff), BACKOFF_BASE_MS);
}

/// An open network has nothing to hand a handshake, so it goes from
/// association straight to address configuration.
#[test]
fn an_open_network_skips_the_handshake() {
    let mut connection = Connection::new(device(), Vec::new());
    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Open,
    )]));

    let request = assoc_request(&out);
    assert_eq!(request.wpa_versions, 0);
    assert!(request.ies.is_empty());
    assert!(request.akms.is_empty());

    let out = connection.poll(Input::Wireless(associated()));
    assert_eq!(tags(&out), ["ClearTimer", "Notify", "StartDhcp"]);
    assert_eq!(connection.state(), State::Configuring);
}

/// A device that runs the handshake in firmware is given the key instead, and
/// caw stays out of the exchange entirely.
#[test]
fn an_offloading_device_is_handed_the_key() {
    let mut device = device();
    device.caps.offloads_4way_psk = true;
    let mut connection = Connection::new(device, vec![profile_with(PASSPHRASE)]);

    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa2Personal,
    )]));
    match &assoc_request(&out).offload {
        Some(Offload::Pmk(pmk)) => {
            assert_eq!(pmk[..], derive_pmk(PASSPHRASE, SSID).0[..]);
        }
        _ => panic!("the PMK should have been handed to the kernel"),
    }

    // The kernel reports the association only once its own handshake is done.
    let out = connection.poll(Input::Wireless(associated()));
    assert_eq!(tags(&out), ["ClearTimer", "Notify", "StartDhcp"]);
    assert_eq!(connection.state(), State::Configuring);
}

/// A device that offloads SAE gets the password, not a PMK: it runs the
/// Dragonfly exchange itself.
#[test]
fn an_sae_offloading_device_is_handed_the_password() {
    let mut device = device();
    device.caps.offloads_sae = true;
    let profile = Profile::new(
        SSID.to_vec(),
        Security::Wpa3Personal,
        Credential::Passphrase(Secret::new(PASSPHRASE)),
    );
    let mut connection = Connection::new(device, vec![profile]);

    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa3Personal,
    )]));

    assert_eq!(
        connection.state(),
        State::Associating,
        "no exchange runs here"
    );
    match &assoc_request(&out).offload {
        Some(Offload::SaePassword(secret)) => assert_eq!(secret.as_str(), PASSPHRASE),
        _ => panic!("the password should have been handed to the kernel"),
    }
}

/// The AP refusing the association is where a wrong passphrase surfaces on a
/// device that offloads the handshake.
#[test]
fn a_refused_association_is_reported_with_its_status_code() {
    let mut connection = Connection::new(device(), Vec::new());
    connect(&mut connection);
    connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Open,
    )]));

    let out = connection.poll(Input::Wireless(Event::Connected {
        bssid: None,
        status: ConnectStatus::Refused(17),
    }));
    assert_eq!(*failure(&out), Failure::Refused(17));
    assert_eq!(connection.state(), State::Idle);
}

/// An enterprise network is configuration, not a prompt: there is no useful
/// question to ask mid-connection.
#[test]
fn an_enterprise_network_without_a_profile_is_not_prompted_for() {
    let mut connection = Connection::new(device(), Vec::new());
    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa2Enterprise,
    )]));

    // Without the `enterprise` feature caw cannot run 802.1X at all, so the
    // AKM is refused before the credential is ever missed.
    let expected = if cfg!(feature = "enterprise") {
        Failure::NoCredential
    } else {
        Failure::UnsupportedSecurity
    };
    assert_eq!(*failure(&out), expected);
}

/// Disconnecting is the user's decision, and must not start a reconnect.
#[test]
fn disconnecting_stays_disconnected() {
    let (mut connection, _) = connected(vec![profile_with(PASSPHRASE)]);
    let out = connection.poll(Input::Command(Command::Disconnect));

    assert_eq!(tags(&out), ["Disconnect", "Notify"]);
    assert_eq!(connection.state(), State::Idle);
    assert!(connection.ssid().is_none());
    assert!(connection.poll(Input::ScanResults(Vec::new())).is_empty());
}

/// A timer that fired for a state already left cannot be recalled, so it has
/// to be harmless.
#[test]
fn a_stale_timer_does_nothing() {
    let (mut connection, _) = connected(vec![profile_with(PASSPHRASE)]);
    for id in [
        TimerId::ScanTimeout,
        TimerId::AuthTimeout,
        TimerId::AssocTimeout,
        TimerId::ReconnectBackoff,
    ] {
        assert!(connection.poll(Input::Timer(id)).is_empty(), "{id:?}");
        assert_eq!(connection.state(), State::Connected);
    }
}

/// The lease expiring is not the link going away: ask for another address and
/// keep the association.
#[test]
fn a_lost_lease_is_reconfigured_not_reconnected() {
    let (mut connection, _) = connected(vec![profile_with(PASSPHRASE)]);
    let out = connection.poll(Input::Lease(LeaseEvent::Lost(caw_dhcp::Reason::Expired)));

    assert_eq!(tags(&out), ["Notify", "StartDhcp"]);
    assert_eq!(connection.state(), State::Configuring);
}

/// The enterprise path is only compiled with the feature, and its first
/// failure is a configuration one: there is no certificate to check the RADIUS
/// server against, and joining anyway would hand the credential to whoever
/// answers.
#[cfg(feature = "enterprise")]
#[test]
fn an_enterprise_profile_without_a_trust_anchor_is_refused() {
    let profile = Profile::new(
        SSID.to_vec(),
        Security::Wpa2Enterprise,
        Credential::Enterprise {
            identity: "user@example.org".into(),
            anonymous_identity: None,
            server_name: None,
            method: EnterpriseMethod::Peap {
                password: Secret::new("hunter2"),
            },
            ca_cert: None,
        },
    );
    let mut connection = Connection::new(device(), vec![profile]);
    connect(&mut connection);
    let out = connection.poll(Input::ScanResults(vec![bss(
        BSSID,
        SSID,
        -50,
        Security::Wpa2Enterprise,
    )]));

    match failure(&out) {
        Failure::Enterprise(why) => assert!(why.contains("ca_cert"), "{why}"),
        other => panic!("expected a configuration failure, got {other:?}"),
    }
    assert_eq!(connection.state(), State::Idle);
}

#[test]
fn every_failure_says_something_a_person_can_act_on() {
    let cases = [
        Failure::NotFound,
        Failure::Downgrade {
            recorded: Security::Wpa3Personal,
            offered: Security::Open,
        },
        Failure::UnsupportedSecurity,
        Failure::NoCredential,
        Failure::Refused(17),
        Failure::AssocTimeout,
        Failure::WrongCredential,
        Failure::RsnMismatch,
        Failure::AuthFailed,
        Failure::Handshake("timed out".into()),
        Failure::Disconnected {
            reason: 7,
            by_ap: true,
        },
        Failure::Dhcp,
        Failure::Enterprise("no ca_cert".into()),
        Failure::Internal("impossible".into()),
    ];
    for case in cases {
        let rendered = case.to_string();
        assert!(!rendered.is_empty() && rendered.is_ascii(), "{case:?}");
    }
}
