//! Which network to join, with which suites, and when to refuse.
//!
//! Pure functions over scan results and profiles. Nothing here keeps state or
//! performs an action; [`crate::Connection`] calls into it and turns the
//! answers into [`Action`](crate::Action)s.

use caw_80211::{Akm, Cipher, RsnIe, Security};
use caw_nl80211::Bss;

use crate::profile::{Credential, Profile};

/// How much better a candidate must be before it is worth roaming to, in dB.
///
/// Roaming costs an association and a handshake, and signal readings wander by
/// a few dB while nothing moves. Too small a margin makes a station flap
/// between two APs it can hear equally well.
pub const ROAM_MARGIN_DB: i32 = 8;

/// Security levels ordered weakest to strongest.
///
/// Personal and Enterprise are not really comparable, and this collapses them
/// onto one axis anyway, because the question it answers is narrow: is what is
/// on offer now weaker than what this network was when it was first joined.
/// Ranks are shared where the distinction does not affect that answer.
pub fn strength(security: Security) -> u8 {
    match security {
        Security::Open => 0,
        Security::Wep => 1,
        Security::Wpa1Personal | Security::Wpa1Enterprise => 2,
        // Unauthenticated encryption: better than plaintext, weaker than
        // anything with a credential behind it.
        Security::Owe => 3,
        Security::Wpa2Personal | Security::Wpa2Enterprise => 4,
        // Transition mode sits between its two halves: it is not WPA3, because
        // an attacker in range can still offer the PSK half.
        Security::Wpa2Wpa3Personal => 5,
        Security::Wpa3Personal | Security::Wpa3Enterprise => 6,
    }
}

/// Whether `offered` clears a profile's recorded floor.
pub fn is_at_least(offered: Security, floor: Security) -> bool {
    strength(offered) >= strength(floor)
}

/// What a profile should record as its floor when a network is first seen.
///
/// Identity except for transition mode: an AP in WPA2/WPA3 transition offers
/// the PSK half and means it, so recording the pair would make caw refuse the
/// network's own advertised security on a device that cannot run SAE. The
/// downgrade defence keeps its teeth either way — Open, WEP and WPA1 all stay
/// below the line.
pub fn security_floor(observed: Security) -> Security {
    match observed {
        Security::Wpa2Wpa3Personal => Security::Wpa2Personal,
        other => other,
    }
}

/// The strongest BSS advertising `ssid`.
///
/// Signal alone, because every BSS in an ESS offers the same network: the
/// choice between them is a radio question. A driver that reports no signal
/// strength sorts last rather than first — see [`Bss::UNKNOWN_SIGNAL`].
pub fn best_bss<'a>(scan: &'a [Bss], ssid: &[u8]) -> Option<&'a Bss> {
    scan.iter()
        .filter(|bss| bss.ssid == ssid)
        .max_by_key(|bss| bss.signal_dbm)
}

/// The strongest BSS the machine has a profile for.
///
/// A known network beats an unknown one however strong the unknown one is,
/// which is what makes this the autoconnect rule rather than a signal survey.
pub fn best_known<'a>(scan: &'a [Bss], profiles: &'a [Profile]) -> Option<(&'a Bss, &'a Profile)> {
    scan.iter()
        .filter_map(|bss| {
            profiles
                .iter()
                .find(|p| p.autoconnect && p.ssid == bss.ssid)
                .map(|p| (bss, p))
        })
        .max_by_key(|(bss, _)| bss.signal_dbm)
}

/// A BSS in the same ESS worth leaving the current one for.
pub fn roam_target<'a>(
    scan: &'a [Bss],
    ssid: &[u8],
    current: [u8; 6],
    current_signal: i32,
) -> Option<&'a Bss> {
    let floor = current_signal.saturating_add(ROAM_MARGIN_DB);
    scan.iter()
        .filter(|bss| bss.ssid == ssid && bss.bssid != current && bss.signal_dbm >= floor)
        .max_by_key(|bss| bss.signal_dbm)
}

/// The AKM to negotiate: the strongest one the AP offers that this credential
/// can satisfy and this build can run.
///
/// This is where a WPA2/WPA3 transition network becomes a WPA3 connection.
/// SAE comes first in the list, so a passphrase profile on an AP offering both
/// joins with SAE and never sees the PSK half — the case
/// [`security_floor`] is careful not to punish.
///
/// The device's capabilities are not an input. nl80211 reports which of the
/// 4-way handshake and SAE a device will perform *for* caw, not which AKMs it
/// can be part of, and there is no AKM caw can run only through an offload —
/// so the offload bits decide how the exchange runs, in
/// the crate's `auth` module, and never whether it can.
///
/// `credential` is `None` before one has been supplied, which asks a narrower
/// question: which AKM *would* be used, so the caller can tell a network worth
/// prompting for from one caw could not join however good the passphrase.
pub fn choose_akm(rsn: &RsnIe, credential: Option<&Credential>) -> Option<Akm> {
    /// Strongest first within each family. Which family applies is decided by
    /// the credential, so the two interleave harmlessly.
    const PREFERENCE: [Akm; 5] = [
        Akm::Sae,
        Akm::Dot1xSha256,
        Akm::PskSha256,
        Akm::Dot1x,
        Akm::Psk,
    ];

    PREFERENCE
        .into_iter()
        .find(|&akm| rsn.akms.contains(&akm) && satisfies(akm, credential) && runnable(akm))
}

/// Whether a credential is the kind this AKM asks for.
pub fn satisfies(akm: Akm, credential: Option<&Credential>) -> bool {
    match credential {
        None => true,
        Some(Credential::None) => false,
        Some(Credential::Passphrase(_)) => akm.is_psk() || akm.is_sae(),
        Some(Credential::Enterprise { .. }) => akm.is_enterprise(),
    }
}

/// Whether caw can run this AKM at all.
///
/// The fast-transition suites are absent deliberately: they key from PMK-R0
/// rather than the PMK, a hierarchy `caw-crypto` does not derive, so
/// negotiating one would produce a PTK that fails at the handshake MIC. An AP
/// that offers FT alongside its plain suite is joined on the plain one. OWE is
/// absent because its Diffie-Hellman has no provider yet.
fn runnable(akm: Akm) -> bool {
    if matches!(akm, Akm::Psk | Akm::PskSha256 | Akm::Sae) {
        return true;
    }
    // 802.1X needs a TLS stack, and the default build has none in the tree.
    cfg!(feature = "enterprise") && matches!(akm, Akm::Dot1x | Akm::Dot1xSha256)
}

/// The pairwise cipher to ask for.
///
/// The 256-bit suites are deliberately absent. `caw-crypto` derives a 48-octet
/// PTK whose temporal key is 128 bits, so negotiating CCMP-256 would install
/// half a key and fail as a decryption error much later. TKIP is absent
/// because it is broken.
pub fn choose_pairwise(rsn: &RsnIe) -> Option<Cipher> {
    const PREFERENCE: [Cipher; 2] = [Cipher::Ccmp128, Cipher::Gcmp128];
    PREFERENCE
        .into_iter()
        .find(|c| rsn.pairwise_ciphers.contains(c))
}

/// The security level an association with this AKM actually provides.
///
/// The downgrade check runs against this rather than against what the beacon
/// advertised, so that a transition-mode network joined with SAE counts as the
/// WPA3 connection it is, and the same network joined with PSK counts as WPA2.
pub fn negotiated_security(akm: Akm, mfp_required: bool) -> Security {
    if akm.is_sae() {
        Security::Wpa3Personal
    } else if akm.is_psk() {
        Security::Wpa2Personal
    } else if akm == Akm::Owe {
        Security::Owe
    } else if akm.is_enterprise() {
        // WPA3-Enterprise is WPA2-Enterprise plus mandatory management frame
        // protection; the AKM alone does not distinguish them.
        if mfp_required || akm == Akm::Dot1xSuiteB192 {
            Security::Wpa3Enterprise
        } else {
            Security::Wpa2Enterprise
        }
    } else {
        // An AKM policy never chooses. Reporting the weakest level means the
        // floor check refuses it rather than letting it through unclassified.
        Security::Open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Secret;
    use crate::tests::{bss, rsn_of};

    fn passphrase() -> Credential {
        Credential::Passphrase(Secret::new("ThisIsAPassword"))
    }

    #[test]
    fn the_strongest_bss_wins_within_one_ssid() {
        let scan = vec![
            bss([1; 6], b"HomeNet", -70, Security::Wpa2Personal),
            bss([2; 6], b"HomeNet", -40, Security::Wpa2Personal),
            bss([3; 6], b"Other", -20, Security::Wpa2Personal),
        ];
        assert_eq!(best_bss(&scan, b"HomeNet").unwrap().bssid, [2; 6]);
        assert!(best_bss(&scan, b"Absent").is_none());
    }

    /// A driver that reports no signal must not outrank one that does.
    #[test]
    fn an_unknown_signal_sorts_last() {
        let scan = vec![
            bss(
                [1; 6],
                b"HomeNet",
                Bss::UNKNOWN_SIGNAL,
                Security::Wpa2Personal,
            ),
            bss([2; 6], b"HomeNet", -90, Security::Wpa2Personal),
        ];
        assert_eq!(best_bss(&scan, b"HomeNet").unwrap().bssid, [2; 6]);
    }

    #[test]
    fn a_known_network_beats_a_stronger_unknown_one() {
        let scan = vec![
            bss([1; 6], b"Cafe", -20, Security::Wpa2Personal),
            bss([2; 6], b"HomeNet", -75, Security::Wpa2Personal),
        ];
        let profiles = vec![Profile::new(
            b"HomeNet".to_vec(),
            Security::Wpa2Personal,
            passphrase(),
        )];
        let (chosen, _) = best_known(&scan, &profiles).unwrap();
        assert_eq!(chosen.bssid, [2; 6]);
    }

    #[test]
    fn autoconnect_off_is_not_a_candidate() {
        let scan = vec![bss([2; 6], b"HomeNet", -75, Security::Wpa2Personal)];
        let mut profile = Profile::new(b"HomeNet".to_vec(), Security::Wpa2Personal, passphrase());
        profile.autoconnect = false;
        assert!(best_known(&scan, &[profile]).is_none());
    }

    #[test]
    fn roaming_needs_a_margin() {
        let scan = vec![
            bss([1; 6], b"HomeNet", -60, Security::Wpa2Personal),
            bss([2; 6], b"HomeNet", -55, Security::Wpa2Personal),
        ];
        assert!(roam_target(&scan, b"HomeNet", [1; 6], -60).is_none());

        let scan = vec![
            bss([1; 6], b"HomeNet", -60, Security::Wpa2Personal),
            bss([2; 6], b"HomeNet", -40, Security::Wpa2Personal),
        ];
        assert_eq!(
            roam_target(&scan, b"HomeNet", [1; 6], -60).unwrap().bssid,
            [2; 6]
        );
    }

    /// The point of the AKM preference order: on an AP offering both, a
    /// passphrase profile joins with SAE.
    #[test]
    fn transition_mode_picks_sae() {
        let rsn = rsn_of(&[Akm::Sae, Akm::Psk], false);
        assert_eq!(choose_akm(&rsn, Some(&passphrase())), Some(Akm::Sae));
        assert_eq!(negotiated_security(Akm::Sae, false), Security::Wpa3Personal);
    }

    #[test]
    fn a_passphrase_is_no_use_on_an_enterprise_network() {
        let rsn = rsn_of(&[Akm::Dot1x], false);
        assert_eq!(choose_akm(&rsn, Some(&passphrase())), None);
    }

    /// FT is advertised beside its plain sibling on nearly every roaming AP,
    /// and keys from a hierarchy caw does not derive.
    #[test]
    fn fast_transition_is_never_chosen() {
        let rsn = rsn_of(&[Akm::FtSae, Akm::FtPsk, Akm::Psk], false);
        assert_eq!(choose_akm(&rsn, Some(&passphrase())), Some(Akm::Psk));

        let rsn = rsn_of(&[Akm::FtSae, Akm::FtPsk], false);
        assert_eq!(choose_akm(&rsn, Some(&passphrase())), None);
    }

    #[test]
    fn only_128_bit_ciphers_are_asked_for() {
        let mut rsn = rsn_of(&[Akm::Psk], false);
        rsn.pairwise_ciphers = vec![Cipher::Ccmp256, Cipher::Gcmp256, Cipher::Tkip];
        assert_eq!(choose_pairwise(&rsn), None);

        rsn.pairwise_ciphers = vec![Cipher::Tkip, Cipher::Ccmp128];
        assert_eq!(choose_pairwise(&rsn), Some(Cipher::Ccmp128));
    }

    #[test]
    fn the_ordering_puts_open_at_the_bottom() {
        assert!(is_at_least(Security::Wpa3Personal, Security::Wpa2Personal));
        assert!(!is_at_least(Security::Open, Security::Wpa2Personal));
        assert!(!is_at_least(Security::Wep, Security::Wpa2Personal));
        assert!(!is_at_least(Security::Wpa1Personal, Security::Wpa2Personal));
        assert!(is_at_least(Security::Open, Security::Open));
    }
}
