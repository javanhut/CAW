//! WPA2/WPA3-Personal pre-shared keys.
//!
//! The whole method is one PBKDF2 call, which is why [`PskProvider`] answers
//! `Local` and never touches the wire. The cost of that call is deliberate:
//! 4096 iterations is what stands between a captured handshake and an offline
//! dictionary attack, so it is not something the caller may tune.

use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::{AuthContext, AuthStage, Error, Pmk, PmkProvider, Step};

/// Iteration count fixed by IEEE 802.11 for the passphrase-to-PSK mapping.
const ITERATIONS: u32 = 4096;

/// PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256).
///
/// The salt is the raw SSID with no length prefix and no padding. That is the
/// reason a PMK can be precomputed per network name: two APs sharing an SSID
/// and a passphrase share a PMK, whoever operates them.
pub fn derive_pmk(passphrase: &str, ssid: &[u8]) -> Pmk {
    let mut pmk = [0u8; 32];
    pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), ssid, ITERATIONS, &mut pmk);
    Pmk(pmk)
}

/// WPA2-Personal: the PMK comes straight from the passphrase and the SSID.
pub struct PskProvider {
    passphrase: Zeroizing<String>,
}

impl PskProvider {
    pub fn new(passphrase: impl Into<String>) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase.into()),
        }
    }
}

impl PmkProvider for PskProvider {
    fn stage(&self) -> AuthStage {
        AuthStage::Local
    }

    fn start(&mut self, ctx: &AuthContext<'_>) -> Result<Step, Error> {
        Ok(Step::Done(derive_pmk(&self.passphrase, ctx.ssid)))
    }

    /// A `Local` provider asks for nothing, so nothing can be a reply to it.
    fn on_frame(&mut self, _ctx: &AuthContext<'_>, _frame: &[u8]) -> Result<Step, Error> {
        Err(Error::Protocol)
    }

    /// Likewise there is no exchange to retransmit; [`Self::start`] already
    /// returned the answer.
    fn on_timeout(&mut self, _ctx: &AuthContext<'_>) -> Result<Step, Error> {
        Err(Error::Protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn ctx<'a>(ssid: &'a [u8]) -> AuthContext<'a> {
        AuthContext {
            ssid,
            bssid: [0; 6],
            own_mac: [0; 6],
            akm: caw_80211::Akm::Psk,
        }
    }

    /// IEEE 802.11i-2004 Annex H.4.2, the reference passphrase mapping.
    #[test]
    fn ieee_80211i_passphrase_vectors() {
        assert_eq!(
            derive_pmk("password", b"IEEE").0[..],
            hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")[..]
        );
        assert_eq!(
            derive_pmk("ThisIsAPassword", b"ThisIsASSID").0[..],
            hex("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")[..]
        );
    }

    /// The salt is the SSID bytes as they appear in the beacon, so an SSID that
    /// is not valid UTF-8 must still derive a key.
    #[test]
    fn ssid_is_raw_bytes() {
        let a = derive_pmk("password", &[0xff, 0x00, 0x80]);
        let b = derive_pmk("password", &[0xff, 0x00, 0x81]);
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn provider_answers_immediately() {
        let mut p = PskProvider::new("password");
        assert_eq!(p.stage(), AuthStage::Local);
        match p.start(&ctx(b"IEEE")).unwrap() {
            Step::Done(pmk) => assert_eq!(
                pmk.0[..],
                hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")[..]
            ),
            _ => panic!("a local provider must not ask to send or wait"),
        }
    }

    #[test]
    fn provider_rejects_frames_and_timeouts() {
        let mut p = PskProvider::new("password");
        assert!(matches!(
            p.on_frame(&ctx(b"IEEE"), &[1, 2, 3]),
            Err(Error::Protocol)
        ));
        assert!(matches!(p.on_timeout(&ctx(b"IEEE")), Err(Error::Protocol)));
    }
}
