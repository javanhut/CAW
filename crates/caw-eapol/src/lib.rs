//! EAPOL: the 4-way handshake, and 802.1X/EAP for Enterprise networks.
//!
//! Both ride EtherType 0x888E on an `AF_PACKET` socket, which is why they
//! share a crate: EAPOL-Key frames carry the 4-way handshake, EAPOL-EAP frames
//! carry the Enterprise authentication that produces the PMK the 4-way needs.
//!
//! The kernel will not do this for us. On mac80211 softmac drivers — nearly
//! every laptop — the 4-way handshake is userspace's job, and so is answering
//! the periodic group rekey. That obligation is what makes `cawd` a daemon
//! rather than a one-shot command.
#![forbid(unsafe_code)]

use caw_crypto::{AuthContext, Pmk, PmkProvider, Ptk, Step};

/// The 4-way handshake. Identical for PSK, SAE and 802.1X once a PMK exists.
pub struct FourWay {
    _pmk: Pmk,
}

/// Outcome of a completed handshake: the keys to install via nl80211.
pub struct Keys {
    pub ptk: Ptk,
    pub gtk: Vec<u8>,
    pub gtk_index: u8,
}

/// One EAP method inside an 802.1X exchange.
///
/// PEAP and TTLS are themselves containers, running an inner method over a TLS
/// tunnel, so implementations may nest.
pub trait EapMethod {
    /// EAP method type code (13 = TLS, 21 = TTLS, 25 = PEAP).
    fn type_code(&self) -> u8;

    /// Handle an EAP-Request, returning the EAP-Response payload.
    fn on_request(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// The Master Session Key, once the method has succeeded. Its first 32
    /// bytes become the PMK.
    fn msk(&self) -> Option<[u8; 64]>;
}

/// 802.1X authenticator: drives an [`EapMethod`] to obtain a PMK.
/// This is the `PostAssoc` implementation of [`PmkProvider`].
pub struct Dot1xProvider {
    _method: Box<dyn EapMethod>,
}

impl PmkProvider for Dot1xProvider {
    fn stage(&self) -> caw_crypto::AuthStage {
        caw_crypto::AuthStage::PostAssoc
    }
    fn start(&mut self, _ctx: &AuthContext<'_>) -> Result<Step, caw_crypto::Error> {
        todo!("await EAP-Request/Identity")
    }
    fn on_frame(&mut self, _ctx: &AuthContext<'_>, _f: &[u8]) -> Result<Step, caw_crypto::Error> {
        todo!("dispatch to method, MSK -> PMK on success")
    }
    fn on_timeout(&mut self, _ctx: &AuthContext<'_>) -> Result<Step, caw_crypto::Error> {
        todo!("retransmit")
    }
}

/// An `AF_PACKET` socket bound to EtherType 0x888E on one interface.
pub struct EapolSocket {
    _priv: (),
}

#[derive(Debug)]
pub enum Error {
    Malformed,
    Crypto(caw_crypto::Error),
    /// The authenticator rejected us.
    Rejected,
}
