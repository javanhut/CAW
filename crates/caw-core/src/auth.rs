//! Turning a credential and an AKM into the thing that produces a PMK.
//!
//! Every WPA flavour ends at the same 256-bit key; what differs is who derives
//! it and when. This module makes that choice once, at the moment a BSS is
//! picked, and hands [`Connection`](crate::Connection) something whose
//! [`AuthStage`] says where in the association it runs.
//!
//! # Offload
//!
//! Some fullmac devices will run the 4-way handshake, or SAE, in firmware and
//! advertise it in `NL80211_ATTR_EXT_FEATURES`. When they do, caw hands the
//! credential to the kernel at association time and runs no state machine at
//! all — the connection goes straight from `Associating` to `Configuring`,
//! because by the time the kernel reports the association the keys are already
//! installed.

use caw_80211::Akm;
use caw_crypto::{AuthContext, AuthStage, Pmk, PmkProvider, PskProvider, SaeProvider, Step};
use zeroize::Zeroizing;

use crate::conn::Failure;
use crate::profile::{Credential, Secret};

/// What a wireless device will do for itself.
///
/// Only the bits that change caw's behaviour. Everything else about a wiphy is
/// the daemon's business, not policy's.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct DeviceCaps {
    /// `NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK`.
    pub offloads_4way_psk: bool,
    /// `NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X`. Not used: the kernel wants
    /// the PMK at association time, and 802.1X does not produce one until
    /// after the station has associated. Recorded so the reason is visible
    /// rather than the capability merely forgotten.
    pub offloads_4way_1x: bool,
    /// `NL80211_EXT_FEATURE_SAE_OFFLOAD`.
    pub offloads_sae: bool,
}

impl From<&caw_nl80211::Wiphy> for DeviceCaps {
    fn from(wiphy: &caw_nl80211::Wiphy) -> Self {
        Self {
            offloads_4way_psk: wiphy.offloads_4way_psk,
            offloads_4way_1x: wiphy.offloads_4way_1x,
            offloads_sae: wiphy.offloads_sae,
        }
    }
}

/// A credential handed to the kernel instead of being used here.
///
/// Note that `caw-nl80211`'s `Connect` has no field for either attribute yet;
/// the decision belongs to this crate regardless, and the transport can catch
/// up without anything above it changing.
pub enum Offload {
    /// `NL80211_ATTR_PMK`: the device runs the 4-way handshake.
    Pmk(Zeroizing<[u8; 32]>),
    /// `NL80211_ATTR_SAE_PASSWORD`: the device runs SAE and the handshake.
    SaePassword(Secret),
}

/// How this association will be authenticated, and how far that has got.
pub(crate) enum Auth {
    /// Nothing to prove and nothing to install.
    Open,
    /// The device does it; see [`Offload`].
    Offloaded(Offload),
    /// Runs before association, over 802.11 authentication frames.
    ///
    /// The concrete type, not `Box<dyn PmkProvider>`, because SAE is the only
    /// pre-association method and the association request has to name the PMK
    /// it derived by its PMKID — which the trait has no way to return.
    PreAssoc(Box<SaeProvider>),
    /// Runs after association, over EAPOL (802.1X).
    PostAssoc(Box<dyn PmkProvider>),
    /// The key is in hand: a local provider answered at once, or a staged one
    /// has finished.
    Ready(Pmk),
    /// The key has been handed to the 4-way handshake, which owns it now.
    Running,
}

/// Build the authentication for one association.
///
/// `ctx` names the pair of addresses and the SSID, which a PSK hashes and SAE
/// binds its password element to, so it has to be the BSS actually chosen and
/// not the network in general.
pub(crate) fn assemble(
    akm: Akm,
    credential: &Credential,
    caps: DeviceCaps,
    ctx: &AuthContext<'_>,
) -> Result<Auth, Failure> {
    let provider: Box<dyn PmkProvider> = match credential {
        Credential::None => return Ok(Auth::Open),

        Credential::Passphrase(secret) if akm.is_sae() => {
            if caps.offloads_sae {
                return Ok(Auth::Offloaded(Offload::SaePassword(secret.clone())));
            }
            let provider = SaeProvider::new(secret.as_str());
            debug_assert_eq!(provider.stage(), AuthStage::PreAssoc);
            return Ok(Auth::PreAssoc(Box::new(provider)));
        }

        Credential::Passphrase(secret) if akm.is_psk() => {
            let mut psk = PskProvider::new(secret.as_str());
            // A local provider answers from `start`, so the PMK exists before
            // anything has been sent — which is what lets it be handed to a
            // device that offloads the handshake.
            let Step::Done(pmk) = psk.start(ctx).map_err(Failure::from_crypto)? else {
                return Err(Failure::Internal(
                    "a local provider asked to send or wait".into(),
                ));
            };
            return Ok(if caps.offloads_4way_psk {
                Auth::Offloaded(Offload::Pmk(Zeroizing::new(pmk.0)))
            } else {
                Auth::Ready(pmk)
            });
        }

        Credential::Enterprise {
            identity,
            anonymous_identity,
            server_name,
            method,
            ca_cert,
        } if akm.is_enterprise() => enterprise(
            identity,
            anonymous_identity.as_deref(),
            server_name.as_deref(),
            method,
            ca_cert.as_deref(),
        )?,

        // The credential does not match the AKM policy chose, which can only
        // happen if the two disagreed about what this network is.
        _ => return Err(Failure::UnsupportedSecurity),
    };

    Ok(match provider.stage() {
        AuthStage::PostAssoc => Auth::PostAssoc(provider),
        // Both handled above: a local provider so that the PMK it returns can
        // be offloaded, SAE so that its PMKID stays reachable.
        AuthStage::Local | AuthStage::PreAssoc => {
            return Err(Failure::Internal(format!(
                "provider for {akm} runs at a stage this crate does not stage here"
            )));
        }
    })
}

/// 802.1X, with the EAP method the profile names inside it.
///
/// # The one impure corner of a decision
///
/// Trust anchors and client certificates are paths in a profile, and this
/// reads them. It is the only place in this crate where a call from inside
/// [`Connection::poll`](crate::Connection::poll) touches the filesystem. The
/// alternative — storing PEM in the profile — takes the trust anchor out of
/// the operator's hands, and passing bytes in from the daemon would put a
/// decision about which file to read outside the crate that makes decisions.
#[cfg(feature = "enterprise")]
fn enterprise(
    identity: &str,
    anonymous_identity: Option<&str>,
    server_name: Option<&str>,
    method: &crate::profile::EnterpriseMethod,
    ca_cert: Option<&std::path::Path>,
) -> Result<Box<dyn PmkProvider>, Failure> {
    use caw_eapol::eap::{EapTls, Peap, TlsConfig, Ttls};
    use caw_eapol::{Dot1xProvider, EapMethod};

    use crate::profile::EnterpriseMethod;

    // Without a name to check, certificate validation has nothing to compare
    // against, and an unverified RADIUS server is one that collects the
    // credential it is handed. The realm is the conventional fallback.
    let name = server_name
        .or_else(|| realm_of(anonymous_identity.unwrap_or(identity)))
        .ok_or_else(|| {
            Failure::Enterprise("no server_name in the profile and no realm in the identity".into())
        })?;

    let mut config = TlsConfig::new(name);
    let ca = ca_cert.ok_or_else(|| Failure::Enterprise("no ca_cert in the profile".into()))?;
    let pem =
        std::fs::read(ca).map_err(|e| Failure::Enterprise(format!("{}: {e}", ca.display())))?;
    config = config
        .with_ca_pem(&pem)
        .map_err(|e| Failure::Enterprise(e.to_string()))?;

    let method: Box<dyn EapMethod> = match method {
        EnterpriseMethod::Peap { password } => Box::new(
            Peap::new(&config, identity, password.as_str())
                .map_err(|e| Failure::Enterprise(e.to_string()))?,
        ),
        EnterpriseMethod::Ttls { password } => Box::new(
            Ttls::new(&config, identity, password.as_str())
                .map_err(|e| Failure::Enterprise(e.to_string()))?,
        ),
        EnterpriseMethod::Tls { client_cert, key } => {
            let cert = std::fs::read(client_cert)
                .map_err(|e| Failure::Enterprise(format!("{}: {e}", client_cert.display())))?;
            let key_pem = std::fs::read(key)
                .map_err(|e| Failure::Enterprise(format!("{}: {e}", key.display())))?;
            config.client_certificate = Some(
                caw_eapol::eap::tls::ClientCertificate::from_pem(&cert, &key_pem)
                    .map_err(|e| Failure::Enterprise(e.to_string()))?,
            );
            Box::new(EapTls::new(&config).map_err(|e| Failure::Enterprise(e.to_string()))?)
        }
    };

    // The outer identity crosses the air in clear text, so a profile with an
    // anonymous one sends that and keeps the real name for inside the tunnel.
    let outer = anonymous_identity.unwrap_or(identity);
    Ok(Box::new(Dot1xProvider::new(outer, method)))
}

/// The part of `user@example.org` after the `@`.
#[cfg(feature = "enterprise")]
fn realm_of(identity: &str) -> Option<&str> {
    identity
        .split_once('@')
        .map(|(_, realm)| realm)
        .filter(|r| !r.is_empty())
}

/// Without the `enterprise` feature there is no TLS stack in the tree, so an
/// Enterprise profile still loads and still says plainly why it cannot be
/// joined.
#[cfg(not(feature = "enterprise"))]
fn enterprise(
    _identity: &str,
    _anonymous_identity: Option<&str>,
    _server_name: Option<&str>,
    _method: &crate::profile::EnterpriseMethod,
    _ca_cert: Option<&std::path::Path>,
) -> Result<Box<dyn PmkProvider>, Failure> {
    Err(Failure::Enterprise(
        "this build has no 802.1X support; rebuild with the `enterprise` feature".into(),
    ))
}
