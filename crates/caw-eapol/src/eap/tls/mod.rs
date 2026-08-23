//! EAP-TLS (RFC 5216) and the TLS tunnel PEAP and TTLS are built on.
//!
//! # Sans-IO, including the TLS
//!
//! `rustls` is driven through its buffer interface — `read_tls`,
//! `process_new_packets`, `write_tls` — rather than its `Stream` wrapper. That
//! is not a stylistic choice: there is no socket here to wrap. The TLS records
//! arrive in pieces inside EAP packets, reassembled by [`crate::eap::frag`],
//! and go back out the same way. `rustls` never learns how its bytes travel,
//! which is exactly the property that lets a whole EAP-TLS exchange be driven
//! from a test.
//!
//! # Certificate validation
//!
//! On, with the configured CA, and there is no way to build a
//! [`TlsConfig`] that skips it by accident: the field that does is named
//! [`danger_accept_any_server_certificate`](TlsConfig::danger_accept_any_server_certificate)
//! and defaults to `false`, and a config with neither a CA nor that flag is
//! rejected at build time rather than silently trusting nothing.
//!
//! This matters more here than it does on the web. The tunnel is what carries
//! the user's password — PEAP hands MSCHAPv2 a challenge/response an attacker
//! can grind offline, TTLS-PAP hands over the password in clear text inside
//! it. An unauthenticated tunnel therefore does not weaken Enterprise, it
//! inverts it: it turns "the network proves itself to you" into "you hand your
//! credentials to whoever answers first".

pub mod export;
pub mod pem;
pub mod provider;

use std::io::Read;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName, UnixTime,
};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

use super::frag::{self, Exchange, Incoming};
use super::packet::eap_type;
use crate::{EapMethod, Error};

/// A client certificate and its key, for EAP-TLS.
#[derive(Clone)]
pub struct ClientCertificate {
    /// Leaf first, then any intermediates. DER.
    pub chain: Vec<Vec<u8>>,
    /// DER, in whichever of the three encodings the PEM label named.
    pub key: PrivateKeyEncoding,
}

/// Which of the three private-key DER encodings a file held.
///
/// Kept explicit rather than guessed: all three are valid DER and telling them
/// apart by sniffing is exactly the kind of heuristic that works until someone
/// generates a key with a different tool.
#[derive(Clone)]
pub enum PrivateKeyEncoding {
    /// `-----BEGIN PRIVATE KEY-----`
    Pkcs8(Vec<u8>),
    /// `-----BEGIN RSA PRIVATE KEY-----`
    Pkcs1(Vec<u8>),
    /// `-----BEGIN EC PRIVATE KEY-----`
    Sec1(Vec<u8>),
}

impl ClientCertificate {
    /// Load a certificate chain and a key from PEM.
    pub fn from_pem(certificate_pem: &[u8], key_pem: &[u8]) -> Result<Self, Error> {
        let chain = pem::certificates(certificate_pem)?;
        let key = [
            ("PRIVATE KEY", PrivateKeyEncoding::Pkcs8 as fn(Vec<u8>) -> _),
            ("RSA PRIVATE KEY", PrivateKeyEncoding::Pkcs1),
            ("EC PRIVATE KEY", PrivateKeyEncoding::Sec1),
        ]
        .into_iter()
        .find_map(|(label, wrap)| {
            pem::blocks(key_pem, label)
                .ok()?
                .into_iter()
                .next()
                .map(wrap)
        })
        .ok_or_else(|| Error::CertificateStore("no private key block in the PEM input".into()))?;
        Ok(Self { chain, key })
    }

    fn key_der(&self) -> PrivateKeyDer<'static> {
        match &self.key {
            PrivateKeyEncoding::Pkcs8(d) => PrivatePkcs8KeyDer::from(d.clone()).into(),
            PrivateKeyEncoding::Pkcs1(d) => PrivatePkcs1KeyDer::from(d.clone()).into(),
            PrivateKeyEncoding::Sec1(d) => PrivateSec1KeyDer::from(d.clone()).into(),
        }
    }
}

/// Everything the TLS side of an Enterprise profile needs.
pub struct TlsConfig {
    /// The name the server certificate must carry. Also the SNI sent.
    pub server_name: String,
    /// Trust anchors, DER. Usually one certificate; a two-tier PKI needs both.
    pub ca_certificates: Vec<Vec<u8>>,
    /// Required by EAP-TLS, unused by PEAP and TTLS.
    pub client_certificate: Option<ClientCertificate>,
    /// Where the crypto comes from; see [`provider`].
    pub crypto_provider: Option<Arc<CryptoProvider>>,
    /// Octets of TLS message per EAP packet.
    pub fragment_size: usize,
    /// Accept any server certificate, from anyone, without checking it.
    ///
    /// This is not a "relaxed" or "permissive" mode. It removes the only thing
    /// standing between the user's credentials and any radio in range that
    /// answers to the SSID, and it exists solely so an operator debugging a
    /// misissued certificate can say so out loud. Never a default, and never
    /// reachable without writing this field's name.
    pub danger_accept_any_server_certificate: bool,
}

impl TlsConfig {
    /// A config that validates. The CA has to be supplied before it will
    /// build.
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            ca_certificates: Vec::new(),
            client_certificate: None,
            crypto_provider: None,
            fragment_size: frag::DEFAULT_FRAGMENT_SIZE,
            danger_accept_any_server_certificate: false,
        }
    }

    /// Add every certificate in a PEM bundle as a trust anchor.
    pub fn with_ca_pem(mut self, pem_bytes: &[u8]) -> Result<Self, Error> {
        self.ca_certificates.extend(pem::certificates(pem_bytes)?);
        Ok(self)
    }

    /// `tls12_only` for PEAP and TTLS: both predate TLS 1.3 and neither has a
    /// specification for running over it, so offering it would produce a
    /// tunnel whose key export nobody agrees on.
    fn build(&self, tls12_only: bool) -> Result<Arc<ClientConfig>, Error> {
        let provider = provider::resolve(self.crypto_provider.clone())?;

        let versions = ClientConfig::builder_with_provider(provider.clone());
        let versions = if tls12_only {
            versions.with_protocol_versions(&[&rustls::version::TLS12])
        } else {
            versions.with_safe_default_protocol_versions()
        }?;

        let verifier = if self.danger_accept_any_server_certificate {
            versions
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCertificate { provider }))
        } else {
            let mut roots = RootCertStore::empty();
            for der in &self.ca_certificates {
                roots
                    .add(CertificateDer::from(der.clone()))
                    .map_err(|e| Error::CertificateStore(e.to_string()))?;
            }
            if roots.is_empty() {
                // An empty root store is not "trust the system store", it is
                // "trust nothing", and it fails at the handshake with an error
                // about the server's certificate. Saying so here instead keeps
                // a missing config file from reading as a hostile AP.
                return Err(Error::CertificateStore(
                    "no CA certificate configured; Enterprise cannot validate the server".into(),
                ));
            }
            versions.with_root_certificates(roots)
        };

        let config = match &self.client_certificate {
            Some(cert) => {
                let chain = cert
                    .chain
                    .iter()
                    .map(|d| CertificateDer::from(d.clone()))
                    .collect();
                verifier.with_client_auth_cert(chain, cert.key_der())?
            }
            None => verifier.with_no_client_auth(),
        };
        Ok(Arc::new(config))
    }
}

/// The verifier behind [`TlsConfig::danger_accept_any_server_certificate`].
///
/// Signature verification is still real — only the chain and the name are
/// skipped — because a verifier that accepted forged signatures would break
/// the handshake rather than merely make it meaningless.
#[derive(Debug)]
struct AcceptAnyServerCertificate {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// What the tunnel wants done with the request it was just given.
pub enum TunnelEvent {
    /// Answer with this Type-Data. Already carries its flags octet.
    Reply(Vec<u8>),
    /// The handshake is finished and there are no TLS bytes outstanding.
    /// `plaintext` is whatever arrived inside the tunnel, which is empty for
    /// EAP-TLS and carries the inner method for PEAP and TTLS.
    Established { plaintext: Vec<u8> },
}

/// The TLS half of EAP-TLS, PEAP and TTLS: fragments in, TLS records out.
///
/// A thin shell. Everything about *framing* lives in
/// [`super::frag::Exchange`], which needs no TLS stack and is tested
/// without one; what is left here is the part that genuinely cannot be
/// separated from `rustls` — feeding it bytes and taking back what it wants to
/// say.
pub struct Tunnel {
    conn: ClientConnection,
    exchange: Exchange,
}

impl Tunnel {
    /// For EAP-TLS: every protocol version the provider offers, including
    /// TLS 1.3, which RFC 9190 specifies for this method and this method only.
    /// The reserved bits stay zero rather than mirroring the peer.
    pub fn new_any_version(cfg: &TlsConfig) -> Result<Self, Error> {
        Self::build(cfg, false, false)
    }

    /// For PEAP and TTLS: TLS 1.2 only, and the peer's version number is
    /// mirrored back in the low three flag bits.
    pub fn new_tls12(cfg: &TlsConfig) -> Result<Self, Error> {
        Self::build(cfg, true, true)
    }

    fn build(cfg: &TlsConfig, tls12_only: bool, mirror_version: bool) -> Result<Self, Error> {
        let name = ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| Error::CertificateStore(e.to_string()))?;
        Ok(Self {
            conn: ClientConnection::new(cfg.build(tls12_only)?, name)?,
            exchange: Exchange::new(cfg.fragment_size, mirror_version),
        })
    }

    pub fn connection(&self) -> &ClientConnection {
        &self.conn
    }

    pub fn handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// An empty packet: EAP-TLS's acknowledgement, and its "I have nothing
    /// more to say" at the end of the handshake.
    pub fn empty_reply(&self) -> Vec<u8> {
        self.exchange.empty_reply()
    }

    /// Feed one EAP-TLS/PEAP/TTLS Type-Data.
    pub fn on_request(&mut self, type_data: &[u8]) -> Result<TunnelEvent, Error> {
        match self.exchange.on_request(type_data)? {
            // The authenticator is opening (or restarting) the exchange.
            // `rustls` already holds the ClientHello it built at construction.
            Incoming::Restart => {}
            Incoming::Reply(type_data) => return Ok(TunnelEvent::Reply(type_data)),
            Incoming::Message(message) => {
                let mut cursor = message.as_slice();
                while !cursor.is_empty() {
                    // `read_tls` takes only what fits in its buffer, so a
                    // multi-record flight needs more than one pass.
                    let taken = self
                        .conn
                        .read_tls(&mut cursor)
                        .map_err(|_| Error::Malformed)?;
                    if taken == 0 {
                        break;
                    }
                    self.conn.process_new_packets()?;
                }
            }
        }
        self.flush_or_established()
    }

    /// Push plaintext into the tunnel and return the first fragment of the
    /// records it produced.
    pub fn send_tunnelled(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        std::io::Write::write_all(&mut self.conn.writer(), plaintext)
            .map_err(|_| Error::Malformed)?;
        let records = self.drain_tls()?;
        self.exchange.send(records).ok_or(Error::UnexpectedMessage)
    }

    /// Close the tunnel down, which RFC 9190 requires of an EAP-TLS 1.3 client
    /// once the server has committed to a result.
    pub fn close_notify(&mut self) -> Result<Vec<u8>, Error> {
        self.conn.send_close_notify();
        let records = self.drain_tls()?;
        Ok(self
            .exchange
            .send(records)
            .unwrap_or_else(|| self.empty_reply()))
    }

    /// Everything `rustls` currently wants on the wire.
    fn drain_tls(&mut self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn
                .write_tls(&mut out)
                .map_err(|_| Error::UnexpectedMessage)?;
        }
        Ok(out)
    }

    /// Everything the peer sent inside the tunnel, if anything.
    fn drain_plaintext(&mut self) -> Result<Vec<u8>, Error> {
        let mut plaintext = Vec::new();
        let mut chunk = [0u8; 2048];
        loop {
            match self.conn.reader().read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => plaintext.extend_from_slice(&chunk[..n]),
                // The tunnel is open and simply has nothing buffered.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return Err(Error::Malformed),
            }
        }
        Ok(plaintext)
    }

    fn flush_or_established(&mut self) -> Result<TunnelEvent, Error> {
        let records = self.drain_tls()?;
        if let Some(first) = self.exchange.send(records) {
            return Ok(TunnelEvent::Reply(first));
        }
        if self.conn.is_handshaking() {
            // Nothing to send and not finished: the peer is still talking, so
            // acknowledge and wait rather than treating it as an error.
            return Ok(TunnelEvent::Reply(self.empty_reply()));
        }
        Ok(TunnelEvent::Established {
            plaintext: self.drain_plaintext()?,
        })
    }
}

/// EAP-TLS, type 13. Mutual certificate authentication with no inner method.
pub struct EapTls {
    tunnel: Tunnel,
    msk: Option<[u8; export::MSK_LEN]>,
}

impl EapTls {
    pub fn new(config: &TlsConfig) -> Result<Self, Error> {
        Ok(Self {
            // EAP-TLS is the one method RFC 9190 covers, so TLS 1.3 is offered.
            tunnel: Tunnel::new_any_version(config)?,
            msk: None,
        })
    }
}

impl EapMethod for EapTls {
    fn type_code(&self) -> u8 {
        eap_type::TLS
    }

    fn on_request(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self.tunnel.on_request(data)? {
            TunnelEvent::Reply(type_data) => Ok(Some(type_data)),
            TunnelEvent::Established { plaintext } => {
                if self.msk.is_none() {
                    self.msk = Some(export::export_msk(
                        self.tunnel.connection(),
                        eap_type::TLS,
                        export::TLS12_LABEL_EAP_TLS,
                    )?);
                }
                // RFC 9190 §2.5: under TLS 1.3 the server commits to its
                // result with a single protected octet inside the tunnel, and
                // the client answers by closing the tunnel. Under TLS 1.2 the
                // handshake itself was the last word and the client just sends
                // an empty packet.
                if plaintext.is_empty() {
                    Ok(Some(self.tunnel.empty_reply()))
                } else {
                    Ok(Some(self.tunnel.close_notify()?))
                }
            }
        }
    }

    fn msk(&self) -> Option<[u8; 64]> {
        self.msk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Validation is the default and stays the default; a config that cannot
    /// validate must fail to build rather than fall back to trusting nothing.
    #[test]
    fn a_config_with_no_ca_refuses_to_build() {
        let cfg = TlsConfig::new("radius.example.net");
        assert!(!cfg.danger_accept_any_server_certificate);
        // Reached before the provider lookup would have failed, because a
        // missing CA is the more specific complaint of the two.
        match cfg.build(false) {
            Err(Error::CertificateStore(_)) | Err(Error::NoCryptoProvider) => {}
            _ => panic!("a config with no trust anchor must not build"),
        }
    }

    #[test]
    fn the_insecure_switch_has_to_be_named_to_be_reached() {
        let mut cfg = TlsConfig::new("radius.example.net");
        cfg.danger_accept_any_server_certificate = true;
        // Without a provider nothing builds, which is the point of
        // `provider`: the failure is loud and specific.
        assert!(matches!(cfg.build(false), Err(Error::NoCryptoProvider)));
    }

    /// All three methods compose into the provider, and all three report a
    /// missing crypto provider rather than quietly picking one.
    #[test]
    fn every_method_reports_a_missing_provider() {
        let mut cfg = TlsConfig::new("radius.example.net");
        // Isolate the provider error from the missing-CA one.
        cfg.danger_accept_any_server_certificate = true;
        assert!(matches!(EapTls::new(&cfg), Err(Error::NoCryptoProvider)));
        assert!(matches!(
            super::super::peap::Peap::new(&cfg, "user", "pass"),
            Err(Error::NoCryptoProvider)
        ));
        assert!(matches!(
            super::super::ttls::Ttls::new(&cfg, "user", "pass"),
            Err(Error::NoCryptoProvider)
        ));
    }

    /// Compile-time only: an EAP method is a trait object the 802.1X provider
    /// accepts, which is the whole contract between this module and `dot1x`.
    fn _methods_are_drivable(method: Box<dyn EapMethod>) -> crate::Dot1xProvider {
        crate::Dot1xProvider::new("anonymous@example.net", method)
    }

    #[test]
    fn a_ca_bundle_loads_from_pem() {
        let pem = b"-----BEGIN CERTIFICATE-----\nTWFu\n-----END CERTIFICATE-----\n";
        let cfg = TlsConfig::new("radius.example.net")
            .with_ca_pem(pem)
            .unwrap();
        assert_eq!(cfg.ca_certificates, vec![b"Man".to_vec()]);
    }
}
