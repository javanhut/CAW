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
//!
//! # Sans-IO
//!
//! [`FourWay`] consumes frames and returns [`Action`]s. It opens no socket and
//! reads no clock: the daemon owns the packet socket and the retransmit timer,
//! and [`socket`] is the only module here that touches either. That is what
//! lets a complete handshake — including the negative cases that matter most —
//! run as a unit test on any host, with no kernel and no radio.
#![forbid(unsafe_code)]

use caw_crypto::{KeyDescriptorVersion, Pmk, Ptk, derive_ptk};

pub mod eap;
pub mod key;
pub mod socket;

pub use eap::{Dot1xProvider, EapCode, EapPacket};
pub use key::{Gtk, KeyFrame, KeyInfo};
pub use socket::EapolSocket;

/// EtherType for EAPOL. A packet socket wants this in network byte order, for
/// which [`socket`] uses `rustix`'s pre-swapped `eth::PAE`.
pub const ETHERTYPE_EAPOL: u16 = 0x888E;

/// Protocol version, packet type, body length.
pub const EAPOL_HDR_LEN: usize = 4;

/// How long the daemon should wait before feeding us [`Input::Timeout`].
pub const RETRY_INTERVAL_MS: u32 = 1_000;

/// Retransmissions before the handshake is declared dead.
///
/// A supplicant is the reactive half of the exchange, so this is a backstop
/// rather than the main recovery path: a lost message 2 is normally repaired
/// by the authenticator resending message 1. The bound is what turns a
/// handshake that will never finish into a reported failure instead of a
/// connection that hangs.
pub const RETRY_LIMIT: u8 = 3;

/// The EAPOL packet type, IEEE 802.1X-2010 Table 11-3.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PacketType {
    /// Wraps an EAP packet — the 802.1X exchange.
    Eap = 0,
    /// A supplicant asking the authenticator to start.
    Start = 1,
    Logoff = 2,
    /// Wraps an EAPOL-Key descriptor — the 4-way handshake and group rekey.
    Key = 3,
}

impl PacketType {
    fn from_u8(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Eap),
            1 => Ok(Self::Start),
            2 => Ok(Self::Logoff),
            3 => Ok(Self::Key),
            other => Err(Error::UnsupportedPacketType(other)),
        }
    }
}

/// A decoded EAPOL frame.
pub struct Eapol<'a> {
    pub version: u8,
    pub packet_type: PacketType,
    /// The body, trimmed to the length the header declares.
    pub body: &'a [u8],
    /// Header and body together, and nothing else. This is exactly the input
    /// to an EAPOL-Key MIC, which is why the trailing padding an AP may add to
    /// reach the Ethernet minimum has to be dropped here and not later.
    pub raw: &'a [u8],
}

impl<'a> Eapol<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        let [version, packet_type, hi, lo, rest @ ..] = buf else {
            return Err(Error::Malformed);
        };
        let body_len = u16::from_be_bytes([*hi, *lo]) as usize;
        if rest.len() < body_len {
            return Err(Error::Malformed);
        }
        Ok(Self {
            version: *version,
            packet_type: PacketType::from_u8(*packet_type)?,
            body: &rest[..body_len],
            raw: &buf[..EAPOL_HDR_LEN + body_len],
        })
    }

    /// Build a frame around a body.
    pub fn encode(version: u8, packet_type: PacketType, body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(body.len()).expect("an EAPOL body is at most 64 KiB");
        let mut buf = Vec::with_capacity(EAPOL_HDR_LEN + body.len());
        buf.push(version);
        buf.push(packet_type as u8);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(body);
        buf
    }
}

/// Everything the handshake needs to know about the association it protects.
pub struct Config {
    /// Selects the PTK derivation and, with it, the whole key hierarchy.
    pub akm: caw_80211::Akm,
    pub own_mac: [u8; 6],
    /// The authenticator's address.
    pub bssid: [u8; 6],
    /// The RSN element sent in our association request, byte for byte.
    /// Message 2 has to repeat it exactly or the authenticator will abort.
    pub assoc_rsn_ie: Vec<u8>,
    /// The RSN element from the beacon or probe response, byte for byte.
    /// Message 3 has to repeat *that* exactly; see [`Error::RsnMismatch`].
    pub beacon_rsn_ie: Vec<u8>,
}

/// What the caller should feed the state machine.
pub enum Input<'a> {
    /// A complete EAPOL frame with no Ethernet header — what a `SOCK_DGRAM`
    /// packet socket delivers.
    ///
    /// The caller must only pass frames from the BSS it associated with. The
    /// handshake rejects a foreign frame at the MIC, but message 1 carries no
    /// MIC, so source filtering is the transport's job and not this one's.
    Frame(&'a [u8]),
    /// The retransmit timer the last [`Action::ArmTimer`] asked for expired.
    Timeout,
}

/// What the caller should do, in the order given.
pub enum Action {
    /// Transmit this EAPOL frame to the authenticator.
    Send(Vec<u8>),
    /// (Re)start the retransmit timer for this many milliseconds.
    ArmTimer(u32),
    /// Stop the retransmit timer; nothing is outstanding.
    DisarmTimer,
    /// The pairwise handshake finished. Install these.
    ///
    /// This always follows the [`Action::Send`] of message 4 in the same list,
    /// and the order matters: message 4 goes out unprotected, so installing
    /// the PTK first would encrypt it with a key the authenticator has not
    /// installed yet.
    Complete(Keys),
    /// A group rekey finished. Install this GTK; the pairwise key is untouched.
    NewGtk(Gtk),
}

/// Outcome of a completed handshake: the keys to install via nl80211.
pub struct Keys {
    pub ptk: Ptk,
    pub gtk: Gtk,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Nothing has arrived yet.
    Idle,
    /// Message 2 is out; waiting for message 3.
    AwaitingMsg3,
    /// The pairwise key is installed. The session stays here for the life of
    /// the connection, answering group rekeys.
    Established,
    /// Aborted. Every later input is refused so a caller that ignores an error
    /// cannot drive a half-authenticated session.
    Failed,
}

/// The 4-way handshake, and the group rekeys that follow it.
///
/// One object rather than two, because a rekey is authenticated with the very
/// PTK this handshake derived: splitting them would mean copying the KCK and
/// KEK out to a second state machine that has to be kept in step with the
/// first. Staying resident here is also the reason `cawd` exists — an
/// unanswered rekey gets the station deauthenticated within the hour.
///
/// Identical for PSK, SAE and 802.1X: only the [`Pmk`] differs.
pub struct FourWay {
    pmk: Pmk,
    config: Config,
    snonce: [u8; 32],
    anonce: [u8; 32],
    ptk: Option<Ptk>,
    /// Mirrored from the authenticator's frames. An AP may negotiate a
    /// SHA-256 AKM and still send version 2 descriptors, so this is read from
    /// the wire rather than inferred from [`Config::akm`].
    descriptor_version: KeyDescriptorVersion,
    /// Also mirrored: some authenticators are particular about the 802.1X
    /// protocol version they get back.
    protocol_version: u8,
    /// Highest replay counter accepted so far.
    rx_counter: Option<u64>,
    state: State,
    last_sent: Option<Vec<u8>>,
    retries: u8,
}

impl FourWay {
    /// Start a handshake, drawing a fresh SNonce from the kernel CSPRNG.
    ///
    /// The SNonce is generated once here rather than per message, because an
    /// authenticator that retransmits message 1 must not make the supplicant
    /// derive a second PTK for the same association.
    pub fn new(pmk: Pmk, config: Config) -> Result<Self, Error> {
        Ok(Self::with_snonce(pmk, config, random_nonce()?))
    }

    fn with_snonce(pmk: Pmk, config: Config, snonce: [u8; 32]) -> Self {
        Self {
            pmk,
            config,
            snonce,
            anonce: [0; 32],
            ptk: None,
            // Overwritten from message 1; version 2 is the WPA2/CCMP pairing
            // and only ever a placeholder here.
            descriptor_version: KeyDescriptorVersion::HmacSha1,
            protocol_version: 2,
            rx_counter: None,
            state: State::Idle,
            last_sent: None,
            retries: 0,
        }
    }

    /// Feed one input. An error aborts the handshake for good: there is no
    /// state in which a failed MIC or a replayed counter is worth retrying,
    /// and the caller's job on error is to deauthenticate.
    pub fn poll(&mut self, input: Input<'_>) -> Result<Vec<Action>, Error> {
        let result = match input {
            Input::Frame(bytes) => self.on_frame(bytes),
            Input::Timeout => self.on_timeout(),
        };
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }

    fn on_frame(&mut self, bytes: &[u8]) -> Result<Vec<Action>, Error> {
        if self.state == State::Failed {
            return Err(Error::UnexpectedMessage);
        }
        let eapol = Eapol::parse(bytes)?;
        if eapol.packet_type != PacketType::Key {
            // EAPOL-EAP belongs to the 802.1X provider, not here.
            return Ok(Vec::new());
        }
        let frame = KeyFrame::parse(eapol.body)?;
        if frame.descriptor_type != key::DESCRIPTOR_TYPE_RSN {
            return Err(Error::UnsupportedDescriptor(frame.descriptor_type));
        }

        // Only an authenticator sets Key ACK, and only a supplicant sets Key
        // Request. Dropping the rest silently rather than failing matters
        // because an unbound packet socket also sees the frames this station
        // sent (see [`socket`]), and a handshake must not abort on its own
        // echo.
        if !frame.key_info.ack() || frame.key_info.request() {
            return Ok(Vec::new());
        }

        // Every authenticator increments the counter on each frame it sends,
        // retransmissions included, so "strictly greater" is both the standard
        // behaviour and the only rule that cannot be talked into accepting a
        // captured frame a second time.
        if let Some(seen) = self.rx_counter
            && frame.replay_counter <= seen
        {
            return Err(Error::ReplayedCounter);
        }

        match (self.state, frame.key_info.pairwise(), frame.key_info.mic()) {
            // Message 1 is the one frame in the exchange with no MIC. It is
            // accepted after message 2 as well, because that is how an
            // authenticator retries, and in `Established` because that is how
            // it rekeys the pairwise key.
            (_, true, false) => self.on_msg1(&eapol, &frame),
            (State::AwaitingMsg3, true, true) => self.on_msg3(&eapol, &frame, true),
            // Message 3 again after we are established means our message 4 was
            // lost. Answer it, but do *not* hand the PTK back for a second
            // install: reinstalling a pairwise key resets its packet number
            // and replays the keystream, which is the KRACK attack.
            (State::Established, true, true) => self.on_msg3(&eapol, &frame, false),
            (State::Established, false, true) => self.on_group_msg1(&eapol, &frame),
            _ => Err(Error::UnexpectedMessage),
        }
    }

    fn on_timeout(&mut self) -> Result<Vec<Action>, Error> {
        let Some(frame) = self.last_sent.clone() else {
            // Nothing is outstanding — an established session, or a timer the
            // caller failed to disarm.
            return Ok(Vec::new());
        };
        if self.retries >= RETRY_LIMIT {
            return Err(Error::Timeout);
        }
        self.retries += 1;
        Ok(vec![
            Action::Send(frame),
            Action::ArmTimer(RETRY_INTERVAL_MS),
        ])
    }

    /// Message 1: the ANonce arrives, the PTK becomes derivable, and message 2
    /// answers with the SNonce and the RSN element from our association
    /// request.
    fn on_msg1(&mut self, eapol: &Eapol<'_>, msg1: &KeyFrame<'_>) -> Result<Vec<Action>, Error> {
        let descriptor_version = msg1.key_info.version()?;
        let ptk = derive_ptk(
            &self.pmk,
            self.config.akm,
            self.config.bssid,
            self.config.own_mac,
            &msg1.key_nonce,
            &self.snonce,
        )?;

        let msg2 = KeyFrame {
            descriptor_type: key::DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(descriptor_version.bits() | KeyInfo::PAIRWISE | KeyInfo::MIC),
            // Zero in message 2: the key length only means something on the
            // frames that describe a key being distributed.
            key_length: 0,
            replay_counter: msg1.replay_counter,
            key_nonce: self.snonce,
            key_iv: [0; 16],
            key_rsc: [0; 8],
            key_mic: [0; 16],
            key_data: &self.config.assoc_rsn_ie,
        }
        .encode_signed(eapol.version, &ptk.kck, descriptor_version);

        self.anonce = msg1.key_nonce;
        self.descriptor_version = descriptor_version;
        self.protocol_version = eapol.version;
        self.rx_counter = Some(msg1.replay_counter);
        self.ptk = Some(ptk);
        self.state = State::AwaitingMsg3;
        self.retries = 0;
        self.last_sent = Some(msg2.clone());

        Ok(vec![
            Action::Send(msg2),
            Action::ArmTimer(RETRY_INTERVAL_MS),
        ])
    }

    /// Message 3: the first frame either side can authenticate, and the one
    /// that carries the group key.
    fn on_msg3(
        &mut self,
        eapol: &Eapol<'_>,
        msg3: &KeyFrame<'_>,
        install: bool,
    ) -> Result<Vec<Action>, Error> {
        let ptk = self.ptk.as_ref().ok_or(Error::UnexpectedMessage)?;
        key::verify_frame_mic(eapol.raw, &ptk.kck, self.descriptor_version, &msg3.key_mic)?;

        // A different ANonce is a different PTK, so the MIC above could only
        // have verified if the whole exchange restarted behind our back.
        if msg3.key_nonce != self.anonce {
            return Err(Error::NonceMismatch);
        }
        if !msg3.key_info.encrypted() {
            // Key Data holds the GTK. Unwrapped, it would be readable by
            // anyone listening.
            return Err(Error::Malformed);
        }

        let key_data = caw_crypto::unwrap_key_data(&ptk.kek, msg3.key_data)?;

        // The authenticator repeats the RSN element from its own beacon here,
        // under a MIC an attacker cannot forge. Comparing it against what we
        // actually saw on the air is what closes the downgrade: an attacker
        // who rewrote the beacon to advertise a weaker cipher cannot make this
        // line agree.
        let advertised = key::rsn_element(&key_data).ok_or(Error::RsnMissing)?;
        if advertised != self.config.beacon_rsn_ie {
            return Err(Error::RsnMismatch);
        }

        let gtk = key::gtk_kde(&key_data)?;

        let msg4 = KeyFrame {
            descriptor_type: key::DESCRIPTOR_TYPE_RSN,
            key_info: KeyInfo(
                self.descriptor_version.bits() | KeyInfo::PAIRWISE | KeyInfo::MIC | KeyInfo::SECURE,
            ),
            key_length: 0,
            replay_counter: msg3.replay_counter,
            key_nonce: [0; 32],
            key_iv: [0; 16],
            key_rsc: [0; 8],
            key_mic: [0; 16],
            key_data: &[],
        }
        .encode_signed(self.protocol_version, &ptk.kck, self.descriptor_version);

        self.rx_counter = Some(msg3.replay_counter);
        self.state = State::Established;
        // Nothing to retransmit: if message 4 is lost the authenticator
        // repeats message 3, and the branch above answers it.
        self.last_sent = None;
        self.retries = 0;

        let mut actions = vec![Action::Send(msg4), Action::DisarmTimer];
        if install {
            let ptk = self.ptk.as_ref().expect("derived in message 1");
            actions.push(Action::Complete(Keys {
                ptk: Ptk {
                    kck: ptk.kck,
                    kek: ptk.kek,
                    tk: ptk.tk,
                },
                gtk,
            }));
        }
        Ok(actions)
    }

    /// Group message 1: a new GTK arrives under the same KEK. Two messages,
    /// no new pairwise key, and the reason the daemon may never exit.
    fn on_group_msg1(
        &mut self,
        eapol: &Eapol<'_>,
        msg1: &KeyFrame<'_>,
    ) -> Result<Vec<Action>, Error> {
        let ptk = self.ptk.as_ref().ok_or(Error::UnexpectedMessage)?;
        key::verify_frame_mic(eapol.raw, &ptk.kck, self.descriptor_version, &msg1.key_mic)?;
        if !msg1.key_info.encrypted() {
            return Err(Error::Malformed);
        }

        let key_data = caw_crypto::unwrap_key_data(&ptk.kek, msg1.key_data)?;
        let gtk = key::gtk_kde(&key_data)?;

        let msg2 = KeyFrame {
            descriptor_type: key::DESCRIPTOR_TYPE_RSN,
            // Key Type clear: this acknowledges a group key.
            key_info: KeyInfo(self.descriptor_version.bits() | KeyInfo::MIC | KeyInfo::SECURE),
            key_length: 0,
            replay_counter: msg1.replay_counter,
            key_nonce: [0; 32],
            key_iv: [0; 16],
            key_rsc: [0; 8],
            key_mic: [0; 16],
            key_data: &[],
        }
        .encode_signed(self.protocol_version, &ptk.kck, self.descriptor_version);

        self.rx_counter = Some(msg1.replay_counter);
        Ok(vec![Action::Send(msg2), Action::NewGtk(gtk)])
    }
}

/// 32 random octets from `getrandom`, the same source the kernel seeds its own
/// nonces from.
fn random_nonce() -> Result<[u8; 32], Error> {
    let mut nonce = [0u8; 32];
    let mut filled = 0;
    while filled < nonce.len() {
        // A signal can cut `getrandom` short; a partly filled nonce is a
        // catastrophically weak one, so keep asking.
        filled +=
            rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())?;
    }
    Ok(nonce)
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

#[derive(Debug)]
pub enum Error {
    Malformed,
    Crypto(caw_crypto::Error),
    /// The authenticator rejected us.
    Rejected,
    Io(rustix::io::Errno),
    /// An EAPOL packet type this crate does not handle.
    UnsupportedPacketType(u8),
    /// An EAP Code outside the four RFC 3748 defines.
    UnsupportedEapCode(u8),
    /// Key descriptor type 254 is WPA1's, and caw joins CCMP networks only.
    UnsupportedDescriptor(u8),
    /// A frame that does not belong in the current state.
    UnexpectedMessage,
    /// The replay counter did not advance: a captured frame played back.
    ReplayedCounter,
    /// Message 3 named a different ANonce than message 1.
    NonceMismatch,
    /// Message 3 carried no RSN element to compare against the beacon.
    RsnMissing,
    /// The RSN element in message 3 is not the one the beacon advertised — a
    /// downgrade attempt, since the two are supposed to be the same bytes.
    RsnMismatch,
    /// Message 3 or a group rekey carried no GTK.
    GtkMissing,
    /// The handshake stalled through every retransmission.
    Timeout,
    /// A TLS fragment that cannot follow the one before it: a continuation
    /// with nothing to continue, or a restart mid-message.
    FragmentOutOfOrder,
    /// A TLS fragment, or the length one declared, past what caw will hold for
    /// a peer that has not authenticated yet.
    FragmentTooLarge,
    /// EAP-Success arrived before the method produced key material. The frame
    /// is unauthenticated, so believing it would let anyone in radio range end
    /// the exchange.
    PrematureSuccess,
    /// The TLS stack refused the exchange — a bad certificate chain, most
    /// often, which is exactly the case Enterprise exists to catch.
    #[cfg(feature = "enterprise")]
    Tls(rustls::Error),
    /// `rustls` has no crypto provider installed. See
    /// [`eap::tls::provider`] for why caw does not choose one for you.
    #[cfg(feature = "enterprise")]
    NoCryptoProvider,
    /// The configured CA bundle could not be turned into a trust anchor.
    #[cfg(feature = "enterprise")]
    CertificateStore(String),
    /// Nothing has been received on the socket yet, so there is no
    /// authenticator address to answer.
    NoPeer,
    ShortSend,
}

impl From<caw_crypto::Error> for Error {
    fn from(e: caw_crypto::Error) -> Self {
        Error::Crypto(e)
    }
}

#[cfg(feature = "enterprise")]
impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e)
    }
}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed => write!(f, "malformed EAPOL frame"),
            Error::Crypto(e) => write!(f, "{e}"),
            Error::Rejected => write!(f, "the authenticator rejected this station"),
            Error::Io(e) => write!(f, "eapol io: {e}"),
            Error::UnsupportedPacketType(t) => write!(f, "unsupported EAPOL packet type {t}"),
            Error::UnsupportedEapCode(c) => write!(f, "unsupported EAP code {c}"),
            Error::UnsupportedDescriptor(t) => {
                write!(f, "unsupported EAPOL-Key descriptor type {t}")
            }
            Error::UnexpectedMessage => write!(f, "EAPOL-Key message out of sequence"),
            Error::ReplayedCounter => write!(f, "replayed EAPOL-Key counter"),
            Error::NonceMismatch => write!(f, "ANonce changed mid-handshake"),
            Error::RsnMissing => write!(f, "message 3 carried no RSN element"),
            Error::RsnMismatch => {
                write!(
                    f,
                    "RSN element does not match the beacon (downgrade attack)"
                )
            }
            Error::GtkMissing => write!(f, "no GTK in the key data"),
            Error::Timeout => write!(f, "handshake timed out"),
            Error::FragmentOutOfOrder => write!(f, "EAP-TLS fragment out of order"),
            Error::FragmentTooLarge => write!(f, "EAP-TLS fragment longer than expected"),
            Error::PrematureSuccess => {
                write!(f, "EAP-Success before the method produced key material")
            }
            #[cfg(feature = "enterprise")]
            Error::Tls(e) => write!(f, "tls: {e}"),
            #[cfg(feature = "enterprise")]
            Error::NoCryptoProvider => {
                write!(
                    f,
                    "no rustls crypto provider installed (see eap::tls::provider)"
                )
            }
            #[cfg(feature = "enterprise")]
            Error::CertificateStore(e) => write!(f, "CA certificate: {e}"),
            Error::NoPeer => write!(f, "no authenticator address learned yet"),
            Error::ShortSend => write!(f, "short EAPOL send"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
