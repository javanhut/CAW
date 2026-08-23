//! 802.1X: the [`PmkProvider`] that turns an EAP conversation into a PMK.
//!
//! # Where it sits
//!
//! 802.1X is the only PMK provider that runs *after* association, which is why
//! it is the one that lives in this crate rather than in `caw-crypto`: its
//! transport is EAPOL, the same socket and the same frame type as the 4-way
//! handshake. The daemon receives an EAPOL frame, looks at the packet type,
//! and hands type 0 here and type 3 to [`FourWay`](crate::FourWay). Each
//! ignores the other's frames rather than erroring, so the daemon needs no
//! demultiplexing logic of its own.
//!
//! # What it actually does
//!
//! Very little, deliberately. It answers Identity, it Naks methods it cannot
//! run, it forwards everything else to one [`EapMethod`], and when that method
//! produces an MSK it slices the PMK out of it. All the difficulty is in the
//! method; all the security-relevant sequencing is here.

use caw_crypto::{AuthContext, AuthStage, Pmk, PmkProvider, Step};
use zeroize::Zeroizing;

use super::packet::{EAP_HDR_LEN, EapCode, EapPacket, eap_type};
use crate::{EapMethod, Eapol, Error, PacketType, RETRY_LIMIT};

/// PMK = L(MSK, 0, 256): the first 32 octets of the Master Session Key.
///
/// IEEE 802.11-2016 12.7.1.3. The remaining 32 octets of the MSK are the EMSK
/// half, which 802.11 does not use — but the method must still produce all 64,
/// because the export that yields them is a single operation and truncating it
/// early would give a different first half.
pub fn pmk_from_msk(msk: &[u8; 64]) -> Pmk {
    let mut pmk = [0u8; 32];
    pmk.copy_from_slice(&msk[..32]);
    Pmk(pmk)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    /// Waiting for the authenticator to open the conversation.
    Running,
    /// An MSK is available and the PMK has been handed out.
    Done,
    /// Rejected or aborted. Every later input is refused, so a caller that
    /// ignores an error cannot drive a half-authenticated session.
    Failed,
}

/// 802.1X authentication, driving one [`EapMethod`] to obtain a PMK.
///
/// Frames in and out are complete EAPOL frames, exactly as
/// [`FourWay`](crate::FourWay) takes them: the packet socket delivers an EAPOL
/// frame with no Ethernet header, and that is what belongs on both sides of
/// this interface.
pub struct Dot1xProvider {
    /// Sent in EAP-Response/Identity. For a tunnelled method this is the
    /// *outer* identity, and it travels in clear text across the air — which
    /// is why PEAP and TTLS deployments set it to `anonymous` or
    /// `anonymous@realm` and keep the real username for inside the tunnel.
    identity: String,
    method: Box<dyn EapMethod>,
    state: State,
    /// The last EAPOL frame we produced, replayed when the authenticator
    /// repeats a request. Re-running the method for a duplicate request would
    /// advance a TLS handshake or consume an MSCHAPv2 challenge twice.
    last_response: Option<Vec<u8>>,
    /// The identifier `last_response` answers.
    answered: Option<u8>,
    /// Mirrored from the authenticator, like the 4-way handshake does: some
    /// authenticators are particular about the 802.1X version they get back.
    protocol_version: u8,
    /// Consecutive timeouts with no progress.
    idle_rounds: u8,
}

impl Dot1xProvider {
    pub fn new(identity: impl Into<String>, method: Box<dyn EapMethod>) -> Self {
        Self {
            identity: identity.into(),
            method,
            state: State::Running,
            last_response: None,
            answered: None,
            protocol_version: 2,
            idle_rounds: 0,
        }
    }

    /// The negotiated method's type code, for callers reporting progress.
    pub fn method_type(&self) -> u8 {
        self.method.type_code()
    }

    /// An EAPOL-Start frame, for an authenticator that waits to be prompted.
    ///
    /// Not returned by [`PmkProvider::start`], because the packet socket
    /// cannot address the authenticator until it has heard from it — see the
    /// [`socket`](crate::socket) module. A caller that has bound its socket
    /// some other way can send this immediately after association.
    pub fn eapol_start(&self) -> Vec<u8> {
        Eapol::encode(self.protocol_version, PacketType::Start, &[])
    }

    /// Wrap an EAP packet for transmission and remember it for a duplicate.
    fn reply(&mut self, identifier: u8, packet: Vec<u8>) -> Step {
        let frame = Eapol::encode(self.protocol_version, PacketType::Eap, &packet);
        self.last_response = Some(frame.clone());
        self.answered = Some(identifier);
        self.idle_rounds = 0;
        Step::Send(frame)
    }

    fn on_request(&mut self, request: &EapPacket<'_>) -> Result<Step, Error> {
        // A Request with no Type octet is malformed; RFC 3748 §4.1 requires
        // one on every Request and Response.
        let requested = request.eap_type().ok_or(Error::Malformed)?;
        let id = request.identifier;

        if requested == eap_type::IDENTITY {
            let packet = EapPacket::response(id, eap_type::IDENTITY, self.identity.as_bytes());
            return Ok(self.reply(id, packet));
        }

        if requested == eap_type::NOTIFICATION {
            // RFC 3748 §5.2: a displayable message, answered with an empty
            // Notification response. Answering matters more than displaying —
            // an unanswered request stalls the exchange.
            let packet = EapPacket::response(id, eap_type::NOTIFICATION, &[]);
            return Ok(self.reply(id, packet));
        }

        if requested != self.method.type_code() {
            // Nak rather than silence, so an authenticator that opens with a
            // method caw does not implement moves on to one it does instead of
            // timing the station out.
            let packet = EapPacket::nak(id, &[self.method.type_code()]);
            return Ok(self.reply(id, packet));
        }

        match self.method.on_request(request.type_data())? {
            Some(type_data) => {
                let packet = EapPacket::response(id, requested, &type_data);
                Ok(self.reply(id, packet))
            }
            // The method consumed the request and has nothing to say yet.
            None => Ok(Step::Wait),
        }
    }

    fn on_eap(&mut self, packet: &EapPacket<'_>) -> Result<Step, Error> {
        match packet.code {
            // Our own frames come back on an unbound packet socket; a
            // Response is never addressed to a supplicant in any case.
            EapCode::Response => Ok(Step::Wait),

            EapCode::Request => {
                if self.answered == Some(packet.identifier)
                    && let Some(frame) = self.last_response.clone()
                {
                    // A repeat of the request we already answered: our
                    // response was lost. Replaying it is the whole of EAP's
                    // recovery, and re-running the method instead would burn a
                    // challenge or desynchronise a TLS handshake.
                    self.idle_rounds = 0;
                    return Ok(Step::Send(frame));
                }
                self.on_request(packet)
            }

            EapCode::Success => {
                // An EAP-Success is carried in clear text and covered by
                // nothing. Trusting one on its own would let anyone within
                // radio range end the exchange early, so it is only honoured
                // when the method has already produced key material — and that
                // material is what the 4-way handshake then proves the AP
                // shares. A Success arriving before it is a forgery or a
                // method caw cannot key from, and neither is recoverable.
                let msk = Zeroizing::new(self.method.msk().ok_or(Error::PrematureSuccess)?);
                self.state = State::Done;
                self.last_response = None;
                Ok(Step::Done(pmk_from_msk(&msk)))
            }

            EapCode::Failure => Err(Error::Rejected),
        }
    }
}

impl PmkProvider for Dot1xProvider {
    fn stage(&self) -> AuthStage {
        AuthStage::PostAssoc
    }

    /// Nothing to send.
    ///
    /// 802.1X begins with the authenticator's EAP-Request/Identity, which an
    /// AP sends as soon as the station associates. [`Self::eapol_start`] is
    /// there for the authenticators that need prompting.
    fn start(&mut self, _ctx: &AuthContext<'_>) -> Result<Step, caw_crypto::Error> {
        Ok(Step::Wait)
    }

    fn on_frame(
        &mut self,
        _ctx: &AuthContext<'_>,
        frame: &[u8],
    ) -> Result<Step, caw_crypto::Error> {
        let result = (|| {
            let eapol = Eapol::parse(frame)?;
            if eapol.packet_type != PacketType::Eap {
                // EAPOL-Key belongs to the 4-way handshake, not here — and
                // that stays true after this provider has finished, because
                // the 4-way runs *next* on the same socket and a caller that
                // keeps feeding both must not be punished for it.
                return Ok(Step::Wait);
            }
            match self.state {
                State::Running => {}
                // An EAP frame after the PMK was handed out is the
                // authenticator opening a new conversation — a
                // reauthentication, which needs a fresh provider rather than a
                // second PMK from a method whose state is already spent.
                State::Done | State::Failed => return Err(Error::UnexpectedMessage),
            }
            self.protocol_version = eapol.version;

            // An EAPOL body shorter than an EAP header is an EAPOL-Start or
            // Logoff echo rather than something to parse.
            if eapol.body.len() < EAP_HDR_LEN {
                return Ok(Step::Wait);
            }
            let packet = EapPacket::parse(eapol.body)?;
            self.on_eap(&packet)
        })();

        if result.is_err() {
            self.state = State::Failed;
        }
        result.map_err(Into::into)
    }

    /// The authenticator owns retransmission in EAP (RFC 3748 §4.1), so a
    /// timeout here is not our cue to resend — it is the count of how long the
    /// conversation has been silent. Past the bound the exchange is dead, and
    /// saying so beats a connection attempt that never resolves.
    fn on_timeout(&mut self, _ctx: &AuthContext<'_>) -> Result<Step, caw_crypto::Error> {
        if self.state != State::Running {
            return Err(Error::UnexpectedMessage.into());
        }
        self.idle_rounds += 1;
        if self.idle_rounds > RETRY_LIMIT {
            self.state = State::Failed;
            return Err(Error::Timeout.into());
        }
        Ok(Step::Wait)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eap::frag;

    /// A method that records what it was handed and answers with a fixed
    /// script, so the dispatcher can be tested without a TLS stack.
    struct ScriptedMethod {
        type_code: u8,
        seen: Vec<Vec<u8>>,
        replies: Vec<Option<Vec<u8>>>,
        msk: Option<[u8; 64]>,
    }

    impl ScriptedMethod {
        fn new(type_code: u8) -> Self {
            Self {
                type_code,
                seen: Vec::new(),
                replies: Vec::new(),
                msk: None,
            }
        }
    }

    impl EapMethod for ScriptedMethod {
        fn type_code(&self) -> u8 {
            self.type_code
        }
        fn on_request(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            self.seen.push(data.to_vec());
            Ok(if self.replies.is_empty() {
                Some(b"ok".to_vec())
            } else {
                self.replies.remove(0)
            })
        }
        fn msk(&self) -> Option<[u8; 64]> {
            self.msk
        }
    }

    /// The method state a test wants to inspect after the provider has taken
    /// ownership of the box.
    #[derive(Clone, Default)]
    struct Shared(std::rc::Rc<std::cell::RefCell<ScriptedMethod>>);

    impl EapMethod for Shared {
        fn type_code(&self) -> u8 {
            self.0.borrow().type_code
        }
        fn on_request(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            self.0.borrow_mut().on_request(data)
        }
        fn msk(&self) -> Option<[u8; 64]> {
            self.0.borrow().msk
        }
    }

    impl Default for ScriptedMethod {
        fn default() -> Self {
            Self::new(eap_type::PEAP)
        }
    }

    fn ctx() -> AuthContext<'static> {
        AuthContext {
            ssid: b"Enterprise",
            bssid: [0x02, 0, 0, 0, 1, 0],
            own_mac: [0x02, 0, 0, 0, 2, 0],
            akm: caw_80211::Akm::Psk,
        }
    }

    fn request(id: u8, eap_type: u8, type_data: &[u8]) -> Vec<u8> {
        let mut payload = vec![eap_type];
        payload.extend_from_slice(type_data);
        let packet = EapPacket::encode(EapCode::Request, id, &payload);
        Eapol::encode(2, PacketType::Eap, &packet)
    }

    fn bare(id: u8, code: EapCode) -> Vec<u8> {
        Eapol::encode(2, PacketType::Eap, &EapPacket::encode(code, id, &[]))
    }

    /// Unwrap a `Step::Send` back into the EAP packet it carries.
    fn sent(step: Step) -> Vec<u8> {
        let Step::Send(frame) = step else {
            panic!("expected a frame to send");
        };
        let eapol = Eapol::parse(&frame).unwrap();
        assert_eq!(eapol.packet_type, PacketType::Eap);
        eapol.body.to_vec()
    }

    fn provider(shared: &Shared) -> Dot1xProvider {
        Dot1xProvider::new("anonymous@example.net", Box::new(shared.clone()))
    }

    #[test]
    fn runs_after_association_and_waits_for_the_authenticator() {
        let mut p = provider(&Shared::default());
        assert_eq!(p.stage(), AuthStage::PostAssoc);
        assert!(matches!(p.start(&ctx()), Ok(Step::Wait)));
    }

    #[test]
    fn answers_identity_with_the_configured_identity() {
        let mut p = provider(&Shared::default());
        let step = p
            .on_frame(&ctx(), &request(1, eap_type::IDENTITY, &[]))
            .unwrap();
        let body = sent(step);
        let reply = EapPacket::parse(&body).unwrap();
        assert_eq!(reply.code, EapCode::Response);
        assert_eq!(reply.identifier, 1);
        assert_eq!(reply.eap_type(), Some(eap_type::IDENTITY));
        assert_eq!(reply.type_data(), b"anonymous@example.net");
    }

    #[test]
    fn naks_a_method_it_cannot_run_and_names_the_one_it_can() {
        let mut p = provider(&Shared::default());
        // EAP-MD5, which caw does not implement.
        let step = p.on_frame(&ctx(), &request(2, 4, &[0x10])).unwrap();
        let body = sent(step);
        let reply = EapPacket::parse(&body).unwrap();
        assert_eq!(reply.eap_type(), Some(eap_type::NAK));
        assert_eq!(reply.type_data(), &[eap_type::PEAP]);
    }

    #[test]
    fn dispatches_the_negotiated_method_and_prepends_its_type() {
        let shared = Shared::default();
        let mut p = provider(&shared);
        let step = p
            .on_frame(&ctx(), &request(3, eap_type::PEAP, &[frag::FLAG_START]))
            .unwrap();
        let body = sent(step);
        let reply = EapPacket::parse(&body).unwrap();
        assert_eq!(reply.eap_type(), Some(eap_type::PEAP));
        assert_eq!(reply.type_data(), b"ok");
        // The method sees its Type-Data, not the Type octet.
        assert_eq!(shared.0.borrow().seen, vec![vec![frag::FLAG_START]]);
    }

    #[test]
    fn answers_a_notification_so_the_exchange_does_not_stall() {
        let mut p = provider(&Shared::default());
        let step = p
            .on_frame(&ctx(), &request(4, eap_type::NOTIFICATION, b"hello"))
            .unwrap();
        let body = sent(step);
        let reply = EapPacket::parse(&body).unwrap();
        assert_eq!(reply.eap_type(), Some(eap_type::NOTIFICATION));
        assert!(reply.type_data().is_empty());
    }

    /// A method with nothing to say yet must not produce an empty frame.
    #[test]
    fn a_method_that_returns_nothing_produces_no_frame() {
        let shared = Shared::default();
        shared.0.borrow_mut().replies = vec![None];
        let mut p = provider(&shared);
        assert!(matches!(
            p.on_frame(&ctx(), &request(5, eap_type::PEAP, &[0])),
            Ok(Step::Wait)
        ));
    }

    /// A repeated request must replay the answer, not re-enter the method: a
    /// second pass would advance a TLS handshake the authenticator has not
    /// seen the first half of.
    #[test]
    fn a_repeated_request_replays_the_answer_without_re_running_the_method() {
        let shared = Shared::default();
        let mut p = provider(&shared);
        let first = sent(
            p.on_frame(&ctx(), &request(6, eap_type::PEAP, &[0xaa]))
                .unwrap(),
        );
        let again = sent(
            p.on_frame(&ctx(), &request(6, eap_type::PEAP, &[0xaa]))
                .unwrap(),
        );
        assert_eq!(first, again);
        assert_eq!(shared.0.borrow().seen.len(), 1);
    }

    #[test]
    fn a_new_identifier_re_enters_the_method() {
        let shared = Shared::default();
        let mut p = provider(&shared);
        p.on_frame(&ctx(), &request(7, eap_type::PEAP, &[1]))
            .unwrap();
        p.on_frame(&ctx(), &request(8, eap_type::PEAP, &[2]))
            .unwrap();
        assert_eq!(shared.0.borrow().seen.len(), 2);
    }

    #[test]
    fn success_after_key_material_yields_the_first_half_of_the_msk() {
        let shared = Shared::default();
        let mut msk = [0u8; 64];
        for (i, b) in msk.iter_mut().enumerate() {
            *b = i as u8;
        }
        shared.0.borrow_mut().msk = Some(msk);

        let mut p = provider(&shared);
        let step = p.on_frame(&ctx(), &bare(9, EapCode::Success)).unwrap();
        let Step::Done(pmk) = step else {
            panic!("a keyed method plus EAP-Success is a completed authentication");
        };
        assert_eq!(pmk.0, msk[..32]);
    }

    /// EAP-Success is unauthenticated. Honouring one before the method has
    /// keys would let anyone in radio range end the exchange.
    #[test]
    fn rejects_a_success_that_arrives_before_any_key_material() {
        let mut p = provider(&Shared::default());
        assert!(p.on_frame(&ctx(), &bare(9, EapCode::Success)).is_err());
        // And the session is dead afterwards, not merely unsuccessful.
        assert!(
            p.on_frame(&ctx(), &request(10, eap_type::IDENTITY, &[]))
                .is_err()
        );
    }

    #[test]
    fn failure_ends_the_exchange() {
        let mut p = provider(&Shared::default());
        assert!(matches!(
            p.on_frame(&ctx(), &bare(9, EapCode::Failure)),
            Err(caw_crypto::Error::AuthFailed)
        ));
    }

    /// The daemon feeds every EAPOL frame to both state machines; each must
    /// ignore the other's. The 4-way handshake runs immediately after 802.1X
    /// on the same socket, so this has to hold after completion too.
    #[test]
    fn ignores_eapol_key_frames_before_and_after_completion() {
        let shared = Shared::default();
        shared.0.borrow_mut().msk = Some([7u8; 64]);
        let mut p = provider(&shared);
        let key_frame = Eapol::encode(2, PacketType::Key, &[0u8; 95]);

        assert!(matches!(p.on_frame(&ctx(), &key_frame), Ok(Step::Wait)));
        assert!(matches!(
            p.on_frame(&ctx(), &bare(9, EapCode::Success)),
            Ok(Step::Done(_))
        ));
        assert!(matches!(p.on_frame(&ctx(), &key_frame), Ok(Step::Wait)));
    }

    /// Our own responses come back on an unbound packet socket.
    #[test]
    fn ignores_its_own_responses() {
        let mut p = provider(&Shared::default());
        let echo = Eapol::encode(
            2,
            PacketType::Eap,
            &EapPacket::response(1, eap_type::IDENTITY, b"anonymous@example.net"),
        );
        assert!(matches!(p.on_frame(&ctx(), &echo), Ok(Step::Wait)));
    }

    #[test]
    fn mirrors_the_authenticators_protocol_version() {
        let mut p = provider(&Shared::default());
        let packet = EapPacket::encode(EapCode::Request, 1, &[eap_type::IDENTITY]);
        let frame = Eapol::encode(1, PacketType::Eap, &packet);
        let Step::Send(out) = p.on_frame(&ctx(), &frame).unwrap() else {
            panic!("identity is always answered");
        };
        assert_eq!(out[0], 1);
    }

    #[test]
    fn silence_eventually_fails_instead_of_hanging() {
        let mut p = provider(&Shared::default());
        for _ in 0..RETRY_LIMIT {
            assert!(matches!(p.on_timeout(&ctx()), Ok(Step::Wait)));
        }
        assert!(p.on_timeout(&ctx()).is_err());
    }

    #[test]
    fn rejects_a_malformed_eap_packet() {
        let mut p = provider(&Shared::default());
        // Declared length of 64 with a 1-byte payload.
        let frame = Eapol::encode(2, PacketType::Eap, &[1, 1, 0, 64, 1]);
        assert!(p.on_frame(&ctx(), &frame).is_err());
    }

    #[test]
    fn eapol_start_is_available_for_authenticators_that_need_prompting() {
        let p = provider(&Shared::default());
        let frame = p.eapol_start();
        let parsed = Eapol::parse(&frame).unwrap();
        assert_eq!(parsed.packet_type, PacketType::Start);
        assert!(parsed.body.is_empty());
    }
}
