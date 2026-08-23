//! Fragmentation for the TLS-based EAP methods, RFC 5216 §3.1.
//!
//! A TLS handshake is several kilobytes; an EAP packet has to fit inside an
//! EAPOL frame on an Ethernet-sized link. EAP-TLS, PEAP and TTLS therefore
//! share one framing: a flags octet, an optional 32-bit total length, and a
//! slice of the TLS message.
//!
//! ```text
//!  0 1 2 3 4 5 6 7
//! +-+-+-+-+-+-+-+-+
//! |L M S R R R R R|   L = length included, M = more fragments, S = start
//! +-+-+-+-+-+-+-+-+   R = reserved (EAP-TLS) / version (PEAP, TTLS)
//! ```
//!
//! # Why this is not behind the `enterprise` feature
//!
//! Nothing here knows what TLS is. It is length arithmetic over a byte buffer,
//! and it is exactly the part of Enterprise that a hostile authenticator can
//! reach before any certificate has been checked — a declared length is an
//! allocation request from an unauthenticated peer. Keeping it in the default
//! build means its bounds checks are compiled and tested even when no TLS
//! stack is present.
//!
//! # Ordering
//!
//! EAP has no fragment sequence number. Ordering is guaranteed by the
//! request/response lock-step alone: the peer sends one fragment, waits for
//! the acknowledgement, sends the next. That leaves exactly one detectable
//! ordering fault, and [`Reassembler`] rejects it — a continuation fragment
//! with nothing in progress, which is what a lost or reordered first fragment
//! looks like from here.

use crate::Error;

/// The TLS Message Length field is present.
pub const FLAG_LENGTH_INCLUDED: u8 = 0x80;
/// More fragments follow; acknowledge this one.
pub const FLAG_MORE_FRAGMENTS: u8 = 0x40;
/// Start of a TLS exchange. Only an authenticator sets it.
pub const FLAG_START: u8 = 0x20;
/// The low three bits: reserved in EAP-TLS, the version number in PEAP and
/// TTLS. Kept as a mask because a peer's version has to be mirrored back.
pub const VERSION_MASK: u8 = 0x07;

/// Ceiling on a reassembled TLS message.
///
/// A TLS record is at most 16 KiB and a handshake flight is a handful of them;
/// 64 KiB is generous for a legitimate server and small enough that the
/// declared length of a hostile one cannot be turned into an allocation that
/// matters. The check happens on the *declared* length, before any memory is
/// reserved, which is the only place it is worth anything.
pub const MAX_TLS_MESSAGE: usize = 64 * 1024;

/// Bytes of TLS message per EAP packet.
///
/// Sized so an EAP-TLS packet still fits a 1500-octet link after the EAPOL,
/// EAP and fragment headers and the 802.11 encapsulation underneath, with room
/// to spare. Under-filling a fragment costs a round trip; over-filling one
/// produces an EAPOL frame the AP silently drops, which looks like a hung
/// handshake and is far harder to diagnose.
pub const DEFAULT_FRAGMENT_SIZE: usize = 1398;

/// One parsed fragment: the flags octet, the length if it carried one, and the
/// TLS bytes.
#[derive(Clone, Copy)]
pub struct Fragment<'a> {
    pub flags: u8,
    /// The total length of the message being reassembled, present only on a
    /// first fragment.
    pub declared_len: Option<u32>,
    pub data: &'a [u8],
}

impl<'a> Fragment<'a> {
    /// Parse the Type-Data of an EAP-TLS/PEAP/TTLS request.
    pub fn parse(type_data: &'a [u8]) -> Result<Self, Error> {
        let [flags, rest @ ..] = type_data else {
            return Err(Error::Malformed);
        };
        let (declared_len, data) = if flags & FLAG_LENGTH_INCLUDED != 0 {
            let (len, rest) = rest.split_at_checked(4).ok_or(Error::Malformed)?;
            (
                Some(u32::from_be_bytes(len.try_into().expect("split at 4"))),
                rest,
            )
        } else {
            (None, rest)
        };
        Ok(Self {
            flags: *flags,
            declared_len,
            data,
        })
    }

    pub fn more(&self) -> bool {
        self.flags & FLAG_MORE_FRAGMENTS != 0
    }

    pub fn start(&self) -> bool {
        self.flags & FLAG_START != 0
    }

    /// The peer's protocol version, which PEAP and TTLS expect mirrored back.
    pub fn version(&self) -> u8 {
        self.flags & VERSION_MASK
    }
}

/// Reassembles a TLS message from the fragments an authenticator sends.
#[derive(Default)]
pub struct Reassembler {
    buf: Vec<u8>,
    /// Set by the first fragment's Length field, and thereafter the only thing
    /// bounding how much a peer may make us hold.
    declared: Option<usize>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// True while fragments are outstanding.
    pub fn in_progress(&self) -> bool {
        self.declared.is_some() || !self.buf.is_empty()
    }

    /// Drop a partial message — used when the authenticator restarts the
    /// exchange with the Start flag.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.declared = None;
    }

    /// Feed one fragment. Returns the complete message once the last one
    /// arrives.
    pub fn push(&mut self, fragment: &Fragment<'_>) -> Result<Option<Vec<u8>>, Error> {
        if let Some(declared) = fragment.declared_len {
            // A length arriving mid-message means the peer restarted without
            // telling us. Accepting it would silently splice two different TLS
            // messages together; the handshake would then fail somewhere far
            // less informative.
            if self.in_progress() {
                return Err(Error::FragmentOutOfOrder);
            }
            let declared = declared as usize;
            if declared > MAX_TLS_MESSAGE {
                return Err(Error::FragmentTooLarge);
            }
            self.declared = Some(declared);
        } else if !self.in_progress() && fragment.more() {
            // A continuation with nothing to continue: the first fragment was
            // lost or reordered. RFC 5216 requires the Length field on the
            // first fragment of a fragmented message, so this cannot be a
            // legitimate opening packet.
            return Err(Error::FragmentOutOfOrder);
        }

        self.buf.extend_from_slice(fragment.data);
        match self.declared {
            Some(declared) if self.buf.len() > declared => {
                self.reset();
                return Err(Error::FragmentTooLarge);
            }
            // No Length was offered, so the ceiling is the only bound left.
            None if self.buf.len() > MAX_TLS_MESSAGE => {
                self.reset();
                return Err(Error::FragmentTooLarge);
            }
            _ => {}
        }

        if fragment.more() {
            return Ok(None);
        }
        // The last fragment has arrived; a total short of the declared length
        // means the message is truncated, and handing a truncated TLS flight
        // to the TLS stack only moves the error somewhere less specific.
        if self.declared.is_some_and(|d| self.buf.len() != d) {
            self.reset();
            return Err(Error::FragmentTooLarge);
        }
        self.declared = None;
        Ok(Some(std::mem::take(&mut self.buf)))
    }
}

/// Splits an outgoing TLS message across EAP packets.
///
/// The peer acknowledges each fragment with an empty packet, so this hands out
/// one fragment per call and the caller drives it from those acknowledgements.
pub struct Fragmenter {
    pending: Vec<u8>,
    sent: usize,
    fragment_size: usize,
}

impl Fragmenter {
    pub fn new(fragment_size: usize) -> Self {
        Self {
            pending: Vec::new(),
            sent: 0,
            fragment_size: fragment_size.max(1),
        }
    }

    /// Queue a complete TLS message for transmission.
    pub fn queue(&mut self, message: Vec<u8>) {
        self.pending = message;
        self.sent = 0;
    }

    /// True once every fragment has been handed out.
    pub fn is_empty(&self) -> bool {
        self.sent >= self.pending.len()
    }

    /// The next fragment's Type-Data, `base_flags` carrying the method's
    /// version bits.
    pub fn next(&mut self, base_flags: u8) -> Option<Vec<u8>> {
        if self.is_empty() {
            return None;
        }
        let first = self.sent == 0;
        let end = (self.sent + self.fragment_size).min(self.pending.len());
        let chunk = &self.pending[self.sent..end];
        let more = end < self.pending.len();

        let mut flags = base_flags;
        if more {
            flags |= FLAG_MORE_FRAGMENTS;
        }
        // The Length field goes on the first fragment only, and only when the
        // message is actually fragmented: sending it on a single-packet
        // message is legal but wastes four octets on every short flight.
        let include_len = first && more;
        if include_len {
            flags |= FLAG_LENGTH_INCLUDED;
        }

        let mut out = Vec::with_capacity(1 + 4 + chunk.len());
        out.push(flags);
        if include_len {
            let total = u32::try_from(self.pending.len()).expect("bounded by MAX_TLS_MESSAGE");
            out.extend_from_slice(&total.to_be_bytes());
        }
        out.extend_from_slice(chunk);

        self.sent = end;
        Some(out)
    }
}

/// The request/response lock-step EAP-TLS, PEAP and TTLS share above the TLS
/// stack.
///
/// One [`Reassembler`], one [`Fragmenter`] and the rule that decides which of
/// them a given request belongs to. It is separated from the TLS stack because
/// every fault that matters here is a framing fault — an acknowledgement that
/// carried data, a continuation with nothing to continue, a length a peer
/// should not be allowed to declare — and none of them need a certificate,
/// a key exchange or a crypto provider to provoke. Keeping this side of the
/// line means those cases are tested in the default build.
pub struct Exchange {
    inbound: Reassembler,
    outbound: Fragmenter,
    base_flags: u8,
    mirror_version: bool,
}

/// What a received request turned out to be.
pub enum Incoming {
    /// The peer is opening or restarting the exchange. Any partial message has
    /// been dropped; the TLS stack's current output is the answer.
    Restart,
    /// Send these bytes and wait — either an acknowledgement of a fragment
    /// still to come, or the next fragment of our own message.
    Reply(Vec<u8>),
    /// A complete TLS message, ready for the TLS stack.
    Message(Vec<u8>),
}

impl Exchange {
    /// `mirror_version` for PEAP and TTLS, whose version number rides in the
    /// low flag bits and has to be echoed; EAP-TLS leaves them reserved.
    pub fn new(fragment_size: usize, mirror_version: bool) -> Self {
        Self {
            inbound: Reassembler::new(),
            outbound: Fragmenter::new(fragment_size),
            base_flags: 0,
            mirror_version,
        }
    }

    /// The flags every outgoing packet starts from.
    pub fn base_flags(&self) -> u8 {
        self.base_flags
    }

    /// A packet with flags and nothing else: the acknowledgement, and the
    /// "nothing further to say" that ends an EAP-TLS exchange.
    pub fn empty_reply(&self) -> Vec<u8> {
        vec![self.base_flags]
    }

    pub fn on_request(&mut self, type_data: &[u8]) -> Result<Incoming, Error> {
        let fragment = Fragment::parse(type_data)?;
        if self.mirror_version {
            self.base_flags = fragment.version();
        }
        if fragment.start() {
            self.inbound.reset();
            return Ok(Incoming::Restart);
        }
        if !self.outbound.is_empty() {
            // We are mid-transmission, so this request is the peer
            // acknowledging our last fragment. Data here means it answered a
            // half-sent message, and continuing would interleave two flights.
            if !fragment.data.is_empty() {
                return Err(Error::FragmentOutOfOrder);
            }
            let next = self
                .outbound
                .next(self.base_flags)
                .expect("a non-empty fragmenter yields a fragment");
            return Ok(Incoming::Reply(next));
        }
        match self.inbound.push(&fragment)? {
            // More to come; the peer waits for an acknowledgement first.
            None => Ok(Incoming::Reply(self.empty_reply())),
            Some(message) => Ok(Incoming::Message(message)),
        }
    }

    /// Queue an outgoing message and take its first fragment. `None` for an
    /// empty message, which is not something to send but something to skip.
    pub fn send(&mut self, message: Vec<u8>) -> Option<Vec<u8>> {
        if message.is_empty() {
            return None;
        }
        self.outbound.queue(message);
        self.outbound.next(self.base_flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frag(flags: u8, declared: Option<u32>, data: &[u8]) -> Vec<u8> {
        let mut out = vec![flags];
        if let Some(d) = declared {
            out.extend_from_slice(&d.to_be_bytes());
        }
        out.extend_from_slice(data);
        out
    }

    fn push(r: &mut Reassembler, wire: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        r.push(&Fragment::parse(wire)?)
    }

    #[test]
    fn an_unfragmented_message_arrives_whole() {
        let mut r = Reassembler::new();
        let wire = frag(0, None, b"hello");
        assert_eq!(push(&mut r, &wire).unwrap().unwrap(), b"hello");
        assert!(!r.in_progress());
    }

    #[test]
    fn three_fragments_reassemble_in_order() {
        let mut r = Reassembler::new();
        let a = frag(FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS, Some(9), b"abc");
        let b = frag(FLAG_MORE_FRAGMENTS, None, b"def");
        let c = frag(0, None, b"ghi");

        assert!(push(&mut r, &a).unwrap().is_none());
        assert!(r.in_progress());
        assert!(push(&mut r, &b).unwrap().is_none());
        assert_eq!(push(&mut r, &c).unwrap().unwrap(), b"abcdefghi");
        assert!(!r.in_progress());
    }

    /// A continuation fragment with nothing to continue is the only ordering
    /// fault EAP's lock-step leaves visible.
    #[test]
    fn rejects_a_continuation_fragment_with_nothing_in_progress() {
        let mut r = Reassembler::new();
        let orphan = frag(FLAG_MORE_FRAGMENTS, None, b"def");
        assert!(matches!(
            push(&mut r, &orphan),
            Err(Error::FragmentOutOfOrder)
        ));
    }

    /// A second Length field mid-message would splice two TLS flights.
    #[test]
    fn rejects_a_restart_in_the_middle_of_a_message() {
        let mut r = Reassembler::new();
        let a = frag(FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS, Some(6), b"abc");
        let b = frag(FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS, Some(6), b"abc");
        assert!(push(&mut r, &a).unwrap().is_none());
        assert!(matches!(push(&mut r, &b), Err(Error::FragmentOutOfOrder)));
    }

    #[test]
    fn rejects_more_data_than_the_first_fragment_declared() {
        let mut r = Reassembler::new();
        let a = frag(FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS, Some(4), b"abc");
        let b = frag(0, None, b"defgh");
        assert!(push(&mut r, &a).unwrap().is_none());
        assert!(matches!(push(&mut r, &b), Err(Error::FragmentTooLarge)));
        // The partial message is dropped, so the next exchange starts clean.
        assert!(!r.in_progress());
    }

    #[test]
    fn rejects_a_final_fragment_short_of_the_declared_length() {
        let mut r = Reassembler::new();
        let a = frag(FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS, Some(16), b"abc");
        let b = frag(0, None, b"def");
        assert!(push(&mut r, &a).unwrap().is_none());
        assert!(matches!(push(&mut r, &b), Err(Error::FragmentTooLarge)));
    }

    /// The declared length is an allocation request from a peer that has not
    /// authenticated yet, so it is refused before a byte is reserved.
    #[test]
    fn rejects_an_absurd_declared_length() {
        let mut r = Reassembler::new();
        let wire = frag(
            FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS,
            Some(u32::MAX),
            b"a",
        );
        assert!(matches!(push(&mut r, &wire), Err(Error::FragmentTooLarge)));
    }

    /// The Length field is optional on a message that fits one packet, and
    /// leaving it out must not look like a truncated message.
    #[test]
    fn a_message_with_no_declared_length_still_completes() {
        let mut r = Reassembler::new();
        let only = frag(0, None, &[0u8; 8]);
        assert_eq!(push(&mut r, &only).unwrap().unwrap(), [0u8; 8]);
        assert!(!r.in_progress());
    }

    #[test]
    fn rejects_a_length_flag_with_no_length_behind_it() {
        assert!(matches!(
            Fragment::parse(&[FLAG_LENGTH_INCLUDED, 0, 0]),
            Err(Error::Malformed)
        ));
    }

    #[test]
    fn rejects_an_empty_type_data() {
        assert!(matches!(Fragment::parse(&[]), Err(Error::Malformed)));
    }

    #[test]
    fn version_bits_are_readable_for_mirroring() {
        let f = Fragment::parse(&[FLAG_START | 1]).unwrap();
        assert!(f.start());
        assert_eq!(f.version(), 1);
    }

    #[test]
    fn fragmenter_and_reassembler_agree() {
        let message: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let mut out = Fragmenter::new(1398);
        out.queue(message.clone());

        let mut r = Reassembler::new();
        let mut rounds = 0;
        let reassembled = loop {
            let wire = out
                .next(0)
                .expect("fragments remain until the message is whole");
            rounds += 1;
            if let Some(done) = push(&mut r, &wire).unwrap() {
                break done;
            }
            assert!(!out.is_empty(), "an acknowledged fragment was not the last");
        };
        assert_eq!(reassembled, message);
        assert_eq!(rounds, 4);
        assert!(out.is_empty());
        assert!(out.next(0).is_none());
    }

    /// A message that fits in one packet carries no Length field: four octets
    /// on every short flight is a real cost on a 1500-octet link.
    #[test]
    fn a_single_fragment_message_omits_the_length() {
        let mut out = Fragmenter::new(1398);
        out.queue(b"short".to_vec());
        let wire = out.next(0).unwrap();
        assert_eq!(wire, b"\x00short");
    }

    /// PEAP's version bits ride in the same octet as the flags and must
    /// survive fragmentation.
    #[test]
    fn base_flags_are_carried_into_every_fragment() {
        let mut out = Fragmenter::new(4);
        out.queue(b"abcdefgh".to_vec());
        let first = out.next(1).unwrap();
        let second = out.next(1).unwrap();
        assert_eq!(first[0], FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS | 1);
        assert_eq!(second[0], 1);
    }

    fn exchange_reply(step: Incoming) -> Vec<u8> {
        match step {
            Incoming::Reply(td) => td,
            Incoming::Restart => panic!("expected a reply, got a restart"),
            Incoming::Message(_) => panic!("expected a reply, got a complete message"),
        }
    }

    #[test]
    fn a_start_flag_drops_a_partial_message() {
        let mut x = Exchange::new(1398, false);
        let opening = frag(FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS, Some(9), b"abc");
        assert!(matches!(
            x.on_request(&opening).unwrap(),
            Incoming::Reply(_)
        ));
        assert!(matches!(
            x.on_request(&[FLAG_START]).unwrap(),
            Incoming::Restart
        ));
        // The half-message is gone, so a fresh single-packet message parses.
        match x.on_request(&frag(0, None, b"hello")).unwrap() {
            Incoming::Message(m) => assert_eq!(m, b"hello"),
            _ => panic!("the restart should have cleared the reassembler"),
        }
    }

    #[test]
    fn an_inbound_message_is_acknowledged_until_it_is_whole() {
        let mut x = Exchange::new(1398, false);
        let a = frag(FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS, Some(6), b"abc");
        assert_eq!(exchange_reply(x.on_request(&a).unwrap()), vec![0]);
        match x.on_request(&frag(0, None, b"def")).unwrap() {
            Incoming::Message(m) => assert_eq!(m, b"abcdef"),
            _ => panic!("the last fragment completes the message"),
        }
    }

    #[test]
    fn an_outbound_message_is_driven_by_the_peers_acknowledgements() {
        let mut x = Exchange::new(4, false);
        let first = x.send(b"abcdefgh".to_vec()).unwrap();
        assert_eq!(
            first,
            vec![
                FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS,
                0,
                0,
                0,
                8,
                b'a',
                b'b',
                b'c',
                b'd'
            ]
        );
        // An empty packet is the acknowledgement.
        assert_eq!(
            exchange_reply(x.on_request(&[0]).unwrap()),
            vec![0, b'e', b'f', b'g', b'h']
        );
        // And now the peer's next request is a real one again.
        match x.on_request(&frag(0, None, b"ok")).unwrap() {
            Incoming::Message(m) => assert_eq!(m, b"ok"),
            _ => panic!("nothing is outstanding after the last fragment"),
        }
    }

    /// A peer that answers a half-sent message rather than acknowledging it
    /// would have us interleave two flights into the TLS stack.
    #[test]
    fn rejects_data_where_an_acknowledgement_belongs() {
        let mut x = Exchange::new(4, false);
        x.send(b"abcdefgh".to_vec()).unwrap();
        assert!(matches!(
            x.on_request(&frag(0, None, b"surprise")),
            Err(Error::FragmentOutOfOrder)
        ));
    }

    #[test]
    fn an_oversized_declaration_is_refused_at_the_exchange() {
        let mut x = Exchange::new(1398, false);
        let wire = frag(
            FLAG_LENGTH_INCLUDED | FLAG_MORE_FRAGMENTS,
            Some(u32::MAX),
            b"a",
        );
        assert!(matches!(x.on_request(&wire), Err(Error::FragmentTooLarge)));
    }

    /// PEAP and TTLS carry their version in the flags octet and expect it
    /// mirrored; EAP-TLS leaves those bits reserved and must not copy them.
    #[test]
    fn the_peers_version_is_mirrored_only_when_the_method_has_one() {
        let mut peap = Exchange::new(1398, true);
        peap.on_request(&[FLAG_START | 1]).unwrap();
        assert_eq!(peap.base_flags(), 1);
        assert_eq!(peap.empty_reply(), vec![1]);

        let mut eap_tls = Exchange::new(1398, false);
        eap_tls.on_request(&[FLAG_START | 1]).unwrap();
        assert_eq!(eap_tls.base_flags(), 0);
    }

    /// An empty TLS flight is nothing to send, not an empty packet to send.
    #[test]
    fn sending_nothing_yields_no_fragment() {
        let mut x = Exchange::new(1398, false);
        assert!(x.send(Vec::new()).is_none());
    }
}
