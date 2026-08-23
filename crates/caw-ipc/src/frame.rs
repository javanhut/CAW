//! Newline-delimited JSON framing, for both ends of the socket.
//!
//! A newline is a safe delimiter here because JSON escapes the one inside a
//! string as `\n`: a raw `0x0A` in the stream can only be the end of a
//! message, so framing needs no length prefix and a human can read the wire
//! with `socat`.
//!
//! [`Decoder`] is the half `cawd` needs — it takes whatever a non-blocking
//! read produced, however the bytes happened to be split, and yields whole
//! messages. [`read`] is the blocking convenience the CLI wants instead.

use std::io::{BufRead, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroize;

/// Longest message [`Decoder`] will buffer before giving up on the peer.
///
/// The socket is reachable by every user on the machine, so an unterminated
/// line is a way to make the daemon allocate without bound. A megabyte is far
/// past anything the protocol sends — the largest is a scan of a few hundred
/// networks.
pub const MAX_LINE: usize = 1 << 20;

/// Serialize one message, newline included.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, Error> {
    let mut buf = serde_json::to_vec(msg)?;
    buf.push(b'\n');
    Ok(buf)
}

/// Write one message and flush it.
///
/// Flushing matters: a request the peer is waiting on that sits in a buffer
/// looks exactly like a daemon that has hung.
pub fn write<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), Error> {
    w.write_all(&encode(msg)?)?;
    w.flush()?;
    Ok(())
}

/// Read one message, blocking. `None` at end of stream.
///
/// Blank lines are skipped rather than rejected, so a stream that was hand
/// written or `cat`ed still parses.
pub fn read<R: BufRead, T: DeserializeOwned>(r: &mut R) -> Result<Option<T>, Error> {
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return Ok(Some(serde_json::from_str(trimmed)?));
    }
}

/// Reassembles messages from arbitrarily chopped-up reads.
///
/// One per connection: it holds the tail of a message whose newline has not
/// arrived yet.
pub struct Decoder {
    buf: Vec<u8>,
    limit: usize,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self::with_limit(MAX_LINE)
    }

    pub fn with_limit(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit,
        }
    }

    /// Add bytes just read from the socket.
    pub fn extend(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Bytes held back waiting for a newline.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// The next complete message, if one has arrived.
    ///
    /// An error is about the peer, not the connection: the offending line has
    /// already been consumed, so a caller that reports it can carry on with
    /// the next message. [`Error::TooLong`] is the exception — nothing is left
    /// to resynchronise on, and the caller should close the connection.
    // Not `Iterator::next`, and cannot be: the caller names the type it wants
    // per call, since the daemon reads `Request`s off a connection and the CLI
    // reads `ServerMessage`s off the same kind of stream.
    #[allow(clippy::should_implement_trait)]
    pub fn next<T: DeserializeOwned>(&mut self) -> Option<Result<T, Error>> {
        loop {
            let Some(newline) = self.buf.iter().position(|&b| b == b'\n') else {
                if self.buf.len() > self.limit {
                    self.clear();
                    return Some(Err(Error::TooLong));
                }
                return None;
            };

            // Tolerate CRLF, which is what a peer written against a text
            // protocol tends to send.
            let end = match self.buf[..newline].last() {
                Some(b'\r') => newline - 1,
                _ => newline,
            };
            let line = &self.buf[..end];
            let parsed = if line.iter().all(|b| b.is_ascii_whitespace()) {
                None
            } else {
                Some(serde_json::from_slice::<T>(line).map_err(Error::Json))
            };

            // Wipe before discarding: a `Secret` request would otherwise sit
            // in this buffer's spare capacity until something overwrote it.
            self.buf[..=newline].zeroize();
            self.buf.drain(..=newline);

            if let Some(result) = parsed {
                return Some(result);
            }
        }
    }

    fn clear(&mut self) {
        self.buf.zeroize();
        self.buf.clear();
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// A line exceeded [`MAX_LINE`] with no newline in sight.
    TooLong,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "ipc io: {e}"),
            Self::Json(e) => write!(f, "malformed message: {e}"),
            Self::TooLong => write!(f, "message longer than {MAX_LINE} bytes"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::TooLong => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, Request, Response, Secret, ServerMessage};

    #[test]
    fn encode_terminates_with_exactly_one_newline() {
        let bytes = encode(&Request::Status).unwrap();
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn decodes_two_messages_from_one_read() {
        let mut dec = Decoder::new();
        dec.extend(&encode(&Request::Status).unwrap());
        dec.extend(&encode(&Request::ListPorts).unwrap());

        assert!(matches!(dec.next::<Request>(), Some(Ok(Request::Status))));
        assert!(matches!(
            dec.next::<Request>(),
            Some(Ok(Request::ListPorts))
        ));
        assert!(dec.next::<Request>().is_none());
        assert_eq!(dec.pending(), 0);
    }

    /// The reason the decoder exists: a non-blocking read can stop anywhere,
    /// including inside a UTF-8 sequence or a JSON string.
    #[test]
    fn reassembles_a_message_fed_one_byte_at_a_time() {
        let wire = encode(&Request::Connect {
            ssid: "Häuser".into(),
            port: Some("wlan0".into()),
        })
        .unwrap();

        let mut dec = Decoder::new();
        let (last, head) = wire.split_last().unwrap();
        for byte in head {
            dec.extend(&[*byte]);
            assert!(
                dec.next::<Request>().is_none(),
                "decoded before the newline arrived"
            );
        }
        dec.extend(&[*last]);
        match dec.next::<Request>() {
            Some(Ok(Request::Connect { ssid, port })) => {
                assert_eq!(ssid, "Häuser");
                assert_eq!(port.as_deref(), Some("wlan0"));
            }
            other => panic!("{other:?} is not the message that went in"),
        }
    }

    #[test]
    fn skips_blank_and_crlf_terminated_lines() {
        let mut dec = Decoder::new();
        dec.extend(b"\n  \n{\"Status\":null}\r\n");
        assert!(matches!(dec.next::<Request>(), Some(Ok(Request::Status))));
        assert!(dec.next::<Request>().is_none());
    }

    /// One bad line must not poison the connection: the daemon reports it and
    /// keeps reading.
    #[test]
    fn resynchronises_after_a_malformed_line() {
        let mut dec = Decoder::new();
        dec.extend(b"{not json}\n");
        dec.extend(&encode(&Request::Status).unwrap());

        assert!(matches!(dec.next::<Request>(), Some(Err(Error::Json(_)))));
        assert!(matches!(dec.next::<Request>(), Some(Ok(Request::Status))));
    }

    #[test]
    fn refuses_a_line_that_never_ends() {
        let mut dec = Decoder::with_limit(64);
        dec.extend(&[b'x'; 65]);
        assert!(matches!(dec.next::<Request>(), Some(Err(Error::TooLong))));
        // The buffer is dropped with the error, so a hostile peer cannot make
        // the daemon hold the bytes it already sent.
        assert_eq!(dec.pending(), 0);
    }

    #[test]
    fn secret_survives_a_round_trip_intact() {
        let mut dec = Decoder::new();
        dec.extend(
            &encode(&Request::Secret {
                token: 9,
                value: Secret::new("pässwörd with spaces"),
            })
            .unwrap(),
        );
        match dec.next::<Request>() {
            Some(Ok(Request::Secret { token, value })) => {
                assert_eq!(token, 9);
                assert_eq!(value.expose(), "pässwörd with spaces");
            }
            _ => panic!("secret did not round trip"),
        }
    }

    #[test]
    fn events_then_response_over_one_stream() {
        let mut wire = Vec::new();
        write(&mut wire, &ServerMessage::Event(Event::Scanning)).unwrap();
        write(
            &mut wire,
            &ServerMessage::Event(Event::Associating {
                bssid: "aa:bb:cc:dd:ee:ff".into(),
            }),
        )
        .unwrap();
        write(&mut wire, &ServerMessage::Response(Response::Ok)).unwrap();

        let mut dec = Decoder::new();
        dec.extend(&wire);
        assert!(matches!(
            dec.next::<ServerMessage>(),
            Some(Ok(ServerMessage::Event(Event::Scanning)))
        ));
        assert!(matches!(
            dec.next::<ServerMessage>(),
            Some(Ok(ServerMessage::Event(Event::Associating { .. })))
        ));
        assert!(matches!(
            dec.next::<ServerMessage>(),
            Some(Ok(ServerMessage::Response(Response::Ok)))
        ));
        assert!(dec.next::<ServerMessage>().is_none());
    }

    #[test]
    fn blocking_read_stops_at_end_of_stream() {
        let mut wire = Vec::new();
        write(&mut wire, &Request::Status).unwrap();
        let mut cursor = std::io::Cursor::new(wire);

        assert!(matches!(
            read::<_, Request>(&mut cursor).unwrap(),
            Some(Request::Status)
        ));
        assert!(read::<_, Request>(&mut cursor).unwrap().is_none());
    }
}
