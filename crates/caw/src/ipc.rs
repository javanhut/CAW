//! The client end of the `cawd` socket.
//!
//! The only module in the CLI that touches the kernel for anything other than
//! rtnetlink, and it carries no protocol knowledge: [`caw_ipc`] owns the wire
//! format, this owns the file descriptor.
//!
//! The exchange is blocking, unlike the daemon's, because the CLI has exactly
//! one thing in flight and nothing to do while it waits — and because `connect`
//! spends most of its time waiting for a human to type. Ctrl-C works throughout
//! for the ordinary reason: the terminal is untouched except inside
//! [`crate::prompt`].

use std::os::fd::OwnedFd;

use caw_ipc::{Decoder, Request, Response, SOCKET_PATH, ServerMessage, frame};
use rustix::io::Errno;
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use zeroize::Zeroize;

/// The unit that owns [`SOCKET_PATH`], named in full so the advice can be
/// pasted.
const SERVICE: &str = "cawd";

#[derive(Debug)]
pub enum Error {
    /// Nothing is listening on the socket.
    NotRunning,
    /// The socket is there but this user may not open it.
    Forbidden,
    /// The daemon closed the connection before answering.
    Closed,
    /// The daemon answered with [`Response::Error`].
    Daemon(String),
    /// The daemon answered, but not with what the request called for.
    Unexpected,
    Frame(frame::Error),
    Io(Errno),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Stated as a fact about the machine, with the fix, and once:
            // a stopped service is not a mistake anyone made.
            Self::NotRunning => write!(
                f,
                "the {SERVICE} service is not running, and wireless commands go through it.\n\
                 \x20 start it now:      sudo systemctl start {SERVICE}\n\
                 \x20 start it at boot:  sudo systemctl enable --now {SERVICE}"
            ),
            Self::Forbidden => write!(
                f,
                "not allowed to open {SOCKET_PATH}.\n\
                 \x20 changing the network needs root or membership of the `{group}` group:\n\
                 \x20   sudo usermod -aG {group} \"$USER\"",
                group = caw_ipc::GROUP
            ),
            Self::Closed => write!(f, "the {SERVICE} service closed the connection"),
            Self::Daemon(message) => f.write_str(message),
            Self::Unexpected => write!(f, "the {SERVICE} service sent an unexpected reply"),
            Self::Frame(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "talking to {SERVICE}: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// One connection to the daemon, for the life of one command.
pub struct Client {
    fd: OwnedFd,
    decoder: Decoder,
}

impl Client {
    pub fn connect() -> Result<Self, Error> {
        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            // CLOEXEC so the socket cannot leak into anything this process
            // goes on to run.
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(Error::Io)?;

        let addr = SocketAddrUnix::new(SOCKET_PATH).map_err(Error::Io)?;
        rustix::net::connect(&fd, &addr).map_err(|e| match e {
            // No socket file, or one left behind by a daemon that is gone:
            // both mean the same thing to the person at the keyboard.
            Errno::NOENT | Errno::CONNREFUSED => Error::NotRunning,
            Errno::ACCESS | Errno::PERM => Error::Forbidden,
            other => Error::Io(other),
        })?;

        Ok(Self {
            fd,
            decoder: Decoder::new(),
        })
    }

    pub fn send(&mut self, request: &Request) -> Result<(), Error> {
        let mut line = frame::encode(request).map_err(Error::Frame)?;
        let result = self.write_all(&line);
        // A `Secret` was just serialized into this buffer; freeing it without
        // wiping would leave the passphrase in the allocator's free list.
        line.zeroize();
        result
    }

    /// The next message from the daemon, which may be an [`Event`] pushed
    /// while the request is still in flight.
    ///
    /// [`Event`]: caw_ipc::Event
    pub fn next(&mut self) -> Result<ServerMessage, Error> {
        loop {
            if let Some(message) = self.decoder.next::<ServerMessage>() {
                return message.map_err(Error::Frame);
            }

            let mut chunk = [0u8; 4096];
            match rustix::io::read(&self.fd, &mut chunk) {
                Ok(0) => return Err(Error::Closed),
                Ok(n) => self.decoder.extend(&chunk[..n]),
                Err(Errno::INTR) => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }

    /// Send `request` and return its [`Response`], reporting each event on the
    /// way through `on_event`.
    ///
    /// The commands that only wait — `scan`, `disconnect`, `status` — are all
    /// this shape. `connect` is not, because it has to answer an event rather
    /// than just print it, and so drives [`Self::next`] itself.
    pub fn request(
        &mut self,
        request: &Request,
        mut on_event: impl FnMut(&caw_ipc::Event),
    ) -> Result<Response, Error> {
        self.send(request)?;
        loop {
            match self.next()? {
                ServerMessage::Event(event) => on_event(&event),
                ServerMessage::Response(Response::Error { message }) => {
                    return Err(Error::Daemon(message));
                }
                ServerMessage::Response(response) => return Ok(response),
            }
        }
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            match rustix::io::write(&self.fd, bytes) {
                Ok(0) => return Err(Error::Closed),
                Ok(n) => bytes = &bytes[n..],
                Err(Errno::INTR) => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }
        Ok(())
    }
}
