//! The Unix socket server at `/run/caw/caw.sock`.
//!
//! Non-blocking throughout, because the reactor has one thread and a client
//! that stops reading must not be able to stall the handshake of a connection
//! that is halfway through. Reads go into a [`Decoder`] per connection, since
//! a read can stop anywhere in a line; writes go into a per-connection outbox
//! that is drained whenever `poll` says the socket will take more.
//!
//! Authorization lives in [`crate::auth`]; this module only records the peer
//! credentials the kernel attached at accept time.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use caw_ipc::{Decoder, FrameError, Request, Response, ServerMessage};
use rustix::fs::Mode;
use rustix::io::Errno;
use rustix::net::{AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType, sockopt};

use crate::auth::Peer;
use crate::{Error, log};

/// Identifies a connection for as long as the daemon runs. Not an index:
/// clients come and go and an index would be reused under a stale reference.
pub type ClientId = u64;

/// How much unwritten output one client may accumulate before it is dropped.
///
/// A client that never reads is otherwise a way to make the daemon grow
/// without bound. A full scan of a crowded band is tens of kilobytes, so this
/// is generous by a wide margin.
const MAX_OUTBOX: usize = 1 << 20;

/// Connections waiting to be accepted. The kernel queues them while the
/// reactor is busy performing an action.
const BACKLOG: i32 = 32;

pub struct Server {
    listener: OwnedFd,
    path: PathBuf,
    clients: Vec<Client>,
    next_id: ClientId,
}

impl Server {
    /// Bind and listen, creating `/run/caw` if it is not there.
    ///
    /// systemd's `RuntimeDirectory=` makes the directory in production, but
    /// running `cawd` by hand from a shell has to work too.
    pub fn bind(path: &Path) -> Result<Self, Error> {
        if let Some(dir) = path.parent() {
            match rustix::fs::mkdir(dir, Mode::from_raw_mode(0o755)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(e) => return Err(Error::Socket(e)),
            }
        }
        clear_stale(path)?;

        let listener = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        rustix::net::bind(&listener, &SocketAddrUnix::new(path)?)?;
        // Every user may connect, because reading is open to every user; the
        // requests that change something are refused by peer credentials, not
        // by the mode. Set explicitly after `bind`, which applies the umask
        // and would otherwise leave the socket unreachable to anyone but
        // root.
        rustix::fs::chmod(path, Mode::from_raw_mode(0o666))?;
        rustix::net::listen(&listener, BACKLOG)?;

        Ok(Self {
            listener,
            path: path.to_path_buf(),
            clients: Vec::new(),
            next_id: 1,
        })
    }

    pub fn listener(&self) -> BorrowedFd<'_> {
        self.listener.as_fd()
    }

    pub fn clients(&self) -> &[Client] {
        &self.clients
    }

    pub fn client(&self, id: ClientId) -> Option<&Client> {
        self.clients.iter().find(|c| c.id == id)
    }

    fn client_mut(&mut self, id: ClientId) -> Option<&mut Client> {
        self.clients.iter_mut().find(|c| c.id == id)
    }

    /// Take everything the kernel has queued on the listener.
    ///
    /// A connection whose credentials cannot be read is dropped rather than
    /// served: with nothing to authorize against, there is no safe default.
    pub fn accept(&mut self) -> Vec<ClientId> {
        let mut accepted = Vec::new();
        loop {
            let fd = match rustix::net::accept_with(
                &self.listener,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            ) {
                Ok(fd) => fd,
                Err(Errno::AGAIN) => return accepted,
                Err(Errno::INTR) => continue,
                // A connection that died between the kernel queueing it and
                // us taking it is not a reason to stop accepting.
                Err(e) => {
                    log::warn(format_args!("accept failed: {e}"));
                    return accepted;
                }
            };
            let peer = match sockopt::socket_peercred(&fd) {
                Ok(cred) => Peer::from_ucred(cred),
                Err(e) => {
                    log::warn(format_args!("no peer credentials on a client: {e}"));
                    continue;
                }
            };

            let id = self.next_id;
            self.next_id += 1;
            self.clients.push(Client {
                id,
                peer,
                fd,
                decoder: Decoder::new(),
                out: Vec::new(),
                sent: 0,
                closed: false,
            });
            accepted.push(id);
        }
    }

    /// Read whatever has arrived from one client and decode complete requests.
    ///
    /// A line that does not parse is answered and the connection kept: one
    /// bad request is the client's problem, not the connection's. Anything
    /// worse — a line with no end, a dead socket — closes it.
    pub fn read(&mut self, id: ClientId) -> Vec<Request> {
        let mut requests = Vec::new();
        let Some(client) = self.client_mut(id) else {
            return requests;
        };

        let mut buf = [0u8; 4096];
        loop {
            match rustix::io::read(&client.fd, &mut buf[..]) {
                Ok(0) => {
                    client.closed = true;
                    break;
                }
                Ok(n) => client.decoder.extend(&buf[..n]),
                Err(Errno::AGAIN) => break,
                Err(Errno::INTR) => continue,
                Err(_) => {
                    client.closed = true;
                    break;
                }
            }
        }

        let mut refusals = Vec::new();
        while let Some(decoded) = client.decoder.next::<Request>() {
            match decoded {
                Ok(request) => requests.push(request),
                Err(FrameError::TooLong) => {
                    refusals.push(Response::error("request too long"));
                    client.closed = true;
                    break;
                }
                Err(e) => refusals.push(Response::error(e.to_string())),
            }
        }

        for refusal in refusals {
            self.send(id, refusal);
        }
        requests
    }

    /// Queue a message and push as much of the outbox as the socket takes.
    ///
    /// Writing immediately rather than waiting for `poll` to report the
    /// socket writable saves a trip round the loop, which is the whole
    /// latency budget of a status query.
    pub fn send(&mut self, id: ClientId, msg: impl Into<ServerMessage>) {
        let msg = msg.into();
        let Some(client) = self.client_mut(id) else {
            return;
        };
        match caw_ipc::encode(&msg) {
            Ok(bytes) => client.out.extend_from_slice(&bytes),
            // Only an unserializable value can land here, which would be a bug
            // in our own types rather than anything the client did.
            Err(e) => {
                log::warn(format_args!("dropping a reply that would not encode: {e}"));
                return;
            }
        }
        client.flush();
    }

    pub fn flush(&mut self, id: ClientId) {
        if let Some(client) = self.client_mut(id) {
            client.flush();
        }
    }

    pub fn close(&mut self, id: ClientId) {
        if let Some(client) = self.client_mut(id) {
            client.closed = true;
        }
    }

    /// Drop the connections that are finished, naming them so the caller can
    /// forget anything it was holding on their behalf.
    pub fn reap(&mut self) -> Vec<ClientId> {
        let mut gone = Vec::new();
        self.clients.retain(|c| {
            let keep = !c.closed || c.has_pending_output();
            if !keep {
                gone.push(c.id);
            }
            keep
        });
        gone
    }
}

impl Drop for Server {
    /// Remove the socket. A stale one left behind is a daemon that appears to
    /// be running to anything that only checks for the file.
    fn drop(&mut self) {
        let _ = rustix::fs::unlink(&self.path);
    }
}

pub struct Client {
    pub id: ClientId,
    /// Credentials the kernel recorded when this connection was made. They
    /// describe the process that connected, not whatever it may have become.
    pub peer: Peer,
    fd: OwnedFd,
    decoder: Decoder,
    out: Vec<u8>,
    /// How much of `out` has reached the socket.
    sent: usize,
    closed: bool,
}

impl Client {
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    pub fn has_pending_output(&self) -> bool {
        self.sent < self.out.len()
    }

    fn flush(&mut self) {
        while self.sent < self.out.len() {
            // MSG_NOSIGNAL: a client that hangs up mid-write must give us an
            // EPIPE to handle, not a SIGPIPE that ends the daemon.
            match rustix::net::send(&self.fd, &self.out[self.sent..], SendFlags::NOSIGNAL) {
                Ok(n) => self.sent += n,
                Err(Errno::AGAIN) => break,
                Err(Errno::INTR) => continue,
                Err(_) => {
                    self.closed = true;
                    self.out.clear();
                    self.sent = 0;
                    return;
                }
            }
        }

        if self.sent == self.out.len() {
            self.out.clear();
            self.sent = 0;
        } else if self.out.len() - self.sent > MAX_OUTBOX {
            log::warn(format_args!(
                "client {} is not reading; dropping it",
                self.id
            ));
            self.closed = true;
            self.out.clear();
            self.sent = 0;
        }
    }
}

/// Remove a socket file left behind by a daemon that died, and refuse to
/// start when one is actually listening.
///
/// Connecting is the only way to tell those apart: unlinking whatever is
/// there would silently steal the socket from a running `cawd`, and every
/// client would keep talking to a daemon nothing can reach.
fn clear_stale(path: &Path) -> Result<(), Error> {
    if !path.exists() {
        return Ok(());
    }
    let probe = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    match rustix::net::connect(&probe, &SocketAddrUnix::new(path)?) {
        Ok(()) => Err(Error::AlreadyRunning(path.to_path_buf())),
        Err(Errno::CONNREFUSED) | Err(Errno::NOENT) => {
            rustix::fs::unlink(path)?;
            Ok(())
        }
        Err(e) => Err(Error::Socket(e)),
    }
}
