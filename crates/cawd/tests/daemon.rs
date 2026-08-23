//! End-to-end tests against a real `cawd` process.
//!
//! The reactor is the one part of the daemon that cannot be unit tested — it
//! is nothing but descriptors — so it is tested by running it: spawn the
//! binary on a socket of this test's own, talk the protocol to it, and check
//! what comes back. Everything here works without a radio, which is why the
//! requests are the ones that only need rtnetlink or nothing at all.
//!
//! These run as whatever user the test runs as. Under the dev container that
//! is root, so they exercise the "allowed" half of the authorization table;
//! the refusal half is in `auth`'s unit tests, because dropping privileges to
//! test it for real needs `setresuid`, which is `unsafe`.

use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use caw_ipc::{Request, Response, ServerMessage, frame};

/// A `cawd` running on a socket of its own, killed when the test ends.
struct Daemon {
    child: Child,
    socket: PathBuf,
}

impl Daemon {
    fn start(name: &str) -> Self {
        let socket =
            std::env::temp_dir().join(format!("cawd-test-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let child = Command::new(env!("CARGO_BIN_EXE_cawd"))
            .arg("--socket")
            .arg(&socket)
            // These tests are about the protocol, not about radios. A daemon
            // that started joining saved networks would take whatever wireless
            // hardware the host has with it.
            .arg("--no-autoconnect")
            .spawn()
            .expect("cawd starts");
        Self { child, socket }
    }

    fn connect(&self) -> Client {
        Client::connect(&self.socket)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

struct Client {
    write: UnixStream,
    read: BufReader<UnixStream>,
}

impl Client {
    /// Connect, retrying while the daemon starts.
    ///
    /// Waiting for the socket file to exist is not enough: `cawd` unlinks a
    /// stale one and binds its own, so the path can be there and refuse
    /// connections for a moment.
    fn connect(socket: &Path) -> Self {
        let deadline = Instant::now() + Duration::from_secs(10);
        let write = loop {
            match UnixStream::connect(socket) {
                Ok(stream) => break stream,
                Err(e) if Instant::now() >= deadline => {
                    panic!("cawd never listened on {}: {e}", socket.display())
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        let read = BufReader::new(write.try_clone().expect("dup"));
        Self { write, read }
    }

    fn send(&mut self, request: &Request) {
        frame::write(&mut self.write, request).expect("request goes out");
    }

    /// The next message, which the tests here expect to be a response: none of
    /// them start something that reports progress.
    fn response(&mut self) -> Response {
        // A daemon that never answers must fail the test rather than hang it.
        self.write
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout is settable");
        match frame::read::<_, ServerMessage>(&mut self.read).expect("a well-formed reply") {
            Some(ServerMessage::Response(response)) => response,
            Some(ServerMessage::Event(event)) => panic!("expected a response, got {event:?}"),
            None => panic!("the daemon closed the connection"),
        }
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.write.write_all(bytes).expect("raw bytes go out");
    }
}

#[test]
fn answers_a_status_query() {
    let daemon = Daemon::start("status");
    let mut client = daemon.connect();

    client.send(&Request::Status);
    match client.response() {
        // Nothing has been asked of it yet, so the state machine is idle and
        // there is no port to name.
        Response::Status(status) => assert_eq!(status.state, "Idle"),
        other => panic!("{other:?}"),
    }
}

/// The port list comes from rtnetlink, which works in any network namespace.
#[test]
fn lists_ports_over_the_socket() {
    let daemon = Daemon::start("ports");
    let mut client = daemon.connect();

    client.send(&Request::ListPorts);
    match client.response() {
        Response::Ports(ports) => {
            assert!(
                ports.iter().any(|p| p.name == "lo"),
                "loopback is always there: {ports:?}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unknown_port_is_an_error_not_a_crash() {
    let daemon = Daemon::start("noport");
    let mut client = daemon.connect();

    client.send(&Request::PortInfo {
        name: "definitely-not-a-port".to_owned(),
    });
    match client.response() {
        Response::Error { message } => assert!(message.contains("no such port"), "{message}"),
        other => panic!("{other:?}"),
    }
}

/// One malformed line is the client's problem, not the connection's.
#[test]
fn survives_a_malformed_request_and_keeps_serving() {
    let daemon = Daemon::start("malformed");
    let mut client = daemon.connect();

    client.raw(b"{this is not json}\n");
    assert!(matches!(client.response(), Response::Error { .. }));

    client.send(&Request::Status);
    assert!(matches!(client.response(), Response::Status(_)));
}

/// Several clients at once is the normal case: a `caw connect` in one
/// terminal and a `caw status` in another.
#[test]
fn serves_two_clients_at_once() {
    let daemon = Daemon::start("two");
    let mut first = daemon.connect();
    let mut second = daemon.connect();

    first.send(&Request::Status);
    second.send(&Request::ListPorts);

    assert!(matches!(first.response(), Response::Status(_)));
    assert!(matches!(second.response(), Response::Ports(_)));
}

#[test]
fn shutdown_answers_then_removes_the_socket() {
    let mut daemon = Daemon::start("shutdown");
    let mut client = daemon.connect();

    client.send(&Request::Shutdown);
    assert!(matches!(client.response(), Response::Ok));

    let status = daemon.child.wait().expect("cawd exits");
    assert!(status.success(), "{status:?}");
    assert!(
        !daemon.socket.exists(),
        "a socket left behind looks like a running daemon"
    );
}

/// Taking over a socket another daemon is listening on would leave every
/// client talking to a daemon nothing can reach.
#[test]
fn refuses_to_start_on_a_live_socket() {
    let daemon = Daemon::start("contended");
    // Make sure it really is listening before the second one tries.
    let mut client = daemon.connect();

    let second = Command::new(env!("CARGO_BIN_EXE_cawd"))
        .arg("--socket")
        .arg(&daemon.socket)
        .output()
        .expect("the second cawd runs");

    assert!(!second.status.success());
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(stderr.contains("another cawd"), "{stderr}");
    // And the first one is still serving.
    client.send(&Request::Status);
    assert!(matches!(client.response(), Response::Status(_)));
}

/// A socket file left behind by a daemon that died must not stop the next one.
#[test]
fn clears_a_stale_socket() {
    let socket = std::env::temp_dir().join(format!("cawd-test-stale-{}.sock", std::process::id()));
    // Binding and dropping leaves the path behind with nothing listening,
    // which is exactly what a daemon that was killed leaves.
    drop(std::os::unix::net::UnixListener::bind(&socket).expect("bind"));
    assert!(socket.exists());
    // Another test spawning a process at the same moment forks a copy of that
    // listener, and it stays connectable until that child execs. Wait for the
    // path to start refusing, or this test would connect to a socket about to
    // vanish and see the write fail.
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(&socket).is_ok() {
        assert!(
            Instant::now() < deadline,
            "the stale socket never went away"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_cawd"))
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("cawd starts");

    let mut client = Client::connect(&socket);
    client.send(&Request::Status);
    assert!(matches!(client.response(), Response::Status(_)));

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&socket);
}
