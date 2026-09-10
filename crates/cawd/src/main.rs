//! The caw daemon.
//!
//! Owns every file descriptor and every timer; owns no decisions. It polls its
//! descriptors, hands what arrives to `caw_core::Connection`, and performs the
//! actions it gets back.
//!
//! # Why a daemon at all
//!
//! An access point rotates the group key periodically, typically hourly. If no
//! userspace process answers that EAPOL exchange the AP deauthenticates us, so
//! a connection is only as durable as the process holding the EAPOL socket.
//! Reconnect, roaming and suspend/resume need the same residency.
//!
//! # Why no async runtime
//!
//! There are on the order of six descriptors here. A `poll` loop over them is
//! smaller and easier to reason about than an executor, and because every
//! state machine below is sans-IO, there is nothing to await. `rustix` gives
//! us `poll` and `timerfd` without libc.
//!
//! # Stopping
//!
//! Two ways, one teardown. SIGTERM (what `systemctl stop` and `kill` send)
//! and SIGINT (Ctrl-C at a terminal) arrive through the self-pipe in
//! [`signals`]; [`caw_ipc::Request::Shutdown`] arrives over the socket as
//! `caw shutdown`, from root or the `caw` group. Either sets the reactor
//! stopping, and it disconnects — so the access point sees a station leaving
//! rather than one that stopped answering — flushes its clients and removes
//! the socket. rustix has no `signalfd` and offers `sigaction` only as an
//! `unsafe fn`, so the handler comes from `signal-hook`; see [`signals`].
#![forbid(unsafe_code)]

mod auth;
mod engine;
mod ipc;
mod links;
mod log;
mod reactor;
mod signals;
mod timers;

use std::path::PathBuf;
use std::process::ExitCode;

use crate::reactor::Reactor;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log::error(format_args!("{e}"));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Error> {
    let Some(options) = parse_args()? else {
        return Ok(());
    };
    Reactor::new(&options.socket, options.autoconnect)?.run()
}

const USAGE: &str = "\
usage: cawd [--socket PATH] [--no-autoconnect]

  --socket PATH     listen here instead of /run/caw/caw.sock
  --no-autoconnect  never join a saved network unless asked to
  -h, --help        show this
";

/// How the daemon was asked to run.
struct Options {
    socket: PathBuf,
    autoconnect: bool,
}

/// `None` when the arguments asked for something already done, such as help.
///
/// Hand-parsed rather than through clap: a handful of options do not justify a
/// dependency in a program whose interface is a socket.
fn parse_args() -> Result<Option<Options>, Error> {
    // Autoconnect defaults on. A daemon enabled at boot that leaves the radio
    // idle is a machine you have to be sitting in front of to put on the
    // network, which is the opposite of what enabling it was for.
    let mut options = Options {
        socket: PathBuf::from(caw_ipc::SOCKET_PATH),
        autoconnect: true,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "--socket" => {
                options.socket = args
                    .next()
                    .ok_or_else(|| Error::Usage("--socket needs a path".to_owned()))?
                    .into();
            }
            "--no-autoconnect" => options.autoconnect = false,
            other => return Err(Error::Usage(format!("unknown argument {other}"))),
        }
    }
    Ok(Some(options))
}

#[derive(Debug)]
pub enum Error {
    Socket(rustix::io::Errno),
    /// Something is already listening on the socket, so this daemon would
    /// take over an address its clients are already using.
    AlreadyRunning(PathBuf),
    Usage(String),
}

impl From<rustix::io::Errno> for Error {
    fn from(e: rustix::io::Errno) -> Self {
        Error::Socket(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Socket(e) => write!(f, "{e}"),
            Error::AlreadyRunning(path) => {
                write!(f, "another cawd is listening on {}", path.display())
            }
            Error::Usage(msg) => write!(f, "{msg}\n\n{USAGE}"),
        }
    }
}

impl std::error::Error for Error {}
