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
//! # Known gap: SIGTERM
//!
//! The reactor has no `signalfd`, and cannot have one while this crate is
//! `#![forbid(unsafe_code)]`: rustix 1.1.4 does not implement `signalfd` at
//! all — it is listed in `rustix::not_implemented::yet` — and the signal calls
//! it does have (`kernel_sigprocmask`, `kernel_sigaction`, `kernel_sigwait`)
//! are `unsafe fn` behind its `runtime` feature. There is no safe path from a
//! signal to a pollable descriptor without libc.
//!
//! So `cawd` is stopped through the socket: `caw shutdown`, which sends
//! [`caw_ipc::Request::Shutdown`] from root or the `caw` group and runs the
//! teardown a SIGTERM handler would — disconnect, then remove the socket. The
//! systemd unit uses it as `ExecStop=`, so `systemctl stop cawd` takes the
//! clean path too. On a plain SIGTERM the kernel closes the descriptors and
//! `RuntimeDirectory=` removes `/run/caw`, so nothing is left behind — but the
//! station leaves the air without deauthenticating and the AP holds it until
//! the inactivity timeout. Closing that last gap needs one `signalfd` in
//! rustix, and one arm in [`reactor`].
#![forbid(unsafe_code)]

mod auth;
mod engine;
mod ipc;
mod links;
mod log;
mod reactor;
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
