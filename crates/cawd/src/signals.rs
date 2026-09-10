//! SIGTERM and SIGINT, as a pollable descriptor.
//!
//! A signal handler may do almost nothing, and none of it reaches a `poll`
//! loop directly, so the handler writes one byte to a pipe and the reactor
//! watches the read end — the self-pipe trick. `signal-hook` installs the
//! handler: the `sigaction` call is `unsafe` and lives there, and the
//! registration it exposes is safe because writing to a pipe is one of the
//! few things a handler is allowed to do. It goes through the `libc` crate,
//! which binds the libc `std` already links on Linux; nothing new is linked
//! (ARCHITECTURE.md §2).

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::io::Errno;
use rustix::pipe::{PipeFlags, pipe_with};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::low_level::pipe::register;

pub struct Signals {
    read: OwnedFd,
}

impl Signals {
    /// Install the handlers. SIGTERM is what systemd and `kill` send; SIGINT
    /// is Ctrl-C at a terminal `cawd` was started from by hand.
    ///
    /// Non-blocking on both ends: the handler must never block, and the
    /// reactor drains without waiting.
    pub fn open() -> std::io::Result<Self> {
        let (read, write) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)?;
        register(SIGTERM, write.try_clone()?)?;
        register(SIGINT, write)?;
        Ok(Self { read })
    }

    /// Empty the pipe. Several signals may have arrived; one wakeup answers
    /// them all, and the reactor stops once.
    pub fn drain(&self) {
        let mut buf = [0u8; 64];
        loop {
            match rustix::io::read(&self.read, &mut buf) {
                Ok(0) | Err(Errno::AGAIN) => return,
                Ok(_) | Err(Errno::INTR) => continue,
                Err(_) => return,
            }
        }
    }
}

impl AsFd for Signals {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }
}
