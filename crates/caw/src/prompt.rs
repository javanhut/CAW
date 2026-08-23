//! Reading a credential from the terminal.
//!
//! A passphrase must never reach argv — `ps` shows argv to every user on the
//! machine — so the only place `caw connect` can take one is the tty, and the
//! tty must not echo it.
//!
//! # Why the terminal goes further than clearing ECHO
//!
//! Clearing `ECHO` alone leaves `ISIG` set, so Ctrl-C at the prompt raises
//! `SIGINT`, whose default disposition kills the process before any destructor
//! runs — and the terminal is left with echo off, which looks to the user like
//! their shell has broken. Installing a signal handler instead is not
//! available here: `sigaction` is `unsafe`, rustix exposes no `signalfd`, and
//! this crate is `#![forbid(unsafe_code)]`.
//!
//! So `ISIG` and `ICANON` come off too and the interrupt character is read as
//! an ordinary byte. That costs the kernel's line editing, which is why the
//! loop below implements erase and kill itself, and buys a prompt that always
//! restores the terminal because nothing can bypass [`Restore`]'s `Drop`.

use std::io::{BufRead, Write};
use std::os::fd::{AsFd, BorrowedFd};

use rustix::io::Errno;
use rustix::termios::{
    self, LocalModes, OptionalActions, SpecialCodeIndex, Termios, tcgetattr, tcsetattr,
};
use zeroize::Zeroizing;

/// Control characters the loop acts on, named because the numbers are not
/// self-explanatory.
const ETX: u8 = 0x03; // Ctrl-C
const EOT: u8 = 0x04; // Ctrl-D
const BS: u8 = 0x08; // Ctrl-H
const NAK: u8 = 0x15; // Ctrl-U
const DEL: u8 = 0x7f; // Backspace on most terminals

#[derive(Debug)]
pub enum Error {
    /// The user pressed Ctrl-C. The terminal has already been restored.
    Interrupted,
    /// Input ended before a line did.
    Eof,
    NotUtf8,
    Io(Errno),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interrupted => f.write_str("cancelled"),
            Self::Eof => f.write_str("no input: the prompt reached end of file"),
            Self::NotUtf8 => f.write_str("what was typed is not valid UTF-8"),
            Self::Io(e) => write!(f, "reading from the terminal: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// Whether what is typed should appear on screen.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Echo {
    Shown,
    Hidden,
}

/// Ask for one line, wiping it from this process's memory when the caller
/// drops it.
///
/// The prompt goes to stderr, not stdout: it is not output, and writing it to
/// stdout would hide it whenever the command is piped.
///
/// When stdin is not a terminal the line is read plainly, so a passphrase can
/// still be fed in from a file or a secret manager without appearing in argv.
pub fn ask(prompt: &str, echo: Echo) -> Result<Zeroizing<String>, Error> {
    let stdin = std::io::stdin();
    if !termios::isatty(stdin.as_fd()) {
        return read_piped(&stdin);
    }

    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    let result = read_tty(stdin.as_fd(), echo);
    // Nothing was echoed, including the Return that ended the line, so the
    // cursor is still on the prompt.
    if echo == Echo::Hidden || result.is_err() {
        eprintln!();
    }
    result
}

fn read_piped(stdin: &std::io::Stdin) -> Result<Zeroizing<String>, Error> {
    let mut line = Zeroizing::new(String::new());
    if stdin.lock().read_line(&mut line).map_err(io_errno)? == 0 {
        return Err(Error::Eof);
    }
    let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
    Ok(Zeroizing::new(trimmed))
}

fn read_tty(fd: BorrowedFd<'_>, echo: Echo) -> Result<Zeroizing<String>, Error> {
    let _restore = Restore::apply(fd, echo)?;

    let mut typed = Zeroizing::new(Vec::<u8>::new());
    loop {
        let mut byte = [0u8; 1];
        match rustix::io::read(fd, &mut byte) {
            Ok(0) => return Err(Error::Eof),
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(e) => return Err(Error::Io(e)),
        }

        match byte[0] {
            b'\n' | b'\r' => break,
            ETX => return Err(Error::Interrupted),
            EOT if typed.is_empty() => return Err(Error::Eof),
            EOT => break,
            BS | DEL => {
                erase_char(&mut typed);
                if echo == Echo::Shown {
                    // Move back over the glyph, blank it, move back again.
                    eprint!("\u{8} \u{8}");
                    let _ = std::io::stderr().flush();
                }
            }
            NAK => {
                typed.clear();
                if echo == Echo::Shown {
                    eprint!("\r\u{1b}[2K");
                    let _ = std::io::stderr().flush();
                }
            }
            // Every other control character is dropped rather than stored:
            // with ICANON off they would otherwise end up inside the
            // passphrase, where nothing would ever show them.
            b if b < 0x20 => {}
            b => {
                typed.push(b);
                if echo == Echo::Shown {
                    let _ = std::io::stderr().write_all(&byte);
                    let _ = std::io::stderr().flush();
                }
            }
        }
    }

    // `from_utf8` on the buffer itself would move it out of `Zeroizing`, so the
    // bytes are borrowed and the buffer is left to wipe itself on drop.
    let text = std::str::from_utf8(&typed).map_err(|_| Error::NotUtf8)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Remove one character, not one byte: a passphrase may be any UTF-8, and
/// popping a single byte would leave a half-encoded character behind.
fn erase_char(buf: &mut Vec<u8>) {
    while let Some(&b) = buf.last() {
        buf.pop();
        if b & 0xc0 != 0x80 {
            break;
        }
    }
}

/// Puts the terminal back exactly as it was found.
///
/// The whole point of the type: the restore runs from `Drop`, so it happens on
/// the success path, on an error return, and on a panic alike.
struct Restore<'a> {
    fd: BorrowedFd<'a>,
    saved: Termios,
}

impl<'a> Restore<'a> {
    fn apply(fd: BorrowedFd<'a>, echo: Echo) -> Result<Self, Error> {
        let saved = tcgetattr(fd).map_err(Error::Io)?;
        let mut wanted = saved.clone();

        // ICANON off so Ctrl-C arrives as a byte instead of waiting for
        // Return; ISIG off so it arrives at all rather than becoming SIGINT.
        wanted.local_modes -= LocalModes::ICANON | LocalModes::ISIG;
        if echo == Echo::Hidden {
            wanted.local_modes -= LocalModes::ECHO;
        }
        // With ICANON off these decide what a read waits for: one byte, no
        // timer.
        wanted.special_codes[SpecialCodeIndex::VMIN] = 1;
        wanted.special_codes[SpecialCodeIndex::VTIME] = 0;

        // TCSAFLUSH discards anything typed ahead of the prompt, so a
        // passphrase cannot be captured from a keystroke made before the
        // terminal stopped echoing.
        tcsetattr(fd, OptionalActions::Flush, &wanted).map_err(Error::Io)?;
        Ok(Self { fd, saved })
    }
}

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.fd, OptionalActions::Now, &self.saved);
    }
}

fn io_errno(e: std::io::Error) -> Error {
    match e.raw_os_error() {
        Some(code) => Error::Io(Errno::from_raw_os_error(code)),
        None => Error::Eof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erase_removes_a_whole_character() {
        let mut buf = "aé".as_bytes().to_vec();
        assert_eq!(buf.len(), 3);
        erase_char(&mut buf);
        assert_eq!(buf, b"a");
        erase_char(&mut buf);
        assert!(buf.is_empty());
        erase_char(&mut buf);
        assert!(buf.is_empty());
    }
}
