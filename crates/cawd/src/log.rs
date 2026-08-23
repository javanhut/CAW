//! Diagnostics, on stderr.
//!
//! No log file and no log crate. systemd captures stderr into the journal, so
//! a file of our own would be one more thing to rotate and one more place to
//! look; running `cawd` by hand puts the same lines in the terminal.

use std::fmt::Arguments;

pub fn info(args: Arguments<'_>) {
    eprintln!("cawd: {args}");
}

pub fn warn(args: Arguments<'_>) {
    eprintln!("cawd: warning: {args}");
}

pub fn error(args: Arguments<'_>) {
    eprintln!("cawd: error: {args}");
}
