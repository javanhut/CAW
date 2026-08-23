//! The subcommands that go through `cawd`.
//!
//! Every one of them is the same three steps — connect, send, render — so the
//! interesting code is elsewhere: the wire format in [`caw_ipc`], the tables in
//! [`crate::render`], the terminal in [`crate::prompt`].
//!
//! One rule about the two streams: stdout carries what a script would read —
//! the scan table, the status block — and everything else goes to stderr. So
//! `caw scan > networks` captures the table alone and still shows the user
//! that a scan is under way, and `caw connect`, whose whole output is a
//! narrative interrupted by a prompt, writes that narrative on one stream and
//! cannot interleave with itself.

use std::error::Error;

use caw_ipc::{Event, Request, Response, Secret, SecretKind, ServerMessage};

use crate::ipc::Client;
use crate::prompt::{self, Echo};
use crate::render;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

pub fn scan(port: Option<String>) -> Result<()> {
    let mut client = Client::connect()?;
    let response = client.request(&Request::Scan { port }, report)?;

    let Response::Networks(networks) = response else {
        return Err(crate::ipc::Error::Unexpected.into());
    };

    if networks.is_empty() {
        eprintln!("no networks in range");
        return Ok(());
    }
    print!("{}", render::scan_table(networks));
    Ok(())
}

/// `caw connect <ssid>`.
///
/// The one command that answers the daemon rather than only listening to it:
/// [`Event::NeedSecret`] is a question, and the reply carries a passphrase,
/// which is why it is asked for here and not taken from argv where `ps` would
/// publish it to every user on the machine.
pub fn connect(ssid: &str, port: Option<String>) -> Result<()> {
    let mut client = Client::connect()?;
    client.send(&Request::Connect {
        ssid: ssid.to_owned(),
        port,
    })?;

    loop {
        match client.next()? {
            ServerMessage::Event(Event::NeedSecret {
                token,
                prompt,
                kind,
            }) => {
                let value = ask(&prompt, kind)?;
                client.send(&Request::Secret {
                    token,
                    value: Secret::new(value.as_str()),
                })?;
            }
            ServerMessage::Event(Event::Connected) => eprintln!("connected to {ssid}"),
            ServerMessage::Event(Event::Failed { reason }) => {
                return Err(format!("could not connect to {ssid}: {reason}").into());
            }
            ServerMessage::Event(event) => report(&event),
            ServerMessage::Response(Response::Error { message }) => {
                return Err(crate::ipc::Error::Daemon(message).into());
            }
            ServerMessage::Response(Response::Ok) => return Ok(()),
            ServerMessage::Response(_) => {
                return Err(crate::ipc::Error::Unexpected.into());
            }
        }
    }
}

pub fn disconnect(ssid: &str) -> Result<()> {
    let mut client = Client::connect()?;
    match client.request(
        &Request::Disconnect {
            ssid: ssid.to_owned(),
        },
        report,
    )? {
        Response::Ok => {
            eprintln!("disconnected from {ssid}");
            Ok(())
        }
        _ => Err(crate::ipc::Error::Unexpected.into()),
    }
}

pub fn status() -> Result<()> {
    let mut client = Client::connect()?;
    match client.request(&Request::Status, report)? {
        Response::Status(status) => {
            print!("{}", render::status_block(&status));
            Ok(())
        }
        _ => Err(crate::ipc::Error::Unexpected.into()),
    }
}

/// `caw shutdown`.
///
/// The graceful way down. `cawd` has no SIGTERM handler — there is no safe
/// path from a signal to a pollable descriptor without libc, and every crate
/// here is `#![forbid(unsafe_code)]` — so killing it leaves the station on the
/// air without deauthenticating, and the access point holds the slot until it
/// times out. This asks over the socket instead, and the daemon disconnects
/// before it exits.
///
/// The daemon answers `Ok` and *then* stops, so the reply is already in the
/// socket buffer by the time it goes; a closed connection after that is the
/// daemon having done what was asked, not a failure.
pub fn shutdown() -> Result<()> {
    let mut client = Client::connect()?;
    match client.request(&Request::Shutdown, report) {
        Ok(Response::Ok) => {
            eprintln!("cawd stopped");
            Ok(())
        }
        Ok(_) => Err(crate::ipc::Error::Unexpected.into()),
        Err(crate::ipc::Error::Closed) => {
            eprintln!("cawd stopped");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// `caw port set <name> dhcp`.
///
/// This one goes through the daemon even though its sibling `port up` does
/// not: a lease has to be renewed for as long as it is held, and a process
/// that exits cannot renew anything.
///
/// **Not wired up yet.** `caw_ipc::Request` has no variant for address
/// configuration, so there is nothing to send. When one lands this becomes the
/// same three lines as [`disconnect`] — connect, `client.request(...)`, print
/// — and needs nothing else from this crate.
pub fn set_dhcp(name: &str) -> Result<()> {
    // Deliberately checked before opening the socket: the gap is in the
    // protocol, and reporting it as a daemon failure would send whoever hits
    // it looking in the wrong place.
    Err(
        format!("cannot configure dhcp on {name} yet: the cawd protocol has no request for it")
            .into(),
    )
}

/// Print an event that only says how far along the connection is.
fn report(event: &Event) {
    if let Some(line) = render::progress(event) {
        eprintln!("{line}");
    }
}

/// Ask for one credential.
///
/// A username is not a secret and hiding it only makes it easy to mistype, so
/// it alone is echoed.
fn ask(text: &str, kind: SecretKind) -> Result<zeroize::Zeroizing<String>> {
    let echo = match kind {
        SecretKind::Username => Echo::Shown,
        SecretKind::Passphrase | SecretKind::Password => Echo::Hidden,
    };
    Ok(prompt::ask(&format!("{text}: "), echo)?)
}
