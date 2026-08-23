//! The caw command line.
//!
//! Port commands talk to rtnetlink directly rather than through `cawd`. They
//! are stateless kernel queries: `ports` and `port info` need no privilege and
//! no daemon, and requiring one would add a failure mode to commands that need
//! nothing. Wireless commands do need the daemon, because a connection has to
//! outlive the process that started it, and those go over the socket.
//!
//! Nothing here links the crypto or wireless stack; the CLI's whole knowledge
//! of WPA is the security string the daemon sends it to print.
#![forbid(unsafe_code)]

mod cli;
mod ipc;
mod port;
mod prompt;
mod render;
mod table;
mod wireless;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{AddressMode, Cli, Command, PortAction};

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Ports => port::list(),
        Command::Port { action } => match action {
            PortAction::Up { name } => port::set_up(&name, true),
            PortAction::Info {
                name,
                protocol,
                mac,
            } => port::info(&name, protocol, mac),
            PortAction::Set { name, mode } => match mode {
                AddressMode::Dhcp => wireless::set_dhcp(&name),
            },
        },
        Command::Scan { port } => wireless::scan(port),
        Command::Connect { ssid, port } => wireless::connect(&ssid, port),
        Command::Disconnect { ssid } => wireless::disconnect(&ssid),
        Command::Status => wireless::status(),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("caw: {e}");
            ExitCode::FAILURE
        }
    }
}
