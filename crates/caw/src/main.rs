//! The caw command line.
//!
//! Port commands talk to rtnetlink directly rather than through `cawd`. They
//! are stateless kernel queries: `ports` and `port info` need no privilege and
//! no daemon, and requiring one would add a failure mode to commands that need
//! nothing. Wireless commands do need the daemon, because a connection has to
//! outlive the process that started it, and those go over the socket.
#![forbid(unsafe_code)]

mod cli;
mod port;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, Command, PortAction};

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
            PortAction::Set { name, mode } => {
                not_implemented(&format!("port set {name} {}", mode_name(&mode)))
            }
        },
        Command::Scan => not_implemented("scan"),
        Command::Connect { ssid } => not_implemented(&format!("connect {ssid}")),
        Command::Disconnect { ssid } => not_implemented(&format!("disconnect {ssid}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("caw: {e}");
            ExitCode::FAILURE
        }
    }
}

fn mode_name(mode: &cli::AddressMode) -> &'static str {
    match mode {
        cli::AddressMode::Dhcp => "dhcp",
    }
}

fn not_implemented(what: &str) -> Result<(), Box<dyn std::error::Error>> {
    Err(format!("`{what}` is not implemented yet").into())
}
