mod cli;

use clap::Parser;

use crate::cli::{Cli, Command, PortAction};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Ports => not_implemented("ports"),
        Command::Scan => not_implemented("scan"),
        Command::Connect { ssid } => not_implemented(&format!("connect {ssid}")),
        Command::Disconnect { ssid } => not_implemented(&format!("disconnect {ssid}")),
        Command::Port { action } => match action {
            PortAction::Up { name } => not_implemented(&format!("port up {name}")),
            PortAction::Info {
                name,
                protocol,
                mac,
            } => {
                let mut what = format!("port info {name}");
                if protocol {
                    what.push_str(" --protocol");
                }
                if mac {
                    what.push_str(" --mac");
                }
                not_implemented(&what);
            }
            PortAction::Set { name, mode } => {
                not_implemented(&format!("port set {name} {}", mode_name(&mode)))
            }
        },
    }
}

fn mode_name(mode: &cli::AddressMode) -> &'static str {
    match mode {
        cli::AddressMode::Dhcp => "dhcp",
    }
}

fn not_implemented(what: &str) -> ! {
    eprintln!("caw: `{what}` is not implemented yet");
    std::process::exit(1)
}
