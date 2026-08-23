//! The command surface.
//!
//! Action first — `caw port up eth0`, not `caw up port eth0` — so the noun a
//! command acts on stays next to the flags that describe it. Doc comments are
//! the help text, which is why they are written for a reader at a terminal.

use clap::{Parser, Subcommand, ValueEnum};

/// Corvus Access Wifi - a wifi and network utility for Raven Linux.
#[derive(Parser)]
#[command(name = "caw", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// List the available network ports.
    Ports,
    /// Inspect and configure a network port.
    Port {
        #[command(subcommand)]
        action: PortAction,
    },
    /// Scan for wireless networks.
    Scan {
        /// Scan on this port only, when the machine has more than one radio.
        #[arg(long)]
        port: Option<String>,
    },
    /// Connect to a wireless network, asking for a passphrase if one is needed.
    Connect {
        /// Name (SSID) of the network.
        ssid: String,
        /// Connect using this port, when the machine has more than one radio.
        #[arg(long)]
        port: Option<String>,
    },
    /// Disconnect from a wireless network.
    Disconnect {
        /// Name (SSID) of the network.
        ssid: String,
    },
    /// Show the current wireless connection.
    Status,
    /// Stop the caw daemon, leaving any joined network cleanly first.
    ///
    /// The daemon deauthenticates before it exits, so the access point frees
    /// the station straight away instead of holding it until a timeout.
    Shutdown,
}

#[derive(Subcommand)]
pub enum PortAction {
    /// Activate a port and set it up.
    Up {
        /// Name of the port, e.g. eth0.
        name: String,
    },
    /// Show information about a port.
    Info {
        /// Name of the port, e.g. eth0.
        name: String,
        /// Show the ipv4 and ipv6 information.
        #[arg(long)]
        protocol: bool,
        /// Show the MAC address.
        #[arg(long)]
        mac: bool,
    },
    /// Configure addressing for a port.
    Set {
        /// Name of the port, e.g. eth0.
        name: String,
        /// How the port should obtain its addresses.
        mode: AddressMode,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AddressMode {
    /// Set ipv4 and ipv6 with dhcp.
    Dhcp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?} should parse: {e}"))
    }

    #[test]
    fn the_command_tree_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn scan_takes_an_optional_port() {
        assert!(matches!(
            parse(&["caw", "scan"]).command,
            Command::Scan { port: None }
        ));
        match parse(&["caw", "scan", "--port", "wlan0"]).command {
            Command::Scan { port } => assert_eq!(port.as_deref(), Some("wlan0")),
            _ => panic!("expected scan"),
        }
    }

    #[test]
    fn connect_takes_an_ssid_and_an_optional_port() {
        match parse(&["caw", "connect", "HomeNet"]).command {
            Command::Connect { ssid, port } => {
                assert_eq!(ssid, "HomeNet");
                assert_eq!(port, None);
            }
            _ => panic!("expected connect"),
        }
        match parse(&["caw", "connect", "HomeNet", "--port", "wlan0"]).command {
            Command::Connect { ssid, port } => {
                assert_eq!(ssid, "HomeNet");
                assert_eq!(port.as_deref(), Some("wlan0"));
            }
            _ => panic!("expected connect"),
        }
    }

    /// The security property the whole prompt exists for: there must be no way
    /// to put a passphrase on the command line, because `ps` shows argv to
    /// every user on the machine.
    #[test]
    fn connect_refuses_a_second_positional_argument() {
        assert!(Cli::try_parse_from(["caw", "connect", "HomeNet", "hunter2"]).is_err());
        assert!(
            Cli::try_parse_from(["caw", "connect", "HomeNet", "--passphrase", "hunter2"]).is_err()
        );
    }

    #[test]
    fn disconnect_and_status_parse() {
        match parse(&["caw", "disconnect", "HomeNet"]).command {
            Command::Disconnect { ssid } => assert_eq!(ssid, "HomeNet"),
            _ => panic!("expected disconnect"),
        }
        assert!(matches!(parse(&["caw", "status"]).command, Command::Status));
    }

    /// Stopping the daemon takes no arguments: there is one of it, and it is
    /// found through the socket rather than named.
    #[test]
    fn shutdown_takes_nothing() {
        assert!(matches!(
            parse(&["caw", "shutdown"]).command,
            Command::Shutdown
        ));
        assert!(Cli::try_parse_from(["caw", "shutdown", "cawd"]).is_err());
    }

    /// The port commands keep the shape they already had.
    #[test]
    fn port_actions_stay_action_first() {
        match parse(&["caw", "port", "up", "eth0"]).command {
            Command::Port {
                action: PortAction::Up { name },
            } => assert_eq!(name, "eth0"),
            _ => panic!("expected port up"),
        }
        match parse(&["caw", "port", "info", "eth0", "--mac"]).command {
            Command::Port {
                action:
                    PortAction::Info {
                        name,
                        protocol,
                        mac,
                    },
            } => {
                assert_eq!(name, "eth0");
                assert!(!protocol);
                assert!(mac);
            }
            _ => panic!("expected port info"),
        }
        match parse(&["caw", "port", "set", "eth0", "dhcp"]).command {
            Command::Port {
                action: PortAction::Set { name, mode },
            } => {
                assert_eq!(name, "eth0");
                assert_eq!(mode, AddressMode::Dhcp);
            }
            _ => panic!("expected port set"),
        }
        assert!(matches!(parse(&["caw", "ports"]).command, Command::Ports));
    }

    #[test]
    fn an_unknown_address_mode_is_rejected() {
        assert!(Cli::try_parse_from(["caw", "port", "set", "eth0", "static"]).is_err());
    }
}
