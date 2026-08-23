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
    Scan,
    /// Connect to a wireless network.
    Connect {
        /// Name (SSID) of the network.
        ssid: String,
    },
    /// Disconnect from a wireless network.
    Disconnect {
        /// Name (SSID) of the network.
        ssid: String,
    },
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

#[derive(Clone, Debug, ValueEnum)]
pub enum AddressMode {
    /// Set ipv4 and ipv6 with dhcp.
    Dhcp,
}
