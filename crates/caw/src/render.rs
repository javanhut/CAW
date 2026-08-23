//! Turning daemon replies into terminal output.
//!
//! Deliberately free of the socket: every function here takes a value and
//! returns a `String`, so the tables can be checked against fixtures on any
//! host, exactly as the protocol code below `cawd` is.

use std::collections::HashSet;

use caw_ipc::{ConnectionStatus, Event, NetworkSummary};

use crate::table;

/// How a network without a name is shown. An access point that suppresses its
/// SSID still appears in a scan, and a blank cell reads as a bug.
const HIDDEN: &str = "(hidden)";

/// Signal strength as a word.
///
/// Raw dBm is a log scale most people cannot place — is -67 good? — so the
/// number is kept but a judgement is put beside it. The boundaries follow the
/// usual planning figures: -67 dBm is the point below which voice and video
/// start to suffer, and -80 dBm is roughly where a link stops being usable.
pub fn quality(dbm: i32) -> &'static str {
    match dbm {
        d if d >= -50 => "excellent",
        d if d >= -60 => "good",
        d if d >= -67 => "fair",
        d if d >= -80 => "weak",
        _ => "poor",
    }
}

/// `-42 dBm (excellent)` — the measurement and its meaning in one cell.
pub fn signal_cell(dbm: i32) -> String {
    format!("{dbm} dBm ({})", quality(dbm))
}

/// Channel number and band for a centre frequency, or `None` if the frequency
/// is outside the bands 802.11 numbers this way.
pub fn channel(freq_mhz: u32) -> Option<(u32, &'static str)> {
    match freq_mhz {
        2484 => Some((14, "2.4 GHz")),
        2412..=2472 => Some(((freq_mhz - 2407) / 5, "2.4 GHz")),
        // 5935 is 6 GHz channel 2, which sits below the band's own numbering
        // and so has to be spelled out.
        5935 => Some((2, "6 GHz")),
        5170..=5895 => Some(((freq_mhz - 5000) / 5, "5 GHz")),
        5955..=7115 => Some(((freq_mhz - 5950) / 5, "6 GHz")),
        _ => None,
    }
}

/// `6 (2.4 GHz)`, falling back to the raw frequency for anything unnumbered —
/// 60 GHz, or a band newer than this table.
pub fn channel_cell(freq_mhz: u32) -> String {
    match channel(freq_mhz) {
        Some((ch, band)) => format!("{ch} ({band})"),
        None => format!("{freq_mhz} MHz"),
    }
}

/// The scan table, strongest first.
///
/// One row per SSID, not per BSS. `caw connect` takes an SSID, so the SSID is
/// the unit the user chooses between; a mesh or a repeated network would
/// otherwise fill the screen with rows that are indistinguishable here and
/// interchangeable in practice. The strongest sighting wins, since that is the
/// one the radio would associate with. Nameless networks are kept apart by
/// BSSID because they are not interchangeable at all.
pub fn scan_table(mut networks: Vec<NetworkSummary>) -> String {
    networks.sort_by(|a, b| {
        b.signal_dbm
            .cmp(&a.signal_dbm)
            .then_with(|| a.ssid.cmp(&b.ssid))
    });

    let mut seen = HashSet::new();
    networks.retain(|n| {
        seen.insert(if n.ssid.is_empty() {
            n.bssid.clone()
        } else {
            n.ssid.clone()
        })
    });

    let rows: Vec<Vec<String>> = networks
        .iter()
        .map(|n| {
            vec![
                if n.ssid.is_empty() {
                    HIDDEN.to_owned()
                } else {
                    n.ssid.clone()
                },
                signal_cell(n.signal_dbm),
                channel_cell(n.freq_mhz),
                n.security.clone(),
                if n.known {
                    "*".to_owned()
                } else {
                    String::new()
                },
            ]
        })
        .collect();

    table::render(&["SSID", "SIGNAL", "CHANNEL", "SECURITY", "KNOWN"], &rows)
}

/// The current connection, laid out like `caw port info` so the two read the
/// same way.
pub fn status_block(s: &ConnectionStatus) -> String {
    let mut out = format!("{}\n", s.port);
    let mut field = |label: &str, value: &str| {
        out.push_str(&format!("  {label:<11}{value}\n"));
    };

    field("state", &s.state);
    field("network", s.ssid.as_deref().unwrap_or("-"));

    for (label, is_v6) in [("ipv4", false), ("ipv6", true)] {
        let mut any = false;
        for addr in s.addrs.iter().filter(|a| a.contains(':') == is_v6) {
            field(label, addr);
            any = true;
        }
        if !any {
            field(label, "-");
        }
    }
    out
}

/// One line of progress for the events that only report where the connection
/// has got to. Returns `None` for the events that change what the CLI does
/// next — those belong to the caller.
pub fn progress(event: &Event) -> Option<String> {
    Some(match event {
        Event::Scanning => "scanning".to_owned(),
        Event::Associating { bssid } => format!("associating with {bssid}"),
        Event::Authenticating => "authenticating".to_owned(),
        Event::Configuring => "configuring addresses".to_owned(),
        Event::Connected | Event::Failed { .. } | Event::NeedSecret { .. } => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(
        ssid: &str,
        bssid: &str,
        dbm: i32,
        freq: u32,
        security: &str,
        known: bool,
    ) -> NetworkSummary {
        NetworkSummary {
            ssid: ssid.to_owned(),
            bssid: bssid.to_owned(),
            signal_dbm: dbm,
            freq_mhz: freq,
            security: security.to_owned(),
            known,
        }
    }

    #[test]
    fn quality_words_bracket_the_planning_figures() {
        assert_eq!(quality(-20), "excellent");
        assert_eq!(quality(-50), "excellent");
        assert_eq!(quality(-51), "good");
        assert_eq!(quality(-60), "good");
        assert_eq!(quality(-61), "fair");
        assert_eq!(quality(-67), "fair");
        assert_eq!(quality(-68), "weak");
        assert_eq!(quality(-80), "weak");
        assert_eq!(quality(-81), "poor");
    }

    #[test]
    fn signal_keeps_the_number_beside_the_word() {
        assert_eq!(signal_cell(-42), "-42 dBm (excellent)");
        assert_eq!(signal_cell(-91), "-91 dBm (poor)");
    }

    #[test]
    fn frequencies_map_to_channels() {
        assert_eq!(channel(2412), Some((1, "2.4 GHz")));
        assert_eq!(channel(2437), Some((6, "2.4 GHz")));
        assert_eq!(channel(2472), Some((13, "2.4 GHz")));
        assert_eq!(channel(2484), Some((14, "2.4 GHz")));
        assert_eq!(channel(5180), Some((36, "5 GHz")));
        assert_eq!(channel(5745), Some((149, "5 GHz")));
        assert_eq!(channel(5935), Some((2, "6 GHz")));
        assert_eq!(channel(5955), Some((1, "6 GHz")));
        assert_eq!(channel(6175), Some((45, "6 GHz")));
    }

    #[test]
    fn an_unnumbered_frequency_falls_back_to_megahertz() {
        assert_eq!(channel(58320), None);
        assert_eq!(channel_cell(58320), "58320 MHz");
        assert_eq!(channel_cell(2437), "6 (2.4 GHz)");
    }

    #[test]
    fn scan_table_sorts_by_signal_and_marks_known_networks() {
        let table = scan_table(vec![
            net(
                "Neighbour",
                "aa:00:00:00:00:01",
                -78,
                2462,
                "WPA2-Personal",
                false,
            ),
            net(
                "HomeNet",
                "aa:00:00:00:00:02",
                -42,
                5180,
                "WPA3-Personal",
                true,
            ),
            net("CoffeeShop", "aa:00:00:00:00:03", -61, 2437, "Open", false),
        ]);

        assert_eq!(
            table,
            "\
SSID        SIGNAL               CHANNEL       SECURITY       KNOWN
HomeNet     -42 dBm (excellent)  36 (5 GHz)    WPA3-Personal  *
CoffeeShop  -61 dBm (fair)       6 (2.4 GHz)   Open
Neighbour   -78 dBm (weak)       11 (2.4 GHz)  WPA2-Personal
"
        );
    }

    /// `caw connect` takes an SSID, so the table shows one row per SSID and
    /// keeps the strongest sighting of it.
    #[test]
    fn repeated_ssids_collapse_to_their_strongest_bss() {
        let table = scan_table(vec![
            net(
                "Mesh",
                "aa:00:00:00:00:01",
                -70,
                2437,
                "WPA2-Personal",
                false,
            ),
            net(
                "Mesh",
                "aa:00:00:00:00:02",
                -45,
                5180,
                "WPA2-Personal",
                false,
            ),
            net(
                "Mesh",
                "aa:00:00:00:00:03",
                -80,
                2412,
                "WPA2-Personal",
                false,
            ),
        ]);
        assert_eq!(table.lines().count(), 2, "{table}");
        assert!(table.contains("-45 dBm"), "{table}");
    }

    /// Nameless networks are not interchangeable, so they are kept apart by
    /// BSSID rather than collapsed into one `(hidden)` row.
    #[test]
    fn hidden_networks_are_named_and_kept_apart() {
        let table = scan_table(vec![
            net("", "aa:00:00:00:00:01", -50, 2437, "WPA2-Personal", false),
            net("", "aa:00:00:00:00:02", -60, 2437, "WPA2-Personal", false),
        ]);
        assert_eq!(table.matches(HIDDEN).count(), 2, "{table}");
    }

    #[test]
    fn status_reads_like_port_info() {
        let status = ConnectionStatus {
            port: "wlan0".to_owned(),
            ssid: Some("HomeNet".to_owned()),
            state: "connected".to_owned(),
            addrs: vec!["192.168.1.24/24".to_owned(), "fe80::1/64".to_owned()],
        };
        assert_eq!(
            status_block(&status),
            "\
wlan0
  state      connected
  network    HomeNet
  ipv4       192.168.1.24/24
  ipv6       fe80::1/64
"
        );
    }

    #[test]
    fn status_shows_a_dash_for_what_is_missing() {
        let status = ConnectionStatus {
            port: "wlan0".to_owned(),
            ssid: None,
            state: "disconnected".to_owned(),
            addrs: vec![],
        };
        assert_eq!(
            status_block(&status),
            "\
wlan0
  state      disconnected
  network    -
  ipv4       -
  ipv6       -
"
        );
    }

    #[test]
    fn progress_covers_only_the_informational_events() {
        assert_eq!(progress(&Event::Scanning).as_deref(), Some("scanning"));
        assert_eq!(
            progress(&Event::Associating {
                bssid: "aa:bb:cc:dd:ee:ff".to_owned()
            })
            .as_deref(),
            Some("associating with aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(progress(&Event::Connected), None);
        assert_eq!(
            progress(&Event::Failed {
                reason: "x".to_owned()
            }),
            None
        );
    }
}
