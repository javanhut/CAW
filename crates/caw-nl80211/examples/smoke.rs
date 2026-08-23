//! Exercises every kernel-facing path against a real radio.
//!
//! Needs mac80211_hwsim and an AP to find:
//!
//! ```text
//! docker run --rm --privileged --net=host -v /lib/modules:/lib/modules:ro \
//!     -v "$PWD":/work caw-dev bash -c '
//!         ip link set wlan0 up
//!         hostapd -B hostapd.conf
//!         cd /work && cargo run -p caw-nl80211 --example smoke'
//! ```
//!
//! Association is expected to end in a reason-15 deauthentication: the 4-way
//! handshake is `caw-eapol`'s job and does not run here.

use caw_nl80211::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut nl = Nl80211::open()?;
    let family = nl.family();
    println!(
        "family {} groups {:?} mask {:#x}",
        family.id,
        family.groups,
        family.groups.mask()?
    );

    for w in nl.wiphys()? {
        println!(
            "wiphy {} {} ap={} offload: psk={} 1x={} sae={}",
            w.index, w.name, w.supports_ap, w.offloads_4way_psk, w.offloads_4way_1x, w.offloads_sae
        );
    }

    let ifaces = nl.interfaces()?;
    for i in &ifaces {
        println!(
            "iface {} {} wiphy {} {}",
            i.ifindex, i.name, i.wiphy, i.iftype
        );
    }
    let name = std::env::args().nth(1).unwrap_or_else(|| "wlan0".into());
    let ifindex = ifaces
        .iter()
        .find(|i| i.name == name)
        .ok_or_else(|| format!("no interface {name}"))?
        .ifindex;

    let mut events = nl.events()?;
    nl.trigger_scan(ifindex, &[])?;
    wait_for(&mut events, |e| {
        matches!(e, Event::ScanComplete { .. } | Event::ScanAborted { .. })
    })?;

    let results = nl.scan_results(ifindex)?;
    for b in &results {
        println!(
            "  {:02x?} {:?} {} MHz {} dBm {} ms ago {}",
            b.bssid,
            String::from_utf8_lossy(&b.ssid),
            b.freq_mhz,
            b.signal_dbm,
            b.last_seen_ms,
            b.security
        );
    }

    let Some(bss) = results.iter().find(|b| b.rsn.is_some()) else {
        println!("no WPA network in range; stopping before association");
        return Ok(());
    };
    let rsn = bss.rsn.as_ref().expect("filtered on");
    let pairwise: Vec<u32> = rsn
        .pairwise_ciphers
        .iter()
        .copied()
        .filter_map(cipher_suite)
        .collect();
    let akms: Vec<u32> = rsn.akms.iter().copied().map(akm_suite).collect();

    nl.connect(
        ifindex,
        &Connect {
            ssid: &bss.ssid,
            bssid: Some(bss.bssid),
            freq_mhz: Some(bss.freq_mhz),
            auth_type: NL80211_AUTHTYPE_OPEN_SYSTEM,
            wpa_versions: NL80211_WPA_VERSION_2,
            pairwise_ciphers: &pairwise,
            group_cipher: cipher_suite(rsn.group_cipher),
            akms: &akms,
            mfp: None,
            // The AP's own element serves only because this test AP advertises
            // exactly one cipher and one AKM. A real station composes its own.
            ies: &rsn.raw,
        },
    )?;

    let connected = wait_for(&mut events, |e| matches!(e, Event::Connected { .. }))?;
    println!("connect: {connected:?}");
    if !matches!(
        connected,
        Event::Connected {
            status: ConnectStatus::Success,
            ..
        }
    ) {
        return Err("association failed".into());
    }

    // Junk keys: the kernel validates the attributes, not the material.
    nl.new_pairwise_key(ifindex, bss.bssid, WLAN_CIPHER_SUITE_CCMP, &[0u8; 16])?;
    nl.new_group_key(ifindex, 1, WLAN_CIPHER_SUITE_CCMP, &[0u8; 16], &[0u8; 6])?;
    nl.set_default_key(ifindex, 1, KeyScope::Multicast)?;
    println!("keys installed");

    nl.disconnect(ifindex, 3)?;
    println!("disconnected");
    Ok(())
}

fn wait_for(
    events: &mut Events,
    want: impl Fn(&Event) -> bool,
) -> Result<Event, Box<dyn std::error::Error>> {
    for _ in 0..150 {
        for event in events.read()? {
            println!("event: {event:?}");
            if want(&event) {
                return Ok(event);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("timed out waiting for an event".into())
}
