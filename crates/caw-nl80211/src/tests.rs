//! Everything here runs without a kernel: the wire format is the contract, and
//! a wrong constant or a mis-indexed bitmap has to fail on the test host
//! rather than three states into a connection attempt.

use caw_netlink::{ATTR_HDR_LEN, HDR_LEN, Message, align};

use crate::attr::{Attrs, GENL_HDRLEN, NLA_F_NESTED, genlmsghdr, u16_of};
use crate::consts::*;
use crate::wiphy::WiphyChunk;
use crate::{Bss, Connect, Event, ExtFeatures, Family, Groups, KeyScope, Nest, mbm_to_dbm, msg};

/// Encode one attribute, independently of [`Nest`], so that a parser bug and
/// a builder bug cannot cancel out.
fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = ATTR_HDR_LEN + payload.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align(len), 0);
    out
}

fn attrs_of(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// A generic-netlink message body: `genlmsghdr` then attributes.
fn body(cmd: u8, parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = genlmsghdr(cmd, 0).to_vec();
    out.extend_from_slice(&attrs_of(parts));
    out
}

/// The body of a request built by [`msg`], with its netlink header checked and
/// stripped.
fn built_body(msg: &[u8]) -> &[u8] {
    let len = u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
    assert_eq!(len, msg.len(), "nlmsg_len must cover the whole message");
    &msg[HDR_LEN..]
}

fn msg_kind(msg: &[u8]) -> u16 {
    u16::from_ne_bytes([msg[4], msg[5]])
}

/// The WPA2-PSK RSN element, byte for byte as an AP sends it.
const RSN_WPA2_PSK: [u8; 22] = [
    0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
];

#[test]
fn nest_round_trips_through_attrs() {
    let bytes = Nest::new()
        .attr_u8(NL80211_KEY_DEFAULT_TYPE_UNICAST, 7)
        .attr_u32(NL80211_ATTR_IFINDEX, 3)
        .attr(NL80211_ATTR_SSID, b"caw")
        .flag(NL80211_ATTR_PRIVACY)
        .finish();

    let parsed: Vec<_> = Attrs::new(&bytes).collect();
    assert_eq!(parsed.len(), 4);
    assert_eq!(parsed[0].u8(), Some(7));
    assert_eq!(parsed[1].u32(), Some(3));
    assert_eq!(parsed[2].payload, b"caw");
    // "caw" is three bytes; the next attribute must still start aligned.
    assert!(parsed[3].payload.is_empty());
    assert_eq!(parsed[3].kind, NL80211_ATTR_PRIVACY);
}

#[test]
fn nested_flag_is_masked_off_the_type() {
    // The kernel sets NLA_F_NESTED on everything nla_nest_start opens, so an
    // unmasked NL80211_ATTR_BSS arrives as 0x802f and matches nothing.
    let raw = attr(NL80211_ATTR_BSS | NLA_F_NESTED, &[0; 4]);
    let found = Attrs::new(&raw).find(NL80211_ATTR_BSS);
    assert!(found.is_some());
}

#[test]
fn malformed_attribute_length_terminates_iteration() {
    assert_eq!(Attrs::new(&[0u8; 8]).count(), 0);
    // A length past the end of the buffer is not read.
    assert_eq!(Attrs::new(&[0xff, 0xff, 0x01, 0x00]).count(), 0);
}

#[test]
fn family_reply_yields_id_and_group_ids() {
    let group = |name: &str, id: u32| {
        let mut fields = name.as_bytes().to_vec();
        fields.push(0);
        attrs_of(&[
            attr(CTRL_ATTR_MCAST_GRP_NAME, &fields),
            attr(CTRL_ATTR_MCAST_GRP_ID, &id.to_ne_bytes()),
        ])
    };
    // Numbering deliberately non-contiguous and out of order: the kernel
    // allocates group ids globally, so nothing about them may be assumed.
    let groups = attrs_of(&[
        attr(1, &group("config", 3)),
        attr(2, &group("scan", 4)),
        attr(3, &group("regulatory", 5)),
        attr(4, &group("mlme", 6)),
    ]);
    let reply = body(
        1,
        &[
            attr(CTRL_ATTR_FAMILY_NAME, b"nl80211\0"),
            attr(CTRL_ATTR_FAMILY_ID, &28u16.to_ne_bytes()),
            attr(CTRL_ATTR_MCAST_GROUPS | NLA_F_NESTED, &groups),
        ],
    );

    let family = Family::parse(&reply).expect("family id present");
    assert_eq!(family.id, 28);
    assert_eq!(
        family.groups,
        Groups {
            scan: Some(4),
            mlme: Some(6),
            config: Some(3),
        }
    );
}

#[test]
fn family_without_an_id_is_not_a_family() {
    let reply = body(1, &[attr(CTRL_ATTR_FAMILY_NAME, b"nl80211\0")]);
    assert!(Family::parse(&reply).is_none());
}

#[test]
fn group_mask_covers_the_subscribed_groups() {
    let groups = Groups {
        scan: Some(4),
        mlme: Some(6),
        config: Some(3),
    };
    // Numbered from one: the kernel tests bit `group - 1`. An off-by-one here
    // subscribes to the neighbouring group, and because nl80211 lays its
    // groups out consecutively that still delivers scan results while silently
    // dropping every association result.
    assert_eq!(groups.mask().unwrap(), (1 << 3) | (1 << 5) | (1 << 2));

    // An unadvertised group contributes nothing rather than failing.
    assert_eq!(Groups::default().mask().unwrap(), 0);

    // The last id the mask reaches, and the first it does not. An id that
    // cannot be subscribed has to be reported, because an event that never
    // arrives looks like a hung connection.
    assert_eq!(
        Groups {
            scan: Some(32),
            ..Default::default()
        }
        .mask()
        .unwrap(),
        1 << 31
    );
    for id in [0, 33] {
        assert!(matches!(
            Groups {
                scan: Some(id),
                ..Default::default()
            }
            .mask(),
            Err(crate::Error::GroupOutOfRange { name: "scan", .. })
        ));
    }
}

#[test]
fn ext_feature_bits_are_indexed_from_the_first_byte() {
    // Bit index 15 is bit 7 of byte 1, bit index 16 is bit 0 of byte 2, and
    // bit index 38 is bit 6 of byte 4. Getting this wrong makes caw run a
    // handshake the device wanted to do, or skip one it did not.
    assert_eq!(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK, 15);
    assert_eq!(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X, 16);
    assert_eq!(NL80211_EXT_FEATURE_SAE_OFFLOAD, 38);

    let psk_only = ExtFeatures::new(&[0x00, 0x80, 0x00, 0x00, 0x00]);
    assert!(psk_only.has(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK));
    assert!(!psk_only.has(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X));
    assert!(!psk_only.has(NL80211_EXT_FEATURE_SAE_OFFLOAD));

    let dot1x_and_sae = ExtFeatures::new(&[0x00, 0x00, 0x01, 0x00, 0x40]);
    assert!(!dot1x_and_sae.has(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK));
    assert!(dot1x_and_sae.has(NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_1X));
    assert!(dot1x_and_sae.has(NL80211_EXT_FEATURE_SAE_OFFLOAD));

    // A kernel older than a feature sends a shorter array; that reads as
    // unsupported, not as a parse error.
    assert!(!ExtFeatures::new(&[0xff]).has(NL80211_EXT_FEATURE_SAE_OFFLOAD));
    assert!(!ExtFeatures::default().has(0));
}

#[test]
fn split_wiphy_dump_merges_into_one_phy() {
    let message = |parts: &[Vec<u8>]| {
        let payload = body(NL80211_CMD_NEW_WIPHY, parts);
        (payload, 0u32)
    };
    let chunk_of = |payload: &[u8]| {
        WiphyChunk::parse(&Message {
            len: (HDR_LEN + payload.len()) as u32,
            kind: 28,
            flags: 0,
            seq: 1,
            pid: 0,
            payload,
        })
        .expect("chunk carries a wiphy index")
    };

    let (names, _) = message(&[
        attr(NL80211_ATTR_WIPHY, &0u32.to_ne_bytes()),
        attr(NL80211_ATTR_WIPHY_NAME, b"phy0\0"),
        attr(
            NL80211_ATTR_SUPPORTED_IFTYPES | NLA_F_NESTED,
            &attrs_of(&[
                attr(NL80211_IFTYPE_STATION as u16, &[]),
                attr(NL80211_IFTYPE_AP as u16, &[]),
            ]),
        ),
    ]);
    let (features, _) = message(&[
        attr(NL80211_ATTR_WIPHY, &0u32.to_ne_bytes()),
        attr(NL80211_ATTR_EXT_FEATURES, &[0x00, 0x80, 0x00, 0x00, 0x40]),
    ]);

    let mut wiphy = chunk_of(&names).into_wiphy();
    chunk_of(&features).merge_into(&mut wiphy);

    assert_eq!(wiphy.index, 0);
    assert_eq!(wiphy.name, "phy0");
    // The later chunk said nothing about interface types; it must not undo
    // what the earlier one established.
    assert!(wiphy.supports_ap);
    assert!(wiphy.offloads_4way_psk);
    assert!(!wiphy.offloads_4way_1x);
    assert!(wiphy.offloads_sae);
}

#[test]
fn interface_parses_ifindex_wiphy_and_mac() {
    let payload = body(
        NL80211_CMD_NEW_INTERFACE,
        &[
            attr(NL80211_ATTR_IFINDEX, &7u32.to_ne_bytes()),
            attr(NL80211_ATTR_WIPHY, &1u32.to_ne_bytes()),
            attr(NL80211_ATTR_IFNAME, b"wlan0\0"),
            attr(NL80211_ATTR_IFTYPE, &NL80211_IFTYPE_STATION.to_ne_bytes()),
            attr(NL80211_ATTR_MAC, &[0x02, 0, 0, 0, 0x01, 0]),
        ],
    );
    let iface = crate::Interface::parse(&Message {
        len: (HDR_LEN + payload.len()) as u32,
        kind: 28,
        flags: 0,
        seq: 1,
        pid: 0,
        payload: &payload,
    })
    .expect("an interface with an ifindex");

    assert_eq!(iface.ifindex, 7);
    assert_eq!(iface.wiphy, 1);
    assert_eq!(iface.name, "wlan0");
    assert_eq!(iface.iftype, crate::IfType::Station);
    assert_eq!(iface.iftype.as_str(), "managed");
    assert_eq!(iface.mac, Some([0x02, 0, 0, 0, 0x01, 0]));
}

#[test]
fn wdev_without_a_netdev_is_skipped() {
    // A P2P device has a wdev but no ifindex, so nothing in caw can address it.
    let payload = body(
        NL80211_CMD_NEW_INTERFACE,
        &[attr(NL80211_ATTR_WIPHY, &1u32.to_ne_bytes())],
    );
    assert!(
        crate::Interface::parse(&Message {
            len: (HDR_LEN + payload.len()) as u32,
            kind: 28,
            flags: 0,
            seq: 1,
            pid: 0,
            payload: &payload,
        })
        .is_none()
    );
}

/// One BSS as a scan dump delivers it: a WPA2-PSK AP on channel 1.
fn captured_bss() -> Vec<u8> {
    let mut ies = vec![0x00, 0x08];
    ies.extend_from_slice(b"caw-test"); // SSID
    ies.extend_from_slice(&[0x03, 0x01, 0x01]); // DS parameter set, channel 1
    ies.extend_from_slice(&RSN_WPA2_PSK);

    attrs_of(&[
        attr(NL80211_BSS_BSSID, &[0x02, 0x00, 0x00, 0x00, 0x01, 0x00]),
        attr(NL80211_BSS_FREQUENCY, &2412u32.to_ne_bytes()),
        // ESS | Privacy | Short Slot Time
        attr(NL80211_BSS_CAPABILITY, &0x0411u16.to_ne_bytes()),
        attr(NL80211_BSS_INFORMATION_ELEMENTS, &ies),
        attr(NL80211_BSS_SIGNAL_MBM, &(-4550i32).to_ne_bytes()),
        attr(NL80211_BSS_SEEN_MS_AGO, &120u32.to_ne_bytes()),
    ])
}

#[test]
fn bss_parses_from_a_scan_dump() {
    let bss = Bss::parse(&captured_bss()).expect("a BSS with a BSSID");

    assert_eq!(bss.bssid, [0x02, 0x00, 0x00, 0x00, 0x01, 0x00]);
    assert_eq!(bss.ssid, b"caw-test");
    assert_eq!(bss.freq_mhz, 2412);
    assert_eq!(bss.signal_dbm, -46);
    assert_eq!(bss.last_seen_ms, 120);
    assert_eq!(bss.security, caw_80211::Security::Wpa2Personal);

    // The RSN element must survive byte for byte: the 4-way handshake compares
    // it against the copy in message 3.
    let rsn = bss.rsn.expect("an RSN element");
    assert_eq!(rsn.raw, RSN_WPA2_PSK);
    assert_eq!(rsn.akms, vec![caw_80211::Akm::Psk]);
    assert_eq!(
        crate::cipher_suite(rsn.group_cipher),
        Some(WLAN_CIPHER_SUITE_CCMP)
    );
    assert_eq!(crate::akm_suite(rsn.akms[0]), WLAN_AKM_SUITE_PSK);
}

#[test]
fn scan_dump_message_finds_its_nested_bss() {
    let payload = body(
        NL80211_CMD_NEW_SCAN_RESULTS,
        &[
            attr(NL80211_ATTR_GENERATION_STAND_IN, &1u32.to_ne_bytes()),
            attr(NL80211_ATTR_BSS | NLA_F_NESTED, &captured_bss()),
        ],
    );
    let bss = Attrs::of_body(&payload)
        .find(NL80211_ATTR_BSS)
        .and_then(|a| Bss::parse(a.payload))
        .expect("the nested BSS");
    assert_eq!(bss.ssid, b"caw-test");
}

/// NL80211_ATTR_GENERATION, which the kernel puts in front of every dumped
/// BSS. Only used here, to prove the BSS is found past it.
const NL80211_ATTR_GENERATION_STAND_IN: u16 = 46;

#[test]
fn bss_without_a_bssid_is_not_a_bss() {
    let nest = attr(NL80211_BSS_FREQUENCY, &2412u32.to_ne_bytes());
    assert!(Bss::parse(&nest).is_none());
}

#[test]
fn a_bss_with_no_signal_sorts_last() {
    let nest = attr(NL80211_BSS_BSSID, &[0; 6]);
    let bss = Bss::parse(&nest).unwrap();
    assert_eq!(bss.signal_dbm, Bss::UNKNOWN_SIGNAL);
    assert!(bss.signal_dbm < -100);
    // No elements at all, and no Privacy bit: an open network.
    assert_eq!(bss.security, caw_80211::Security::Open);
}

#[test]
fn signal_rounds_to_nearest_dbm() {
    assert_eq!(mbm_to_dbm(-4500), -45);
    // Truncation would call this -45, half a dB better than it is.
    assert_eq!(mbm_to_dbm(-4550), -46);
    assert_eq!(mbm_to_dbm(-4549), -45);
    assert_eq!(mbm_to_dbm(-4551), -46);
    assert_eq!(mbm_to_dbm(-9000), -90);
    assert_eq!(mbm_to_dbm(0), 0);
    assert_eq!(mbm_to_dbm(4550), 46);
}

#[test]
fn connect_carries_the_negotiated_suites() {
    let bytes = msg::connect(
        28,
        9,
        7,
        &Connect {
            ssid: b"caw-test",
            bssid: Some([0x02, 0, 0, 0, 0x01, 0]),
            freq_mhz: Some(2412),
            auth_type: NL80211_AUTHTYPE_OPEN_SYSTEM,
            wpa_versions: NL80211_WPA_VERSION_2,
            pairwise_ciphers: &[WLAN_CIPHER_SUITE_CCMP],
            group_cipher: Some(WLAN_CIPHER_SUITE_CCMP),
            akms: &[WLAN_AKM_SUITE_PSK],
            mfp: None,
            ies: &RSN_WPA2_PSK,
        },
    );

    assert_eq!(msg_kind(&bytes), 28);
    let payload = built_body(&bytes);
    assert_eq!(payload[..GENL_HDRLEN], [NL80211_CMD_CONNECT, 0, 0, 0]);

    let get = |kind| Attrs::of_body(payload).find(kind);
    assert_eq!(get(NL80211_ATTR_IFINDEX).unwrap().u32(), Some(7));
    assert_eq!(get(NL80211_ATTR_SSID).unwrap().payload, b"caw-test");
    assert_eq!(
        get(NL80211_ATTR_MAC).unwrap().payload,
        [0x02, 0, 0, 0, 0x01, 0]
    );
    assert_eq!(get(NL80211_ATTR_WIPHY_FREQ).unwrap().u32(), Some(2412));
    assert_eq!(
        get(NL80211_ATTR_WPA_VERSIONS).unwrap().u32(),
        Some(NL80211_WPA_VERSION_2)
    );
    assert_eq!(
        get(NL80211_ATTR_CIPHER_SUITE_GROUP).unwrap().u32(),
        Some(WLAN_CIPHER_SUITE_CCMP)
    );
    assert_eq!(
        get(NL80211_ATTR_AKM_SUITES).unwrap().u32(),
        Some(WLAN_AKM_SUITE_PSK)
    );
    // The kernel reads a suite list as an array of u32, not as a nest.
    let pairwise = get(NL80211_ATTR_CIPHER_SUITES_PAIRWISE).unwrap();
    assert_eq!(pairwise.payload.len(), 4);
    assert_eq!(pairwise.u32(), Some(WLAN_CIPHER_SUITE_CCMP));
    // Privacy is a flag, and is what tells the kernel keys will follow.
    assert!(get(NL80211_ATTR_PRIVACY).unwrap().payload.is_empty());
    assert!(get(NL80211_ATTR_USE_MFP).is_none());
    // Without this the association request carries no RSN element and the AP
    // refuses it with status 40; the crypto suites alone are not enough.
    assert_eq!(get(NL80211_ATTR_IE).unwrap().payload, RSN_WPA2_PSK);
}

#[test]
fn an_open_network_connects_without_privacy() {
    let bytes = msg::connect(
        28,
        1,
        7,
        &Connect {
            ssid: b"open",
            ..Default::default()
        },
    );
    let payload = built_body(&bytes);
    let get = |kind| Attrs::of_body(payload).find(kind);
    assert!(get(NL80211_ATTR_PRIVACY).is_none());
    assert!(get(NL80211_ATTR_WPA_VERSIONS).is_none());
    assert!(get(NL80211_ATTR_IE).is_none());
    assert_eq!(
        get(NL80211_ATTR_AUTH_TYPE).unwrap().u32(),
        Some(NL80211_AUTHTYPE_OPEN_SYSTEM)
    );
}

#[test]
fn wpa3_connects_with_sae_and_mandatory_mfp() {
    let bytes = msg::connect(
        28,
        1,
        7,
        &Connect {
            ssid: b"sae",
            auth_type: NL80211_AUTHTYPE_SAE,
            wpa_versions: NL80211_WPA_VERSION_3,
            pairwise_ciphers: &[WLAN_CIPHER_SUITE_CCMP],
            group_cipher: Some(WLAN_CIPHER_SUITE_CCMP),
            akms: &[WLAN_AKM_SUITE_SAE],
            mfp: Some(NL80211_MFP_REQUIRED),
            ..Default::default()
        },
    );
    let payload = built_body(&bytes);
    let get = |kind| Attrs::of_body(payload).find(kind);
    assert_eq!(
        get(NL80211_ATTR_AUTH_TYPE).unwrap().u32(),
        Some(NL80211_AUTHTYPE_SAE)
    );
    assert_eq!(
        get(NL80211_ATTR_USE_MFP).unwrap().u32(),
        Some(NL80211_MFP_REQUIRED)
    );
}

#[test]
fn a_scan_with_no_ssid_still_probes() {
    // Without an SSID entry the kernel scans passively and never finds a
    // network that only answers directed probes.
    let bytes = msg::trigger_scan(28, 1, 7, &[]);
    let payload = built_body(&bytes);
    let ssids = Attrs::of_body(payload)
        .find(NL80211_ATTR_SCAN_SSIDS)
        .expect("a wildcard entry");
    let entries: Vec<_> = Attrs::new(ssids.payload).collect();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].payload.is_empty());

    let bytes = msg::trigger_scan(28, 1, 7, &[b"one", b"two"]);
    let payload = built_body(&bytes);
    let ssids = Attrs::of_body(payload)
        .find(NL80211_ATTR_SCAN_SSIDS)
        .unwrap();
    let entries: Vec<_> = Attrs::new(ssids.payload)
        .map(|a| a.payload.to_vec())
        .collect();
    assert_eq!(entries, vec![b"one".to_vec(), b"two".to_vec()]);
}

#[test]
fn pairwise_key_goes_in_at_index_zero() {
    let bytes = msg::new_pairwise_key(
        28,
        1,
        7,
        [0x02, 0, 0, 0, 0x01, 0],
        WLAN_CIPHER_SUITE_CCMP,
        &[0xab; 16],
    );
    let payload = built_body(&bytes);
    assert_eq!(payload[0], NL80211_CMD_NEW_KEY);

    let get = |kind| Attrs::of_body(payload).find(kind);
    assert_eq!(get(NL80211_ATTR_KEY_IDX).unwrap().u8(), Some(0));
    assert_eq!(get(NL80211_ATTR_KEY_DATA).unwrap().payload, [0xab; 16]);
    assert_eq!(
        get(NL80211_ATTR_KEY_CIPHER).unwrap().u32(),
        Some(WLAN_CIPHER_SUITE_CCMP)
    );
    assert_eq!(
        get(NL80211_ATTR_KEY_TYPE).unwrap().u32(),
        Some(NL80211_KEYTYPE_PAIRWISE)
    );
    // The peer address is also what tells the kernel this is pairwise.
    assert_eq!(
        get(NL80211_ATTR_MAC).unwrap().payload,
        [0x02, 0, 0, 0, 0x01, 0]
    );
}

#[test]
fn group_key_carries_its_replay_counter_and_no_peer() {
    let bytes = msg::new_group_key(
        28,
        1,
        7,
        2,
        WLAN_CIPHER_SUITE_CCMP,
        &[0xcd; 16],
        &[1, 2, 3, 4, 5, 6],
    );
    let payload = built_body(&bytes);
    let get = |kind| Attrs::of_body(payload).find(kind);
    assert_eq!(get(NL80211_ATTR_KEY_IDX).unwrap().u8(), Some(2));
    assert_eq!(
        get(NL80211_ATTR_KEY_SEQ).unwrap().payload,
        [1, 2, 3, 4, 5, 6]
    );
    assert_eq!(
        get(NL80211_ATTR_KEY_TYPE).unwrap().u32(),
        Some(NL80211_KEYTYPE_GROUP)
    );
    assert!(get(NL80211_ATTR_MAC).is_none());
}

#[test]
fn default_key_names_the_traffic_it_covers() {
    let bytes = msg::set_default_key(28, 1, 7, 2, KeyScope::Multicast);
    let payload = built_body(&bytes);
    assert_eq!(payload[0], NL80211_CMD_SET_KEY);

    let get = |kind| Attrs::of_body(payload).find(kind);
    assert_eq!(get(NL80211_ATTR_KEY_IDX).unwrap().u8(), Some(2));
    assert!(get(NL80211_ATTR_KEY_DEFAULT).unwrap().payload.is_empty());

    let types: Vec<_> = Attrs::new(get(NL80211_ATTR_KEY_DEFAULT_TYPES).unwrap().payload)
        .map(|a| a.kind)
        .collect();
    assert_eq!(types, vec![NL80211_KEY_DEFAULT_TYPE_MULTICAST]);

    let both = msg::set_default_key(28, 1, 7, 0, KeyScope::Both);
    let types: Vec<_> = Attrs::of_body(built_body(&both))
        .find(NL80211_ATTR_KEY_DEFAULT_TYPES)
        .map(|a| Attrs::new(a.payload).map(|t| t.kind).collect())
        .unwrap();
    assert_eq!(
        types,
        vec![
            NL80211_KEY_DEFAULT_TYPE_UNICAST,
            NL80211_KEY_DEFAULT_TYPE_MULTICAST
        ]
    );
}

#[test]
fn disconnect_reason_is_sixteen_bits() {
    let bytes = msg::disconnect(28, 1, 7, 3);
    let payload = built_body(&bytes);
    let reason = Attrs::of_body(payload)
        .find(NL80211_ATTR_REASON_CODE)
        .unwrap();
    assert_eq!(reason.payload.len(), 2);
    assert_eq!(u16_of(&reason), Some(3));
}

#[test]
fn power_save_is_a_u32_state_on_the_interface() {
    let bytes = msg::set_power_save(28, 1, 7, false);
    assert_eq!(msg_kind(&bytes), 28);
    let payload = built_body(&bytes);
    assert_eq!(payload[0], NL80211_CMD_SET_POWER_SAVE);

    let attrs: Vec<_> = Attrs::of_body(payload).collect();
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].kind, NL80211_ATTR_IFINDEX);
    assert_eq!(attrs[0].u32(), Some(7));
    assert_eq!(attrs[1].kind, NL80211_ATTR_PS_STATE);
    // The kernel rejects anything but the two enum values, so a bool must
    // not be sent as a flag or a u8.
    assert_eq!(attrs[1].payload.len(), 4);
    assert_eq!(attrs[1].u32(), Some(NL80211_PS_DISABLED));

    let on = msg::set_power_save(28, 2, 7, true);
    let state = Attrs::of_body(built_body(&on))
        .find(NL80211_ATTR_PS_STATE)
        .unwrap();
    assert_eq!(state.u32(), Some(NL80211_PS_ENABLED));
}

#[test]
fn events_decode_from_their_command() {
    let scan = body(
        NL80211_CMD_NEW_SCAN_RESULTS,
        &[
            attr(NL80211_ATTR_WIPHY, &0u32.to_ne_bytes()),
            attr(NL80211_ATTR_IFINDEX, &7u32.to_ne_bytes()),
        ],
    );
    assert_eq!(
        Event::decode(&scan),
        Some(Event::ScanComplete {
            wiphy: 0,
            ifindex: 7
        })
    );

    let aborted = body(
        NL80211_CMD_SCAN_ABORTED,
        &[attr(NL80211_ATTR_IFINDEX, &7u32.to_ne_bytes())],
    );
    assert_eq!(
        Event::decode(&aborted),
        Some(Event::ScanAborted {
            wiphy: 0,
            ifindex: 7
        })
    );

    let gone = body(
        NL80211_CMD_DISCONNECT,
        &[
            attr(NL80211_ATTR_REASON_CODE, &15u16.to_ne_bytes()),
            attr(NL80211_ATTR_DISCONNECTED_BY_AP, &[]),
        ],
    );
    assert_eq!(
        Event::decode(&gone),
        Some(Event::Disconnected {
            reason: 15,
            by_ap: true
        })
    );

    // A locally requested disconnect carries neither.
    assert_eq!(
        Event::decode(&body(NL80211_CMD_DISCONNECT, &[])),
        Some(Event::Disconnected {
            reason: 0,
            by_ap: false
        })
    );

    let frame = body(
        NL80211_CMD_FRAME,
        &[attr(NL80211_ATTR_FRAME, &[0xb0, 0x00])],
    );
    assert_eq!(Event::decode(&frame), Some(Event::Frame(vec![0xb0, 0x00])));

    // Regulatory changes and survey results ride the same groups.
    assert_eq!(Event::decode(&body(36, &[])), None);
    assert_eq!(Event::decode(&[]), None);
}

#[test]
fn a_connect_timeout_is_not_a_success() {
    // The kernel sends NL80211_ATTR_TIMED_OUT and no status code at all when
    // no AP answered, and no BSSID either. Reading the missing status as zero
    // would report a connection that never happened, and requiring the BSSID
    // would drop the event and hang the state machine waiting for a result
    // that already came.
    let timed_out = body(
        NL80211_CMD_CONNECT,
        &[
            attr(NL80211_ATTR_TIMED_OUT, &[]),
            attr(NL80211_ATTR_IFINDEX, &7u32.to_ne_bytes()),
        ],
    );
    assert_eq!(
        Event::decode(&timed_out),
        Some(Event::Connected {
            bssid: None,
            status: crate::ConnectStatus::TimedOut,
        })
    );

    // Success is also reported without a status code, but with a BSSID.
    let connected = body(
        NL80211_CMD_CONNECT,
        &[attr(NL80211_ATTR_MAC, &[0x02, 0, 0, 0, 0x01, 0])],
    );
    assert_eq!(
        Event::decode(&connected),
        Some(Event::Connected {
            bssid: Some([0x02, 0, 0, 0, 0x01, 0]),
            status: crate::ConnectStatus::Success,
        })
    );

    // A refusal carries a real 802.11 status code.
    let refused = body(
        NL80211_CMD_CONNECT,
        &[
            attr(NL80211_ATTR_MAC, &[0x02, 0, 0, 0, 0x01, 0]),
            attr(NL80211_ATTR_STATUS_CODE, &1u16.to_ne_bytes()),
        ],
    );
    assert!(matches!(
        Event::decode(&refused),
        Some(Event::Connected {
            status: crate::ConnectStatus::Refused(1),
            ..
        })
    ));
}

#[test]
fn external_auth_reads_bssid_not_mac() {
    // The kernel sends NL80211_ATTR_BSSID here, unlike every other MLME event.
    let start = body(
        NL80211_CMD_EXTERNAL_AUTH,
        &[
            attr(NL80211_ATTR_BSSID, &[0x02, 0, 0, 0, 0x01, 0]),
            attr(NL80211_ATTR_SSID, b"sae-net"),
            attr(NL80211_ATTR_AKM_SUITES, &WLAN_AKM_SUITE_SAE.to_ne_bytes()),
            attr(
                NL80211_ATTR_EXTERNAL_AUTH_ACTION,
                &NL80211_EXTERNAL_AUTH_START.to_ne_bytes(),
            ),
        ],
    );
    assert_eq!(
        Event::decode(&start),
        Some(Event::ExternalAuth {
            bssid: [0x02, 0, 0, 0, 0x01, 0],
            ssid: b"sae-net".to_vec(),
            abort: false,
        })
    );

    let abort = body(
        NL80211_CMD_EXTERNAL_AUTH,
        &[
            attr(NL80211_ATTR_BSSID, &[0x02, 0, 0, 0, 0x01, 0]),
            attr(NL80211_ATTR_SSID, b"sae-net"),
            attr(
                NL80211_ATTR_EXTERNAL_AUTH_ACTION,
                &NL80211_EXTERNAL_AUTH_ABORT.to_ne_bytes(),
            ),
        ],
    );
    assert!(matches!(
        Event::decode(&abort),
        Some(Event::ExternalAuth { abort: true, .. })
    ));
}

#[test]
fn suite_selectors_match_the_rsn_element() {
    // 00-0F-AC:4 is CCMP-128, and the kernel wants it as one big-endian word.
    assert_eq!(WLAN_CIPHER_SUITE_CCMP, 0x000f_ac04);
    assert_eq!(WLAN_AKM_SUITE_PSK, 0x000f_ac02);
    assert_eq!(WLAN_AKM_SUITE_SAE, 0x000f_ac08);
    assert_eq!(suite([0x00, 0x0f, 0xac], 4), WLAN_CIPHER_SUITE_CCMP);

    // A vendor selector keeps its own OUI rather than being guessed away.
    let vendor = [0x00, 0x50, 0xf2, 0x02];
    assert_eq!(
        crate::cipher_suite(caw_80211::Cipher::Unknown(vendor)),
        Some(0x0050_f202)
    );
    // "Use the group key" is not something a station can ask for.
    assert_eq!(crate::cipher_suite(caw_80211::Cipher::UseGroup), None);
}
