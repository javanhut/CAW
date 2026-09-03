# caw architecture

This describes the intended end state, not only what is built today. Sections
marked **planned** are designed but not yet implemented; see
[Status](#status) for what actually works right now.

---

## 1. What caw is

caw connects an Arch Linux machine to a network. It replaces the
`iw` + `wpa_supplicant` + `dhcpcd` stack, and the `iwd` + `iwctl` pair, with a
single opinionated tool.

It is not a thin wrapper. caw speaks netlink to the kernel directly and
implements WPA — including the 4-way handshake, SAE and 802.1X — itself. It
never shells out to another program.

### Design goals

1. **Simple for the common case.** Joining a home network should be one
   command with one prompt. The complexity of `wpa_supplicant.conf` is a
   failure of interface design, not an inherent property of WiFi.
2. **Direct control when wanted.** The easy path must not be the only path.
3. **Pure Rust.** No C libraries, no `unsafe` in caw's own code.
4. **No hidden daemons the user must debug.** One service, one socket, and
   commands that need neither work without them.

### Why not just use what exists

`wpa_supplicant` carries two decades of enterprise and vendor configuration
surface, and its control interface reflects that. `iwd` fixed the architecture
— it talks nl80211 directly and implements its own crypto, which is the model
caw follows — but it is C, requires D-Bus, and `iwctl` puts the daemon in the
path of everything, including questions the kernel could answer by itself.

caw takes iwd's architecture, drops D-Bus, and keeps the daemon out of the way
of anything that does not need it.

---

## 2. Purity constraints, honestly stated

Three claims are often bundled together. They are not equally achievable.

| Claim | Status | Notes |
|---|---|---|
| No C libraries | **Achieved** | No libnl, no OpenSSL, no wpa_supplicant. `rustix` on its `linux_raw` backend issues syscalls directly, bypassing libc. All crypto is RustCrypto. |
| No `unsafe` in caw | **Achieved** | Every crate carries `#![forbid(unsafe_code)]`, enforced by the compiler. |
| No `unsafe` anywhere in the tree | **Impossible** | `std` does not expose `AF_NETLINK`. There is no safe path to a netlink socket; a raw syscall is `unsafe` by definition. `rustix` contains that so caw does not. |

Rust's `std` also links a libc on Linux regardless. Fighting that means
`no_std`, which is not worth it for this program. The meaningful version of the
goal — *caw does the work itself, in safe Rust, without delegating to C
tooling* — holds.

### The one planned exception

WPA2/3-Enterprise needs TLS, and `rustls` requires a crypto provider. The
options are `aws-lc-rs` (C), `ring` (C and assembly), or `rustls-rustcrypto`
(pure Rust, but currently `0.0.2-alpha` — too immature for code guarding
enterprise credentials against a hostile network).

Enterprise is therefore feature-gated. The default build stays pure:

```bash
make                      # Open / WPA2-PSK / WPA3-SAE — no C
make FEATURES=enterprise  # adds 802.1X, pulls in rustls + a C provider
```

If `rustls-rustcrypto` matures, swapping the provider touches nothing above the
`EapMethod` trait.

---

## 3. What the kernel does, and what caw must do

This split drives the whole design, and it is not what most people assume.

```
                    kernel (cfg80211 / mac80211)        caw
  scan                    performs                   requests, parses results
  association             performs                   requests
  4-way handshake            NO                      performs   <-- the crux
  group rekey                NO                      performs
  key installation        performs                   supplies keys
  SAE                        NO*                     performs
  802.1X / EAP               NO                      performs
  DHCP                       NO                      performs
```

\* Some fullmac devices advertise `NL80211_EXT_FEATURE_4WAY_HANDSHAKE_STA_PSK`
or SAE offload and will do it in firmware. caw uses the offload when the device
reports it, and falls back to doing the work itself otherwise.

**On mac80211 softmac drivers — iwlwifi, ath9k/10k/11k, mt76, rtw88, i.e.
nearly every laptop — userspace performs the 4-way handshake.** That single
fact is why caw needs its own crypto, its own EAPOL socket, and a daemon.

### Why a daemon is mandatory

An access point rotates the group key periodically, typically hourly. If no
userspace process answers that EAPOL exchange, the AP deauthenticates the
client. A fire-and-forget `caw connect` would produce a connection that dies
within the hour.

A connection is therefore only as durable as the process holding the EAPOL
socket. Reconnect after suspend, roaming between access points, and
reconnect-at-boot need the same residency. Hence `cawd`.

---

## 4. Crate layout

Layering is enforced by the compiler: dependency edges only point downward.

```
        caw (CLI)                          cawd (daemon)
          │   │                        ┌────────┴────────┐
          │   └──── caw-ipc ───────────┘             caw-core
          │                                    ┌────────┼──────────┐
      caw-rtnl ◄──────────────────────────────┘   caw-eapol   caw-dhcp
          │                                            │
          │                        caw-nl80211    caw-crypto
          │                             │  └───────────┘
          │                             │       │
          └────── caw-netlink ──────────┘   caw-80211
```

| Crate | Responsibility |
|---|---|
| `caw-netlink` | `AF_NETLINK` sockets, `nlmsghdr`/`nlattr` codec, dump handling |
| `caw-rtnl` | links, addresses, routes |
| `caw-80211` | 802.11 frame and IE parsing — RSN IE, SSID, ciphers, AKMs |
| `caw-nl80211` | wiphy enumeration, scan, associate, key install, power save, external auth |
| `caw-crypto` | PMK/PTK derivation, MIC, key wrap, SAE |
| `caw-eapol` | `AF_PACKET` transport, 4-way handshake, EAP methods |
| `caw-dhcp` | DHCPv4, DHCPv6, SLAAC |
| `caw-core` | profiles, policy, the connection state machine |
| `caw-ipc` | wire types shared by CLI and daemon |
| `cawd` | the reactor: owns every socket and timer |
| `caw` | the command line |

`caw-80211` exists separately because the RSN IE is not merely informational:
it is fed into the 4-way handshake and covered by the MIC, so the scan path and
the authentication path need the same parser and the same byte-exact
re-encoding.

---

## 5. Core design decisions

### 5.1 Sans-IO everywhere below the daemon

No state machine below `cawd` touches a socket or a clock. They consume bytes
and return actions:

```rust
impl Connection {
    pub fn poll(&mut self, input: Input) -> Vec<Action>;
}
```

`cawd` owns every file descriptor and every timer, and owns no decisions.
`caw-core` owns every decision and no file descriptors.

Two consequences:

- **Everything is testable without hardware.** A full 4-way handshake can be
  driven against published RFC vectors on any host — no kernel, no radio, no
  container. Only the integration layer needs Linux.
- **The daemon can be replaced.** The protocol logic has no opinion about how
  bytes arrive.

### 5.2 No async runtime

`cawd` watches roughly six descriptors: rtnetlink, generic netlink, the EAPOL
packet socket, the IPC listener, a `timerfd` and a `signalfd`. A `poll` loop
over them is smaller and easier to reason about than an executor, and because
every state machine is sans-IO there is nothing to await.

`tokio` would also pull in the `libc` crate. `rustix` provides `poll`,
`timerfd` and `signalfd` without it.

### 5.3 Not everything goes through the daemon

| Command | Path | Why |
|---|---|---|
| `caw ports` | direct rtnetlink | stateless kernel query, no privilege needed |
| `caw port info` | direct rtnetlink | same |
| `caw port up` | direct rtnetlink | one-shot, no persistent state; needs root |
| `caw scan` | via `cawd` | shares the wireless socket and scan cache |
| `caw connect` | via `cawd` | needs a connection that outlives the CLI |
| `caw disconnect` | via `cawd` | same |

Routing `caw ports` through a daemon would add a failure mode — daemon not
running — to a command that needs nothing. The CLI links `caw-rtnl` and
`caw-ipc`, and never links the crypto or wireless stack.

### 5.4 The authentication abstraction

Every WPA flavour ends in the same place: a 256-bit Pairwise Master Key fed to
the 4-way handshake. What differs is how the PMK is obtained, and critically
*when* and *over which transport*:

| Method | Stage | Transport | PMK from |
|---|---|---|---|
| WPA2-PSK | local | none | `PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256)` |
| WPA3-SAE | pre-association | 802.11 authentication frames | Dragonfly exchange |
| OWE | association | Diffie-Hellman in association IEs | DH shared secret |
| 802.1X | post-association | EAPOL-EAP | first 32 bytes of the MSK |

A trait assuming a single transport breaks on the others. So `PmkProvider`
declares its stage and exchanges opaque frames; the caller owns the socket and
decides where each frame goes:

```rust
pub trait PmkProvider {
    fn stage(&self) -> AuthStage;                                    // Local | PreAssoc | PostAssoc
    fn start(&mut self, ctx: &AuthContext<'_>) -> Result<Step, Error>;
    fn on_frame(&mut self, ctx: &AuthContext<'_>, frame: &[u8]) -> Result<Step, Error>;
    fn on_timeout(&mut self, ctx: &AuthContext<'_>) -> Result<Step, Error>;
}

pub enum Step { Send(Vec<u8>), Wait, Done(Pmk) }
```

The trait lives in `caw-crypto` because that is the lowest crate both
implementers share: `caw-crypto` provides the PSK and SAE providers,
`caw-eapol` provides the 802.1X one.

Enterprise nests a second trait, since PEAP and TTLS are containers that run an
inner method inside a TLS tunnel:

```rust
pub trait EapMethod {
    fn type_code(&self) -> u8;                                       // 13 = TLS, 21 = TTLS, 25 = PEAP
    fn on_request(&mut self, data: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn msk(&self) -> Option<[u8; 64]>;
}
```

Once any provider yields a PMK, the 4-way handshake is identical for all of
them. That is the payoff: one handshake implementation, one key-install path.

---

## 6. Connection lifecycle

```
    Idle
     │  connect
     ▼
  Scanning ──────────── no matching BSS ──────────┐
     │  BSS chosen by policy                      │
     ▼                                            │
  Authenticating   (SAE runs here, pre-assoc)     │
     │                                            │
     ▼                                            ▼
  Associating ──────── rejected ──────────────► Failed
     │                                            ▲
     ▼                                            │
  Handshaking      (4-way; 802.1X runs inside)    │
     │  keys installed via NL80211_CMD_NEW_KEY    │
     ▼                                            │
  Configuring      (DHCPv4 / SLAAC)               │
     │                                            │
     ▼                                            │
  Connected ◄──── rekey ────┐                     │
     │  deauth / carrier loss│                    │
     ▼                       └── group rekey EAPOL exchange
  Reconnecting ── backoff ──► Scanning
```

`Connected` is not a resting state. The daemon stays in the EAPOL exchange for
the life of the connection, answering group rekeys. Roaming re-enters
`Authenticating` for the new BSS without tearing down the IP configuration
where the network allows it.

### Autoconnect

`Idle` has a second way out. `Command::Autoconnect` enters `Scanning` with no
target at all: which network to join is a question for the scan results, and
`policy::best_known` answers it with the strongest BSS the machine has a saved
profile for. Everything downstream of that choice is the ordinary lifecycle —
same downgrade check, same AKM negotiation, same handshake.

The split is the usual one. `caw-core` decides *which* network qualifies; the
daemon decides *when* to ask, on a timer that backs off from ten seconds to
five minutes while nothing known is in range, and idles at a minute once
something is joined. The daemon's loop stops there: `caw-core` does its own
reconnecting with its own backoff once a network has actually been joined, so
the two never both retry the same link.

Two restrictions are worth stating, because they are what makes joining a
network with nobody watching safe:

- **A credential or nothing.** There is no client attached to answer
  `Action::RequestSecret`, so only a profile that already holds a credential
  can be joined unattended. `Profile::new` sets `autoconnect` for exactly those
  and leaves it off for `Credential::None` — an open network authenticates
  nothing, so a saved one is a name any AP in range can also broadcast, and the
  downgrade floor has nothing to bite on when the recorded level is already
  Open. A PSK or SAE network cannot be impersonated that way: the 4-way
  handshake is mutual, and an AP without the passphrase fails it.
- **Off is reachable.** `cawd --no-autoconnect` turns the loop off for the
  machine; clearing `autoconnect` in a profile turns it off for one network.

---

## 7. IPC

Newline-delimited JSON over a Unix socket at `/run/caw/caw.sock`. No D-Bus.

A request may be answered by a stream of events before its final response, so
`caw connect` can report progress through association, handshake and address
configuration rather than blocking silently.

```
caw connect HomeNet
   │  {"Connect":{"ssid":"HomeNet","port":null}}
   ▼
cawd
   │  {"Scanning":null}
   │  {"Associating":{"bssid":"aa:bb:cc:dd:ee:ff"}}
   │  {"NeedSecret":{"token":1,"prompt":"Passphrase for HomeNet","kind":"Passphrase"}}
   ◄─ {"Secret":{"token":1,"value":"..."}}
   │  {"Authenticating":null}
   │  {"Configuring":null}
   │  {"Connected":null}
   ▼
  Ok
```

Secrets travel over the socket in a `Secret` message rather than on argv, where
`ps` would expose them to every user on the machine.

`Request::Shutdown` is on the same socket, and is how the daemon is stopped:

```
caw shutdown
   │  "Shutdown"
   ▼
cawd                              disconnect, then unlink the socket
   │
   ▼
  Ok
```

It is a state change, so it needs root or the `caw` group like any other. The
`Ok` is written before the teardown begins, so it is already in the socket
buffer when the daemon goes; a closed connection after that is success, not a
failure, and the CLI treats it as such.

This exists because `cawd` cannot catch SIGTERM. rustix 1.1.4 has no
`signalfd` — it is listed in `rustix::not_implemented::yet` — and the signal
calls it does have are `unsafe fn` behind its `runtime` feature, so there is no
safe path from a signal to a pollable descriptor without libc. The unit file
uses `caw shutdown` as its `ExecStop=`. On a plain `kill` nothing is left
behind, because `RuntimeDirectory=` removes `/run/caw` and the kernel closes
the descriptors, but the station leaves the air without deauthenticating and
the AP holds the slot until its inactivity timeout.

---

## 8. Security model

**Privilege.** `cawd` runs as root but holds only `CAP_NET_ADMIN` (netlink,
key installation) and `CAP_NET_RAW` (the EAPOL packet socket). The systemd unit
drops everything else and applies the usual hardening, with one deliberate
exception: `/dev/rfkill` stays reachable, because a soft-blocked radio is a
leading cause of "wifi does not work" and caw should be able to report and
clear it.

**Authorization.** The daemon checks peer credentials on the socket
(`SO_PEERCRED`) rather than relying on file mode alone. Read-only commands —
scan, status — are open. State-changing commands require root or membership of
the `caw` group, created by `/usr/lib/sysusers.d/caw.conf`.

**Secrets at rest.** Profiles live under `/var/lib/caw/`, mode 0700, files
0600, root-only. Not the kernel keyring: `keyctl` is not exposed by `rustix`,
and a root-only file is sufficient given the daemon already runs as root.
Key material is wrapped in `Zeroize` types so it is cleared on drop.

**Downgrade protection.** A profile records the security level at which a
network was first seen. caw refuses to join an SSID with weaker security than
recorded, so an attacker cannot present an open network under a known name.

---

## 9. Testing

Three layers, because WiFi is awkward to test:

1. **Unit tests, no kernel.** Everything sans-IO — codecs, KDFs, handshake
   state machines — runs anywhere, including macOS. Crypto is checked against
   published RFC and IEEE test vectors.
2. **Integration against a real kernel.** `docker/caw-dev` builds an Arch
   container with the Rust toolchain, run `--privileged --net=host` so netlink
   works against the host kernel.
3. **Radio-level tests with virtual hardware.** `docker/hwsim-setup.sh` loads
   `mac80211_hwsim`, giving two virtual radios that can associate with each
   other. One runs an access point, the other runs caw, which exercises a
   genuine 4-way handshake with no physical hardware.

`iw` and `hostapd` appear in the dev container as **test oracles and test
fixtures only** — to independently confirm kernel state, and to be the AP under
test. caw never invokes them, and they are not runtime dependencies.

---

## 10. Installed layout

```
/usr/bin/caw                            the CLI
/usr/bin/cawd                           the daemon
/usr/lib/systemd/system/cawd.service    unit, hardened, CAP_NET_ADMIN + CAP_NET_RAW
/usr/lib/sysusers.d/caw.conf            creates the `caw` group
/usr/share/licenses/caw/LICENSE
/run/caw/caw.sock                       IPC socket        (RuntimeDirectory)
/var/lib/caw/profiles/                  saved networks    (StateDirectory, 0700)
```

The `Makefile` honours `DESTDIR` and `PREFIX`, so a PKGBUILD is just:

```bash
build()   { make; }
package() { make DESTDIR="$pkgdir" install; }
```

It deliberately does not run `systemctl` or `systemd-sysusers`; that is the
package manager's job.

---

## 11. Status

| Step | Scope | State |
|---|---|---|
| 1 | `caw-netlink`, `caw-rtnl` — `ports`, `port up`, `port info` | **done** |
| 2 | `caw-80211`, `caw-nl80211` — `scan` with real security modes | planned |
| 3 | `caw-crypto`, `caw-eapol` — WPA2-PSK, first connection | planned |
| 4 | `caw-dhcp` — `port set dhcp`, traffic-carrying connections | planned |
| 5 | `caw-ipc`, `cawd`, `caw-core` — rekey, reconnect, suspend/resume | planned |
| 6 | WPA3-SAE, then 802.1X/EAP | planned |

Steps 3 and 4 run in-process behind a direct path until step 5 moves them
behind the daemon. The sans-IO split is what makes that migration cheap: the
state machines do not change, only who calls `poll`.

### Known constraints

- caw is Linux-only. `caw-netlink` and `caw-rtnl` cannot compile on macOS,
  because `rustix`'s netlink API is `cfg(linux_kernel)`-gated. Use the dev
  container on other hosts.
- Wireless interfaces are currently detected via `/sys/class/net/*/phy80211`,
  because a managed-mode WiFi interface reports `ARPHRD_ETHER` exactly like a
  wired NIC. nl80211 supersedes this at step 2.
- There are no man pages or shell completions yet. Both are generatable from
  the clap definitions once the CLI settles.
- `cawd` cannot catch SIGTERM, for the reason given in §7, so a clean stop goes
  through `caw shutdown` (or `systemctl stop cawd`, which runs it). A `kill`
  leaves nothing behind on disk but does not deauthenticate. Closing that gap
  needs one `signalfd` in rustix and one arm in the reactor's dispatch.
