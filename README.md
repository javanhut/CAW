# CAW (Corvus Access Wifi)

A wifi and network terminal utility written in Rust for Raven Linux.

CAW makes connecting to wireless networks easy, without the difficulty of other
terminal tools. It speaks netlink to the kernel directly and implements WPA
itself, so it does not need `iw`, `iwctl`, `wpa_supplicant` or `dhcpcd`, and
never shells out to another program.

- **Pure Rust.** No C libraries. Every crate is `#![forbid(unsafe_code)]`.
- **Opinionated.** One command and one prompt to join a network.
- **Out of the way.** Commands that need no daemon do not use one.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it all fits together.

## Required Installations

- Make
- Rust

## Optional Installations

- [ImLazy](https://github.com/javanhut/ImLazy.git)

## Make Install

```bash
make
sudo make install
sudo systemctl enable --now cawd
```

Installs to `/usr`. Honours `DESTDIR` and `PREFIX`, so a PKGBUILD is just
`build() { make; }` and `package() { make DESTDIR="$pkgdir" install; }`.

WPA2/3-Enterprise is feature-gated because its TLS stack pulls in a C
dependency; the default build stays pure Rust:

```bash
make FEATURES=enterprise
```

## ImLazy Install

```bash
imlazy
sudo imlazy install
sudo systemctl enable --now cawd
```

## Quick start

### Activate an ethernet port

_(example port name eth0)_

```bash
caw ports                     # List ports
caw port up eth0              # Activate port and set it up
caw port info eth0            # Get all port information for eth0
caw port set eth0 dhcp        # Sets ipv4/ipv6 with dhcp
caw port info eth0 --protocol # Gets ipv4 and ipv6 information
caw port info eth0 --mac      # Get MAC address information of port
```

```
$ caw ports
NAME   TYPE      STATE       MAC                ADDRESSES
lo     loopback  up          -                  127.0.0.1/8, ::1/128
eth0   ethernet  up          5a:94:ef:e4:0c:ee  192.168.1.24/24
wlan0  wireless  no-carrier  02:00:00:00:00:00  -
```

`ports` and `port info` need no privileges and no daemon. `port up` needs root.

`no-carrier` means the port is up but has no usable link — an unplugged cable,
or a radio that has not associated yet.

### Scan for wireless networks

```bash
caw scan
```

### Connect to a wireless network

```bash
caw connect ExampleNetworkName # runs an interactive setup for this network
```

### Disconnect from a wireless network

```bash
caw disconnect ExampleNetworkName
```

## Status

Working: `caw ports`, `caw port up`, `caw port info`.

Planned: `port set`, `scan`, `connect`, `disconnect`. These parse and exit
non-zero with a message. The roadmap is in
[ARCHITECTURE.md](docs/ARCHITECTURE.md#11-status).

## Development

caw is Linux-only — the netlink crates cannot compile on other platforms. On a
non-Linux host, build and test in the provided Arch container:

```bash
docker/caw-dev                # interactive shell
docker/caw-dev make test      # one-shot
```

For wireless work you also need radios. `docker/hwsim-setup.sh` loads
`mac80211_hwsim` and gives you two virtual ones that can associate with each
other, so the scan and handshake paths can be tested without hardware.

```bash
make test      # unit tests
make clippy    # lints, warnings denied
make fmt       # formatting check
```

## Licence

MIT. See [LICENSE](LICENSE).
