#!/usr/bin/env bash
# Provision virtual WiFi radios for testing caw.
#
# The kernel behind Docker here is Fedora CoreOS, which does not ship
# mac80211_hwsim. This fetches the module matching the *exact* running kernel
# (vermagic must match) from Fedora's Koji archive and loads it, giving two
# virtual radios that can associate with each other.
#
# Run once per boot of the Docker VM. Undo with:  rmmod mac80211_hwsim
set -euo pipefail

RADIOS="${1:-2}"

if [ -d /sys/module/mac80211_hwsim ]; then
    echo "mac80211_hwsim already loaded; radios: $(ls /sys/class/ieee80211/ | tr '\n' ' ')"
    exit 0
fi

K="$(uname -r)"                    # e.g. 7.0.9-205.fc44.aarch64
ver="${K%%-*}"                     # 7.0.9
rest="${K#*-}"                     # 205.fc44.aarch64
rel="${rest%.*}"                   # 205.fc44
arch="${rest##*.}"                 # aarch64
rpm="kernel-modules-internal-${ver}-${rel}.${arch}.rpm"
url="https://kojipkgs.fedoraproject.org/packages/kernel/${ver}/${rel}/${arch}/${rpm}"

echo "kernel $K -> $rpm"
tmp="$(mktemp -d)"
curl -sfL -o "$tmp/kmi.rpm" "$url" \
    || { echo "could not fetch $url" >&2; exit 1; }

( cd "$tmp" && rpm2cpio kmi.rpm | cpio -idm 2>/dev/null )
ko="$tmp/lib/modules/$K/internal/drivers/net/wireless/virtual/mac80211_hwsim.ko.xz"
[ -f "$ko" ] || { echo "hwsim module not in rpm" >&2; exit 1; }

xz -dc "$ko" > "$tmp/hwsim.ko"
modprobe cfg80211
modprobe mac80211
insmod "$tmp/hwsim.ko" radios="$RADIOS"
rm -rf "$tmp"

echo "radios: $(ls /sys/class/ieee80211/ | tr '\n' ' ')"
