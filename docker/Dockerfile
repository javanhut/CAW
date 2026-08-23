# Dev/test container for caw.
#
# caw targets Arch Linux. This image is the test bed: it provides the Rust
# toolchain and a real Linux kernel interface (netlink) so the nl80211,
# rtnetlink and EAPOL layers can be exercised without WiFi hardware.
#
# The base is Arch Linux ARM on aarch64 hosts; the official archlinux image
# publishes x86_64 only. Override with --build-arg BASE=archlinux:latest when
# building for x86_64.
ARG BASE=lopsided/archlinux:latest
FROM ${BASE}

# Arch Linux ARM ships a gcc-libs that conflicts with the current base-devel;
# --overwrite lets the full sync resolve it in one pass.
RUN pacman -Syu --noconfirm --overwrite '*' \
        rust cargo base-devel \
        kmod iproute2 iw \
        git python3 \
    && pacman -Scc --noconfirm

WORKDIR /work
# Keep container artifacts out of the host's ./target (different arch/libc).
ENV CARGO_TARGET_DIR=/work/target-container
