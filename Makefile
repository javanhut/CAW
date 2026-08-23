# Installation for Arch Linux.
#
# Honours DESTDIR and PREFIX, so this is directly usable from a PKGBUILD:
#
#     build()   { make; }
#     package() { make DESTDIR="$pkgdir" install; }
#
# Deliberately does not run systemctl, useradd or udevadm: those are the
# package manager's job, and running them here would break packaged installs.

PREFIX          ?= /usr
BINDIR          ?= $(PREFIX)/bin
LIBDIR          ?= $(PREFIX)/lib
DATADIR         ?= $(PREFIX)/share
SYSTEMD_UNITDIR ?= $(LIBDIR)/systemd/system
SYSUSERSDIR     ?= $(LIBDIR)/sysusers.d
LICENSEDIR      ?= $(DATADIR)/licenses/caw

CARGO   ?= cargo
INSTALL ?= install

# Enterprise (802.1X/EAP) needs a TLS stack, which pulls in a C dependency.
# It is off by default so the standard build stays pure Rust:
#     make FEATURES=enterprise
FEATURES ?=
feature_args := $(if $(strip $(FEATURES)),--features "$(strip $(FEATURES))",)

# --locked keeps builds reproducible from the committed Cargo.lock.
CARGO_ARGS ?= --release --locked --workspace $(feature_args)
TARGETDIR  ?= target/release

.PHONY: all build check test clippy fmt clean install uninstall container help

all: build

build:
	$(CARGO) build $(CARGO_ARGS)

check:
	$(CARGO) check --workspace --all-targets $(feature_args)

test:
	$(CARGO) test --workspace $(feature_args)

clippy:
	$(CARGO) clippy --workspace --all-targets $(feature_args) -- -D warnings

fmt:
	$(CARGO) fmt --all --check

clean:
	$(CARGO) clean
	rm -rf target-container

install: build
	$(INSTALL) -Dm755 $(TARGETDIR)/caw  $(DESTDIR)$(BINDIR)/caw
	$(INSTALL) -Dm755 $(TARGETDIR)/cawd $(DESTDIR)$(BINDIR)/cawd
	$(INSTALL) -Dm644 dist/cawd.service $(DESTDIR)$(SYSTEMD_UNITDIR)/cawd.service
	$(INSTALL) -Dm644 dist/caw.sysusers $(DESTDIR)$(SYSUSERSDIR)/caw.conf
	$(INSTALL) -Dm644 LICENSE           $(DESTDIR)$(LICENSEDIR)/LICENSE

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/caw
	rm -f $(DESTDIR)$(BINDIR)/cawd
	rm -f $(DESTDIR)$(SYSTEMD_UNITDIR)/cawd.service
	rm -f $(DESTDIR)$(SYSUSERSDIR)/caw.conf
	rm -f $(DESTDIR)$(LICENSEDIR)/LICENSE
	-rmdir $(DESTDIR)$(LICENSEDIR) 2>/dev/null || true

# caw talks to the kernel, so tests need Linux. On a non-Linux host this runs
# the suite in the Arch container instead.
container:
	docker/caw-dev make test

help:
	@echo 'targets: build check test clippy fmt install uninstall clean container'
	@echo 'vars:    PREFIX=$(PREFIX) DESTDIR= FEATURES='
