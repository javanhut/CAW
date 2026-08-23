//! The caw daemon.
//!
//! Owns every file descriptor and every timer; owns no decisions. It polls its
//! descriptors, hands what arrives to `caw_core::Connection`, and performs the
//! actions it gets back.
//!
//! # Why a daemon at all
//!
//! An access point rotates the group key periodically, typically hourly. If no
//! userspace process answers that EAPOL exchange the AP deauthenticates us, so
//! a connection is only as durable as the process holding the EAPOL socket.
//! Reconnect, roaming and suspend/resume need the same residency.
//!
//! # Why no async runtime
//!
//! There are on the order of six descriptors here. A `poll` loop over them is
//! smaller and easier to reason about than an executor, and because every
//! state machine below is sans-IO, there is nothing to await. `rustix` gives
//! us `poll`, `timerfd` and `signalfd` without libc.
#![forbid(unsafe_code)]

fn main() {
    todo!("reactor: poll {{ rtnl, genl, eapol, ipc, timerfd, signalfd }}")
}

/// The descriptors the reactor watches.
struct Reactor {
    /// rtnetlink: link and address changes.
    _rtnl: caw_netlink::Socket,
    /// generic netlink: nl80211 commands and multicast events.
    _genl: caw_netlink::Socket,
    /// AF_PACKET on EtherType 0x888E: handshake and rekey.
    _eapol: caw_eapol::EapolSocket,
    /// Accepts CLI clients on /run/caw/caw.sock.
    _ipc: IpcListener,
}

/// Unix socket server.
///
/// Authorization is by peer credentials (SO_PEERCRED) rather than socket mode
/// alone: reads (scan, status) are open, mutations require root or membership
/// of the `caw` group. Secrets travel over this socket in a
/// [`caw_ipc::Request::Secret`] rather than on argv, where `ps` would show them.
struct IpcListener {
    _priv: (),
}
