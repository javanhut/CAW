//! End-to-end exercise of the DHCP plumbing, for a network namespace.
//!
//! Drives exactly what `cawd`'s engine drives -- `Dhcp4` + `Dhcp4Socket` +
//! `Rtnl::{add_broadcast_route, add_address, add_default_route}` -- against a
//! real server on a veth pair, without needing a wireless stack. Not a unit
//! test because it wants root (port 68, netlink writes) and its own netns;
//! see the harness in the RavenLinux notes.
//!
//!     dhcp_e2e <ifname>
//!
//! Exits 0 once a lease is applied and read back from the kernel.

use std::time::{Duration, Instant};

use caw_dhcp::{Action, Dhcp4, Dhcp4Socket, Input, Timer, new_xid};
use caw_rtnl::Rtnl;

fn main() {
    let ifname = std::env::args().nth(1).expect("usage: dhcp_e2e <ifname>");

    let mut rtnl = Rtnl::open().expect("rtnetlink");
    let link = rtnl
        .link_by_name(&ifname)
        .expect("links")
        .expect("no such interface");
    let mac = link.mac.expect("interface has no MAC");

    rtnl.add_broadcast_route(link.index)
        .expect("broadcast route");
    // Without this the OFFER is a martian under rp_filter and never arrives.
    rtnl.add_dhcp_probe_route(link.index).expect("probe route");

    let socket = Dhcp4Socket::open().expect("socket (needs root for port 68)");
    let xid = new_xid().expect("xid");
    let mut machine = Dhcp4::new(mac, xid).with_hostname("dhcp-e2e");

    let mut pending = machine.poll(Input::Start(xid));
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut retransmit_at: Option<Instant> = None;

    loop {
        // Perform what the machine asked, the way the engine does.
        for action in pending.drain(..) {
            match action {
                Action::Broadcast(data) => socket.send_broadcast(&data).expect("broadcast"),
                Action::Unicast { to, data } => socket.send_to(to, &data).expect("unicast"),
                Action::SetTimer {
                    timer: Timer::Retransmit,
                    secs,
                } => {
                    retransmit_at = Some(Instant::now() + Duration::from_secs(secs.into()));
                }
                // Renew/rebind/expiry are hours away; not this test's business.
                Action::SetTimer { .. } => {}
                Action::Configured(lease) => {
                    println!(
                        "lease: {}/{} gw {:?} dns {:?}",
                        lease.addr, lease.prefix_len, lease.gateway, lease.dns
                    );
                    rtnl.add_address(link.index, lease.addr, lease.prefix_len)
                        .expect("add_address");
                    if let Some(gw) = lease.gateway {
                        rtnl.add_default_route(link.index, gw)
                            .expect("add_default_route");
                    }
                    rtnl.del_dhcp_probe_route(link.index)
                        .expect("del_dhcp_probe_route");
                    // Read it back: the kernel, not this program, is the judge.
                    let ok = rtnl.addresses().expect("addresses").iter().any(|a| {
                        a.index == link.index && a.addr == std::net::IpAddr::V4(lease.addr)
                    });
                    assert!(
                        ok,
                        "the kernel does not show the address that was just added"
                    );
                    println!("verified: address is on the interface");
                    std::process::exit(0);
                }
                Action::Deconfigure(reason) => panic!("deconfigured: {reason:?}"),
                Action::Failed => {
                    eprintln!("no server answered {} tries", caw_dhcp::MAX_TRIES);
                    std::process::exit(1);
                }
            }
        }

        if Instant::now() > deadline {
            eprintln!("no lease within 20s");
            std::process::exit(1);
        }

        // The socket is non-blocking; a short nap stands in for the reactor.
        std::thread::sleep(Duration::from_millis(50));
        let mut buf = [0u8; 1500];
        match socket.recv(&mut buf) {
            Ok(n) => pending = machine.poll(Input::Datagram(&buf[..n])),
            Err(caw_dhcp::Error::Io(e)) if e == rustix::io::Errno::AGAIN => {
                if retransmit_at.is_some_and(|at| Instant::now() >= at) {
                    retransmit_at = None;
                    pending = machine.poll(Input::Timeout(Timer::Retransmit));
                }
            }
            Err(e) => panic!("recv: {e}"),
        }
    }
}
