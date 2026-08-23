//! The `ports` and `port` subcommands.

use std::error::Error;

use caw_rtnl::{Address, Kind, Link, Rtnl, format_mac};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Addresses on one link, rendered as `addr/prefix`.
fn addrs_for(addrs: &[Address], index: u32) -> Vec<String> {
    addrs
        .iter()
        .filter(|a| a.index == index)
        .map(|a| format!("{}/{}", a.addr, a.prefix_len))
        .collect()
}

/// A link's state as one word, distinguishing "up but no cable" from "down",
/// which is the difference people actually care about when something is wrong.
fn state_of(link: &Link) -> &'static str {
    if !link.is_up() {
        "down"
    } else if link.has_carrier() {
        "up"
    } else {
        "no-carrier"
    }
}

pub fn list() -> Result<()> {
    let mut rtnl = Rtnl::open()?;
    let links = rtnl.links()?;
    let addrs = rtnl.addresses()?;

    let rows: Vec<Vec<String>> = links
        .iter()
        .map(|l| {
            let a = addrs_for(&addrs, l.index);
            vec![
                l.name.clone(),
                l.kind.as_str().to_owned(),
                state_of(l).to_owned(),
                l.mac.as_ref().map(format_mac).unwrap_or_else(|| "-".into()),
                if a.is_empty() {
                    "-".to_owned()
                } else {
                    a.join(", ")
                },
            ]
        })
        .collect();

    print!(
        "{}",
        crate::table::render(&["NAME", "TYPE", "STATE", "MAC", "ADDRESSES"], &rows,)
    );
    Ok(())
}

pub fn info(name: &str, protocol: bool, mac: bool) -> Result<()> {
    let mut rtnl = Rtnl::open()?;
    let link = rtnl
        .link_by_name(name)?
        .ok_or_else(|| format!("no such port: {name}"))?;
    let addrs = addrs_for(&rtnl.addresses()?, link.index);

    // With no flags, show everything; a flag narrows the output to that field
    // so the command composes with scripts.
    let show_all = !protocol && !mac;

    if show_all {
        println!("{}", link.name);
    }
    if show_all {
        println!("  type       {}", link.kind.as_str());
        println!("  state      {}", state_of(&link));
        println!("  oper       {}", link.oper_state.as_str());
        println!("  index      {}", link.index);
        println!("  mtu        {}", link.mtu);
    }
    if show_all || mac {
        match &link.mac {
            Some(m) => println!(
                "{}{}",
                if show_all { "  mac        " } else { "" },
                format_mac(m)
            ),
            None if show_all => println!("  mac        -"),
            None => {}
        }
    }
    if show_all || protocol {
        let v4: Vec<_> = addrs.iter().filter(|a| !a.contains(':')).collect();
        let v6: Vec<_> = addrs.iter().filter(|a| a.contains(':')).collect();
        for (label, set) in [("ipv4", v4), ("ipv6", v6)] {
            if set.is_empty() {
                if show_all {
                    println!("  {label}       -");
                }
                continue;
            }
            for a in set {
                if show_all {
                    println!("  {label}       {a}");
                } else {
                    println!("{a}");
                }
            }
        }
    }
    Ok(())
}

pub fn set_up(name: &str, up: bool) -> Result<()> {
    let mut rtnl = Rtnl::open()?;
    let link = rtnl
        .link_by_name(name)?
        .ok_or_else(|| format!("no such port: {name}"))?;

    if link.is_up() == up {
        println!("{name} is already {}", if up { "up" } else { "down" });
        return Ok(());
    }

    rtnl.set_up(link.index, up)?;
    println!("{name} is now {}", if up { "up" } else { "down" });
    if up && matches!(link.kind, Kind::Wireless) {
        println!("note: wireless ports also need `caw connect <ssid>` to carry traffic");
    }
    Ok(())
}
