//! Resolving the nl80211 generic-netlink family.
//!
//! Generic netlink families have no fixed `nlmsg_type`; the kernel allocates
//! one at registration and the controller family — the only one at a known id
//! — hands it out by name. The same reply carries the multicast group ids,
//! nested one level deeper, which is why this crate needs a nested attribute
//! walk at all.

use crate::Error;
use crate::attr::Attrs;
use crate::consts::*;

/// A resolved generic-netlink family.
pub struct Family {
    /// The `nlmsg_type` to send this family's commands as.
    pub id: u16,
    pub groups: Groups,
}

/// The nl80211 multicast groups caw listens on.
///
/// `None` means the running kernel did not advertise the group, which is a
/// real possibility on an old or cut-down kernel and not something to paper
/// over: without `mlme` there is no association result to wait for.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Groups {
    /// Scan started, finished, or was aborted.
    pub scan: Option<u32>,
    /// Authentication, association, connect, disconnect, external auth.
    pub mlme: Option<u32>,
    /// Wiphy and interface changes.
    pub config: Option<u32>,
}

impl Groups {
    fn named(&self) -> [(&'static str, Option<u32>); 3] {
        [
            ("scan", self.scan),
            ("mlme", self.mlme),
            ("config", self.config),
        ]
    }

    /// The `nl_groups` bitmask to bind with.
    ///
    /// Subscription rides that mask because `rustix` exposes no
    /// `NETLINK_ADD_MEMBERSHIP`, and reaching past it to a raw `setsockopt`
    /// would mean `unsafe` in caw.
    ///
    /// The mask is numbered from one — the kernel tests bit `group - 1` — while
    /// the controller reports a group's own id, so every id shifts down by one
    /// on the way in. Getting that wrong subscribes to the neighbouring group,
    /// which is quiet rather than loud: nl80211 lays `config`, `scan`,
    /// `regulatory` and `mlme` out consecutively, so an off-by-one still
    /// delivers scan results and silently drops every association result.
    ///
    /// Only 32 groups fit. A kernel that put nl80211 above that is reported
    /// rather than left silently unsubscribed, for the same reason.
    pub fn mask(&self) -> Result<u32, Error> {
        let mut mask = 0;
        for (name, id) in self.named() {
            let Some(id) = id else { continue };
            mask |= id
                .checked_sub(1)
                .and_then(|bit| 1u32.checked_shl(bit))
                .ok_or(Error::GroupOutOfRange { name, id })?;
        }
        Ok(mask)
    }
}

impl Family {
    /// Decode a `CTRL_CMD_NEWFAMILY` reply body, `genlmsghdr` included.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let mut id = None;
        let mut groups = Groups::default();

        for attr in Attrs::of_body(body) {
            match attr.kind {
                CTRL_ATTR_FAMILY_ID => id = crate::attr::u16_of(&attr),
                // A nest of nests: one sub-stream per group, each holding a
                // name and an id.
                CTRL_ATTR_MCAST_GROUPS => {
                    for group in Attrs::new(attr.payload) {
                        let mut name = None;
                        let mut gid = None;
                        for field in Attrs::new(group.payload) {
                            match field.kind {
                                // `Attr::str` borrows the attribute, which
                                // does not outlive the loop; resolution runs
                                // once, so the copy is not worth avoiding.
                                CTRL_ATTR_MCAST_GRP_NAME => {
                                    name = field.str().map(str::to_owned);
                                }
                                CTRL_ATTR_MCAST_GRP_ID => gid = field.u32(),
                                _ => {}
                            }
                        }
                        match name.as_deref() {
                            Some("scan") => groups.scan = gid,
                            Some("mlme") => groups.mlme = gid,
                            Some("config") => groups.config = gid,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Some(Self { id: id?, groups })
    }
}
