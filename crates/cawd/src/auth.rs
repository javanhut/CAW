//! Who may ask for what.
//!
//! Authorization is by peer credentials rather than by the socket's mode. The
//! socket has to be reachable by everyone, because reading — scan results,
//! status, the port list — is open to any user; only the requests that change
//! something are restricted. `SO_PEERCRED` is what tells the two apart, and
//! the kernel fills it in at connect time, so it cannot be forged by a client
//! that later drops privileges or exits.
//!
//! Group membership is resolved by reading `/etc/group` and `/etc/passwd`
//! directly. Going through NSS would mean linking libc's resolver, which is
//! exactly the C dependency this tree is built to avoid, and shelling out to
//! `getent` is worse: it is a fork, a `PATH` lookup and a parse of someone
//! else's output format.

use std::path::Path;

use rustix::net::UCred;

/// The process on the other end of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

impl Peer {
    pub fn from_ucred(cred: UCred) -> Self {
        Self {
            pid: cred.pid.as_raw_pid(),
            uid: cred.uid.as_raw(),
            gid: cred.gid.as_raw(),
        }
    }
}

/// One entry of `/etc/group`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub gid: u32,
    /// Names listed in the fourth field. These are the supplementary members;
    /// a user whose *primary* group this is does not appear here at all.
    pub members: Vec<String>,
}

/// Find one group by name.
///
/// Malformed lines are skipped rather than fatal: `/etc/group` picks up NIS
/// compatibility entries (`+:::`), comments and hand-edited damage, and none
/// of that should stop the daemon from finding the line it came for.
pub fn find_group(contents: &str, name: &str) -> Option<Group> {
    for line in contents.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let (Some(group_name), Some(_passwd), Some(gid)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if group_name != name {
            continue;
        }
        let Ok(gid) = gid.trim().parse::<u32>() else {
            continue;
        };
        let members = fields
            .next()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .collect();
        return Some(Group { gid, members });
    }
    None
}

/// The login name for a uid, from `/etc/passwd`.
pub fn user_name(contents: &str, uid: u32) -> Option<String> {
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(':');
        let (Some(name), Some(_passwd), Some(field_uid)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if field_uid.trim().parse::<u32>() == Ok(uid) {
            return Some(name.to_owned());
        }
    }
    None
}

/// The group and user databases, as text.
///
/// Re-read for each connection rather than cached at startup: adding yourself
/// to the `caw` group should take effect on your next command, not on the
/// daemon's next restart. Two small files per accepted connection is nothing
/// next to the netlink round trips that follow. A file that cannot be read is
/// treated as empty, which denies rather than grants.
pub struct Database {
    group: String,
    passwd: String,
}

impl Database {
    pub fn load() -> Self {
        Self::from_paths("/etc/group", "/etc/passwd")
    }

    pub fn from_paths(group: impl AsRef<Path>, passwd: impl AsRef<Path>) -> Self {
        Self {
            group: std::fs::read_to_string(group).unwrap_or_default(),
            passwd: std::fs::read_to_string(passwd).unwrap_or_default(),
        }
    }

    #[cfg(test)]
    fn from_text(group: &str, passwd: &str) -> Self {
        Self {
            group: group.to_owned(),
            passwd: passwd.to_owned(),
        }
    }

    /// May this peer issue a request that changes something?
    ///
    /// Root always may. Otherwise the peer must be in the `caw` group, either
    /// as its primary group — the only one `SO_PEERCRED` reports — or by name
    /// in the group's member list, which is where a supplementary membership
    /// shows up.
    pub fn may_change_state(&self, peer: Peer, group_name: &str) -> bool {
        if peer.uid == 0 {
            return true;
        }
        let Some(group) = find_group(&self.group, group_name) else {
            // No such group: nobody but root can have been put in it.
            return false;
        };
        if peer.gid == group.gid {
            return true;
        }
        user_name(&self.passwd, peer.uid).is_some_and(|name| group.members.contains(&name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = "\
root:x:0:
# a comment
wheel:x:998:alice
caw:x:975:alice,bob
+:::
";

    const PASSWD: &str = "\
root:x:0:0::/root:/bin/bash
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1001:975::/home/bob:/bin/bash
mallory:x:1002:1002::/home/mallory:/bin/bash
";

    fn peer(uid: u32, gid: u32) -> Peer {
        Peer { pid: 42, uid, gid }
    }

    #[test]
    fn finds_a_group_and_its_members() {
        let group = find_group(GROUP, "caw").unwrap();
        assert_eq!(group.gid, 975);
        assert_eq!(group.members, ["alice", "bob"]);
    }

    #[test]
    fn a_group_with_no_members_parses_as_empty() {
        let group = find_group(GROUP, "root").unwrap();
        assert_eq!(group.gid, 0);
        assert!(group.members.is_empty());
    }

    #[test]
    fn missing_group_is_none_rather_than_a_guess() {
        assert!(find_group(GROUP, "netdev").is_none());
        assert!(find_group("", "caw").is_none());
    }

    /// Every one of these appears in the wild. None may hide a later line.
    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let damaged = "\
garbage with no colons
caw:x
caw:x:not-a-number:alice
:::
+:::

caw:x:975:alice
";
        let group = find_group(damaged, "caw").unwrap();
        assert_eq!(group.gid, 975);
        assert_eq!(group.members, ["alice"]);
    }

    #[test]
    fn members_field_tolerates_stray_commas_and_spaces() {
        let group = find_group("caw:x:975:,alice, bob,,\n", "caw").unwrap();
        assert_eq!(group.members, ["alice", "bob"]);
    }

    #[test]
    fn resolves_a_uid_to_a_name() {
        assert_eq!(user_name(PASSWD, 1000).as_deref(), Some("alice"));
        assert_eq!(user_name(PASSWD, 0).as_deref(), Some("root"));
        assert_eq!(user_name(PASSWD, 4242), None);
        assert_eq!(user_name("broken\nalice:x:zzz:\n", 1000), None);
    }

    #[test]
    fn root_may_change_state() {
        let db = Database::from_text(GROUP, PASSWD);
        assert!(db.may_change_state(peer(0, 0), "caw"));
    }

    /// bob's *primary* group is `caw`, which is all `SO_PEERCRED` reports.
    #[test]
    fn primary_group_member_may_change_state() {
        let db = Database::from_text(GROUP, PASSWD);
        assert!(db.may_change_state(peer(1001, 975), "caw"));
    }

    /// alice is in `caw` supplementarily, so her peer credentials say gid
    /// 1000 and only the member list can vouch for her.
    #[test]
    fn supplementary_group_member_may_change_state() {
        let db = Database::from_text(GROUP, PASSWD);
        assert!(db.may_change_state(peer(1000, 1000), "caw"));
    }

    #[test]
    fn an_unrelated_user_may_not() {
        let db = Database::from_text(GROUP, PASSWD);
        assert!(!db.may_change_state(peer(1002, 1002), "caw"));
    }

    /// A uid with no passwd entry cannot be matched against the member list,
    /// and a name that only looks like a member does not count.
    #[test]
    fn an_unknown_uid_may_not() {
        let db = Database::from_text(GROUP, PASSWD);
        assert!(!db.may_change_state(peer(4242, 4242), "caw"));
    }

    #[test]
    fn a_missing_caw_group_denies_everyone_but_root() {
        let db = Database::from_text("root:x:0:\n", PASSWD);
        assert!(db.may_change_state(peer(0, 0), "caw"));
        assert!(!db.may_change_state(peer(1000, 1000), "caw"));
    }

    /// Unreadable files must not become an open door.
    #[test]
    fn an_unreadable_database_denies() {
        let db = Database::from_paths("/nonexistent/group", "/nonexistent/passwd");
        assert!(!db.may_change_state(peer(1000, 1000), "caw"));
        assert!(db.may_change_state(peer(0, 0), "caw"));
    }
}
