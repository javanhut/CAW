//! Saved networks: what caw remembers about a network between connections.
//!
//! One file per SSID under [`DEFAULT_DIR`], mode 0600, in a directory that is
//! mode 0700. Not the kernel keyring: `keyctl` is not exposed by `rustix`, and
//! a root-only file is sufficient given the daemon already runs as root.
//!
//! Every entry point takes the base directory as a parameter rather than
//! reaching for a global path, so a test can point them at a temporary
//! directory and the daemon can be told where its state lives.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use caw_80211::Security;
use rustix::fs::{Mode, OFlags};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::Error;

/// Where profiles live on an installed system. `StateDirectory` in the unit
/// file creates it 0700.
pub const DEFAULT_DIR: &str = "/var/lib/caw/profiles";

/// A saved network.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Profile {
    #[serde(with = "ssid_bytes")]
    pub ssid: Vec<u8>,
    /// What the network advertised when the profile was written. Display only;
    /// [`Profile::min_security`] is the field with teeth.
    #[serde(with = "security_str")]
    pub security: Security,
    pub credential: Credential,
    /// Join this network without being asked when it is in range. See
    /// [`Profile::new`] for why a credential-less network does not get this by
    /// default.
    pub autoconnect: bool,
    /// Refuse to join this SSID with weaker security than first seen, so an
    /// attacker cannot present an open network under a known name and collect
    /// whatever the machine sends next.
    #[serde(with = "security_str")]
    pub min_security: Security,
}

impl Profile {
    /// A profile for a network just joined, recording its security as the
    /// floor for every later join. See [`crate::policy::security_floor`] for
    /// why the recorded floor is not always the observed level.
    ///
    /// Autoconnect is on for anything with a credential behind it and off for
    /// anything without. A PSK or SAE network proves it is itself — an
    /// impostor broadcasting the SSID cannot finish the handshake — but an
    /// open network authenticates nothing, so a saved one is just a name
    /// anybody in range can also broadcast, and `min_security` has nothing to
    /// bite on when the recorded floor is already Open. Turning the field back
    /// on is a deliberate edit of the profile.
    pub fn new(ssid: Vec<u8>, security: Security, credential: Credential) -> Self {
        let autoconnect = !matches!(credential, Credential::None);
        Self {
            ssid,
            security,
            credential,
            autoconnect,
            min_security: crate::policy::security_floor(security),
        }
    }

    /// Whether joining at `offered` would be a downgrade from what this
    /// profile recorded.
    pub fn accepts(&self, offered: Security) -> bool {
        crate::policy::is_at_least(offered, self.min_security)
    }
}

/// How a network is authenticated.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Credential {
    /// An open or OWE network: nothing to supply.
    None,
    /// WPA2-PSK or WPA3-SAE. The same string serves both, which is why a
    /// transition-mode network needs only one profile.
    Passphrase(Secret),
    Enterprise {
        identity: String,
        /// The identity sent in the clear, outside the TLS tunnel. PEAP and
        /// TTLS deployments set it to `anonymous@realm`.
        anonymous_identity: Option<String>,
        /// The name the RADIUS server's certificate must carry. Without it the
        /// realm of the identity is used, and without that a connection is
        /// refused rather than made to an unverified server.
        server_name: Option<String>,
        method: EnterpriseMethod,
        /// PEM trust anchors for the RADIUS server's certificate.
        ca_cert: Option<PathBuf>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum EnterpriseMethod {
    Peap { password: Secret },
    Ttls { password: Secret },
    Tls { client_cert: PathBuf, key: PathBuf },
}

/// A credential held in memory: zeroed on drop, and redacted in `Debug`.
///
/// The `Debug` impl is not cosmetic. A `Profile` reaches a log or an error
/// message as a whole, and a derived `Debug` would take the passphrase with it.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Compares two secrets this process already holds, so there is no oracle to
/// leak to: it answers "has the passphrase changed", never "is this the
/// passphrase".
impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl Eq for Secret {}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    /// The `String` is moved into the `Zeroizing`, not copied, so the buffer
    /// that ends up wiped is the one serde allocated. What cannot be reached
    /// is serde_json's own parse scratch — an argument for keeping profile
    /// files 0600 rather than for a different type here.
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(Zeroizing::new(String::deserialize(d)?)))
    }
}

/// The file name a profile for `ssid` is stored under, without a directory.
///
/// An SSID is arbitrary bytes: it may contain a slash, a NUL, a leading dot,
/// or nothing that is valid UTF-8. Percent-escaping everything outside
/// `[A-Za-z0-9_-]` keeps ordinary names readable in `ls` while staying a
/// bijection, which matters because this name is how a profile is found again.
pub fn file_name(ssid: &[u8]) -> String {
    let mut out = String::with_capacity(ssid.len() + 5);
    for &b in ssid {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push_str(".json");
    out
}

/// The inverse of [`file_name`]. `None` for anything this crate did not write,
/// which is how [`load_all`] skips an interrupted save or an editor's backup
/// without opening it.
pub fn ssid_from_file_name(name: &str) -> Option<Vec<u8>> {
    let stem = name.strip_suffix(".json")?;
    let mut out = Vec::with_capacity(stem.len());
    let mut rest = stem.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        match first {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => {
                out.push(first);
                rest = tail;
            }
            b'%' => {
                let hex = tail.get(..2)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                rest = &tail[2..];
            }
            _ => return None,
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The full path of `ssid`'s profile under `dir`.
pub fn path_for(dir: &Path, ssid: &[u8]) -> PathBuf {
    dir.join(file_name(ssid))
}

/// Read one profile. `None` when there is no such file, which is the ordinary
/// answer for a network that has never been joined.
pub fn load(dir: &Path, ssid: &[u8]) -> Result<Option<Profile>, Error> {
    match std::fs::read(path_for(dir, ssid)) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Every profile in `dir`, in no particular order.
///
/// A file that does not parse is skipped rather than failing the whole load:
/// one corrupt profile must not cost the machine every other network it knows.
pub fn load_all(dir: &Path) -> Result<Vec<Profile>, Error> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };

    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if ssid_from_file_name(name).is_none() {
            continue;
        }
        if let Ok(bytes) = std::fs::read(entry.path())
            && let Ok(profile) = serde_json::from_slice(&bytes)
        {
            out.push(profile);
        }
    }
    Ok(out)
}

/// Write a profile, replacing any earlier one for the same SSID.
///
/// Through a temporary file and a rename, so an interrupted write leaves the
/// previous profile intact rather than a truncated one: losing a passphrase to
/// a power cut is a worse failure than not saving the new one. The `fsync` is
/// what makes that guarantee hold across a crash and not merely a signal.
pub fn save(dir: &Path, profile: &Profile) -> Result<(), Error> {
    if profile.ssid.is_empty() {
        return Err(Error::EmptySsid);
    }
    create_dir(dir)?;

    let json = serde_json::to_vec_pretty(profile)?;
    let final_path = path_for(dir, &profile.ssid);
    let mut temp_path = final_path.clone().into_os_string();
    temp_path.push(".tmp");
    let temp_path = PathBuf::from(temp_path);

    let fd = rustix::fs::open(
        &temp_path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )?;
    // `open` applies the mode only when it creates the file, so a leftover
    // temporary from an interrupted save could otherwise keep whatever
    // permissions it had.
    rustix::fs::fchmod(&fd, Mode::RUSR | Mode::WUSR)?;

    let mut file = File::from(fd);
    file.write_all(&json)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&temp_path, &final_path)?;
    Ok(())
}

/// Forget a network. `false` when there was nothing to forget.
pub fn delete(dir: &Path, ssid: &[u8]) -> Result<bool, Error> {
    match std::fs::remove_file(path_for(dir, ssid)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// 0700, because the file mode alone would not stop another user listing which
/// networks this machine knows.
fn create_dir(dir: &Path) -> Result<(), Error> {
    match rustix::fs::mkdir(dir, Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// `Security` lives in `caw-80211`, which has no serde dependency, so the
/// mapping is here. The stored form is the one `caw status` prints, so a
/// profile stays readable by a human with an editor.
mod security_str {
    use super::*;

    pub fn serialize<S: Serializer>(security: &Security, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(security.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Security, D::Error> {
        let name = String::deserialize(d)?;
        const KNOWN: [Security; 10] = [
            Security::Open,
            Security::Wep,
            Security::Wpa1Personal,
            Security::Wpa1Enterprise,
            Security::Wpa2Personal,
            Security::Wpa3Personal,
            Security::Wpa2Wpa3Personal,
            Security::Wpa2Enterprise,
            Security::Wpa3Enterprise,
            Security::Owe,
        ];
        KNOWN
            .into_iter()
            .find(|s| s.as_str() == name)
            .ok_or_else(|| D::Error::custom(format!("unknown security level {name:?}")))
    }
}

/// An SSID is bytes, and JSON has no byte string. It is stored in the same
/// escaped form as the file name so that one encoding covers both, and so that
/// an SSID which is not UTF-8 survives the round trip.
mod ssid_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(ssid: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let escaped = file_name(ssid);
        s.serialize_str(escaped.strip_suffix(".json").expect("file_name appends it"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let escaped = String::deserialize(d)?;
        ssid_from_file_name(&format!("{escaped}.json"))
            .ok_or_else(|| D::Error::custom(format!("malformed ssid {escaped:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TempDir;

    fn psk_profile(ssid: &[u8]) -> Profile {
        Profile::new(
            ssid.to_vec(),
            Security::Wpa2Personal,
            Credential::Passphrase(Secret::new("ThisIsAPassword")),
        )
    }

    #[test]
    fn round_trips_through_the_store() {
        let dir = TempDir::new();
        let profile = psk_profile(b"HomeNet");

        assert_eq!(load(dir.path(), b"HomeNet").unwrap(), None);
        save(dir.path(), &profile).unwrap();
        assert_eq!(load(dir.path(), b"HomeNet").unwrap(), Some(profile));
        assert!(delete(dir.path(), b"HomeNet").unwrap());
        assert!(!delete(dir.path(), b"HomeNet").unwrap());
    }

    /// The salt of the PSK is the SSID exactly as it came off the air, so a
    /// name that is not text has to survive being stored and read back.
    #[test]
    fn a_non_utf8_ssid_survives() {
        let dir = TempDir::new();
        let ssid = vec![0xff, b'/', 0x00, b'.', 0x80];
        let profile = psk_profile(&ssid);

        save(dir.path(), &profile).unwrap();
        let loaded = load(dir.path(), &ssid).unwrap().expect("saved just now");
        assert_eq!(loaded.ssid, ssid);
        assert_eq!(load_all(dir.path()).unwrap(), vec![loaded]);
    }

    #[test]
    fn file_names_escape_what_a_path_cannot_hold() {
        assert_eq!(file_name(b"HomeNet"), "HomeNet.json");
        assert_eq!(file_name(b"../etc"), "%2E%2E%2Fetc.json");
        assert_eq!(file_name(b"a b"), "a%20b.json");
        for ssid in [&b"HomeNet"[..], b"../etc", b"a b", &[0xff, 0x00]] {
            assert_eq!(ssid_from_file_name(&file_name(ssid)).as_deref(), Some(ssid));
        }
        assert_eq!(ssid_from_file_name("HomeNet.json.tmp"), None);
        assert_eq!(ssid_from_file_name(".json"), None);
    }

    /// A profile holds a passphrase; anything else on the machine reading it is
    /// the failure this mode exists to prevent.
    #[test]
    fn a_profile_file_is_private() {
        use rustix::fs::Mode;

        let dir = TempDir::new();
        save(dir.path(), &psk_profile(b"HomeNet")).unwrap();

        let stat = rustix::fs::stat(path_for(dir.path(), b"HomeNet")).unwrap();
        let mode = Mode::from_raw_mode(stat.st_mode as _);
        assert_eq!(mode & Mode::RWXU, Mode::RUSR | Mode::WUSR);
        assert!(!mode.intersects(Mode::RWXG | Mode::RWXO), "group or other");

        let dir_stat = rustix::fs::stat(dir.path()).unwrap();
        let dir_mode = Mode::from_raw_mode(dir_stat.st_mode as _);
        assert!(!dir_mode.intersects(Mode::RWXG | Mode::RWXO), "directory");
    }

    /// An overwrite must not leave the store without the old profile if it is
    /// interrupted, and must not leave the temporary file behind if it is not.
    #[test]
    fn overwriting_leaves_no_debris() {
        let dir = TempDir::new();
        save(dir.path(), &psk_profile(b"HomeNet")).unwrap();

        let mut second = psk_profile(b"HomeNet");
        second.credential = Credential::Passphrase(Secret::new("another"));
        save(dir.path(), &second).unwrap();

        assert_eq!(load(dir.path(), b"HomeNet").unwrap(), Some(second));
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["HomeNet.json"]);
    }

    #[test]
    fn a_passphrase_does_not_reach_a_debug_line() {
        let rendered = format!("{:?}", psk_profile(b"HomeNet"));
        assert!(!rendered.contains("ThisIsAPassword"), "{rendered}");
    }

    #[test]
    fn an_unreadable_file_does_not_hide_the_rest() {
        let dir = TempDir::new();
        save(dir.path(), &psk_profile(b"HomeNet")).unwrap();
        std::fs::write(dir.path().join("Broken.json"), b"{ not json").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();

        let all = load_all(dir.path()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].ssid, b"HomeNet");
    }

    #[test]
    fn an_empty_ssid_is_refused() {
        let dir = TempDir::new();
        let profile = psk_profile(b"");
        assert!(matches!(save(dir.path(), &profile), Err(Error::EmptySsid)));
    }

    /// The stored form is the one a human sees, so it is asserted verbatim.
    #[test]
    fn the_stored_form_is_readable() {
        let json = serde_json::to_string(&psk_profile(b"HomeNet")).unwrap();
        assert_eq!(
            json,
            r#"{"ssid":"HomeNet","security":"WPA2-Personal","credential":{"Passphrase":"ThisIsAPassword"},"autoconnect":true,"min_security":"WPA2-Personal"}"#
        );
    }

    /// A network first seen in WPA3 transition mode offers PSK as well as SAE,
    /// so recording the pair as the floor would later refuse the network's own
    /// weaker half. See `policy::security_floor`.
    #[test]
    fn a_transition_network_records_its_weaker_half() {
        let profile = Profile::new(
            b"HomeNet".to_vec(),
            Security::Wpa2Wpa3Personal,
            Credential::Passphrase(Secret::new("x")),
        );
        assert_eq!(profile.min_security, Security::Wpa2Personal);
        assert!(profile.accepts(Security::Wpa3Personal));
        assert!(profile.accepts(Security::Wpa2Personal));
        assert!(!profile.accepts(Security::Open));
    }
}
