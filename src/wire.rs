//! The existing cvld/cplc wire boundary; no issuer dependency on device builds.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Feed {
    pub revision: u64,
    pub policy_epoch: u64,
    pub key_ring: Vec<u8>,
    /// The community's signed genesis document; required until a fingerprint-anchored
    /// charter has bootstrapped, then must match the fingerprint when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_transitions: Vec<KeyTransition>,
    pub manifest: Vec<u8>,
    pub settings: Vec<u8>,
    pub schema: Vec<u8>,
    pub schema_versions: Vec<u8>,
    pub communities: Vec<u8>,
    pub revocations: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_board: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub purpose: String,
    pub community: String,
    pub revision: u64,
    pub policy_epoch: u64,
    pub key_ring: Vec<u8>,
    pub schema_version: u32,
    #[serde(default)]
    pub balance_revision: Option<u64>,
    #[serde(default)]
    pub root_board_revision: Option<u64>,
    #[serde(default)]
    pub ohttp: Option<cblv::keys::Directory>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot<T> {
    pub community: String,
    pub revision: u64,
    pub policy_epoch: u64,
    pub content: T,
}

/// Authenticated revocations, not a history of member activity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocations {
    pub(crate) members: BTreeSet<String>,
    pub(crate) devices: BTreeSet<[u8; 32]>,
    // None identifies a legacy publication; it provides no passkey authority.
    #[serde(default)]
    pub(crate) passkeys: Option<BTreeSet<Vec<u8>>>,
}
impl Revocations {
    pub fn member_revoked(&self, member: &str) -> bool {
        self.members.contains(member)
    }
    pub fn device_revoked(&self, device: &[u8; 32]) -> bool {
        self.devices.contains(device)
    }
    /// Original credential-ID projection. Missing legacy data fails closed.
    pub fn passkey_revoked(&self, credential: &[u8]) -> crate::Result<bool> {
        if credential.is_empty() || credential.len() > 1024 {
            return Err(crate::Error::Malformed);
        }
        Ok(self
            .passkeys
            .as_ref()
            .ok_or(crate::Error::Unavailable)?
            .contains(credential))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct History {
    pub purpose: String,
    pub current: u32,
    pub versions: Vec<SchemaVersion>,
}

/// A checked schema and its cshm classification against its predecessor.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaVersion {
    pub schema: cshm::Schema,
    pub changes: Option<cshm::ChangeSet>,
}

/// Public routing metadata is checked against the original signed transition.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyTransition {
    pub revision: u64,
    pub proof: Vec<u8>,
}

/// Why a community's key chain ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    /// The community was dissolved.
    Dissolved,
    /// The platform ended the community.
    Banned,
}

/// One end-of-chain entry of the platform feed. A member device that holds the
/// fingerprint deletes that membership's local data. Carries no names and no
/// member information.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ended {
    /// SHA-256 of the ended community's genesis document, 64 lowercase hex characters.
    #[serde(with = "hex32")]
    pub fingerprint: [u8; 32],
    /// Why the chain ended.
    pub reason_class: EndReason,
    /// Unix seconds at which it ended.
    pub ended_at: u64,
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let text: String = value.iter().map(|byte| format!("{byte:02x}")).collect();
        serializer.serialize_str(&text)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        let bad = || serde::de::Error::custom("fingerprint");
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
        }
        Ok(out)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Communities {
    List(Vec<String>),
    Detailed(Detailed),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Detailed {
    communities: Vec<String>,
    #[serde(default)]
    ended: Vec<Ended>,
}

/// The Communities snapshot content: a plain list of names, or an object that
/// also lists the ended chains.
pub(crate) fn communities(content: serde_json::Value) -> crate::Result<(Vec<String>, Vec<Ended>)> {
    match serde_json::from_value(content).map_err(|_| crate::Error::Malformed)? {
        Communities::List(names) => Ok((names, Vec::new())),
        Communities::Detailed(Detailed { communities, ended }) => Ok((communities, ended)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_plain_list_has_no_ended_chains() {
        let (names, ended) = communities(json!(["a", "b"])).unwrap();
        assert_eq!(names, ["a", "b"]);
        assert!(ended.is_empty());
    }

    #[test]
    fn ended_entries_carry_fingerprint_reason_and_time() {
        let hex = "ab".repeat(32);
        let (names, ended) = communities(json!({
            "communities": ["a"],
            "ended": [{"fingerprint": hex, "reason_class": "banned", "ended_at": 7}]
        }))
        .unwrap();
        assert_eq!(names, ["a"]);
        assert_eq!(
            ended,
            [Ended {
                fingerprint: [0xab; 32],
                reason_class: EndReason::Banned,
                ended_at: 7
            }]
        );
        assert_eq!(
            serde_json::to_value(ended[0]).unwrap()["fingerprint"],
            json!(hex)
        );
        let (_, none) = communities(json!({"communities": []})).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn malformed_ended_entries_are_refused() {
        let hex = "ab".repeat(32);
        let entry = |fingerprint: &str, reason: &str| json!({"communities": [], "ended": [{"fingerprint": fingerprint, "reason_class": reason, "ended_at": 1}]});
        assert!(communities(entry(&hex, "dissolved")).is_ok());
        assert!(communities(entry(&hex, "expelled")).is_err());
        assert!(communities(entry("AB", "banned")).is_err());
        assert!(communities(entry(&"AB".repeat(32), "banned")).is_err());
        assert!(communities(entry(&"zz".repeat(32), "banned")).is_err());
        assert!(communities(json!({"communities": [], "ended": [], "extra": 1})).is_err());
        assert!(communities(json!({"ended": []})).is_err());
        assert!(communities(json!(null)).is_err());
    }
}
