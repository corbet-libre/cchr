//! The existing cvld/cplc wire boundary; no issuer dependency on device builds.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Feed {
    pub revision: u64,
    pub policy_epoch: u64,
    pub key_ring: Vec<u8>,
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
