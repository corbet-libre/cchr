//! Charter verifies cvld's original public bytes. It never admits a member.
#![forbid(unsafe_code)]
mod json;
mod wire;
use serde_json::Value;
use std::fmt;
pub use wire::{Revocations, SchemaVersion};

pub type Result<T> = std::result::Result<T, Error>;
/// Fixed diagnostics deliberately omit payloads, identities and dependency errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Limit,
    Unauthenticated,
    Scope,
    Signature,
    Incoherent,
    Rollback,
    Equivocation,
    Expired,
    ClockRegression,
    Unavailable,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Maximum JSON transport bytes, including cvld's integer-array encoding of COSE.
pub const MAX_FEED_BYTES: usize = 32 * 1024 * 1024;
const MAX_COSE_BYTES: usize = (1 << 20) + 8192;

/// A trusted adapter's assertion about a freshly authenticated HTTPS response.
///
/// Construct only after authenticating the configured origin (TLS, no redirects,
/// no body cache), or from separately authenticated operator configuration.
/// Parsing an untrusted feed is NOT sufficient to construct this capability.
/// `minimum_revision` must come from this fresh authority or a trusted floor.
/// This is an explicit trust boundary, not a TLS implementation.
pub struct AuthenticatedOrigin {
    origin: String,
    community: String,
    ring: csgn::KeyRing,
    minimum_revision: u64,
    observed_at: u64,
    valid_until: u64,
}
impl AuthenticatedOrigin {
    pub fn from_authenticated_response(
        origin: &str,
        community: &str,
        ring: &[u8],
        minimum_revision: u64,
        observed_at: u64,
        valid_until: u64,
    ) -> Result<Self> {
        let origin = origin_name(origin)?;
        let ring = csgn::KeyRing::from_cbor(ring).map_err(|_| Error::Unauthenticated)?;
        if ring.issuer() != community || minimum_revision == 0 || observed_at >= valid_until {
            return Err(Error::Unauthenticated);
        }
        Ok(Self {
            origin,
            community: community.into(),
            ring,
            minimum_revision,
            observed_at,
            valid_until,
        })
    }
}
fn origin_name(value: &str) -> Result<String> {
    let url = url::Url::parse(value).map_err(|_| Error::Scope)?;
    if url.scheme() != "https"
        || url.path() != "/"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Scope);
    }
    Ok(url.origin().ascii_serialization())
}

/// The five existing snapshot kinds, in a fixed order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Settings,
    Schema,
    SchemaVersions,
    Communities,
    Revocations,
}
impl Kind {
    fn cose(self) -> csgn::Kind {
        match self {
            Self::Settings => csgn::Kind::SettingsSnapshot,
            Self::Schema | Self::SchemaVersions => csgn::Kind::SchemaSnapshot,
            Self::Communities => csgn::Kind::CommunitiesSnapshot,
            Self::Revocations => csgn::Kind::RevocationListSnapshot,
        }
    }
    fn index(self) -> usize {
        self as usize
    }
}
const KINDS: [Kind; 5] = [
    Kind::Settings,
    Kind::Schema,
    Kind::SchemaVersions,
    Kind::Communities,
    Kind::Revocations,
];

/// Immutable authenticated publication; its original signature bytes are retained.
pub struct Publication {
    revision: u64,
    bytes: Vec<u8>,
    content: Value,
}
impl Publication {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn content(&self) -> &Value {
        &self.content
    }
}

/// Verified public material. Only Charter can construct it. This is not admission.
pub struct VerifiedCharter {
    community: String,
    revision: u64,
    epoch: u64,
    deadline: u64,
    ring: csgn::KeyRing,
    manifest: Vec<u8>,
    publications: [Publication; 5],
    schema: cshm::Schema,
    history: Vec<SchemaVersion>,
    revocations: Revocations,
}
impl VerifiedCharter {
    pub fn community(&self) -> &str {
        &self.community
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn policy_epoch(&self) -> u64 {
        self.epoch
    }
    pub fn valid_until(&self) -> u64 {
        self.deadline
    }
    pub fn key_ring(&self) -> &csgn::KeyRing {
        &self.ring
    }
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest
    }
    pub fn publication(&self, kind: Kind) -> &Publication {
        &self.publications[kind.index()]
    }
    pub fn schema(&self) -> &cshm::Schema {
        &self.schema
    }
    pub fn schema_history(&self) -> &[SchemaVersion] {
        &self.history
    }
    pub fn revocations(&self) -> &Revocations {
        &self.revocations
    }
    /// Borrow original authenticated publications for Guard. This is not an
    /// admission: Guard still requires a valid credential, device binding,
    /// complete rich policy, profile and pin evidence. The action is trusted
    /// application configuration, never selected by a submitted presentation.
    pub fn admission_policy<'a>(
        &'a self,
        action: &'a str,
        now: u64,
        maximum_snapshot_age: u64,
    ) -> Result<cgrd::PublishedPolicy<'a>> {
        if now >= self.deadline {
            return Err(Error::Expired);
        }
        Ok(cgrd::PublishedPolicy {
            policy: cgrd::Policy {
                community: &self.community,
                keys: &self.ring,
                now,
                minimum_epoch: self.epoch,
                minimum_settings_revision: self.publication(Kind::Settings).revision(),
                minimum_schema_revision: self.publication(Kind::Schema).revision(),
                maximum_snapshot_age,
                settings: self.publication(Kind::Settings).signed_bytes(),
            },
            revocations: self.publication(Kind::Revocations).signed_bytes(),
            minimum_revocations_revision: self.publication(Kind::Revocations).revision(),
            action,
        })
    }
}
impl fmt::Debug for VerifiedCharter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCharter").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unbootstrapped,
    Current,
    Unavailable,
}
/// Change notification means replace the whole view; it is not an event history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Changes {
    Unchanged,
    Replace { revision: u64, policy_epoch: u64 },
}

/// Volatile, single-scope state machine. Time is always injected in Unix seconds.
/// Restart begins unbootstrapped; devices may retain floors only in their vault.
pub struct Charter {
    origin: String,
    community: String,
    current: Option<VerifiedCharter>,
    high_water: u64,
}
impl Charter {
    pub fn new(origin: &str, community: &str) -> Result<Self> {
        if community.is_empty() || community.len() > 256 || community.contains('\0') {
            return Err(Error::Scope);
        }
        Ok(Self {
            origin: origin_name(origin)?,
            community: community.into(),
            current: None,
            high_water: 0,
        })
    }
    /// Return the canonical origin bound at construction, without asserting trust.
    pub fn origin(&self) -> &str {
        &self.origin
    }
    fn observe(&mut self, now: u64) -> Result<()> {
        if now < self.high_water {
            return Err(Error::ClockRegression);
        }
        self.high_water = now;
        Ok(())
    }
    pub fn state(&mut self, now: u64) -> State {
        if self.observe(now).is_err() {
            return State::Unavailable;
        }
        match &self.current {
            None => State::Unbootstrapped,
            Some(v) if now < v.deadline => State::Current,
            Some(_) => State::Unavailable,
        }
    }
    pub fn current(&mut self, now: u64) -> Result<&VerifiedCharter> {
        self.observe(now)?;
        let value = self.current.as_ref().ok_or(Error::Unavailable)?;
        if now >= value.deadline {
            return Err(Error::Expired);
        }
        Ok(value)
    }
    pub fn changes_since(&mut self, revision: u64, now: u64) -> Result<Changes> {
        let value = self.current(now)?;
        if revision > value.revision {
            return Err(Error::Rollback);
        }
        Ok(if revision == value.revision {
            Changes::Unchanged
        } else {
            Changes::Replace {
                revision: value.revision,
                policy_epoch: value.epoch,
            }
        })
    }
    /// Verify a complete candidate without mutating installed material or floors.
    /// The synchronous Verifying phase commits all five kinds together, or none.
    pub fn install(
        &mut self,
        bytes: &[u8],
        authority: &AuthenticatedOrigin,
        now: u64,
    ) -> Result<&VerifiedCharter> {
        self.observe(now)?;
        if bytes.len() > MAX_FEED_BYTES {
            return Err(Error::Limit);
        }
        if authority.origin != self.origin
            || authority.community != self.community
            || now < authority.observed_at
            || now >= authority.valid_until
        {
            return Err(Error::Unauthenticated);
        }
        let feed: wire::Feed = json::decode(bytes)?;
        if feed.key_ring != authority.ring.to_cbor() {
            return Err(Error::Unauthenticated);
        }
        let signed = authority
            .ring
            .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| Error::Signature)?;
        let manifest: wire::Manifest = json::decode(signed.payload())?;
        if manifest.purpose != "cplc.trust.v1"
            || manifest.community != self.community
            || manifest.revision != feed.revision
            || manifest.policy_epoch != feed.policy_epoch
            || manifest.key_ring != feed.key_ring
            || manifest.schema_version == 0
            || feed.revision == 0
            || feed.revision > i64::MAX as u64
            || feed.policy_epoch == 0
            || feed.policy_epoch > i64::MAX as u64
        {
            return Err(Error::Incoherent);
        }
        if feed.revision < authority.minimum_revision {
            return Err(Error::Rollback);
        }
        if let Some(old) = &self.current {
            if feed.revision < old.revision
                || feed.policy_epoch < old.epoch
                || manifest.schema_version < old.schema.version
            {
                return Err(Error::Rollback);
            }
            if feed.revision == old.revision && feed.manifest != old.manifest {
                return Err(Error::Equivocation);
            }
        }
        let mut deadline = signed.valid_until();
        let mut publications = Vec::with_capacity(5);
        for (kind, cose) in KINDS.into_iter().zip([
            feed.settings,
            feed.schema,
            feed.schema_versions,
            feed.communities,
            feed.revocations,
        ]) {
            if cose.len() > MAX_COSE_BYTES {
                return Err(Error::Limit);
            }
            let signed = authority
                .ring
                .verify(&cose, kind.cose(), now)
                .map_err(|_| Error::Signature)?;
            let doc: wire::Snapshot<Value> = json::decode(signed.payload())?;
            if doc.community != self.community
                || doc.policy_epoch != feed.policy_epoch
                || doc.revision == 0
                || doc.revision > feed.revision
            {
                return Err(Error::Incoherent);
            }
            if let Some(old) = &self.current {
                let prior = old.publication(kind);
                if doc.revision < prior.revision {
                    return Err(Error::Rollback);
                }
                if (doc.revision == prior.revision && cose != prior.bytes)
                    || (feed.revision == old.revision && cose != prior.bytes)
                {
                    return Err(Error::Equivocation);
                }
            }
            deadline = deadline.min(signed.valid_until());
            publications.push(Publication {
                revision: doc.revision,
                bytes: cose,
                content: doc.content,
            });
        }
        let publications: [Publication; 5] =
            publications.try_into().map_err(|_| Error::Incoherent)?;
        if !publications[0].content.is_object() {
            return Err(Error::Malformed);
        }
        let schema: cshm::Schema = serde_json::from_value(publications[1].content.clone())
            .map_err(|_| Error::Malformed)?;
        schema
            .validate_definition()
            .map_err(|_| Error::Incoherent)?;
        if schema.community != self.community || schema.version != manifest.schema_version {
            return Err(Error::Incoherent);
        }
        let history: wire::History = serde_json::from_value(publications[2].content.clone())
            .map_err(|_| Error::Malformed)?;
        validate_history(&history, &schema)?;
        if let Some(old) = &self.current {
            for prior in &old.history {
                let retained = history
                    .versions
                    .iter()
                    .find(|v| v.schema.version == prior.schema.version)
                    .ok_or(Error::Incoherent)?;
                if retained.schema != prior.schema || retained.changes != prior.changes {
                    return Err(Error::Equivocation);
                }
            }
        }
        let communities: Vec<String> = serde_json::from_value(publications[3].content.clone())
            .map_err(|_| Error::Malformed)?;
        if communities.len() > 256
            || communities.iter().any(|v| v.is_empty() || v.len() > 256)
            || communities
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != communities.len()
        {
            return Err(Error::Incoherent);
        }
        let revocations = serde_json::from_value(publications[4].content.clone())
            .map_err(|_| Error::Malformed)?;
        self.current = Some(VerifiedCharter {
            community: self.community.clone(),
            revision: feed.revision,
            epoch: feed.policy_epoch,
            deadline,
            ring: authority.ring.clone(),
            manifest: feed.manifest,
            publications,
            schema,
            history: history.versions,
            revocations,
        });
        self.current(now)
    }
}
fn validate_history(history: &wire::History, schema: &cshm::Schema) -> Result<()> {
    if history.purpose != "cplc.schema-versions.v1"
        || history.current != schema.version
        || history.versions.is_empty()
        || history.versions.len() > 256
    {
        return Err(Error::Incoherent);
    }
    for (i, entry) in history.versions.iter().enumerate() {
        entry
            .schema
            .validate_definition()
            .map_err(|_| Error::Incoherent)?;
        if entry.schema.community != schema.community {
            return Err(Error::Scope);
        }
        if i == 0 {
            if entry.changes.is_some() {
                return Err(Error::Incoherent);
            }
        } else {
            // cshm requires the successor version to be strictly greater,
            // rejecting duplicate and decreasing archive entries before classification.
            let actual = cshm::classify_changes(&history.versions[i - 1].schema, &entry.schema)
                .map_err(|_| Error::Incoherent)?;
            if entry.changes.as_ref() != Some(&actual) {
                return Err(Error::Incoherent);
            }
        }
    }
    if history.versions.last().map(|e| &e.schema) != Some(schema) {
        return Err(Error::Incoherent);
    }
    Ok(())
}
