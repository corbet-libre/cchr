//! Charter verifies cvld's original public bytes. It never admits a member.
#![forbid(unsafe_code)]
pub mod birth;

/// The oldest signed snapshot a product reader accepts, in seconds (two UTC days).
///
/// Issue times are day-rounded and signed validity is at least 2 days, so a smaller limit rejects
/// healthy snapshots; staleness is bounded by the signed validity. This is a code constant, never a
/// deployment or operator setting.
pub const MAXIMUM_SNAPSHOT_AGE: u64 = 2 * 86_400;
pub mod genesis_stamp;
pub mod revision_stamp;
pub use revision_stamp::{
    PAIR_ACTION, RevisionError, VerifiedRevision, pair_payload, verify_revision,
};
mod json;
mod passkeys;
pub use passkeys::VerifiedPasskeyBinding;
pub use passkeys::VerifiedPasskeyCertificate;
mod wire;
pub use birth::{
    BIRTH_STATEMENT_PURPOSE, BirthError, BirthGenesisEvidence, BirthStatement,
    MAX_BIRTH_EVIDENCE_BYTES, VerifiedBirth, birth_statement_digest, verify_birth_genesis,
    wallet_fingerprint,
};
pub use genesis_stamp::{
    GenesisError, GenesisStampEvidence, LINEAGE_GENESIS_ACTION, MAX_GENESIS_EVIDENCE_BYTES,
    StampKeyPeriod, StampTrust, VerifiedGenesis, genesis_stamp_scope, global_stamp_trust,
    lineage_genesis_action, lineage_genesis_action_for, lineage_stamp_scope, verify_genesis,
    verify_genesis_parts,
};
use serde_json::Value;
use std::fmt;
pub use wire::{EndReason, Ended, Revocations, SchemaVersion};

/// Most end-of-chain entries one platform feed may carry.
pub const MAX_ENDED: usize = 4096;

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

/// Public publishing authority from trusted per-community deployment configuration.
/// Never populate this value from a feed response or member request.
#[derive(Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub origin: String,
    pub community: String,
    pub key_ring: Vec<u8>,
    pub minimum_revision: u64,
    /// Sequence of public key-ring changes, never the signer's storage revision.
    pub ring_revision: u64,
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
    issued_at: u64,
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

/// A verified chain head a member vault can keep: the key-ring revision and the
/// digest of that exact ring. A later feed must extend this chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainPin {
    pub ring_revision: u64,
    pub head: [u8; 32],
}

/// Verified public material. Only Charter can construct it. This is not admission.
pub struct VerifiedCharter {
    community: String,
    revision: u64,
    epoch: u64,
    deadline: u64,
    ring: csgn::KeyRing,
    ring_revision: u64,
    fingerprint: Option<[u8; csgn::FINGERPRINT_LEN]>,
    manifest: Vec<u8>,
    publications: [Publication; 5],
    settings: crbk::Snapshot,
    schema: cshm::Schema,
    history: Vec<SchemaVersion>,
    revocations: Revocations,
    ended: Vec<Ended>,
    balance: Option<cbcn::balance::Balance>,
    root_board: Option<cbcn::root_board::RootBoard>,
    ohttp: Option<cblv::keys::Snapshot>,
}
impl VerifiedCharter {
    /// Oblivious HTTP relay and gateway keys from the signed manifest, if the
    /// community publishes any. Only this verified value reaches a client.
    pub fn ohttp(&self) -> Option<&cblv::keys::Snapshot> {
        self.ohttp.as_ref()
    }
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
    /// The founding-key fingerprint this feed was verified against; `None` for a
    /// charter configured with a key ring instead of a fingerprint.
    pub fn fingerprint(&self) -> Option<&[u8; csgn::FINGERPRINT_LEN]> {
        self.fingerprint.as_ref()
    }
    /// The chain head to pin after this verification.
    pub fn chain_pin(&self) -> ChainPin {
        ChainPin {
            ring_revision: self.ring_revision,
            head: self.ring.digest(),
        }
    }
    /// Chains the platform has ended (dissolved or banned communities), from the
    /// verified Communities snapshot. Empty for a community feed.
    pub fn ended(&self) -> &[Ended] {
        &self.ended
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
    /// Original authenticated Rulebook snapshot, including protected issuance
    /// time. Product owners apply their canonical setting projection to this
    /// borrowed value; Charter does not invent setting keys or defaults.
    pub fn settings(&self, now: u64) -> Result<&crbk::Snapshot> {
        if now < self.publication(Kind::Settings).issued_at {
            return Err(Error::ClockRegression);
        }
        if now >= self.deadline {
            return Err(Error::Expired);
        }
        Ok(&self.settings)
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
    /// Original authenticated accounting document. Absence provides no accounting
    /// capability; the accounting owner must still check economic/artifact semantics.
    pub fn balance(&self) -> Option<&cbcn::balance::Balance> {
        self.balance.as_ref()
    }
    /// Authenticated public owner bytes. Consumers must decode with CPSD and
    /// check descriptor scope, epoch and lifetime against this current view.
    pub fn root_board(&self) -> Option<&cbcn::root_board::RootBoard> {
        self.root_board.as_ref()
    }
    /// [`Self::admission_policy`] with the product's one snapshot age limit,
    /// [`MAXIMUM_SNAPSHOT_AGE`]. Every product reader uses this; no age is configured.
    pub fn current_admission_policy<'a>(
        &'a self,
        action: &'a str,
        now: u64,
    ) -> Result<cgrd::PublishedPolicy<'a>> {
        self.admission_policy(action, now, MAXIMUM_SNAPSHOT_AGE)
    }

    /// Borrow original authenticated publications for Guard. This is not an
    /// admission: Guard still requires a valid credential, device binding,
    /// issuer admission decision, profile and pin evidence. The action is trusted
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
                expected_issuance_action: action,
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
    /// `None` only for a fingerprint-anchored charter that has not bootstrapped.
    ring: Option<csgn::KeyRing>,
    /// Set when the chain root is a genesis fingerprint rather than a configured ring.
    fingerprint: Option<[u8; csgn::FINGERPRINT_LEN]>,
    /// A previously verified head the walk from genesis must pass through.
    pin: Option<ChainPin>,
    ring_revision: u64,
    minimum_revision: u64,
}
impl Charter {
    pub fn new(configuration: Configuration) -> Result<Self> {
        let Configuration {
            origin,
            community,
            key_ring,
            minimum_revision,
            ring_revision,
        } = configuration;
        if community.is_empty() || community.len() > 256 || community.contains('\0') {
            return Err(Error::Scope);
        }
        let ring = csgn::KeyRing::from_cbor(&key_ring).map_err(|_| Error::Unauthenticated)?;
        if ring.issuer() != community || minimum_revision == 0 {
            return Err(Error::Unauthenticated);
        }
        Ok(Self {
            origin: origin_name(&origin)?,
            community,
            current: None,
            high_water: 0,
            ring: Some(ring),
            fingerprint: None,
            pin: None,
            ring_revision,
            minimum_revision,
        })
    }
    /// Anchor the community's key chain on the fingerprint of its genesis document.
    /// The first installed feed must carry the genesis document; every later key
    /// is accepted only through an unbroken chain of transitions from it, each
    /// signed by the previous key. No key material is configured.
    pub fn from_fingerprint(
        origin: String,
        community: String,
        fingerprint: [u8; csgn::FINGERPRINT_LEN],
        minimum_revision: u64,
    ) -> Result<Self> {
        if community.is_empty()
            || community.len() > csgn::MAX_ISSUER_LEN
            || community.contains('\0')
            || minimum_revision == 0
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            origin: origin_name(&origin)?,
            community,
            current: None,
            high_water: 0,
            ring: None,
            fingerprint: Some(fingerprint),
            pin: None,
            ring_revision: 0,
            minimum_revision,
        })
    }
    /// Require every feed to extend a previously verified chain head: the ring at
    /// the pinned revision must be exactly the pinned digest (a different one is a
    /// fork) and the chain may not end below it (rollback). Only for a
    /// fingerprint-anchored charter that has not bootstrapped, because the check
    /// needs the walk from genesis.
    pub fn with_pin(mut self, pin: ChainPin) -> Result<Self> {
        if self.fingerprint.is_none() || self.ring.is_some() {
            return Err(Error::Scope);
        }
        self.pin = Some(pin);
        Ok(self)
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
    pub fn install(&mut self, bytes: &[u8], now: u64) -> Result<&VerifiedCharter> {
        self.observe(now)?;
        if bytes.len() > MAX_FEED_BYTES {
            return Err(Error::Limit);
        }
        let feed: wire::Feed = json::decode(bytes)?;
        if feed.key_transitions.len() > 256 {
            return Err(Error::Limit);
        }
        let genesis = match (&feed.genesis, self.fingerprint) {
            (Some(document), Some(fingerprint)) => {
                let genesis = csgn::verify_genesis(document).map_err(|_| Error::Signature)?;
                if genesis.fingerprint() != fingerprint || genesis.community() != self.community {
                    return Err(Error::Unauthenticated);
                }
                Some(genesis)
            }
            _ => None,
        };
        let (mut ring, start_revision) = match (&self.ring, genesis) {
            (Some(ring), _) => (ring.clone(), self.ring_revision),
            (None, Some(genesis)) => (genesis.ring(), 0),
            (None, None) => return Err(Error::Unauthenticated),
        };
        let chained = self.fingerprint.is_some();
        let mut ring_revision = start_revision;
        // With a pin, the ring at the pinned revision must be exactly the pinned one.
        let mut pinned_ok = self
            .pin
            .is_none_or(|pin| pin.ring_revision == 0 && pin.head == ring.digest());
        for transition in &feed.key_transitions {
            // Older retained proofs are not authority and need not remain unexpired.
            if transition.revision <= start_revision {
                continue;
            }
            if transition.revision <= ring_revision {
                return Err(Error::Rollback);
            }
            // From a genesis fingerprint every link must exist: no gaps, so no
            // unproven key can be slipped between two proven ones.
            if chained && transition.revision != ring_revision + 1 {
                return Err(Error::Incoherent);
            }
            let verified = if chained {
                csgn::verify_transition_at_issue(&ring, &transition.proof)
            } else {
                csgn::verify_transition(&ring, &transition.proof, now)
            }
            .map_err(|_| Error::Signature)?;
            if verified.previous() != &ring
                || verified.revision() != transition.revision
                || verified.next() == verified.previous()
            {
                return Err(Error::Incoherent);
            }
            ring = verified.next().clone();
            ring_revision = verified.revision();
            if let Some(pin) = self.pin.filter(|pin| pin.ring_revision == ring_revision) {
                pinned_ok = ring.digest() == pin.head;
            }
        }
        if let Some(pin) = self.pin {
            if ring_revision < pin.ring_revision {
                return Err(Error::Rollback);
            }
            if !pinned_ok {
                return Err(Error::Equivocation);
            }
        }
        if feed.key_ring != ring.to_cbor() {
            return Err(Error::Unauthenticated);
        }
        let signed = ring
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
        if feed.revision < self.minimum_revision {
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
        let balance = match (&feed.balance, manifest.balance_revision) {
            (None, None) => None,
            (Some(bytes), Some(revision)) if revision <= feed.revision => {
                let material =
                    cbcn::balance::Balance::verify(&ring, bytes, feed.policy_epoch, revision, now)
                        .map_err(balance_error)?;
                // Apply the same duplicate-field policy at every payload depth.
                let _: Value = json::decode(material.payload())?;
                deadline = deadline.min(material.valid_until());
                Some(material)
            }
            _ => return Err(Error::Incoherent),
        };
        if let Some(previous) = self.current.as_ref().and_then(|view| view.balance.as_ref()) {
            balance
                .as_ref()
                .ok_or(Error::Rollback)?
                .check_successor(previous)
                .map_err(balance_error)?;
        }
        let root_board = match (&feed.root_board, manifest.root_board_revision) {
            (None, None) => None,
            (Some(bytes), Some(revision)) if revision <= feed.revision => {
                let material = cbcn::root_board::RootBoard::verify(
                    &ring,
                    bytes,
                    feed.policy_epoch,
                    revision,
                    now,
                )
                .map_err(balance_error)?;
                let _: Value = json::decode(material.payload())?;
                deadline = deadline.min(material.valid_until());
                Some(material)
            }
            _ => return Err(Error::Incoherent),
        };
        if let Some(previous) = self
            .current
            .as_ref()
            .and_then(|view| view.root_board.as_ref())
        {
            root_board
                .as_ref()
                .ok_or(Error::Rollback)?
                .check_successor(previous)
                .map_err(balance_error)?;
        }
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
            let signed = ring
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
            let issued_at = signed.issued_at();
            publications.push(Publication {
                revision: doc.revision,
                issued_at,
                bytes: cose,
                content: doc.content,
            });
        }
        let publications: [Publication; 5] =
            publications.try_into().map_err(|_| Error::Incoherent)?;
        let settings = crbk::Snapshot {
            community: self.community.clone(),
            kind: crbk::SnapshotKind::Settings,
            revision: publications[0].revision,
            policy_epoch: feed.policy_epoch,
            issued: i64::try_from(publications[0].issued_at).map_err(|_| Error::Malformed)?,
            content: serde_json::from_value(publications[0].content.clone())
                .map_err(|_| Error::Malformed)?,
        };
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
        let (communities, ended) = wire::communities(publications[3].content.clone())?;
        if communities.len() > 256
            || communities.iter().any(|v| v.is_empty() || v.len() > 256)
            || communities
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != communities.len()
            || ended.len() > MAX_ENDED
            || ended
                .iter()
                .map(|entry| entry.fingerprint)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != ended.len()
        {
            return Err(Error::Incoherent);
        }
        let revocations: Revocations = serde_json::from_value(publications[4].content.clone())
            .map_err(|_| Error::Malformed)?;
        if revocations
            .passkeys
            .as_ref()
            .is_some_and(|ids| ids.iter().any(|id| id.is_empty() || id.len() > 1024))
        {
            return Err(Error::Malformed);
        }
        let ohttp = manifest
            .ohttp
            .map(cblv::keys::Directory::verify)
            .transpose()
            .map_err(|_| Error::Malformed)?;
        self.current = Some(VerifiedCharter {
            community: self.community.clone(),
            revision: feed.revision,
            epoch: feed.policy_epoch,
            deadline,
            ring: ring.clone(),
            ring_revision,
            fingerprint: self.fingerprint,
            manifest: feed.manifest,
            publications,
            settings,
            schema,
            history: history.versions,
            revocations,
            ended,
            balance,
            root_board,
            ohttp,
        });
        self.ring = Some(ring);
        self.ring_revision = ring_revision;
        self.current(now)
    }
}
fn balance_error(error: cbcn::Error) -> Error {
    match error {
        cbcn::Error::Signature => Error::Signature,
        cbcn::Error::Rollback => Error::Rollback,
        cbcn::Error::Equivocation => Error::Equivocation,
        _ => Error::Incoherent,
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
