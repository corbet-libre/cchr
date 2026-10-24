//! Genesis lineage evidence by confirmation stamp (one-confirmation model).
//!
//! A member's FIRST community lineage (the Keys `Created` receipt, epoch 1, revision 1) counts
//! when one wallet confirmation stamp covers its exact digest under the member's pseudonym. The
//! verification is offline and needs no device crate: the stamp key comes from the wallet's
//! signed key ring (retired keys stay with their validity periods), the expiry cohort from the
//! rulebook, the scope is the community fingerprint, the action is `lineage_genesis` and its
//! payload binds the receipt and the time `at` at which the device made it. Validity is judged at
//! `at`, never at the verifier's clock: a stamp expires within two cohorts, the lineage it
//! anchored does not.
//!
//! Peers verify against the current Charter ([`verify_genesis`]); the server, which checks
//! rulebook and revocation itself, verifies the same evidence without a Charter
//! ([`verify_genesis_parts`]). The stamp proves possession of the passport secret behind the
//! member's pseudonym; it is not globally current lineage and grants no later lineage change.
use crate::VerifiedCharter;
use ckmg::{Change, Lineage, PublicKey, Receipt};
use cpsd::{
    ActionKind, CommunityId, PayloadDigest, StampAction, StampParams, StampPresentation,
    StampPublicKey, StampSalt, StampScope, VerifiedStamp, verify_stamp,
};

/// Stamp action kind of a member's first community lineage.
pub const LINEAGE_GENESIS_ACTION: &str = "lineage_genesis";

/// Upper bound of encoded genesis stamp evidence (the local Storage value bound).
pub const MAX_GENESIS_EVIDENCE_BYTES: usize = 1024 * 1024;

// Wire constants are unchanged from their first home in cvlt: evidence made there verifies here.
const PAYLOAD_CONTEXT: &str = "cvlt 2026-10-15 lineage genesis stamp v1";
const STAMP_PURPOSE: &str = "cvlt.lineage-evidence.stamp.v1";

/// Fixed genesis evidence refusal, with no supplied identities or presentation bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisError {
    /// The receipt, its device attestation or its genesis shape (Created, epoch 1, revision 1)
    /// failed.
    Receipt,
    /// The community or member differs from the receipt's signed binding or the stamp pseudonym.
    Scope,
    /// The verifier's time precedes the receipt time.
    Clock,
    /// The stamp, its key period or its expiry cohort refused the evidence at the receipt time.
    Stamp,
    /// The current Charter refused (settings expired, member revoked).
    Policy(crate::Error),
    /// Malformed evidence bytes.
    Invalid,
    /// Evidence bytes exceed [`MAX_GENESIS_EVIDENCE_BYTES`].
    Limit,
}
impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "genesis stamp evidence: {self:?}")
    }
}
impl std::error::Error for GenesisError {}

/// One key of the wallet's signed stamp key ring with its validity period (`valid_from`
/// inclusive, `valid_until` exclusive; `None` while current). Retired keys stay in the ring so
/// that evidence made before a rotation still verifies.
#[derive(Clone)]
pub struct StampKeyPeriod {
    key: StampPublicKey,
    valid_from: u64,
    valid_until: Option<u64>,
}
impl StampKeyPeriod {
    /// A key period; an empty or inverted period is refused.
    pub fn new(
        key: StampPublicKey,
        valid_from: u64,
        valid_until: Option<u64>,
    ) -> Result<Self, GenesisError> {
        if valid_until.is_some_and(|until| until <= valid_from) {
            return Err(GenesisError::Stamp);
        }
        Ok(Self {
            key,
            valid_from,
            valid_until,
        })
    }
    fn covers(&self, at: u64) -> bool {
        self.valid_from <= at && self.valid_until.is_none_or(|until| at < until)
    }
}
impl std::fmt::Debug for StampKeyPeriod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StampKeyPeriod")
            .field("key_id", self.key.key_id())
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .finish()
    }
}

/// The stamp trust genesis evidence is verified with: the wallet's stamp key ring from the
/// SIGNED global status (the caller authenticates it, as for cpsd's `verify_stamp`) and the
/// rulebook's stamp cohort. Key ids are unique.
#[derive(Clone, Debug)]
pub struct StampTrust {
    keys: Vec<StampKeyPeriod>,
    params: StampParams,
    epoch: Option<u64>,
}
impl StampTrust {
    /// Refuses an empty ring and duplicate key ids.
    pub fn new(keys: Vec<StampKeyPeriod>, params: StampParams) -> Result<Self, GenesisError> {
        if keys.is_empty() {
            return Err(GenesisError::Stamp);
        }
        for (i, key) in keys.iter().enumerate() {
            if keys[..i]
                .iter()
                .any(|other| other.key.key_id() == key.key.key_id())
            {
                return Err(GenesisError::Stamp);
            }
        }
        Ok(Self {
            keys,
            params,
            epoch: None,
        })
    }

    /// The stamp epoch of the signed global status this trust was read from
    /// ([`global_stamp_trust`]): the epoch stamps are verified at, identical for
    /// every member. `None` for a trust assembled by hand. A holder expects this
    /// epoch on the stamps it is issued (`cpsd::OpaqueHolder::finish_stamp`),
    /// never an epoch taken from the wallet's own reply.
    pub fn epoch(&self) -> Option<u64> {
        self.epoch
    }
}

/// The stamp scope of `community` with its community fingerprint (`csgn::community_fingerprint`;
/// `None` while unfounded): `cpsd::StampScope::of_community`.
pub fn genesis_stamp_scope(
    community: &str,
    fingerprint: Option<&[u8; 32]>,
) -> Result<StampScope, GenesisError> {
    let id = CommunityId::new(community).map_err(|_| GenesisError::Scope)?;
    Ok(StampScope::of_community(id, fingerprint))
}

/// The stamp scope of the community `current` verifies. The device building a stamp request,
/// the server and every verifier use this one scope.
pub fn lineage_stamp_scope(current: &VerifiedCharter) -> Result<StampScope, GenesisError> {
    genesis_stamp_scope(current.community(), current.fingerprint())
}

/// The `lineage_genesis` action for `receipt` made at `at` with the device's secret `salt`.
pub fn lineage_genesis_action(
    receipt: &Receipt,
    salt: [u8; 32],
    at: u64,
) -> Result<StampAction, GenesisError> {
    let challenge = receipt
        .passkey_challenge()
        .map_err(|_| GenesisError::Receipt)?;
    lineage_genesis_action_for(challenge, salt, at)
}

/// The `lineage_genesis` action over a receipt's lineage challenge digest (its
/// `passkey_challenge`, which binds the receipt's operation and complete change), for a device
/// that requests the stamp before its creation is activated: payload =
/// BLAKE3 derive_key(context, challenge || le64(at)).
pub fn lineage_genesis_action_for(
    challenge: [u8; 32],
    salt: [u8; 32],
    at: u64,
) -> Result<StampAction, GenesisError> {
    let mut hasher = blake3::Hasher::new_derive_key(PAYLOAD_CONTEXT);
    hasher.update(&challenge);
    hasher.update(&at.to_le_bytes());
    Ok(StampAction::new(
        ActionKind::new(LINEAGE_GENESIS_ACTION).map_err(|_| GenesisError::Stamp)?,
        PayloadDigest::from_bytes(*hasher.finalize().as_bytes()),
        StampSalt::from_bytes(salt),
    ))
}

/// Public genesis stamp evidence: the receipt, the presentation of its `lineage_genesis` slot,
/// the device's salt of that slot (public once presented) and the receipt time `at` the payload
/// binds. Decoding grants nothing; verify at every use.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisStampEvidence {
    purpose: String,
    receipt: Receipt,
    presentation: Vec<u8>,
    salt: [u8; 32],
    at: u64,
}
impl std::fmt::Debug for GenesisStampEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GenesisStampEvidence([redacted])")
    }
}
impl GenesisStampEvidence {
    /// Evidence over `receipt` with the presentation of its `lineage_genesis` slot.
    pub fn new(
        receipt: Receipt,
        presentation: &StampPresentation,
        salt: [u8; 32],
        at: u64,
    ) -> Self {
        Self {
            purpose: STAMP_PURPOSE.into(),
            receipt,
            presentation: presentation.to_bytes(),
            salt,
            at,
        }
    }
    /// The receipt this evidence anchors.
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    /// The receipt time the stamp payload binds.
    pub fn at(&self) -> u64 {
        self.at
    }
    /// The slot salt.
    pub fn salt(&self) -> [u8; 32] {
        self.salt
    }
    /// The decoded slot presentation.
    pub fn presentation(&self) -> Result<StampPresentation, GenesisError> {
        StampPresentation::from_bytes(&self.presentation).map_err(|_| GenesisError::Stamp)
    }
    /// The presentation bytes as carried.
    pub fn presentation_bytes(&self) -> &[u8] {
        &self.presentation
    }
    /// Encoded evidence (JSON). Receivers bound it by [`MAX_GENESIS_EVIDENCE_BYTES`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, GenesisError> {
        serde_json::to_vec(self).map_err(|_| GenesisError::Invalid)
    }
    /// Decode untrusted bytes without granting authority.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisError> {
        if bytes.len() > MAX_GENESIS_EVIDENCE_BYTES {
            return Err(GenesisError::Limit);
        }
        let evidence: Self = serde_json::from_slice(bytes).map_err(|_| GenesisError::Invalid)?;
        if evidence.purpose != STAMP_PURPOSE {
            return Err(GenesisError::Invalid);
        }
        Ok(evidence)
    }
}

/// What a verified genesis stamp established. The stamp is returned so the verifier can record
/// its one use (`cpsd::StampLedger`); this value grants no current authority by itself.
pub struct VerifiedGenesis<'a> {
    lineage: &'a Lineage,
    author: PublicKey,
    stamp: VerifiedStamp,
}
impl<'a> VerifiedGenesis<'a> {
    /// The receipt's signed first lineage.
    pub fn lineage(&self) -> &'a Lineage {
        self.lineage
    }
    /// The device key that attested the receipt.
    pub fn author(&self) -> &PublicKey {
        &self.author
    }
    /// The verified stamp (its digest is the one-use reference).
    pub fn stamp(&self) -> &VerifiedStamp {
        &self.stamp
    }
    /// The verified stamp, to record it one-use.
    pub fn into_stamp(self) -> VerifiedStamp {
        self.stamp
    }
}
impl std::fmt::Debug for VerifiedGenesis<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedGenesis([redacted])")
    }
}

/// Verify `presentation` as the genesis evidence of `receipt` for `expected_member` against the
/// current Charter (settings live at `now`, member not revoked, the Charter's fingerprint).
#[allow(clippy::too_many_arguments)]
pub fn verify_genesis<'a>(
    current: &VerifiedCharter,
    trust: &StampTrust,
    receipt: &'a Receipt,
    presentation: &StampPresentation,
    salt: [u8; 32],
    at: u64,
    expected_member: &str,
    now: u64,
) -> Result<VerifiedGenesis<'a>, GenesisError> {
    let (lineage, author) =
        genesis_receipt(receipt, current.community(), expected_member, at, now)?;
    current.settings(now).map_err(GenesisError::Policy)?;
    if current.revocations().member_revoked(expected_member) {
        return Err(GenesisError::Policy(crate::Error::Unauthenticated));
    }
    let stamp = genesis_stamp(
        trust,
        &lineage_stamp_scope(current)?,
        receipt,
        presentation,
        salt,
        at,
        expected_member,
    )?;
    Ok(VerifiedGenesis {
        lineage,
        author,
        stamp,
    })
}

/// Verify `evidence` for `expected_member` of `community` (with its community fingerprint)
/// without a Charter: for a verifier that checks rulebook and revocation itself, such as the
/// server at publication bind.
pub fn verify_genesis_parts<'a>(
    community: &str,
    fingerprint: Option<&[u8; 32]>,
    trust: &StampTrust,
    evidence: &'a GenesisStampEvidence,
    expected_member: &str,
    now: u64,
) -> Result<VerifiedGenesis<'a>, GenesisError> {
    let (lineage, author) = genesis_receipt(
        &evidence.receipt,
        community,
        expected_member,
        evidence.at,
        now,
    )?;
    let stamp = genesis_stamp(
        trust,
        &genesis_stamp_scope(community, fingerprint)?,
        &evidence.receipt,
        &evidence.presentation()?,
        evidence.salt,
        evidence.at,
        expected_member,
    )?;
    Ok(VerifiedGenesis {
        lineage,
        author,
        stamp,
    })
}

/// The receipt is an attested first lineage of `expected_member` in `community`, made no later
/// than the verifier observes it.
fn genesis_receipt<'a>(
    receipt: &'a Receipt,
    community: &str,
    expected_member: &str,
    at: u64,
    now: u64,
) -> Result<(&'a Lineage, PublicKey), GenesisError> {
    // Attested, and the member's first lineage: Created at epoch 1, revision 1.
    let (lineage, author) = receipt
        .attested_lineage()
        .ok()
        .filter(|(lineage, _)| {
            matches!(receipt.change, Change::Created(_))
                & (lineage.epoch == 1)
                & (lineage.revision == 1)
        })
        .ok_or(GenesisError::Receipt)?;
    if lineage.binding.community() != community || lineage.binding.member() != expected_member {
        return Err(GenesisError::Scope);
    }
    if now < at {
        return Err(GenesisError::Clock);
    }
    Ok((lineage, author))
}

/// The stamp covers the receipt's genesis action under `expected_member`'s pseudonym, signed by
/// a key valid at `at`, judged at `at`.
fn genesis_stamp(
    trust: &StampTrust,
    scope: &StampScope,
    receipt: &Receipt,
    presentation: &StampPresentation,
    salt: [u8; 32],
    at: u64,
    expected_member: &str,
) -> Result<VerifiedStamp, GenesisError> {
    let key = trust
        .keys
        .iter()
        .find(|period| period.key.key_id() == presentation.key_id())
        .filter(|period| period.covers(at))
        .ok_or(GenesisError::Stamp)?;
    let action = lineage_genesis_action(receipt, salt, at)?;
    // The revealed epoch is the one the key signed; the live epoch check belongs to the
    // community at acceptance.
    let verified = verify_stamp(
        std::slice::from_ref(&key.key),
        &trust.params,
        scope,
        presentation.epoch(),
        &action,
        presentation,
        at,
    )
    .map_err(|_| GenesisError::Stamp)?;
    if verified.pseudonym().to_hex() != expected_member {
        return Err(GenesisError::Scope);
    }
    Ok(verified)
}

/// Issuer of the wallet's signed global status (`cgbl:<scope>`, scope `global`).
const GLOBAL_STATUS_ISSUER: &str = "cgbl:global";

/// The part of the wallet's signed global status (`cgbl::Status`, version 2) that names its
/// stamp keys. Other fields are the wallet's and are ignored here.
#[derive(serde::Deserialize)]
struct GlobalStampStatus {
    version: u32,
    purpose: String,
    scope: String,
    epoch: u64,
    #[serde(default)]
    stamp_public_key: Option<Vec<u8>>,
    #[serde(default)]
    stamp_keys: Vec<GlobalStampKey>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GlobalStampKey {
    public_key: Vec<u8>,
    valid_from: u64,
    #[serde(default)]
    valid_until: Option<u64>,
}

/// The wallet's stamp trust from its signed global status, for a device that verifies stamps
/// (its own genesis evidence) without the server's anchors: `status` must verify under the
/// global `key_ring` (csgn CBOR, issuer `cgbl:global`) at `now`. Every recorded key keeps its
/// period; before rings were recorded the current key alone counts, valid from the start. The
/// expiry cohort is the current (open) key's. A status without a stamp key, more than one open
/// period, or an open period that is not the current key is refused.
pub fn global_stamp_trust(
    key_ring: &[u8],
    status: &[u8],
    now: u64,
) -> Result<StampTrust, GenesisError> {
    let ring = csgn::KeyRing::from_cbor(key_ring).map_err(|_| GenesisError::Invalid)?;
    if ring.issuer() != GLOBAL_STATUS_ISSUER {
        return Err(GenesisError::Stamp);
    }
    let verified = ring
        .verify(status, csgn::Kind::SettingsSnapshot, now)
        .map_err(|_| GenesisError::Stamp)?;
    let status: GlobalStampStatus =
        serde_json::from_slice(verified.payload()).map_err(|_| GenesisError::Invalid)?;
    if status.version != 2 || status.purpose != "global-passport-status" || status.scope != "global"
    {
        return Err(GenesisError::Stamp);
    }
    let current = status.stamp_public_key.ok_or(GenesisError::Stamp)?;
    let key = |bytes: &[u8]| StampPublicKey::from_bytes(bytes).map_err(|_| GenesisError::Stamp);
    let params = key(&current)?.params();
    let keys = if status.stamp_keys.is_empty() {
        vec![StampKeyPeriod::new(key(&current)?, 0, None)?]
    } else {
        let mut open = status
            .stamp_keys
            .iter()
            .filter(|period| period.valid_until.is_none());
        if open.next().map(|period| &period.public_key) != Some(&current) || open.next().is_some() {
            return Err(GenesisError::Stamp);
        }
        status
            .stamp_keys
            .iter()
            .map(|period| {
                StampKeyPeriod::new(
                    key(&period.public_key)?,
                    period.valid_from,
                    period.valid_until,
                )
            })
            .collect::<Result<_, _>>()?
    };
    let mut trust = StampTrust::new(keys, params)?;
    trust.epoch = Some(status.epoch);
    Ok(trust)
}
