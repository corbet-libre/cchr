//! Revision evidence of a pairing (lineage revision above 1).
use crate::VerifiedCharter;
use crate::genesis_stamp::{GenesisError, StampTrust, lineage_stamp_scope};
use ckmg::{Change, Lineage, PairingApproval, PublicKey, Receipt};
use cpsd::{
    ActionKind, PayloadDigest, StampAction, StampPresentation, StampSalt, VerifiedStamp,
};

/// Stamp action kind of the ONE pairing slot per community.
pub const PAIR_ACTION: &str = "device_pair";

/// Fixed revision evidence refusal, with no supplied identities or presentation bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevisionError {
    /// Not an attested `DeviceAuthorized` receipt of a revision above 1.
    Receipt,
    /// Community or member differs from the receipt's binding or the stamp's pseudonym.
    Scope,
    /// The host signature is missing, wrong, or its key is not in the current devices.
    Host,
    /// The stamp is not a valid pairing stamp over exactly this digest.
    Stamp,
    /// The Charter refused: settings not live or the member revoked.
    Policy(crate::Error),
    /// The evidence is dated after the verifier's clock.
    Clock,
}

/// What verified revision evidence established.
pub struct VerifiedRevision<'a> {
    lineage: &'a Lineage,
    host: PublicKey,
    new_key: PublicKey,
    stamp: VerifiedStamp,
}
impl<'a> VerifiedRevision<'a> {
    /// The receipt's signed lineage.
    pub fn lineage(&self) -> &'a Lineage {
        self.lineage
    }
    /// The host device key that approved.
    pub fn host(&self) -> &PublicKey {
        &self.host
    }
    /// The key the revision adds.
    pub fn new_key(&self) -> &PublicKey {
        &self.new_key
    }
    /// The verified stamp, to record it one-use.
    pub fn into_stamp(self) -> VerifiedStamp {
        self.stamp
    }
}

/// Payload digest of a community's pairing stamp slot: SHA-256 over the domain tag, then
/// length-prefixed `community`, the member's `member_id` (pseudonym), the NEW `device_key`, the
/// community's own opaque pairing `session` value, and the planned lineage `revision` (a flag
/// byte, then its 32-byte digest when planned). The stamp therefore approves exactly this key
/// for this member in this community within this pairing, and, when the host knows the
/// revision at stamp time, the revision that will carry the key too.
///
/// `session` is one value PER community: a value shared across communities would link a
/// member's memberships. Revision evidence ([`verify_revision`]) always requires the revision
/// bound: the digest is then also what the host's device key signs.
pub fn pair_payload(
    community: &str,
    member_id: &str,
    device_key: &[u8; 32],
    session: &[u8; 32],
    revision: Option<&[u8; 32]>,
) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"cvld.device-pair.v1\0");
    for text in [community, member_id] {
        hasher.update((text.len() as u16).to_be_bytes());
        hasher.update(text.as_bytes());
    }
    hasher.update(device_key);
    hasher.update(session);
    match revision {
        Some(revision) => {
            hasher.update([1]);
            hasher.update(revision);
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

/// Verify the evidence of a pairing revision: the lineage of a `DeviceAuthorized` receipt above
/// revision 1 counts when BOTH (1) the host device key, the receipt's author, signed the
/// pairing digest ([`ckmg::PairingApproval`]) and is in the CURRENT lineage's `devices`
/// (`devices`, the verifier's latest lineage of the member; a removed host, or a key that is no
/// device such as a delegate, is refused), and (2) one wallet stamp covers the same digest under
/// the member's pseudonym. The digest binds community, member, the key the receipt adds, the
/// community's pairing `session` and the receipt's own challenge. The member must not be
/// revoked and the stamp is judged at `at` (never after `now`), like genesis evidence.
#[allow(clippy::too_many_arguments)]
pub fn verify_revision<'a>(
    current: &VerifiedCharter,
    trust: &StampTrust,
    devices: &Lineage,
    receipt: &'a Receipt,
    presentation: &StampPresentation,
    salt: [u8; 32],
    session: &[u8; 32],
    host_signature: &[u8; 64],
    at: u64,
    expected_member: &str,
    now: u64,
) -> Result<VerifiedRevision<'a>, RevisionError> {
    let (lineage, host) = receipt
        .attested_lineage()
        .map_err(|_| RevisionError::Receipt)?;
    let Change::DeviceAuthorized(grant) = &receipt.change else {
        return Err(RevisionError::Receipt);
    };
    let new_key = grant.request.device;
    if lineage.revision < 2 || !lineage.devices.contains(&new_key) || new_key == host {
        return Err(RevisionError::Receipt);
    }
    let community = current.community();
    if lineage.binding.community() != community || lineage.binding.member() != expected_member {
        return Err(RevisionError::Scope);
    }
    if now < at {
        return Err(RevisionError::Clock);
    }
    current.settings(now).map_err(RevisionError::Policy)?;
    if current.revocations().member_revoked(expected_member) {
        return Err(RevisionError::Policy(crate::Error::Unauthenticated));
    }
    // The host: a device of the member's CURRENT lineage, never a delegate or removed key.
    if devices.binding != lineage.binding || !devices.devices.contains(&host) {
        return Err(RevisionError::Host);
    }
    let challenge = receipt
        .passkey_challenge()
        .map_err(|_| RevisionError::Receipt)?;
    let digest = pair_payload(
        community,
        expected_member,
        new_key.value(),
        session,
        Some(&challenge),
    );
    let approval =
        PairingApproval::new(community, &digest).map_err(|_| RevisionError::Scope)?;
    ckmg::verify_ed25519(host.value(), &approval.message(), host_signature)
        .map_err(|_| RevisionError::Host)?;
    let action = StampAction::new(
        ActionKind::new(PAIR_ACTION).map_err(|_| RevisionError::Stamp)?,
        PayloadDigest::from_bytes(digest),
        StampSalt::from_bytes(salt),
    );
    let stamp = trust
        .verify_action(
            &lineage_stamp_scope(current).map_err(|_| RevisionError::Scope)?,
            &action,
            presentation,
            at,
            expected_member,
        )
        .map_err(|error| match error {
            GenesisError::Scope => RevisionError::Scope,
            _ => RevisionError::Stamp,
        })?;
    Ok(VerifiedRevision {
        lineage,
        host,
        new_key,
        stamp,
    })
}
impl std::fmt::Debug for VerifiedRevision<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedRevision([redacted])")
    }
}
