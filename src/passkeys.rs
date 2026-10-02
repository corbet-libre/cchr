//! Policy-authenticated original Keyhole material. This is not a G3 verdict.
use crate::{Error, Kind, MAX_COSE_BYTES, Result, VerifiedCharter, json};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    purpose: String,
    community: String,
    member: String,
    policy_epoch: u64,
    credential: ckyh::lineage::PublicCredential,
}

/// Borrowed current Policy binding of one original Keyhole credential.
/// It proves neither possession of that passkey nor accepted lineage. The owner
/// must additionally verify the exact assertion, session/device freshness and
/// original Keys challenge. Reload current Charter after every authority await.
pub struct VerifiedPasskeyBinding<'a> {
    charter: &'a VerifiedCharter,
    body: Binding,
    signed: &'a [u8],
    issued_at: u64,
    deadline: u64,
}
impl VerifiedPasskeyBinding<'_> {
    /// Canonical community pseudonym in the Policy-signed member mapping.
    pub fn member(&self) -> &str {
        &self.body.member
    }
    /// Original effective policy epoch, not a passport or wallet epoch.
    pub fn policy_epoch(&self) -> u64 {
        self.charter.policy_epoch()
    }
    /// Exclusive minimum of original descriptor and complete Charter lifetimes.
    pub fn valid_until(&self) -> u64 {
        self.deadline
    }
    /// Original signature bytes for retaining the authentic public witness.
    pub fn signed_bytes(&self) -> &[u8] {
        self.signed
    }
    /// Exact original Keyhole descriptor, after checking the retained deadline.
    pub fn credential(&self, now: u64) -> Result<&ckyh::lineage::PublicCredential> {
        if now < self.issued_at {
            return Err(Error::ClockRegression);
        }
        if now >= self.deadline {
            return Err(Error::Expired);
        }
        Ok(&self.body.credential)
    }
}
impl VerifiedCharter {
    /// Authenticate a Policy-issued passkey descriptor against this complete
    /// current publication. Neither raw Keyhole JSON nor an old revocation shape
    /// can construct the returned witness. This performs no member query.
    pub fn passkey_binding<'a>(
        &'a self,
        signed: &'a [u8],
        expected_member: &str,
        now: u64,
    ) -> Result<VerifiedPasskeyBinding<'a>> {
        if signed.len() > MAX_COSE_BYTES {
            return Err(Error::Limit);
        }
        self.settings(now)?;
        let envelope = self
            .key_ring()
            .verify(signed, csgn::Kind::Credential, now)
            .map_err(|_| Error::Signature)?;
        let body: Binding = json::decode(envelope.payload())?;
        if body.purpose != "cplc.passkey-lineage.v1"
            || body.community != self.community()
            || body.credential.community() != self.community()
            || body.member != expected_member
            || body.member.is_empty()
            || body.member.len() > 256
            || body.policy_epoch != self.policy_epoch()
            || body.credential.spki().is_empty()
            || body.credential.spki().len() > 8192
            || body.credential.rp_id().is_empty()
            || body.credential.rp_id().len() > 253
            || body.credential.origins().is_empty()
            || body.credential.origins().len() > 32
            || body
                .credential
                .origins()
                .iter()
                .any(|origin| origin.len() > 2048)
        {
            return Err(Error::Scope);
        }
        if self.revocations().member_revoked(&body.member)
            || self
                .revocations()
                .passkey_revoked(body.credential.credential_id())?
        {
            return Err(Error::Unauthenticated);
        }
        let issued_at = envelope
            .issued_at()
            .max(self.publication(Kind::Settings).issued_at)
            .max(self.publication(Kind::Revocations).issued_at);
        if now < issued_at {
            return Err(Error::ClockRegression);
        }
        let deadline = envelope.valid_until().min(self.valid_until());
        Ok(VerifiedPasskeyBinding {
            charter: self,
            body,
            signed,
            issued_at,
            deadline,
        })
    }
}
