//! Birth genesis evidence of the wallet lineage (one-ceremony registration).
//!
//! The create ceremony gives no signature that anyone can verify offline (the attestation is
//! empty, the UV flag sits in unsigned authenticator data). So the wallet, which already is the
//! trust root of the wallet lineage (it signs the passkey certificate that passkey evidence is
//! checked against), signs a `BirthStatement` instead, once per account and only under the birth
//! grant of the creation's own user verification:
//!
//! `{wallet fingerprint, account, credential id, H(credential public key), K, c, D, at}`
//!
//! where `K` is the wallet device key, `c` the seed commitment fixed before the creation and `D`
//! the genesis receipt's lineage challenge digest (`Receipt::passkey_challenge`).
//!
//! [`verify_birth_genesis`] is offline. It checks the statement under the wallet's key ring as of
//! `at` (csgn: unknown keys refuse, keys outside their active period refuse, retired keys stay
//! valid for what they signed while active), that the receipt is the attested genesis (Created,
//! epoch 1, revision 1) of `("wallet", account)`, that its device is `K` and that its challenge
//! digest is `D`. A restoring device additionally checks that the statement names the credential
//! it just signed in with and the device key it derived ([`VerifiedBirth::check_restoring`]).
//! The evidence is wallet-scope only and never sent to a community.
use ckmg::{Change, Lineage, PublicKey, Receipt};
use sha2::{Digest, Sha256};

/// Issuer of the wallet key ring that signs birth statements (and passkey certificates).
pub const WALLET_ISSUER: &str = "wallet";
/// The wallet lineage's community name: the receipt binding is `("wallet", account)`.
pub const WALLET_SCOPE: &str = "wallet";
/// Exact domain separator inside the signed payload. The COSE kind is `Credential`, shared with
/// the passkey certificate, whose purpose differs; neither decodes as the other.
pub const BIRTH_STATEMENT_PURPOSE: &str = "cgbl.wallet-birth-statement.v1";
/// Upper bound of encoded birth evidence.
pub const MAX_BIRTH_EVIDENCE_BYTES: usize = 1024 * 1024;
/// Upper bound of a WebAuthn credential id (the wallet device binding uses the same bound).
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1024;
/// Upper bound of the wallet-local account id.
pub const MAX_ACCOUNT_BYTES: usize = 256;

const EVIDENCE_PURPOSE: &str = "cchr.wallet-birth-evidence.v1";
const DIGEST_TAG: &[u8] = b"cchr.wallet-birth-statement-digest.v1\0";

/// Fixed birth evidence refusal, with no supplied identities or statement bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BirthError {
    /// The statement's signature, key, key period, issuer, kind or lifetime refused at `at`.
    Statement,
    /// The receipt, its device attestation or its genesis shape (Created, epoch 1, revision 1)
    /// failed.
    Receipt,
    /// The wallet, the account or the receipt binding differs from the statement or the expected
    /// values.
    Scope,
    /// The receipt's device is not the statement's `K`.
    Device,
    /// The receipt's lineage challenge digest is not the statement's `D`.
    Digest,
    /// The verifier's time precedes the statement time.
    Clock,
    /// A restoring device's own credential or device key is not the one the statement names.
    Restore,
    /// Malformed evidence or statement bytes.
    Invalid,
    /// Evidence bytes exceed [`MAX_BIRTH_EVIDENCE_BYTES`].
    Limit,
}
impl std::fmt::Display for BirthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "birth genesis evidence: {self:?}")
    }
}
impl std::error::Error for BirthError {}

/// The wallet's fingerprint, computed only through csgn's one community fingerprint function
/// (`founding` = the wallet ring's founding key, `None` while the wallet has no founding
/// document).
pub fn wallet_fingerprint(founding: Option<&[u8; 32]>) -> [u8; 32] {
    csgn::community_fingerprint(WALLET_SCOPE, founding)
}

/// The digest of exact signed statement bytes that the wallet lists in its status revision.
pub fn birth_statement_digest(statement: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DIGEST_TAG)
        .chain_update(statement)
        .finalize()
        .into()
}

/// The signed payload of a birth statement. The wallet builds it with [`BirthStatement::new`],
/// signs [`BirthStatement::to_payload`] and verifiers decode it only after the signature.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BirthStatement {
    purpose: String,
    wallet: [u8; 32],
    account: String,
    credential: Vec<u8>,
    credential_key: [u8; 32],
    device: [u8; 32],
    commitment: [u8; 32],
    digest: [u8; 32],
    at: u64,
}
impl std::fmt::Debug for BirthStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BirthStatement([redacted])")
    }
}
impl BirthStatement {
    /// A statement; empty or oversized identifiers and a zero device key are refused.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet: [u8; 32],
        account: &str,
        credential: &[u8],
        credential_key: [u8; 32],
        device: [u8; 32],
        commitment: [u8; 32],
        digest: [u8; 32],
        at: u64,
    ) -> Result<Self, BirthError> {
        let statement = Self {
            purpose: BIRTH_STATEMENT_PURPOSE.into(),
            wallet,
            account: account.into(),
            credential: credential.to_vec(),
            credential_key,
            device,
            commitment,
            digest,
            at,
        };
        statement.shape()?;
        Ok(statement)
    }
    fn shape(&self) -> Result<(), BirthError> {
        if self.purpose != BIRTH_STATEMENT_PURPOSE
            || self.account.is_empty()
            || self.account.len() > MAX_ACCOUNT_BYTES
            || self.credential.is_empty()
            || self.credential.len() > MAX_CREDENTIAL_ID_BYTES
            || self.device == [0; 32]
        {
            return Err(BirthError::Invalid);
        }
        Ok(())
    }
    /// The exact payload bytes the wallet signs (JSON, fixed field order).
    pub fn to_payload(&self) -> Result<Vec<u8>, BirthError> {
        serde_json::to_vec(self).map_err(|_| BirthError::Invalid)
    }
    fn from_payload(bytes: &[u8]) -> Result<Self, BirthError> {
        let statement: Self = serde_json::from_slice(bytes).map_err(|_| BirthError::Invalid)?;
        statement.shape()?;
        Ok(statement)
    }
    /// The wallet fingerprint.
    pub fn wallet(&self) -> &[u8; 32] {
        &self.wallet
    }
    /// The wallet-local account id. Never send it to a community.
    pub fn account(&self) -> &str {
        &self.account
    }
    /// The credential id of the account's one wallet passkey.
    pub fn credential(&self) -> &[u8] {
        &self.credential
    }
    /// SHA-256 of the credential's public key as the wallet stores it.
    pub fn credential_key(&self) -> &[u8; 32] {
        &self.credential_key
    }
    /// The wallet device key `K` (raw Ed25519).
    pub fn device(&self) -> &[u8; 32] {
        &self.device
    }
    /// The seed commitment `c` of the creation.
    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    /// The genesis receipt's lineage challenge digest `D`.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    /// The time the wallet issued the statement.
    pub fn at(&self) -> u64 {
        self.at
    }
}

/// Public birth genesis evidence: the genesis receipt, the wallet-signed statement (COSE) and the
/// statement time `at` the verification is judged at. Decoding grants nothing; verify at every
/// use.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BirthGenesisEvidence {
    purpose: String,
    receipt: Receipt,
    statement: Vec<u8>,
    at: u64,
}
impl std::fmt::Debug for BirthGenesisEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BirthGenesisEvidence([redacted])")
    }
}
impl BirthGenesisEvidence {
    /// Evidence over `receipt` with the signed `statement` issued at `at`.
    pub fn new(receipt: Receipt, statement: Vec<u8>, at: u64) -> Self {
        Self {
            purpose: EVIDENCE_PURPOSE.into(),
            receipt,
            statement,
            at,
        }
    }
    /// The receipt this evidence anchors.
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    /// The signed statement bytes as carried.
    pub fn statement_bytes(&self) -> &[u8] {
        &self.statement
    }
    /// The statement time.
    pub fn at(&self) -> u64 {
        self.at
    }
    /// Encoded evidence (JSON). Receivers bound it by [`MAX_BIRTH_EVIDENCE_BYTES`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, BirthError> {
        serde_json::to_vec(self).map_err(|_| BirthError::Invalid)
    }
    /// Decode untrusted bytes without granting authority.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BirthError> {
        if bytes.len() > MAX_BIRTH_EVIDENCE_BYTES {
            return Err(BirthError::Limit);
        }
        let evidence: Self = serde_json::from_slice(bytes).map_err(|_| BirthError::Invalid)?;
        if evidence.purpose != EVIDENCE_PURPOSE {
            return Err(BirthError::Invalid);
        }
        Ok(evidence)
    }
}

/// What a verified birth genesis established. It grants no current authority by itself.
pub struct VerifiedBirth<'a> {
    lineage: &'a Lineage,
    device: PublicKey,
    statement: BirthStatement,
    digest: [u8; 32],
}
impl<'a> VerifiedBirth<'a> {
    /// The receipt's signed first lineage.
    pub fn lineage(&self) -> &'a Lineage {
        self.lineage
    }
    /// The device key that attested the receipt (= the statement's `K`).
    pub fn device(&self) -> &PublicKey {
        &self.device
    }
    /// The verified statement.
    pub fn statement(&self) -> &BirthStatement {
        &self.statement
    }
    /// [`birth_statement_digest`] of the signed statement bytes.
    pub fn statement_digest(&self) -> &[u8; 32] {
        &self.digest
    }
    /// The restoring device's extra check: the statement names exactly the credential it just
    /// signed in with and the wallet device key it derived from that sign-in.
    pub fn check_restoring(&self, credential: &[u8], device: &[u8; 32]) -> Result<(), BirthError> {
        if self.statement.credential.as_slice() != credential || &self.statement.device != device {
            return Err(BirthError::Restore);
        }
        Ok(())
    }
}
impl std::fmt::Debug for VerifiedBirth<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedBirth([redacted])")
    }
}

/// Verify `evidence` as the birth genesis of `expected_account`'s wallet lineage, offline, under
/// `ring` (the wallet key ring from its authenticated signed status, issuer `wallet`) for the
/// wallet `expected_wallet` ([`wallet_fingerprint`]). Validity is judged at the statement time,
/// never at `now`, which only has to be no earlier than it.
pub fn verify_birth_genesis<'a>(
    ring: &csgn::KeyRing,
    evidence: &'a BirthGenesisEvidence,
    expected_wallet: &[u8; 32],
    expected_account: &str,
    now: u64,
) -> Result<VerifiedBirth<'a>, BirthError> {
    if ring.issuer() != WALLET_ISSUER {
        return Err(BirthError::Statement);
    }
    if now < evidence.at {
        return Err(BirthError::Clock);
    }
    // csgn: known key, key valid and active at issue, signature, issuer, kind, lifetime bound,
    // and the statement current at `at` (issued no later, expiring after).
    let verified = ring
        .verify(&evidence.statement, csgn::Kind::Credential, evidence.at)
        .map_err(|_| BirthError::Statement)?;
    let statement = BirthStatement::from_payload(verified.payload())?;
    if statement.at != evidence.at {
        return Err(BirthError::Statement);
    }
    if &statement.wallet != expected_wallet || statement.account != expected_account {
        return Err(BirthError::Scope);
    }
    // The receipt is attested and the wallet lineage's genesis: Created at epoch 1, revision 1.
    let receipt = &evidence.receipt;
    let (lineage, device) = receipt
        .attested_lineage()
        .ok()
        .filter(|(lineage, _)| {
            matches!(receipt.change, Change::Created(_))
                & (lineage.epoch == 1)
                & (lineage.revision == 1)
        })
        .ok_or(BirthError::Receipt)?;
    if lineage.binding.community() != WALLET_SCOPE || lineage.binding.member() != statement.account
    {
        return Err(BirthError::Scope);
    }
    // The genesis has exactly one device, and it is K.
    if device.value() != &statement.device || lineage.devices.as_slice() != [device] {
        return Err(BirthError::Device);
    }
    if receipt
        .passkey_challenge()
        .map_err(|_| BirthError::Receipt)?
        != statement.digest
    {
        return Err(BirthError::Digest);
    }
    Ok(VerifiedBirth {
        lineage,
        device,
        digest: birth_statement_digest(&evidence.statement),
        statement,
    })
}
