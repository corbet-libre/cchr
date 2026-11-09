//! Focused kill tests for the mut123 surviving mutants (tests-only, no product change).
//! Each test pins behaviour that exactly one listed mutation would change, so the
//! mutation makes the test FAIL while the real code passes.
#![cfg(not(target_arch = "wasm32"))]
use cchr::{
    Charter, Configuration, Error as CharterError, GenesisError, GenesisStampEvidence,
    MAX_GENESIS_EVIDENCE_BYTES, PAIR_ACTION, RevisionError, Revocations, StampKeyPeriod,
    StampTrust, VerifiedCharter, lineage_genesis_action, lineage_stamp_scope, pair_payload,
    verify_genesis_parts, verify_revision,
};
use ckmg::{
    Authority, Authorization, Binding, Change, Commit, DeviceInfo, Error, Locator, PairingApproval,
    Receipt, RestoreRoot,
};
use cpsd::{
    ActionKind, CommunityId, IssuanceChallenge, KeyId, OpaqueHolder, PayloadDigest, StampAction,
    StampIssuerKey, StampParams, StampPresentation, StampSalt, StampScope, rand::rngs::OsRng,
};
use csgn::{Kind, SecretKey, Signer};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const EPOCH: u64 = 3;
const SALT: [u8; 32] = [5; 32];
const SESSION: [u8; 32] = [77; 32];

#[derive(Clone, Default)]
struct Memory(Rc<RefCell<HashMap<Locator, Vec<u8>>>>);
impl ckmg::SecureStore for Memory {
    async fn load(&mut self, location: &Locator) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.borrow().get(location).cloned())
    }
    async fn compare_exchange(
        &mut self,
        location: &Locator,
        expected: Option<[u8; 32]>,
        next: &[u8],
    ) -> Result<Commit, Error> {
        let mut data = self.0.borrow_mut();
        if data
            .get(location)
            .map(|value| *blake3::hash(value).as_bytes())
            != expected
        {
            return Ok(Commit::Conflict);
        }
        data.insert(*location, next.to_vec());
        Ok(Commit::Committed)
    }
}
struct Clock;
impl ckmg::Clock for Clock {
    fn now(&mut self) -> Result<u64, Error> {
        Ok(NOW)
    }
}
struct Allow;
impl Authority for Allow {
    async fn check(&mut self, _request: Authorization<'_>) -> Result<(), Error> {
        Ok(())
    }
    fn check_device_signing_current(&mut self, _request: Authorization<'_>) -> Result<u64, Error> {
        Ok(NOW)
    }
}

fn first_lineage(scope: &str, member: &str) -> Receipt {
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
    let mut keys = ckmg::Keys::new(Memory::default(), Clock, ckmg::SystemEntropy, Allow);
    futures_executor::block_on(keys.create_scope(
        &prf,
        Binding::new(scope, member).unwrap(),
        DeviceInfo::new("fixture", &[9; 16]).unwrap(),
        b"fixture",
    ))
    .unwrap()
}

fn sign(signer: &mut Signer, kind: Kind, payload: Value, at: u64) -> Vec<u8> {
    signer
        .sign(kind, &serde_json::to_vec(&payload).unwrap(), at, at + 500)
        .unwrap()
}

fn charter(scope: &str, at: u64, revoked_members: &[&str]) -> Charter {
    let mut signer =
        Signer::new(scope, SecretKey::from_seed(&mut [71; 32]), NOW - 1, 1000).unwrap();
    let schema = json!({"community":scope,"version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":scope,"revision":1,
        "policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),"schema_version":1});
    let mut feed = json!({"revision":1,"policy_epoch":1,"key_ring":signer.key_ring().to_cbor(),
        "manifest":sign(&mut signer,Kind::SettingsSnapshot,manifest,at)});
    for (name, kind, content) in [
        ("settings", Kind::SettingsSnapshot, json!({})),
        ("schema", Kind::SchemaSnapshot, schema.clone()),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        ("communities", Kind::CommunitiesSnapshot, json!([scope])),
        (
            "revocations",
            Kind::RevocationListSnapshot,
            json!({"members":revoked_members,"devices":[],"passkeys":[]}),
        ),
    ] {
        feed[name] = json!(sign(
            &mut signer,
            kind,
            json!({"community":scope,"revision":1,"policy_epoch":1,"content":content}),
            at
        ));
    }
    let mut owner = Charter::new(Configuration {
        origin: "https://members.example.com".into(),
        community: scope.into(),
        key_ring: signer.key_ring().to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap();
    owner
        .install(&serde_json::to_vec(&feed).unwrap(), at)
        .unwrap();
    owner
}

fn params() -> StampParams {
    StampParams::new(DAY).unwrap()
}

fn key(name: &str) -> StampIssuerKey {
    StampIssuerKey::generate(&mut OsRng, KeyId::new(name).unwrap(), &params()).unwrap()
}

fn nym(holder: &OpaqueHolder, scope: &str) -> String {
    holder.pseudonym(&CommunityId::new(scope).unwrap()).to_hex()
}

fn trust(keys: &[(&StampIssuerKey, u64, Option<u64>)]) -> StampTrust {
    StampTrust::new(
        keys.iter()
            .map(|(key, from, until)| {
                StampKeyPeriod::new(key.public_key().clone(), *from, *until).unwrap()
            })
            .collect(),
        params(),
    )
    .unwrap()
}

fn stamp(
    holder: &mut OpaqueHolder,
    key: &StampIssuerKey,
    approvals: &[(StampScope, StampAction)],
    now: u64,
) -> StampPresentation {
    let nonce = IssuanceChallenge::generate(&mut OsRng);
    holder.cancel_stamp();
    let request = holder
        .begin_stamp(&mut OsRng, key.public_key(), &nonce, approvals, now)
        .unwrap();
    let blind = key
        .issue_blind(&mut OsRng, &request, &nonce, EPOCH, now)
        .unwrap();
    holder.finish_stamp(&blind, EPOCH, now).unwrap();
    let (scope, action) = &approvals[0];
    holder
        .present_stamp(&mut OsRng, scope, action, now)
        .unwrap()
}

struct Fixture {
    holder: OpaqueHolder,
    member: String,
    key: StampIssuerKey,
    receipt: Receipt,
    owner: Charter,
}

fn fixture() -> Fixture {
    let holder = OpaqueHolder::from_seed(&mut [40; 32]);
    let member = nym(&holder, "alpha");
    Fixture {
        receipt: first_lineage("alpha", &member),
        holder,
        member,
        key: key("stamp-1"),
        owner: charter("alpha", NOW, &[]),
    }
}

fn genesis_evidence(
    holder: &mut OpaqueHolder,
    key: &StampIssuerKey,
    current: &VerifiedCharter,
    receipt: &Receipt,
    at: u64,
    issued: u64,
) -> GenesisStampEvidence {
    let scope = lineage_stamp_scope(current).unwrap();
    let action = lineage_genesis_action(receipt, SALT, at).unwrap();
    let shown = stamp(holder, key, &[(scope, action)], issued);
    GenesisStampEvidence::new(receipt.clone(), &shown, SALT, at)
}

type Machine = ckmg::Keys<Memory, Clock, ckmg::SystemEntropy, Allow>;
fn machine() -> Machine {
    ckmg::Keys::new(Memory::default(), Clock, ckmg::SystemEntropy, Allow)
}

/// Kills genesis_stamp.rs:268 `presentation_bytes -> Vec::leak(Vec::new()|vec![0]|vec![1])`:
/// the carried bytes are exactly the presentation encoding, never empty or one byte.
#[test]
fn presentation_bytes_are_the_exact_presentation_encoding() {
    let mut f = fixture();
    let current = f.owner.current(NOW).unwrap();
    let evidence = genesis_evidence(&mut f.holder, &f.key, current, &f.receipt, NOW, NOW);
    let wire = evidence.presentation().unwrap().to_bytes();
    assert!(!wire.is_empty());
    assert!(wire.len() > 1);
    assert_eq!(evidence.presentation_bytes(), wire.as_slice());
}

/// Kills genesis_stamp.rs:276 `> -> >=` in `from_bytes`: exactly MAX bytes decode.
#[test]
fn genesis_evidence_of_exactly_max_bytes_is_accepted() {
    let mut f = fixture();
    let current = f.owner.current(NOW).unwrap();
    let evidence = genesis_evidence(&mut f.holder, &f.key, current, &f.receipt, NOW, NOW);
    let wire = evidence.to_bytes().unwrap();
    assert!(wire.len() < MAX_GENESIS_EVIDENCE_BYTES);
    let mut padded = wire.clone();
    padded.resize(MAX_GENESIS_EVIDENCE_BYTES, b' ');
    assert_eq!(padded.len(), MAX_GENESIS_EVIDENCE_BYTES);
    let decoded = GenesisStampEvidence::from_bytes(&padded).unwrap();
    assert_eq!(decoded.presentation_bytes(), evidence.presentation_bytes());
    assert_eq!(decoded.at(), NOW);
}

/// Kills genesis_stamp.rs:402/403 `& -> |` in `genesis_receipt`: a non-`Created`
/// lineage of epoch 1 revision 1 (here `Restored`) is refused even though its
/// epoch and revision match, and even though the stamp over it would verify.
#[test]
fn a_restored_first_lineage_is_not_genesis_evidence() {
    let mut f = fixture();
    let member = f.member.clone();
    let prf = ckmg::passkey::PrfOutput::from_bytes(&[11; 32]).unwrap();
    let (restored, anchor) = futures_executor::block_on(async {
        let mut host = machine();
        let created = host
            .create_scope(
                &prf,
                Binding::new("alpha", &member).unwrap(),
                DeviceInfo::new("fixture", &[11; 16]).unwrap(),
                b"fixture",
            )
            .await
            .unwrap();
        host.acknowledge(created.operation).await.unwrap();
        let (anchor, _) = created.attested_lineage().unwrap();
        let anchor = anchor.clone();
        assert_eq!((anchor.epoch, anchor.revision), (1, 1));
        let retained = host.retained_checkpoint().await.unwrap();
        let mut phone = machine();
        let receipt = phone
            .restore_scope(
                &prf,
                &anchor,
                RestoreRoot::Checkpoint(&retained),
                DeviceInfo::new("fixture", &[11; 16]).unwrap(),
                b"fixture",
            )
            .await
            .unwrap();
        assert!(matches!(&receipt.change, Change::Restored(l) if l == &anchor));
        let (lineage, _) = receipt.attested_lineage().unwrap();
        assert_eq!((lineage.epoch, lineage.revision), (1, 1));
        (receipt, anchor)
    });
    assert_eq!(anchor.epoch, 1);
    let current = f.owner.current(NOW).unwrap();
    let fingerprint = current.fingerprint().copied();
    let stamps = trust(&[(&f.key, NOW - DAY, None)]);
    let evidence = genesis_evidence(&mut f.holder, &f.key, current, &restored, NOW, NOW);
    assert_eq!(
        verify_genesis_parts(
            "alpha",
            fingerprint.as_ref(),
            &stamps,
            &evidence,
            &member,
            NOW
        )
        .unwrap_err(),
        GenesisError::Receipt
    );
}

fn digest_of(receipt: &Receipt, member: &str, key: &[u8; 32], session: &[u8; 32]) -> [u8; 32] {
    pair_payload(
        "alpha",
        member,
        key,
        session,
        Some(&receipt.passkey_challenge().unwrap()),
    )
}

async fn host_signature(host: &mut Machine, digest: &[u8; 32]) -> [u8; 64] {
    let approval = PairingApproval::new("alpha", digest).unwrap();
    host.sign_device_ed25519_current(
        ckmg::DeviceFormat::PairingApproval,
        &approval.message(),
        NOW + 60,
    )
    .await
    .unwrap()
}

fn stamp_over(
    holder: &mut OpaqueHolder,
    key: &StampIssuerKey,
    current: &VerifiedCharter,
    digest: [u8; 32],
) -> StampPresentation {
    let scope = lineage_stamp_scope(current).unwrap();
    let action = StampAction::new(
        ActionKind::new(PAIR_ACTION).unwrap(),
        PayloadDigest::from_bytes(digest),
        StampSalt::from_bytes(SALT),
    );
    stamp(holder, key, &[(scope, action)], NOW)
}

/// Kills revision_stamp.rs:118 `< -> >`: a revision-3 pairing (two sequential
/// authorizations) verifies; the mutant refuses every revision above 2.
#[test]
fn a_third_revision_pairing_verifies() {
    let mut f = fixture();
    let member = f.member.clone();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let stamps = trust(&[(&f.key, NOW - DAY, None)]);
    futures_executor::block_on(async {
        let mut host = machine();
        let host_prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
        let created = host
            .create_scope(
                &host_prf,
                Binding::new("alpha", &member).unwrap(),
                DeviceInfo::new("host", &[9; 16]).unwrap(),
                b"fixture",
            )
            .await
            .unwrap();
        host.acknowledge(created.operation).await.unwrap();
        let (anchor, _) = created.attested_lineage().unwrap();
        let anchor = anchor.clone();
        for (seed, name) in [([8u8; 32], "guest1"), ([7u8; 32], "guest2")] {
            let mut guest = machine();
            let guest_prf = ckmg::passkey::PrfOutput::from_bytes(&seed).unwrap();
            let base = host.lineage().await.unwrap();
            let requested = guest
                .request_pairing(
                    &guest_prf,
                    &base,
                    DeviceInfo::new(name, &seed[..16]).unwrap(),
                    &[],
                )
                .await
                .unwrap();
            guest.acknowledge(requested.operation).await.unwrap();
            let Change::PairingRequested(request) = &requested.change else {
                panic!("not a pairing request");
            };
            let receipt = host.authorize_device(request, &[]).await.unwrap();
            host.acknowledge(receipt.operation).await.unwrap();
            if name == "guest2" {
                let Change::DeviceAuthorized(grant) = &receipt.change else {
                    panic!("not an authorization");
                };
                assert_eq!(grant.lineage.revision, 3);
                let key = *grant.request.device.value();
                let good = digest_of(&receipt, &member, &key, &SESSION);
                let presentation = stamp_over(&mut f.holder, &f.key, current, good);
                let signature = host_signature(&mut host, &good).await;
                let verified = verify_revision(
                    current,
                    &stamps,
                    &anchor,
                    &receipt,
                    &presentation,
                    SALT,
                    &SESSION,
                    &signature,
                    NOW,
                    &member,
                    NOW,
                )
                .unwrap();
                assert_eq!(verified.lineage().revision, 3);
                assert_eq!(verified.new_key().value(), &key);
            }
        }
    });
}

/// Kills revision_stamp.rs:125 `< -> >`: a verifier clock after the receipt time
/// accepts, a clock before it refuses with `Clock`.
#[test]
fn revision_evidence_is_judged_at_the_receipt_time_not_the_verifier_clock() {
    let mut f = fixture();
    let member = f.member.clone();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let stamps = trust(&[(&f.key, NOW - DAY, None)]);
    futures_executor::block_on(async {
        let host_prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
        let mut host = machine();
        let created = host
            .create_scope(
                &host_prf,
                Binding::new("alpha", &member).unwrap(),
                DeviceInfo::new("host", &[9; 16]).unwrap(),
                b"fixture",
            )
            .await
            .unwrap();
        host.acknowledge(created.operation).await.unwrap();
        let (anchor, _) = created.attested_lineage().unwrap();
        let anchor = anchor.clone();
        let mut guest = machine();
        let guest_prf = ckmg::passkey::PrfOutput::from_bytes(&[8; 32]).unwrap();
        let requested = guest
            .request_pairing(
                &guest_prf,
                &anchor,
                DeviceInfo::new("guest", &[8; 16]).unwrap(),
                &[],
            )
            .await
            .unwrap();
        guest.acknowledge(requested.operation).await.unwrap();
        let Change::PairingRequested(request) = &requested.change else {
            panic!("not a pairing request");
        };
        let receipt = host.authorize_device(request, &[]).await.unwrap();
        host.acknowledge(receipt.operation).await.unwrap();
        let Change::DeviceAuthorized(grant) = &receipt.change else {
            panic!("not an authorization");
        };
        let key = *grant.request.device.value();
        let good = digest_of(&receipt, &member, &key, &SESSION);
        let presentation = stamp_over(&mut f.holder, &f.key, current, good);
        let signature = host_signature(&mut host, &good).await;
        let at = NOW;
        assert!(
            verify_revision(
                current,
                &stamps,
                &anchor,
                &receipt,
                &presentation,
                SALT,
                &SESSION,
                &signature,
                at,
                &member,
                at + 1,
            )
            .is_ok()
        );
        assert_eq!(
            verify_revision(
                current,
                &stamps,
                &anchor,
                &receipt,
                &presentation,
                SALT,
                &SESSION,
                &signature,
                at,
                &member,
                at - 1,
            )
            .unwrap_err(),
            RevisionError::Clock
        );
    });
}

/// Kills revision_stamp.rs:163 `delete match arm GenesisError::Scope`: a stamp
/// over the right digest but under another pseudonym is `Scope`, not `Stamp`.
#[test]
fn a_thiefs_stamp_over_the_right_digest_is_a_scope_refusal() {
    let mut f = fixture();
    let member = f.member.clone();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let stamps = trust(&[(&f.key, NOW - DAY, None)]);
    futures_executor::block_on(async {
        let host_prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
        let mut host = machine();
        let created = host
            .create_scope(
                &host_prf,
                Binding::new("alpha", &member).unwrap(),
                DeviceInfo::new("host", &[9; 16]).unwrap(),
                b"fixture",
            )
            .await
            .unwrap();
        host.acknowledge(created.operation).await.unwrap();
        let (anchor, _) = created.attested_lineage().unwrap();
        let anchor = anchor.clone();
        let mut guest = machine();
        let guest_prf = ckmg::passkey::PrfOutput::from_bytes(&[8; 32]).unwrap();
        let requested = guest
            .request_pairing(
                &guest_prf,
                &anchor,
                DeviceInfo::new("guest", &[8; 16]).unwrap(),
                &[],
            )
            .await
            .unwrap();
        guest.acknowledge(requested.operation).await.unwrap();
        let Change::PairingRequested(request) = &requested.change else {
            panic!("not a pairing request");
        };
        let receipt = host.authorize_device(request, &[]).await.unwrap();
        host.acknowledge(receipt.operation).await.unwrap();
        let Change::DeviceAuthorized(grant) = &receipt.change else {
            panic!("not an authorization");
        };
        let key = *grant.request.device.value();
        let good = digest_of(&receipt, &member, &key, &SESSION);
        let signature = host_signature(&mut host, &good).await;
        let mut thief = OpaqueHolder::from_seed(&mut [42; 32]);
        let stolen = stamp_over(&mut thief, &f.key, current, good);
        assert_ne!(nym(&thief, "alpha"), member);
        assert_eq!(
            verify_revision(
                current, &stamps, &anchor, &receipt, &stolen, SALT, &SESSION, &signature, NOW,
                &member, NOW,
            )
            .unwrap_err(),
            RevisionError::Scope
        );
    });
}

/// Kills revision_stamp.rs:175 `Debug -> Ok(Default::default())`: the redaction
/// string is the whole output.
#[test]
fn verified_revision_debug_is_redacted() {
    let mut f = fixture();
    let member = f.member.clone();
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    let stamps = trust(&[(&f.key, NOW - DAY, None)]);
    futures_executor::block_on(async {
        let host_prf = ckmg::passkey::PrfOutput::from_bytes(&[9; 32]).unwrap();
        let mut host = machine();
        let created = host
            .create_scope(
                &host_prf,
                Binding::new("alpha", &member).unwrap(),
                DeviceInfo::new("host", &[9; 16]).unwrap(),
                b"fixture",
            )
            .await
            .unwrap();
        host.acknowledge(created.operation).await.unwrap();
        let (anchor, _) = created.attested_lineage().unwrap();
        let anchor = anchor.clone();
        let mut guest = machine();
        let guest_prf = ckmg::passkey::PrfOutput::from_bytes(&[8; 32]).unwrap();
        let requested = guest
            .request_pairing(
                &guest_prf,
                &anchor,
                DeviceInfo::new("guest", &[8; 16]).unwrap(),
                &[],
            )
            .await
            .unwrap();
        guest.acknowledge(requested.operation).await.unwrap();
        let Change::PairingRequested(request) = &requested.change else {
            panic!("not a pairing request");
        };
        let receipt = host.authorize_device(request, &[]).await.unwrap();
        host.acknowledge(receipt.operation).await.unwrap();
        let Change::DeviceAuthorized(grant) = &receipt.change else {
            panic!("not an authorization");
        };
        let key = *grant.request.device.value();
        let good = digest_of(&receipt, &member, &key, &SESSION);
        let presentation = stamp_over(&mut f.holder, &f.key, current, good);
        let signature = host_signature(&mut host, &good).await;
        let verified = verify_revision(
            current,
            &stamps,
            &anchor,
            &receipt,
            &presentation,
            SALT,
            &SESSION,
            &signature,
            NOW,
            &member,
            NOW,
        )
        .unwrap();
        assert_eq!(format!("{verified:?}"), "VerifiedRevision([redacted])");
    });
}

/// Kills wire.rs:70 `device_revoked -> true`: an unrevoked device is not revoked.
#[test]
fn an_unrevoked_device_is_not_revoked() {
    let mut owner = charter("alpha", NOW, &[]);
    let current = owner.current(NOW).unwrap();
    assert!(!current.revocations().device_revoked(&[22; 32]));
    assert!(!current.revocations().device_revoked(&[23; 32]));
}

/// Kills wire.rs:74 `> -> ==` and `> -> >=`: 1024 bytes are a valid credential
/// id bound, 1025 and empty are malformed.
#[test]
fn passkey_credential_ids_are_bounded_at_1024_bytes() {
    let revocations: Revocations = serde_json::from_value(json!({
        "members": [], "devices": [],
        "passkeys": [vec![7u8; 1024], vec![9u8; 64]],
    }))
    .unwrap();
    assert_eq!(revocations.passkey_revoked(&vec![7u8; 1024]), Ok(true));
    assert_eq!(revocations.passkey_revoked(&vec![8u8; 1024]), Ok(false));
    assert_eq!(
        revocations.passkey_revoked(&vec![9u8; 1025]).unwrap_err(),
        CharterError::Malformed
    );
    assert_eq!(
        revocations.passkey_revoked(&[]).unwrap_err(),
        CharterError::Malformed
    );
    let missing: Revocations = serde_json::from_value(json!({
        "members": [], "devices": [],
    }))
    .unwrap();
    assert_eq!(
        missing.passkey_revoked(&vec![9u8; 64]).unwrap_err(),
        CharterError::Unavailable
    );
}
