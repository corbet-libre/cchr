//! Genesis lineage evidence by stamp, verified by Charter: a real Keys `Created` receipt, a real
//! blind stamp from the opaque holder and a real wallet stamp key, against a signed Charter
//! (peers) and without one (the server at publication bind). Validity is judged at the receipt
//! time `at`, never at the verifier's clock.
#![cfg(not(target_arch = "wasm32"))]
use cchr::{
    Charter, Configuration, GenesisError, GenesisStampEvidence, MAX_GENESIS_EVIDENCE_BYTES,
    StampKeyPeriod, StampTrust, VerifiedCharter, genesis_stamp_scope, lineage_genesis_action,
    lineage_genesis_action_for, lineage_stamp_scope, verify_genesis, verify_genesis_parts,
};
use ckmg::{Authority, Authorization, Binding, Commit, DeviceInfo, Error, Locator, Receipt};
use cpsd::{
    CommunityId, IssuanceChallenge, KeyId, OpaqueHolder, StampAction, StampIssuerKey, StampParams,
    StampPresentation, StampScope, rand::rngs::OsRng,
};
use csgn::{Kind, SecretKey, Signer};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::HashMap, rc::Rc};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const EPOCH: u64 = 3;
const SALT: [u8; 32] = [5; 32];

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
}

/// The member's first lineage in `scope`: a Keys `Created` receipt.
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

/// A complete signed Charter of `scope`, current at `at` until `at + 500`.
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

/// One confirmation over `approvals` at `now`, presenting the first approval's slot.
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
    holder.finish_stamp(&blind, now).unwrap();
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

/// Evidence for `receipt` from one stamp issued at `issued` by `holder`, binding the time `at`.
fn evidence(
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

#[test]
fn genesis_evidence_verifies_with_and_without_a_charter_at_the_receipt_time() {
    let mut f = fixture();
    let current = f.owner.current(NOW).unwrap();
    let evidence = evidence(&mut f.holder, &f.key, current, &f.receipt, NOW, NOW);
    let stamps = trust(&[(&f.key, NOW - DAY, None)]);
    let (lineage, author) = f.receipt.attested_lineage().unwrap();

    let peer = verify_genesis(
        current,
        &stamps,
        evidence.receipt(),
        &evidence.presentation().unwrap(),
        evidence.salt(),
        evidence.at(),
        &f.member,
        NOW,
    )
    .unwrap();
    assert_eq!(peer.lineage(), lineage);
    assert_eq!(peer.author(), &author);
    let digest = peer.stamp().digest().to_bytes();
    assert_eq!(format!("{peer:?}"), "VerifiedGenesis([redacted])");

    // The server decodes the same bytes and verifies them without the Charter document.
    let bytes = evidence.to_bytes().unwrap();
    let server = GenesisStampEvidence::from_bytes(&bytes).unwrap();
    assert_eq!(server.presentation_bytes(), evidence.presentation_bytes());
    assert_eq!(format!("{:?}", server.clone()), "GenesisStampEvidence([redacted])");
    let bound = verify_genesis_parts(
        "alpha",
        current.fingerprint(),
        &stamps,
        &server,
        &f.member,
        NOW,
    )
    .unwrap();
    assert_eq!(bound.lineage(), lineage);
    assert_eq!(bound.author(), &author);
    let recorded = bound.into_stamp();
    assert_eq!(recorded.digest().to_bytes(), digest);
    assert_eq!(recorded.action_kind().as_str(), cchr::LINEAGE_GENESIS_ACTION);

    // Three days later the stamp (one-day cohort) has long expired; the lineage still counts.
    let later = NOW + 3 * DAY;
    let mut later_owner = charter("alpha", later, &[]);
    let later_current = later_owner.current(later).unwrap();
    let presentation = evidence.presentation().unwrap();
    let verify = |current: &VerifiedCharter, member: &str, now: u64| {
        verify_genesis(
            current,
            &stamps,
            evidence.receipt(),
            &presentation,
            SALT,
            NOW,
            member,
            now,
        )
        .map(|verified| verified.stamp().digest().to_bytes())
    };
    assert_eq!(verify(later_current, &f.member, later), Ok(digest));
    // Charter rules apply live: expired settings, a revoked member, another community.
    assert_eq!(
        verify(current, &f.member, NOW + 600),
        Err(GenesisError::Policy(cchr::Error::Expired))
    );
    let mut revoked = charter("alpha", later, &[&f.member]);
    assert_eq!(
        verify(revoked.current(later).unwrap(), &f.member, later),
        Err(GenesisError::Policy(cchr::Error::Unauthenticated))
    );
    let mut beta = charter("beta", NOW, &[]);
    assert_eq!(
        verify(beta.current(NOW).unwrap(), &f.member, NOW),
        Err(GenesisError::Scope)
    );
    // Another member, and a verifier clock before the receipt time.
    let other = nym(&OpaqueHolder::from_seed(&mut [41; 32]), "alpha");
    assert_eq!(verify(current, &other, NOW), Err(GenesisError::Scope));
    assert_eq!(verify(current, &f.member, NOW - 1), Err(GenesisError::Clock));

    // A pre-activation device derives the same action from the receipt's challenge digest.
    assert!(
        lineage_genesis_action_for(f.receipt.passkey_challenge().unwrap(), SALT, NOW).unwrap()
            == lineage_genesis_action(&f.receipt, SALT, NOW).unwrap()
    );
}

#[test]
fn the_server_refuses_other_scopes_keys_times_and_stamps() {
    let mut f = fixture();
    let current = f.owner.current(NOW).unwrap();
    let fingerprint = current.fingerprint().copied();
    let evidence = evidence(&mut f.holder, &f.key, current, &f.receipt, NOW, NOW);
    let check = |stamps: &StampTrust, community: &str, print: Option<[u8; 32]>, member: &str| {
        verify_genesis_parts(community, print.as_ref(), stamps, &evidence, member, NOW)
            .map(|verified| verified.lineage().epoch)
    };
    let stamps = trust(&[(&f.key, NOW - DAY, None)]);
    assert_eq!(check(&stamps, "alpha", fingerprint, &f.member), Ok(1));
    assert_eq!(
        check(&stamps, "beta", fingerprint, &f.member),
        Err(GenesisError::Scope)
    );
    assert_eq!(
        check(&stamps, "alpha", Some([7; 32]), &f.member),
        Err(GenesisError::Stamp)
    );
    // The signing key must be valid at the receipt time: not yet valid, retired, or unknown.
    for refused in [
        trust(&[(&f.key, NOW + 1, None)]),
        trust(&[(&f.key, NOW - DAY, Some(NOW))]),
        trust(&[(&key("stamp-2"), 0, None)]),
    ] {
        assert_eq!(
            check(&refused, "alpha", fingerprint, &f.member),
            Err(GenesisError::Stamp)
        );
    }
    // A retired key still verifies evidence made inside its period.
    let retired = trust(&[(&f.key, NOW - DAY, Some(NOW + 1)), (&key("stamp-2"), NOW + 1, None)]);
    assert_eq!(check(&retired, "alpha", fingerprint, &f.member), Ok(1));
    assert_eq!(format!("{retired:?}").matches("StampKeyPeriod").count(), 2);

    // A receipt time outside the stamp's cohort: the stamp was issued three days later.
    let old = NOW - 3 * DAY;
    let stale = self::evidence(&mut f.holder, &f.key, current, &f.receipt, old, NOW);
    assert_eq!(
        verify_genesis_parts("alpha", fingerprint.as_ref(), &stamps, &stale, &f.member, NOW)
            .unwrap_err(),
        GenesisError::Stamp
    );

    // Another holder's valid stamp over this member's receipt proves another pseudonym.
    let mut thief = OpaqueHolder::from_seed(&mut [42; 32]);
    let stolen = self::evidence(&mut thief, &f.key, current, &f.receipt, NOW, NOW);
    assert_eq!(
        verify_genesis_parts("alpha", fingerprint.as_ref(), &stamps, &stolen, &f.member, NOW)
            .unwrap_err(),
        GenesisError::Scope
    );

    // A receipt that is not an attested first lineage is refused before any stamp check.
    let mut unattested = f.receipt.clone();
    unattested.attestation = None;
    let shown = evidence.presentation().unwrap();
    let forged = GenesisStampEvidence::new(unattested, &shown, SALT, NOW);
    assert_eq!(
        verify_genesis_parts("alpha", fingerprint.as_ref(), &stamps, &forged, &f.member, NOW)
            .unwrap_err(),
        GenesisError::Receipt
    );
    // Malformed presentation bytes refuse as a stamp failure.
    let mut wire: Value = serde_json::from_slice(&evidence.to_bytes().unwrap()).unwrap();
    wire["presentation"] = json!([1, 2, 3]);
    let broken = GenesisStampEvidence::from_bytes(&serde_json::to_vec(&wire).unwrap()).unwrap();
    assert_eq!(
        verify_genesis_parts("alpha", fingerprint.as_ref(), &stamps, &broken, &f.member, NOW)
            .unwrap_err(),
        GenesisError::Stamp
    );
}

#[test]
fn trust_scope_and_wire_inputs_are_checked() {
    let stamp_key = key("stamp-1");
    let period = StampKeyPeriod::new(stamp_key.public_key().clone(), 0, None).unwrap();
    assert_eq!(
        StampKeyPeriod::new(stamp_key.public_key().clone(), NOW, Some(NOW)).unwrap_err(),
        GenesisError::Stamp
    );
    assert_eq!(
        StampTrust::new(vec![], params()).unwrap_err(),
        GenesisError::Stamp
    );
    assert_eq!(
        StampTrust::new(vec![period.clone(), period.clone()], params()).unwrap_err(),
        GenesisError::Stamp
    );
    let ring = StampTrust::new(vec![period], params()).unwrap();
    assert!(format!("{:?}", ring.clone()).contains("stamp-1"));

    // The scope of an unfounded community is its id-tagged fingerprint; an invalid id refuses.
    let unfounded = genesis_stamp_scope("alpha", None).unwrap();
    assert_eq!(
        unfounded.fingerprint().to_bytes(),
        csgn::community_fingerprint("alpha", None)
    );
    assert_eq!(genesis_stamp_scope("", None).unwrap_err(), GenesisError::Scope);

    // Wire: oversized, malformed and foreign-purpose bytes are refused.
    assert_eq!(
        GenesisStampEvidence::from_bytes(&vec![b' '; MAX_GENESIS_EVIDENCE_BYTES + 1]).unwrap_err(),
        GenesisError::Limit
    );
    assert_eq!(
        GenesisStampEvidence::from_bytes(b"{}").unwrap_err(),
        GenesisError::Invalid
    );
    let mut f = fixture();
    let current = f.owner.current(NOW).unwrap();
    let evidence = evidence(&mut f.holder, &f.key, current, &f.receipt, NOW, NOW);
    let mut foreign: Value = serde_json::from_slice(&evidence.to_bytes().unwrap()).unwrap();
    foreign["purpose"] = json!("cvlt.lineage-evidence.v1");
    assert_eq!(
        GenesisStampEvidence::from_bytes(&serde_json::to_vec(&foreign).unwrap()).unwrap_err(),
        GenesisError::Invalid
    );
    // Fixed diagnostics carry no evidence.
    let error = GenesisError::Policy(cchr::Error::Expired);
    assert_eq!(
        format!("{error} {:?}", error.clone()),
        "genesis stamp evidence: Policy(Expired) Policy(Expired)"
    );
    assert!(std::error::Error::source(&error).is_none());
}
