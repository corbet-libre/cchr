//! Birth genesis evidence of the wallet lineage: known-answer vectors first (a committed
//! fixture of real wallet-signed bytes over a real Keys `Created` receipt), then property tests:
//! every single-field mutation refuses, unknown and expired keys refuse, retired keys verify for
//! what they signed inside their period, and the restoring device's own check.
use cchr::{
    BIRTH_STATEMENT_PURPOSE, BirthError, BirthGenesisEvidence, BirthStatement,
    MAX_BIRTH_EVIDENCE_BYTES, birth_statement_digest, verify_birth_genesis, wallet_fingerprint,
};
use csgn::KeyRing;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/birth-genesis-v1.json");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn unhex32(text: &str) -> [u8; 32] {
    unhex(text).try_into().unwrap()
}

struct Vector {
    ring: KeyRing,
    evidence: Vec<u8>,
    fixture: Value,
}
fn vector() -> Vector {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    Vector {
        ring: KeyRing::from_cbor(&unhex(fixture["ring"].as_str().unwrap())).unwrap(),
        evidence: fixture["evidence"].as_str().unwrap().as_bytes().to_vec(),
        fixture,
    }
}
impl Vector {
    fn str(&self, name: &str) -> &str {
        self.fixture[name].as_str().unwrap()
    }
    fn u64(&self, name: &str) -> u64 {
        self.fixture[name].as_u64().unwrap()
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn known_answer_birth_genesis_verifies_with_its_exact_fields() {
    let v = vector();
    let wallet = unhex32(v.str("wallet"));
    // The wallet fingerprint is csgn's one community fingerprint of an unfounded "wallet".
    assert_eq!(wallet, wallet_fingerprint(None));
    let evidence = BirthGenesisEvidence::from_bytes(&v.evidence).unwrap();
    // The evidence encoding is canonical: decoding and re-encoding gives the committed bytes.
    assert_eq!(evidence.to_bytes().unwrap(), v.evidence);
    let verified =
        verify_birth_genesis(&v.ring, &evidence, &wallet, v.str("account"), v.u64("now")).unwrap();
    let statement = verified.statement();
    assert_eq!(statement.wallet(), &wallet);
    assert_eq!(statement.account(), v.str("account"));
    assert_eq!(statement.credential(), unhex(v.str("credential")));
    assert_eq!(
        statement.credential_key(),
        &unhex32(v.str("credential_key"))
    );
    assert_eq!(statement.device(), &unhex32(v.str("device")));
    assert_eq!(verified.device().value(), &unhex32(v.str("device")));
    assert_eq!(statement.commitment(), &unhex32(v.str("commitment")));
    assert_eq!(statement.digest(), &unhex32(v.str("digest")));
    assert_eq!(
        evidence.receipt().passkey_challenge().unwrap(),
        unhex32(v.str("digest"))
    );
    assert_eq!(statement.at(), v.u64("at"));
    assert_eq!(evidence.at(), v.u64("at"));
    assert_eq!(
        verified.statement_digest(),
        &unhex32(v.str("statement_digest"))
    );
    assert_eq!(
        birth_statement_digest(evidence.statement_bytes()),
        unhex32(v.str("statement_digest"))
    );
    assert_eq!(verified.lineage().binding.community(), "wallet");
    assert_eq!(verified.lineage().binding.member(), v.str("account"));
    // The payload the wallet signs is pinned byte for byte.
    let rebuilt = BirthStatement::new(
        wallet,
        v.str("account"),
        &unhex(v.str("credential")),
        unhex32(v.str("credential_key")),
        unhex32(v.str("device")),
        unhex32(v.str("commitment")),
        unhex32(v.str("digest")),
        v.u64("at"),
    )
    .unwrap();
    assert_eq!(rebuilt.to_payload().unwrap(), v.str("payload").as_bytes());
    assert_eq!(&rebuilt, statement);
    // The restoring device's own credential and derived key are the ones named.
    verified
        .check_restoring(&unhex(v.str("credential")), &unhex32(v.str("device")))
        .unwrap();
    // The digest function itself (domain-separated SHA-256) is pinned.
    assert_eq!(
        hex(&birth_statement_digest(b"")),
        v.str("empty_statement_digest")
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_byte_of_the_signed_statement_is_bound() {
    let v = vector();
    let wallet = unhex32(v.str("wallet"));
    let evidence: Value = serde_json::from_slice(&v.evidence).unwrap();
    let statement: Vec<u8> = serde_json::from_value(evidence["statement"].clone()).unwrap();
    for i in 0..statement.len() {
        for flip in [0x01_u8, 0x80] {
            let mut changed = statement.clone();
            changed[i] ^= flip;
            let mut tampered = evidence.clone();
            tampered["statement"] = serde_json::json!(changed);
            let tampered =
                BirthGenesisEvidence::from_bytes(&serde_json::to_vec(&tampered).unwrap()).unwrap();
            assert!(
                verify_birth_genesis(&v.ring, &tampered, &wallet, v.str("account"), v.u64("now"))
                    .is_err(),
                "byte {i} flip {flip:#x} verified"
            );
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn evidence_wire_and_expected_values_are_checked() {
    let v = vector();
    let wallet = unhex32(v.str("wallet"));
    let evidence = BirthGenesisEvidence::from_bytes(&v.evidence).unwrap();
    let account = v.str("account");
    let now = v.u64("now");
    let at = v.u64("at");
    // Expected wallet and account.
    let mut other = wallet;
    other[0] ^= 1;
    assert_eq!(
        verify_birth_genesis(&v.ring, &evidence, &other, account, now).unwrap_err(),
        BirthError::Scope
    );
    assert_eq!(
        verify_birth_genesis(&v.ring, &evidence, &wallet, "another-account", now).unwrap_err(),
        BirthError::Scope
    );
    // The verifier's clock may not precede the statement.
    assert_eq!(
        verify_birth_genesis(&v.ring, &evidence, &wallet, account, at - 1).unwrap_err(),
        BirthError::Clock
    );
    // ... but validity is judged at `at`: years later the statement still verifies.
    verify_birth_genesis(&v.ring, &evidence, &wallet, account, at + 10 * 365 * 86_400).unwrap();
    // The carried `at` must be the signed one.
    let mut value: Value = serde_json::from_slice(&v.evidence).unwrap();
    for shifted in [at - 1, at + 1] {
        value["at"] = serde_json::json!(shifted);
        let moved = BirthGenesisEvidence::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            verify_birth_genesis(&v.ring, &moved, &wallet, account, now).unwrap_err(),
            BirthError::Statement
        );
    }
    // Wire: purpose, unknown fields and the size bound.
    let mut value: Value = serde_json::from_slice(&v.evidence).unwrap();
    value["purpose"] = serde_json::json!("cchr.wallet-birth-evidence.v2");
    assert_eq!(
        BirthGenesisEvidence::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        BirthError::Invalid
    );
    let mut value: Value = serde_json::from_slice(&v.evidence).unwrap();
    value["extra"] = serde_json::json!(1);
    assert_eq!(
        BirthGenesisEvidence::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
        BirthError::Invalid
    );
    assert_eq!(
        BirthGenesisEvidence::from_bytes(&vec![b' '; MAX_BIRTH_EVIDENCE_BYTES + 1]).unwrap_err(),
        BirthError::Limit
    );
    // The restoring device refuses a statement naming another credential or device key.
    let verified = verify_birth_genesis(&v.ring, &evidence, &wallet, account, now).unwrap();
    let credential = unhex(v.str("credential"));
    let device = unhex32(v.str("device"));
    let mut other_credential = credential.clone();
    other_credential[0] ^= 1;
    assert_eq!(
        verified.check_restoring(&other_credential, &device),
        Err(BirthError::Restore)
    );
    assert_eq!(
        verified.check_restoring(&credential[1..], &device),
        Err(BirthError::Restore)
    );
    let mut other_device = device;
    other_device[31] ^= 1;
    assert_eq!(
        verified.check_restoring(&credential, &other_device),
        Err(BirthError::Restore)
    );
    // Statement shape.
    assert!(BIRTH_STATEMENT_PURPOSE.ends_with(".v1"));
    for (account, credential, device) in [
        ("", &[1_u8][..], [1; 32]),
        ("a", &[][..], [1; 32]),
        ("a", &[1][..], [0; 32]),
    ] {
        assert_eq!(
            BirthStatement::new(
                wallet, account, credential, [1; 32], device, [1; 32], [1; 32], 1
            )
            .unwrap_err(),
            BirthError::Invalid
        );
    }
    assert_eq!(
        BirthStatement::new(
            wallet,
            &"a".repeat(257),
            &[1],
            [1; 32],
            [1; 32],
            [1; 32],
            [1; 32],
            1
        )
        .unwrap_err(),
        BirthError::Invalid
    );
    assert_eq!(
        BirthStatement::new(
            wallet, "a", &[1; 1025], [1; 32], [1; 32], [1; 32], [1; 32], 1
        )
        .unwrap_err(),
        BirthError::Invalid
    );
}

/// Native property tests: they re-sign statements with the fixture's wallet key and make real
/// Keys receipts.
#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use ckmg::{Authority, Authorization, Binding, Commit, DeviceInfo, Error, Locator, Receipt};
    use csgn::{Kind, SecretKey, Signer};
    use serde_json::json;
    use std::{cell::RefCell, collections::HashMap, rc::Rc};

    const DAY: u64 = 86_400;
    /// The statement time: not a day boundary, so the day-rounded COSE issue time precedes it.
    const AT: u64 = 1_800_000_000;
    const ISSUED: u64 = AT / DAY * DAY;
    const VALIDITY: u64 = 30 * DAY;
    const WALLET_SEED: [u8; 32] = [81; 32];
    const ACCOUNT: &str = "5f0c9a52-6f43-4b8e-9d1a-2c7e1b3a4d60";
    const CREDENTIAL: &[u8] = b"fixture wallet credential id";
    const CREDENTIAL_KEY: [u8; 32] = [33; 32];
    const COMMITMENT: [u8; 32] = [44; 32];
    const PRF: [u8; 32] = [9; 32];

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
            Ok(AT)
        }
    }
    struct Allow;
    impl Authority for Allow {
        async fn check(&mut self, _request: Authorization<'_>) -> Result<(), Error> {
            Ok(())
        }
    }

    /// The first lineage of `member` in `scope`, made with the PRF `prf`.
    fn first_lineage(prf: [u8; 32], scope: &str, member: &str) -> Receipt {
        let prf = ckmg::passkey::PrfOutput::from_bytes(&prf).unwrap();
        let mut keys = ckmg::Keys::new(Memory::default(), Clock, ckmg::SystemEntropy, Allow);
        futures_executor::block_on(keys.create_scope(
            &prf,
            Binding::new(scope, member).unwrap(),
            DeviceInfo::new("fixture", &[9; 16]).unwrap(),
            b"fixture",
        ))
        .unwrap()
    }
    fn wallet_signer() -> Signer {
        Signer::new(
            "wallet",
            SecretKey::from_seed(&mut WALLET_SEED.clone()),
            ISSUED - DAY,
            VALIDITY,
        )
        .unwrap()
    }
    fn device(receipt: &Receipt) -> [u8; 32] {
        *receipt.attested_lineage().unwrap().1.value()
    }
    fn statement_value(receipt: &Receipt) -> Value {
        serde_json::to_value(
            BirthStatement::new(
                wallet_fingerprint(None),
                ACCOUNT,
                CREDENTIAL,
                CREDENTIAL_KEY,
                device(receipt),
                COMMITMENT,
                receipt.passkey_challenge().unwrap(),
                AT,
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn sign_at(signer: &mut Signer, payload: &[u8], issued: u64) -> Vec<u8> {
        signer
            .sign(Kind::Credential, payload, issued, issued + VALIDITY)
            .unwrap()
    }
    fn evidence(receipt: &Receipt, statement: Vec<u8>, at: u64) -> BirthGenesisEvidence {
        BirthGenesisEvidence::from_bytes(
            &BirthGenesisEvidence::new(receipt.clone(), statement, at)
                .to_bytes()
                .unwrap(),
        )
        .unwrap()
    }
    fn check(ring: &KeyRing, evidence: &BirthGenesisEvidence) -> Result<(), BirthError> {
        verify_birth_genesis(ring, evidence, &wallet_fingerprint(None), ACCOUNT, AT + DAY)
            .map(|_| ())
    }

    /// Writes `tests/fixtures/birth-genesis-v1.json` (run once with `--ignored`; the committed
    /// bytes are the known answers, never regenerated to make a test pass).
    #[test]
    #[ignore = "writes the committed known-answer fixture"]
    fn write_known_answer_fixture() {
        let receipt = first_lineage(PRF, "wallet", ACCOUNT);
        let mut signer = wallet_signer();
        let payload = serde_json::to_vec(&statement_value(&receipt)).unwrap();
        let statement = sign_at(&mut signer, &payload, ISSUED);
        let evidence = BirthGenesisEvidence::new(receipt.clone(), statement.clone(), AT);
        let fixture = json!({
            "about": "cchr birth genesis known answers v1: a real ckmg Created receipt of (wallet, account) and a statement signed by the fictional test wallet key SecretKey::from_seed([81; 32]) (csgn Kind::Credential, issuer wallet). Test secrets only.",
            "ring": hex(&signer.key_ring().to_cbor()),
            "evidence": String::from_utf8(evidence.to_bytes().unwrap()).unwrap(),
            "payload": String::from_utf8(payload).unwrap(),
            "wallet": hex(&wallet_fingerprint(None)),
            "account": ACCOUNT,
            "credential": hex(CREDENTIAL),
            "credential_key": hex(&CREDENTIAL_KEY),
            "device": hex(&device(&receipt)),
            "commitment": hex(&COMMITMENT),
            "digest": hex(&receipt.passkey_challenge().unwrap()),
            "at": AT,
            "now": AT + DAY,
            "statement_digest": hex(&birth_statement_digest(&statement)),
            "empty_statement_digest": hex(&birth_statement_digest(b"")),
        });
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/birth-genesis-v1.json"
        );
        std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
    }

    #[test]
    fn the_device_key_is_the_one_the_prf_derives_for_the_wallet() {
        let v = vector();
        let prf = ckmg::passkey::PrfOutput::from_bytes(&PRF).unwrap();
        assert_eq!(
            ckmg::passkey::device_public_key(&prf, "wallet")
                .unwrap()
                .value(),
            &unhex32(v.str("device"))
        );
    }

    #[test]
    fn every_single_field_mutation_of_the_statement_is_refused() {
        let receipt = first_lineage(PRF, "wallet", ACCOUNT);
        let mut signer = wallet_signer();
        let ring = signer.key_ring().clone();
        let good = statement_value(&receipt);
        let payload = serde_json::to_vec(&good).unwrap();
        let signed = sign_at(&mut signer, &payload, ISSUED);
        check(&ring, &evidence(&receipt, signed.clone(), AT)).unwrap();

        let mutate = |field: &str, value: &Value| -> Value {
            let mut changed = good.clone();
            changed[field] = match value {
                Value::String(text) => json!(format!("{text}x")),
                Value::Number(n) => json!(n.as_u64().unwrap() + 1),
                Value::Array(bytes) => {
                    let mut bytes: Vec<u8> = serde_json::from_value(json!(bytes)).unwrap();
                    bytes[0] ^= 1;
                    json!(bytes)
                }
                _ => unreachable!(),
            };
            changed
        };
        let fields: Vec<String> = good.as_object().unwrap().keys().cloned().collect();
        assert_eq!(fields.len(), 9);
        for field in &fields {
            let changed = mutate(field, &good[field]);
            let at = changed["at"].as_u64().unwrap();
            let bytes = serde_json::to_vec(&changed).unwrap();
            // 1. The changed payload under the original signature: never.
            let resigned = sign_at(&mut wallet_signer(), &bytes, ISSUED);
            let forged = splice_payload(&signed, &payload, &bytes);
            assert_eq!(
                check(&ring, &evidence(&receipt, forged, at)).unwrap_err(),
                BirthError::Statement,
                "{field}: unsigned change verified"
            );
            // 2. Even re-signed by the wallet key, every field the evidence binds refuses;
            //    the credential is refused by the restoring device; the credential key and the
            //    seed commitment are the wallet's statements, checked by the server at the
            //    birth device bind, and carried unchanged.
            let resigned = evidence(&receipt, resigned, at);
            let outcome = verify_birth_genesis(
                &ring,
                &resigned,
                &wallet_fingerprint(None),
                ACCOUNT,
                AT + DAY,
            );
            match field.as_str() {
                "purpose" => assert_eq!(outcome.unwrap_err(), BirthError::Invalid),
                "wallet" | "account" => assert_eq!(outcome.unwrap_err(), BirthError::Scope),
                "device" => assert_eq!(outcome.unwrap_err(), BirthError::Device),
                "digest" => assert_eq!(outcome.unwrap_err(), BirthError::Digest),
                // `at + 1` is still inside the COSE period; the receipt does not bind time,
                // so a re-signed later time is the wallet's own statement time.
                "at" => {
                    outcome.unwrap();
                }
                "credential" => assert_eq!(
                    outcome
                        .unwrap()
                        .check_restoring(CREDENTIAL, &device(&receipt))
                        .unwrap_err(),
                    BirthError::Restore
                ),
                "credential_key" | "commitment" => {
                    let verified = outcome.unwrap();
                    assert_ne!(
                        serde_json::to_value(verified.statement()).unwrap(),
                        good,
                        "{field}: a re-signed change must surface"
                    );
                }
                other => panic!("unexpected field {other}"),
            }
        }
    }

    /// Replace the payload inside COSE bytes, keeping the original protected header and
    /// signature (a forgery attempt that changes only the payload).
    fn splice_payload(cose: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
        use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
        let mut message = CoseSign1::from_tagged_slice(cose)
            .or_else(|_| CoseSign1::from_slice(cose))
            .unwrap();
        assert_eq!(message.payload.as_deref(), Some(old));
        message.payload = Some(new.to_vec());
        message.to_tagged_vec().unwrap()
    }

    #[test]
    fn the_receipt_must_be_the_wallet_genesis_of_k_with_digest_d() {
        let receipt = first_lineage(PRF, "wallet", ACCOUNT);
        let mut signer = wallet_signer();
        let ring = signer.key_ring().clone();
        let payload = serde_json::to_vec(&statement_value(&receipt)).unwrap();
        let signed = sign_at(&mut signer, &payload, ISSUED);
        // Another community's first lineage of the same member.
        let alpha = first_lineage(PRF, "alpha", ACCOUNT);
        assert!(check(&ring, &evidence(&alpha, signed.clone(), AT)).is_err());
        // Another account's wallet lineage.
        let other = first_lineage(PRF, "wallet", "1b1c2d3e-0000-4000-8000-000000000001");
        assert_eq!(
            check(&ring, &evidence(&other, signed.clone(), AT)).unwrap_err(),
            BirthError::Scope
        );
        // The same binding made by another device (another PRF): K differs.
        let stranger = first_lineage([10; 32], "wallet", ACCOUNT);
        assert_eq!(
            check(&ring, &evidence(&stranger, signed.clone(), AT)).unwrap_err(),
            BirthError::Device
        );
        // Another genesis of the same device and binding: digest D differs.
        let again = first_lineage(PRF, "wallet", ACCOUNT);
        assert_eq!(device(&again), device(&receipt));
        assert_eq!(
            check(&ring, &evidence(&again, signed.clone(), AT)).unwrap_err(),
            BirthError::Digest
        );
        // A tampered receipt (not a genesis shape, or a broken attestation) refuses.
        let value = serde_json::to_value(&receipt).unwrap();
        for (path, edit) in [("revision", json!(2)), ("epoch", json!(2))] {
            let mut changed = value.clone();
            let lineage = changed["change"]["Created"].as_object_mut().unwrap();
            lineage.insert(path.into(), edit);
            let changed: Receipt = serde_json::from_value(changed).unwrap();
            assert_eq!(
                check(&ring, &evidence(&changed, signed.clone(), AT)).unwrap_err(),
                BirthError::Receipt
            );
        }
        // A receipt that is not a creation.
        let mut changed = value.clone();
        let lineage = changed["change"]["Created"].clone();
        changed["change"] = json!({ "Restored": lineage });
        let changed: Receipt = serde_json::from_value(changed).unwrap();
        assert_eq!(
            check(&ring, &evidence(&changed, signed, AT)).unwrap_err(),
            BirthError::Receipt
        );
    }

    #[test]
    fn unknown_expired_and_retired_keys() {
        let receipt = first_lineage(PRF, "wallet", ACCOUNT);
        let mut signer = wallet_signer();
        let payload = serde_json::to_vec(&statement_value(&receipt)).unwrap();
        let signed = sign_at(&mut signer, &payload, ISSUED);
        let good = evidence(&receipt, signed.clone(), AT);
        // Unknown key: another wallet key, and the same key under another issuer.
        let stranger = Signer::new(
            "wallet",
            SecretKey::from_seed(&mut [82; 32]),
            ISSUED - DAY,
            VALIDITY,
        )
        .unwrap();
        assert_eq!(
            check(stranger.key_ring(), &good).unwrap_err(),
            BirthError::Statement
        );
        let global = Signer::new(
            "cgbl:global",
            SecretKey::from_seed(&mut WALLET_SEED.clone()),
            ISSUED - DAY,
            VALIDITY,
        )
        .unwrap();
        assert_eq!(
            check(global.key_ring(), &good).unwrap_err(),
            BirthError::Statement
        );
        // Retired key: after a rotation the statement it signed while active still verifies.
        signer
            .rotate(SecretKey::from_seed(&mut [83; 32]), ISSUED + 2 * DAY)
            .unwrap();
        let rotated = signer.key_ring().clone();
        assert!(rotated.keys().iter().any(|key| key.retired_at().is_some()));
        check(&rotated, &good).unwrap();
        // ... but a statement made with the old key after its retirement does not (a leaked
        // retired key, or a stale signer).
        let late_at = ISSUED + 3 * DAY + 10;
        let mut late = statement_value(&receipt);
        late["at"] = json!(late_at);
        let late_bytes = serde_json::to_vec(&late).unwrap();
        let stale = sign_at(&mut wallet_signer(), &late_bytes, late_at / DAY * DAY);
        assert_eq!(
            verify_birth_genesis(
                &rotated,
                &evidence(&receipt, stale, late_at),
                &wallet_fingerprint(None),
                ACCOUNT,
                late_at
            )
            .unwrap_err(),
            BirthError::Statement
        );
        // The new key signs new statements.
        let fresh = sign_at(&mut signer, &late_bytes, late_at / DAY * DAY);
        verify_birth_genesis(
            &rotated,
            &evidence(&receipt, fresh, late_at),
            &wallet_fingerprint(None),
            ACCOUNT,
            late_at,
        )
        .unwrap();
        // Expired: a statement time at or after the COSE validity end refuses; so does a time
        // before the COSE issue time (not yet valid at `at`).
        for at in [ISSUED + VALIDITY, ISSUED + VALIDITY + 1, ISSUED - 1] {
            let mut moved = statement_value(&receipt);
            moved["at"] = json!(at);
            let bytes = serde_json::to_vec(&moved).unwrap();
            let cose = sign_at(&mut wallet_signer(), &bytes, ISSUED);
            assert_eq!(
                verify_birth_genesis(
                    &KeyRing::from_cbor(&wallet_signer().key_ring().to_cbor()).unwrap(),
                    &evidence(&receipt, cose, at),
                    &wallet_fingerprint(None),
                    ACCOUNT,
                    ISSUED + 2 * VALIDITY
                )
                .unwrap_err(),
                BirthError::Statement,
                "at {at}"
            );
        }
        // Another COSE kind with the same payload (a settings snapshot) refuses.
        let snapshot = wallet_signer()
            .sign(Kind::SettingsSnapshot, &payload, ISSUED, ISSUED + VALIDITY)
            .unwrap();
        assert_eq!(
            check(
                &KeyRing::from_cbor(&wallet_signer().key_ring().to_cbor()).unwrap(),
                &evidence(&receipt, snapshot, AT)
            )
            .unwrap_err(),
            BirthError::Statement
        );
    }
}
