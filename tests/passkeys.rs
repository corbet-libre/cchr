//! Focused boundary pins for `src/passkeys.rs` (tests-only).
//!
//! Each surviving mutant from the cargo-mutants run on `src/passkeys.rs`
//! must make at least one test here FAIL, while the whole suite passes
//! on the real code.
use cchr::{Charter, Configuration, Error};
use csgn::{Kind as CoseKind, SecretKey, Signer};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;
const ORIGIN: &str = "https://alpha.example.test";
/// Product bound `MAX_COSE_BYTES = (1 << 20) + 8192` (`src/lib.rs`).
const MAX_COSE_BYTES: usize = (1 << 20) + 8192;

fn signer() -> Signer {
    signer_at(NOW - 1)
}

fn signer_at(now: u64) -> Signer {
    Signer::new("alpha", SecretKey::from_seed(&mut [71; 32]), now, 1000).unwrap()
}

fn sign(s: &mut Signer, kind: CoseKind, payload: Value, until: u64) -> Vec<u8> {
    sign_at(s, kind, payload, NOW, until)
}

fn sign_at(s: &mut Signer, kind: CoseKind, payload: Value, issued: u64, until: u64) -> Vec<u8> {
    s.sign(kind, &serde_json::to_vec(&payload).unwrap(), issued, until)
        .unwrap()
}

fn feed_with(s: &mut Signer, revision: u64, epoch: u64, revocations: Value) -> Value {
    let schema = json!({"community":"alpha","version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":"alpha","revision":revision,
        "policy_epoch":epoch,"key_ring":s.key_ring().to_cbor(),"schema_version":1});
    let mut v = json!({"revision":revision,"policy_epoch":epoch,"key_ring":s.key_ring().to_cbor(),
        "manifest":sign(s,CoseKind::SettingsSnapshot,manifest,NOW + 500)});
    for (name, kind, content) in [
        (
            "settings",
            CoseKind::SettingsSnapshot,
            json!({"action.admission":{"all_of":[],"any_of":[{"gate":"voucher"}],"k_of_n":{"k":1,"of":[{"gate":"voucher"}]}}}),
        ),
        ("schema", CoseKind::SchemaSnapshot, schema.clone()),
        (
            "schema_versions",
            CoseKind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        (
            "communities",
            CoseKind::CommunitiesSnapshot,
            json!(["alpha"]),
        ),
        ("revocations", CoseKind::RevocationListSnapshot, revocations),
    ] {
        v[name] = json!(sign(
            s,
            kind,
            json!({"community":"alpha","revision":revision,"policy_epoch":epoch,"content":content}),
            NOW + 500,
        ));
    }
    v
}

fn clean_revocations() -> Value {
    json!({"members":[],"devices":[],"passkeys":[]})
}

/// Feed whose settings-side snapshots issue at `NOW - 100` while revocations
/// issue at `NOW`. The caller must sign the binding envelope first (at
/// `NOW - 100`), because the signer clock only moves forward.
fn feed_revocations_newer(s: &mut Signer, revision: u64, epoch: u64, revocations: Value) -> Value {
    const T0: u64 = NOW - 100;
    let schema = json!({"community":"alpha","version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":"alpha","revision":revision,
        "policy_epoch":epoch,"key_ring":s.key_ring().to_cbor(),"schema_version":1});
    let mut v = json!({"revision":revision,"policy_epoch":epoch,"key_ring":s.key_ring().to_cbor(),
        "manifest":sign_at(s,CoseKind::SettingsSnapshot,manifest,T0,NOW + 500)});
    for (name, kind, content, issued) in [
        (
            "settings",
            CoseKind::SettingsSnapshot,
            json!({"action.admission":{"all_of":[],"any_of":[{"gate":"voucher"}],"k_of_n":{"k":1,"of":[{"gate":"voucher"}]}}}),
            T0,
        ),
        ("schema", CoseKind::SchemaSnapshot, schema.clone(), T0),
        (
            "schema_versions",
            CoseKind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
            T0,
        ),
        (
            "communities",
            CoseKind::CommunitiesSnapshot,
            json!(["alpha"]),
            T0,
        ),
        (
            "revocations",
            CoseKind::RevocationListSnapshot,
            revocations,
            NOW,
        ),
    ] {
        v[name] = json!(sign_at(
            s,
            kind,
            json!({"community":"alpha","revision":revision,"policy_epoch":epoch,"content":content}),
            issued,
            NOW + 500,
        ));
    }
    v
}

fn configuration(s: &Signer) -> Configuration {
    Configuration {
        origin: ORIGIN.into(),
        community: "alpha".into(),
        key_ring: s.key_ring().to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    }
}

fn install_clean(s: &mut Signer) -> Charter {
    let v = feed_with(s, 10, 1, clean_revocations());
    let mut charter = Charter::new(configuration(s)).unwrap();
    charter
        .install(&serde_json::to_vec(&v).unwrap(), NOW)
        .unwrap();
    charter
}

fn credential_id() -> Vec<u8> {
    vec![7u8; 32]
}

fn cert_body(member: &str, credential: &[u8]) -> Value {
    json!({
        "purpose": "ckyh.passkey-certificate.v1",
        "community": "alpha",
        "member": member,
        "issued": NOW,
        "credential_id": credential,
        "rp_id": "alpha.example",
        "origins": ["https://alpha.example"],
        "algorithm": "ES256",
        "spki": vec![9u8; 32],
        "backup_eligible": false,
    })
}

fn cert_signed(s: &mut Signer, member: &str, credential: &[u8], until: u64) -> Vec<u8> {
    sign(
        s,
        CoseKind::Credential,
        cert_body(member, credential),
        until,
    )
}

fn credential_descriptor(credential: &[u8]) -> Value {
    json!({
        "community": "alpha",
        "member": vec![1u8; 16],
        "credential_id": credential,
        "rp_id": "alpha.example",
        "origins": ["https://alpha.example"],
        "algorithm": "ES256",
        "spki": vec![9u8; 64],
        "backup_eligible": false,
    })
}

fn binding_body(member: &str, epoch: u64, credential: Value) -> Value {
    json!({
        "purpose": "cplc.passkey-lineage.v1",
        "community": "alpha",
        "member": member,
        "policy_epoch": epoch,
        "credential": credential,
    })
}

fn binding_signed(s: &mut Signer, body: Value, until: u64) -> Vec<u8> {
    sign(s, CoseKind::Credential, body, until)
}

fn valid_binding(s: &mut Signer, member: &str, credential: &[u8], until: u64) -> Vec<u8> {
    binding_signed(
        s,
        binding_body(member, 1, credential_descriptor(credential)),
        until,
    )
}

macro_rules! test {
    ($name:ident, $body:block) => {
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(target_arch = "wasm32"), test)]
        fn $name() $body
    };
}

// ---- VerifiedPasskeyCertificate::valid_until (16:9 -> 0 / -> 1) ----

test!(
    cert_valid_until_is_the_minimum_of_certificate_and_charter,
    {
        // Short certificate against a longer charter.
        let mut s = signer();
        let mut charter = install_clean(&mut s);
        let signed = cert_signed(&mut s, "alice", &credential_id(), NOW + 100);
        let view = charter.current(NOW).unwrap();
        let cert = view.passkey_certificate(&signed, "alice", NOW).unwrap();
        assert_eq!(cert.valid_until(), NOW + 100);
        // Long certificate against a shorter charter: the charter wins.
        let mut s2 = signer();
        let mut charter2 = install_clean(&mut s2);
        let signed2 = cert_signed(&mut s2, "alice", &credential_id(), NOW + 1000);
        let view2 = charter2.current(NOW).unwrap();
        let cert2 = view2.passkey_certificate(&signed2, "alice", NOW).unwrap();
        assert_eq!(cert2.valid_until(), NOW + 500);
    }
);

// ---- VerifiedPasskeyCertificate::current clock floor (22:16 < vs ==,>,<=) ----

test!(
    cert_current_rejects_a_regressed_clock_but_accepts_the_floor,
    {
        let mut s = signer();
        let mut charter = install_clean(&mut s);
        let signed = cert_signed(&mut s, "alice", &credential_id(), NOW + 100);
        let view = charter.current(NOW).unwrap();
        let cert = view.passkey_certificate(&signed, "alice", NOW).unwrap();
        assert_eq!(
            cert.current(NOW - 1).map(|_| ()).unwrap_err(),
            Error::ClockRegression
        );
        cert.current(NOW).unwrap();
        cert.current(NOW + 1).unwrap();
    }
);

// ---- VerifiedPasskeyCertificate::current expiry (26:16 >= vs <) ----

test!(
    cert_current_rejects_expiry_at_the_deadline_but_accepts_before,
    {
        let mut s = signer();
        let mut charter = install_clean(&mut s);
        let signed = cert_signed(&mut s, "alice", &credential_id(), NOW + 100);
        let view = charter.current(NOW).unwrap();
        let cert = view.passkey_certificate(&signed, "alice", NOW).unwrap();
        assert_eq!(cert.valid_until(), NOW + 100);
        cert.current(NOW + 99).unwrap();
        assert_eq!(
            cert.current(NOW + 100).map(|_| ()).unwrap_err(),
            Error::Expired
        );
    }
);

// ---- VerifiedPasskeyCertificate::current revocation disjunction (33:13 || vs &&)
// ---- plus the whole-body Ok(()) mutant (22:9) ----

test!(
    cert_current_refuses_a_revoked_member_even_with_a_clean_credential,
    {
        let mut s = signer();
        let revocations = json!({"members":["alice"],"devices":[],"passkeys":[]});
        let v = feed_with(&mut s, 10, 1, revocations);
        let mut charter = Charter::new(configuration(&s)).unwrap();
        charter
            .install(&serde_json::to_vec(&v).unwrap(), NOW)
            .unwrap();
        let signed = cert_signed(&mut s, "alice", &credential_id(), NOW + 100);
        let view = charter.current(NOW).unwrap();
        // Real code refuses at construction; a whole-body Ok(()) or a narrowed
        // && gate would hand out a live certificate, which the follow-up refuses.
        match view.passkey_certificate(&signed, "alice", NOW) {
            Err(Error::Unauthenticated) => {}
            Ok(cert) => assert_eq!(
                cert.current(NOW).map(|_| ()).unwrap_err(),
                Error::Unauthenticated
            ),
            Err(other) => panic!("unexpected construction error: {other:?}"),
        }
    }
);

test!(
    cert_current_refuses_a_revoked_credential_even_with_a_clean_member,
    {
        let mut s = signer();
        let revocations = json!({"members":[],"devices":[],"passkeys":[credential_id()]});
        let v = feed_with(&mut s, 10, 1, revocations);
        let mut charter = Charter::new(configuration(&s)).unwrap();
        charter
            .install(&serde_json::to_vec(&v).unwrap(), NOW)
            .unwrap();
        let signed = cert_signed(&mut s, "alice", &credential_id(), NOW + 100);
        let view = charter.current(NOW).unwrap();
        match view.passkey_certificate(&signed, "alice", NOW) {
            Err(Error::Unauthenticated) => {}
            Ok(cert) => assert_eq!(
                cert.current(NOW).map(|_| ()).unwrap_err(),
                Error::Unauthenticated
            ),
            Err(other) => panic!("unexpected construction error: {other:?}"),
        }
    }
);

// ---- VerifiedPasskeyCertificate::credential_id (44:9 -> empty / [0] / [1]) ----

test!(cert_credential_id_returns_the_exact_registered_bytes, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let signed = cert_signed(&mut s, "alice", &credential_id(), NOW + 100);
    let view = charter.current(NOW).unwrap();
    let cert = view.passkey_certificate(&signed, "alice", NOW).unwrap();
    assert_eq!(cert.credential_id(NOW).unwrap(), credential_id().as_slice());
    assert!(!cert.credential_id(NOW).unwrap().is_empty());
    assert_ne!(cert.credential_id(NOW).unwrap(), [0u8; 1].as_slice());
    assert_ne!(cert.credential_id(NOW).unwrap(), [1u8; 1].as_slice());
});

// ---- VerifiedPasskeyBinding getters (96/100/104/108) ----

test!(binding_member_returns_the_exact_pseudonym, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let signed = valid_binding(&mut s, "alice", &[8u8; 32], NOW + 400);
    let view = charter.current(NOW).unwrap();
    let binding = view.passkey_binding(&signed, "alice", NOW).unwrap();
    assert_eq!(binding.member(), "alice");
    assert!(!binding.member().is_empty());
    assert_ne!(binding.member(), "xyzzy");
});

test!(binding_policy_epoch_returns_the_charter_epoch, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let signed = valid_binding(&mut s, "alice", &[8u8; 32], NOW + 400);
    let view = charter.current(NOW).unwrap();
    let binding = view.passkey_binding(&signed, "alice", NOW).unwrap();
    assert_eq!(view.policy_epoch(), 1);
    assert_eq!(binding.policy_epoch(), 1);
    assert_ne!(binding.policy_epoch(), 0);
});

test!(binding_valid_until_is_the_retained_deadline, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let signed = valid_binding(&mut s, "alice", &[8u8; 32], NOW + 400);
    let view = charter.current(NOW).unwrap();
    let binding = view.passkey_binding(&signed, "alice", NOW).unwrap();
    assert_eq!(binding.valid_until(), NOW + 400);
    assert_ne!(binding.valid_until(), 0);
    assert_ne!(binding.valid_until(), 1);
});

test!(binding_signed_bytes_are_the_exact_original_cose, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let signed = valid_binding(&mut s, "alice", &[8u8; 32], NOW + 400);
    let view = charter.current(NOW).unwrap();
    let binding = view.passkey_binding(&signed, "alice", NOW).unwrap();
    assert_eq!(binding.signed_bytes(), signed.as_slice());
    assert!(!binding.signed_bytes().is_empty());
    assert_ne!(binding.signed_bytes(), [0u8; 1].as_slice());
    assert_ne!(binding.signed_bytes(), [1u8; 1].as_slice());
});

// ---- VerifiedPasskeyBinding::credential clock floor (112:16) and expiry (115:16) ----

test!(
    binding_credential_rejects_a_regressed_clock_but_accepts_issuance,
    {
        let mut s = signer();
        let mut charter = install_clean(&mut s);
        let signed = valid_binding(&mut s, "alice", &[8u8; 32], NOW + 400);
        let view = charter.current(NOW).unwrap();
        let binding = view.passkey_binding(&signed, "alice", NOW).unwrap();
        assert_eq!(
            binding.credential(NOW - 1).map(|_| ()).unwrap_err(),
            Error::ClockRegression
        );
        binding.credential(NOW).unwrap();
        binding.credential(NOW + 1).unwrap();
    }
);

test!(
    binding_credential_rejects_expiry_at_the_deadline_but_accepts_before,
    {
        let mut s = signer();
        let mut charter = install_clean(&mut s);
        let signed = valid_binding(&mut s, "alice", &[8u8; 32], NOW + 400);
        let view = charter.current(NOW).unwrap();
        let binding = view.passkey_binding(&signed, "alice", NOW).unwrap();
        assert_eq!(binding.valid_until(), NOW + 400);
        binding.credential(NOW + 399).unwrap();
        assert_eq!(
            binding.credential(NOW + 400).map(|_| ()).unwrap_err(),
            Error::Expired
        );
    }
);

// ---- Exact-boundary acceptance pins (kill the `>`-to-`>=` inner mutants:
// ---- a boundary value must still pass, while the over-boundary tests above
// ---- refuse) ----

test!(binding_lengths_at_exact_bounds_are_accepted, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let view = charter.current(NOW).unwrap();
    // member 256, spki 8192, rp_id 253, 32 origins of 2048 bytes each.
    let member = "x".repeat(256);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["spki"] = json!(vec![9u8; 8192]);
    cred["rp_id"] = json!("x".repeat(253));
    cred["origins"] = json!(vec!["x".repeat(2048); 32]);
    let signed = binding_signed(&mut s, binding_body(&member, 1, cred), NOW + 400);
    let binding = view.passkey_binding(&signed, &member, NOW).unwrap();
    assert_eq!(binding.member(), member);
    binding.credential(NOW).unwrap();
});

// ---- VerifiedCharter::passkey_binding construction clock floor (193:16) ----

test!(
    binding_construction_rejects_a_regressed_clock_but_accepts_issuance,
    {
        // issued_at = max(envelope NOW-100, settings NOW-100, revocations NOW).
        let mut s = signer_at(NOW - 101);
        let signed = sign_at(
            &mut s,
            CoseKind::Credential,
            binding_body("alice", 1, credential_descriptor(&[8u8; 32])),
            NOW - 100,
            NOW + 400,
        );
        let v = feed_revocations_newer(&mut s, 10, 1, clean_revocations());
        let mut charter = Charter::new(configuration(&s)).unwrap();
        charter
            .install(&serde_json::to_vec(&v).unwrap(), NOW)
            .unwrap();
        let view = charter.current(NOW).unwrap();
        assert_eq!(
            view.passkey_binding(&signed, "alice", NOW - 50)
                .map(|_| ())
                .unwrap_err(),
            Error::ClockRegression
        );
        view.passkey_binding(&signed, "alice", NOW).unwrap();
    }
);

// ---- VerifiedCharter::passkey_binding revocation disjunction (183:13) ----

test!(
    binding_construction_refuses_a_revoked_member_even_with_a_clean_credential,
    {
        let mut s = signer();
        let revocations = json!({"members":["alice"],"devices":[],"passkeys":[]});
        let v = feed_with(&mut s, 10, 1, revocations);
        let mut charter = Charter::new(configuration(&s)).unwrap();
        charter
            .install(&serde_json::to_vec(&v).unwrap(), NOW)
            .unwrap();
        let signed = valid_binding(&mut s, "alice", &[8u8; 32], NOW + 400);
        let view = charter.current(NOW).unwrap();
        assert_eq!(
            view.passkey_binding(&signed, "alice", NOW)
                .map(|_| ())
                .unwrap_err(),
            Error::Unauthenticated
        );
    }
);

test!(
    binding_construction_refuses_a_revoked_credential_even_with_a_clean_member,
    {
        let mut s = signer();
        let revocations = json!({"members":[],"devices":[],"passkeys":[vec![8u8; 32]]});
        let v = feed_with(&mut s, 10, 1, revocations);
        let mut charter = Charter::new(configuration(&s)).unwrap();
        charter
            .install(&serde_json::to_vec(&v).unwrap(), NOW)
            .unwrap();
        let signed = valid_binding(&mut s, "alice", &[8u8; 32], NOW + 400);
        let view = charter.current(NOW).unwrap();
        assert_eq!(
            view.passkey_binding(&signed, "alice", NOW)
                .map(|_| ())
                .unwrap_err(),
            Error::Unauthenticated
        );
    }
);

// ---- VerifiedCharter::passkey_binding size gate (152:25 > vs ==,<,>=) ----

test!(binding_oversized_cose_is_a_limit, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let view = charter.current(NOW).unwrap();
    let oversized = vec![0u8; MAX_COSE_BYTES + 1];
    assert_eq!(
        view.passkey_binding(&oversized, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Limit
    );
});

test!(binding_at_exactly_max_cose_is_not_a_limit, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let view = charter.current(NOW).unwrap();
    let exact = vec![0u8; MAX_COSE_BYTES];
    assert_ne!(
        view.passkey_binding(&exact, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Limit
    );
});

test!(binding_small_garbage_is_not_a_limit, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let view = charter.current(NOW).unwrap();
    assert_ne!(
        view.passkey_binding(&[0u8; 32], "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Limit
    );
});

// ---- VerifiedCharter::passkey_binding scope disjunction (162..174 || vs &&) ----
// Each test violates exactly one side of the mutated adjacent pair, so the
// ||-to-&& mutant would wrongly accept while the real code refuses with Scope.

test!(binding_wrong_purpose_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut body = binding_body("alice", 1, credential_descriptor(&[8u8; 32]));
    body["purpose"] = json!("wrong-purpose");
    let signed = binding_signed(&mut s, body, NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_wrong_outer_community_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut body = binding_body("alice", 1, credential_descriptor(&[8u8; 32]));
    body["community"] = json!("beta");
    let signed = binding_signed(&mut s, body, NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_wrong_descriptor_community_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["community"] = json!("beta");
    let signed = binding_signed(&mut s, binding_body("alice", 1, cred), NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_wrong_member_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let signed = valid_binding(&mut s, "bob", &[8u8; 32], NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_empty_member_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let signed = valid_binding(&mut s, "", &[8u8; 32], NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_overlong_member_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let long = "x".repeat(257);
    let signed = valid_binding(&mut s, &long, &[8u8; 32], NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, &long, NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_wrong_policy_epoch_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let signed = binding_signed(
        &mut s,
        binding_body("alice", 2, credential_descriptor(&[8u8; 32])),
        NOW + 400,
    );
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_empty_spki_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["spki"] = json!(Vec::<u8>::new());
    let signed = binding_signed(&mut s, binding_body("alice", 1, cred), NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_overlong_spki_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["spki"] = json!(vec![9u8; 8193]);
    let signed = binding_signed(&mut s, binding_body("alice", 1, cred), NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_empty_rp_id_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["rp_id"] = json!("");
    let signed = binding_signed(&mut s, binding_body("alice", 1, cred), NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_overlong_rp_id_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["rp_id"] = json!("x".repeat(254));
    let signed = binding_signed(&mut s, binding_body("alice", 1, cred), NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_empty_origins_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["origins"] = json!(Vec::<String>::new());
    let signed = binding_signed(&mut s, binding_body("alice", 1, cred), NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_too_many_origins_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["origins"] = json!(vec!["https://alpha.example".to_string(); 33]);
    let signed = binding_signed(&mut s, binding_body("alice", 1, cred), NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});

test!(binding_overlong_origin_is_scope, {
    let mut s = signer();
    let mut charter = install_clean(&mut s);
    let mut cred = credential_descriptor(&[8u8; 32]);
    cred["origins"] = json!(["x".repeat(2049)]);
    let signed = binding_signed(&mut s, binding_body("alice", 1, cred), NOW + 400);
    let view = charter.current(NOW).unwrap();
    assert_eq!(
        view.passkey_binding(&signed, "alice", NOW)
            .map(|_| ())
            .unwrap_err(),
        Error::Scope
    );
});
