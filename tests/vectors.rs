use cblv::keys::KeySource;
use cchr::{Changes, Charter, Configuration, Error, Kind, State};
use csgn::{Kind as CoseKind, SecretKey, Signer};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;
const ORIGIN: &str = "https://alpha.example.test";

fn with_balance(signer: &mut Signer, revision: u64, balance_revision: u64) -> Value {
    let mut value = feed(signer, revision, 1);
    // Routing-only signed fixture. It is intentionally incomplete accounting
    // material; the real captured owner document below is never rewritten.
    let material = json!({"purpose":"cblc.public-verifier.v2","community":"alpha",
        "revision":balance_revision,"policyEpoch":1,"manifestSha256":vec![1_u8;32]});
    value["balance"] = json!(sign(signer, CoseKind::SettingsSnapshot, material));
    replace(
        signer,
        &mut value,
        "manifest",
        CoseKind::SettingsSnapshot,
        |v| v["balance_revision"] = json!(balance_revision),
    );
    value
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn balance_is_atomic_signed_routing_with_independent_floors() {
    let mut signer = signer();
    let first = with_balance(&mut signer, 10, 2);
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(
        charter
            .install(&bytes(&first), NOW)
            .unwrap()
            .balance()
            .unwrap()
            .signed_bytes(),
        serde_json::from_value::<Vec<u8>>(first["balance"].clone()).unwrap()
    );
    charter.install(&bytes(&first), NOW).unwrap();
    for case in 0..8 {
        let mut bad = with_balance(&mut signer, 11, 2);
        let expected = match case {
            0 => {
                bad.as_object_mut().unwrap().remove("balance");
                Error::Incoherent
            }
            1 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "manifest",
                    CoseKind::SettingsSnapshot,
                    |v| {
                        v.as_object_mut().unwrap().remove("balance_revision");
                    },
                );
                Error::Incoherent
            }
            2 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "manifest",
                    CoseKind::SettingsSnapshot,
                    |v| v["balance_revision"] = json!(12),
                );
                Error::Incoherent
            }
            3 => {
                bad = feed(&mut signer, 11, 1);
                Error::Rollback
            }
            4 => {
                bad = with_balance(&mut signer, 11, 1);
                Error::Rollback
            }
            5 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "balance",
                    CoseKind::SettingsSnapshot,
                    |v| v["manifestSha256"] = json!(vec![7; 32]),
                );
                Error::Equivocation
            }
            6 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "balance",
                    CoseKind::SettingsSnapshot,
                    |v| v["purpose"] = json!("settings"),
                );
                Error::Incoherent
            }
            _ => {
                bad["balance"][0] = json!(0);
                Error::Signature
            }
        };
        assert_eq!(charter.install(&bytes(&bad), NOW).unwrap_err(), expected);
        assert_eq!(charter.current(NOW).unwrap().revision(), 10);
    }
    let next = with_balance(&mut signer, 11, 3);
    assert_eq!(
        charter
            .install(&bytes(&next), NOW)
            .unwrap()
            .balance()
            .unwrap()
            .revision(),
        3
    );
    assert_eq!(charter.current(NOW + 500).unwrap_err(), Error::Expired);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn current_owner_capture_keeps_original_signature_and_legacy_capture_refuses() {
    let current: Value =
        serde_json::from_slice(include_bytes!("fixtures/balance-publication-v2.json")).unwrap();
    let ring = csgn::KeyRing::from_cbor(
        &serde_json::from_value::<Vec<u8>>(current["configuredFixtureRing"].clone()).unwrap(),
    )
    .unwrap();
    let original: Vec<u8> = serde_json::from_value(current["signed"].clone()).unwrap();
    let view = cbcn::balance::Balance::verify(&ring, &original, 1, 1, 200).unwrap();
    assert_eq!(view.signed_bytes(), original);
    let payload: Value = serde_json::from_slice(view.payload()).unwrap();
    assert_eq!(payload, current["material"]);
    assert_eq!(payload["purpose"], "cblc.public-verifier.v2");
    assert_eq!(payload["admissionPolicyDigest"], json!(vec![3_u8; 32]));
    assert_eq!(view.valid_until(), 900);
    let mut damaged = original.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        cbcn::balance::Balance::verify(&ring, &damaged, 1, 1, 200),
        Err(cbcn::Error::Signature)
    ));
    let legacy: Value =
        serde_json::from_slice(include_bytes!("fixtures/balance-material.json")).unwrap();
    let ring = csgn::KeyRing::from_cbor(
        &serde_json::from_value::<Vec<u8>>(legacy["configuredFixtureRing"].clone()).unwrap(),
    )
    .unwrap();
    let signed: Vec<u8> = serde_json::from_value(legacy["signed"].clone()).unwrap();
    assert!(matches!(
        cbcn::balance::Balance::verify(&ring, &signed, 1, 1, 200),
        Err(cbcn::Error::Incoherent)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn balance_deadline_and_duplicate_fields_apply_to_the_whole_charter() {
    let mut signer = signer();
    let mut value = with_balance(&mut signer, 10, 1);
    let bytes_value: Vec<u8> = serde_json::from_value(value["balance"].clone()).unwrap();
    let payload = signer
        .key_ring()
        .verify(&bytes_value, CoseKind::SettingsSnapshot, NOW)
        .unwrap()
        .payload()
        .to_vec();
    value["balance"] = json!(
        signer
            .sign(CoseKind::SettingsSnapshot, &payload, NOW, NOW + 10)
            .unwrap()
    );
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(
        charter.install(&bytes(&value), NOW).unwrap().valid_until(),
        NOW + 10
    );
    assert_eq!(charter.current(NOW + 10).unwrap_err(), Error::Expired);
    let duplicate = String::from_utf8(payload).unwrap().replace(
        "\"purpose\":",
        "\"purpose\":\"cblc.public-verifier.v1\",\"purpose\":",
    );
    value["balance"] = json!(
        signer
            .sign(
                CoseKind::SettingsSnapshot,
                duplicate.as_bytes(),
                NOW,
                NOW + 500
            )
            .unwrap()
    );
    assert!(charter.install(&bytes(&value), NOW + 10).is_err());
}

fn signer() -> Signer {
    Signer::new("alpha", SecretKey::from_seed(&mut [71; 32]), NOW - 1, 1000).unwrap()
}
fn sign(s: &mut Signer, kind: CoseKind, payload: Value) -> Vec<u8> {
    s.sign(kind, &serde_json::to_vec(&payload).unwrap(), NOW, NOW + 500)
        .unwrap()
}
fn feed(s: &mut Signer, revision: u64, epoch: u64) -> Value {
    let schema = json!({"community":"alpha","version":1,"public":[],"private":[]});
    let manifest = json!({"purpose":"cplc.trust.v1","community":"alpha","revision":revision,
        "policy_epoch":epoch,"key_ring":s.key_ring().to_cbor(),"schema_version":1});
    let mut v = json!({"revision":revision,"policy_epoch":epoch,"key_ring":s.key_ring().to_cbor(),
        "manifest":sign(s,CoseKind::SettingsSnapshot,manifest)});
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
        (
            "revocations",
            CoseKind::RevocationListSnapshot,
            json!({"members":["revoked"],"devices":vec![[22u8;32]]}),
        ),
    ] {
        v[name] = json!(sign(
            s,
            kind,
            json!({"community":"alpha","revision":revision,"policy_epoch":epoch,"content":content})
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
fn new_charter(origin: &str, community: &str) -> cchr::Result<Charter> {
    let mut config = configuration(&signer());
    config.origin = origin.into();
    config.community = community.into();
    Charter::new(config)
}
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn replace(
    s: &mut Signer,
    v: &mut Value,
    name: &str,
    kind: CoseKind,
    edit: impl FnOnce(&mut Value),
) {
    let cose: Vec<u8> = serde_json::from_value(v[name].clone()).unwrap();
    let verified = s.key_ring().verify(&cose, kind, NOW).unwrap();
    let mut payload: Value = serde_json::from_slice(verified.payload()).unwrap();
    edit(&mut payload);
    v[name] = json!(sign(s, kind, payload));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn coherent_material_is_immutable_and_expiry_cannot_reverse() {
    let mut s = signer();
    let v = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(c.state(NOW), State::Unbootstrapped);
    let current = c.install(&bytes(&v), NOW).unwrap();
    assert_eq!(current.revision(), 10);
    assert_eq!(current.fingerprint(), None);
    let settings = current.settings(NOW).unwrap();
    assert_eq!(settings.community, "alpha");
    assert_eq!(
        settings.revision,
        current.publication(Kind::Settings).revision()
    );
    assert_eq!(settings.policy_epoch, current.policy_epoch());
    assert_eq!(settings.issued, NOW as i64);
    assert_eq!(
        serde_json::to_value(&settings.content).unwrap(),
        *current.publication(Kind::Settings).content()
    );
    assert!(matches!(
        current.settings(NOW - 1),
        Err(Error::ClockRegression)
    ));
    assert!(matches!(
        current.settings(current.valid_until()),
        Err(Error::Expired)
    ));
    assert!(current.revocations().member_revoked("revoked"));
    assert!(current.revocations().device_revoked(&[22; 32]));
    let policy = current.admission_policy("admission", NOW, 86400).unwrap();
    assert_eq!(
        policy.policy.settings,
        current.publication(Kind::Settings).signed_bytes()
    );
    assert_eq!(
        policy.revocations,
        current.publication(Kind::Revocations).signed_bytes()
    );
    assert!(
        !cgrd::check_published(
            &cgrd::Bundle {
                payload: vec![],
                signature: vec![]
            },
            &policy,
            current.publication(Kind::Schema).signed_bytes(),
        )
        .is_admitted()
    );
    assert!(matches!(
        current.admission_policy("admission", current.valid_until(), 86400),
        Err(Error::Expired)
    ));
    assert_eq!(
        current.publication(Kind::Settings).signed_bytes(),
        serde_json::from_value::<Vec<u8>>(v["settings"].clone()).unwrap()
    );
    assert_eq!(format!("{current:?}"), "VerifiedCharter { .. }");
    assert_eq!(c.changes_since(10, NOW).unwrap(), Changes::Unchanged);
    assert!(matches!(
        c.changes_since(0, NOW).unwrap(),
        Changes::Replace { revision: 10, .. }
    ));
    assert_eq!(c.state(NOW + 500), State::Unavailable);
    assert_eq!(c.current(NOW).unwrap_err(), Error::ClockRegression);
    assert_eq!(c.current(NOW + 500).unwrap_err(), Error::Expired);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn invalid_candidates_never_partially_replace_the_installed_set() {
    let mut s = signer();
    let old = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&old), NOW).unwrap();
    for i in 0..10 {
        let mut candidate = feed(&mut s, 11, 2);
        match i {
            0 => {
                candidate.as_object_mut().unwrap().remove("revocations");
            }
            1 => {
                candidate["revocations"] = candidate["settings"].clone();
            }
            2 => replace(
                &mut s,
                &mut candidate,
                "schema",
                CoseKind::SchemaSnapshot,
                |p| p["policy_epoch"] = json!(1),
            ),
            3 => replace(
                &mut s,
                &mut candidate,
                "manifest",
                CoseKind::SettingsSnapshot,
                |p| p["purpose"] = json!("other"),
            ),
            4 => replace(
                &mut s,
                &mut candidate,
                "communities",
                CoseKind::CommunitiesSnapshot,
                |p| p["community"] = json!("beta"),
            ),
            5 => replace(
                &mut s,
                &mut candidate,
                "schema_versions",
                CoseKind::SchemaSnapshot,
                |p| p["content"]["current"] = json!(2),
            ),
            6 => replace(
                &mut s,
                &mut candidate,
                "schema_versions",
                CoseKind::SchemaSnapshot,
                |p| p["content"]["versions"] = json!([]),
            ),
            7 => replace(
                &mut s,
                &mut candidate,
                "settings",
                CoseKind::SettingsSnapshot,
                |p| p["revision"] = json!(9),
            ),
            8 => {
                candidate["manifest"][10] = json!(255);
            }
            _ => replace(
                &mut s,
                &mut candidate,
                "schema",
                CoseKind::SchemaSnapshot,
                |p| p["content"]["version"] = json!(2),
            ),
        }
        assert!(c.install(&bytes(&candidate), NOW).is_err(), "case {i}");
        assert_eq!(c.current(NOW).unwrap().revision(), 10);
    }
    let next = feed(&mut s, 11, 2);
    c.install(&bytes(&next), NOW).unwrap();
    assert_eq!(c.install(&bytes(&old), NOW).unwrap_err(), Error::Rollback);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn same_revision_requires_exact_original_signed_bytes() {
    let mut s = signer();
    let mut v = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&v), NOW).unwrap();
    c.install(&bytes(&v), NOW).unwrap();
    replace(
        &mut s,
        &mut v,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| p["content"] = json!({"changed":true}),
    );
    assert_eq!(c.install(&bytes(&v), NOW).unwrap_err(), Error::Equivocation);
    let mut v = feed(&mut s, 11, 1);
    replace(
        &mut s,
        &mut v,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| {
            p["revision"] = json!(10);
            p["content"] = json!({"changed":true});
        },
    );
    assert_eq!(c.install(&bytes(&v), NOW).unwrap_err(), Error::Equivocation);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn configured_root_and_signed_rotation_are_explicit() {
    let mut s = signer();
    let old = feed(&mut s, 10, 1);
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    charter.install(&bytes(&old), NOW).unwrap();
    let proof = s
        .rotate_with_proof(SecretKey::from_seed(&mut [72; 32]), NOW, NOW + 500)
        .unwrap();
    let mut new = feed(&mut s, 11, 1);
    assert_eq!(
        charter.install(&bytes(&new), NOW).unwrap_err(),
        Error::Unauthenticated
    );
    new["key_transitions"] = json!([{"revision":s.ring_revision(),"proof":proof}]);
    charter.install(&bytes(&new), NOW).unwrap();
    // Previously installed proofs remain harmless, and cannot lower the floor.
    charter.install(&bytes(&new), NOW).unwrap();
    let old_schema: Vec<u8> = serde_json::from_value(old["schema"].clone()).unwrap();
    assert!(
        charter
            .current(NOW)
            .unwrap()
            .key_ring()
            .verify(&old_schema, CoseKind::SchemaSnapshot, NOW)
            .is_ok()
    );
    assert!(charter.install(&bytes(&old), NOW).is_err());
    let mut floor = configuration(&s);
    floor.minimum_revision = 12;
    floor.ring_revision = s.ring_revision();
    let mut restarted = Charter::new(floor).unwrap();
    assert_eq!(
        restarted.install(&bytes(&new), NOW).unwrap_err(),
        Error::Rollback
    );
    let mut first = new_charter(ORIGIN, "alpha").unwrap();
    let mut forged = new.clone();
    forged.as_object_mut().unwrap().remove("key_transitions");
    assert_eq!(
        first.install(&bytes(&forged), NOW).unwrap_err(),
        Error::Unauthenticated
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn duplicate_fields_unknown_fields_trailing_bytes_and_limits_fail() {
    let mut s = signer();
    let mut v = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    let original = bytes(&v);
    let mut duplicate = original.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"revision\":10}");
    assert_eq!(c.install(&duplicate, NOW).unwrap_err(), Error::Malformed);
    let mut trailing = original;
    trailing.push(b'x');
    assert_eq!(c.install(&trailing, NOW).unwrap_err(), Error::Malformed);
    let payload =
        br#"{"community":"alpha","revision":10,"policy_epoch":1,"content":{"x":1,"x":2}}"#;
    v["settings"] = json!(
        s.sign(CoseKind::SettingsSnapshot, payload, NOW, NOW + 500)
            .unwrap()
    );
    assert_eq!(c.install(&bytes(&v), NOW).unwrap_err(), Error::Malformed);
    let huge = vec![b' '; cchr::MAX_FEED_BYTES + 1];
    assert_eq!(c.install(&huge, NOW).unwrap_err(), Error::Limit);
    v["unknown"] = json!(true);
    assert_eq!(c.install(&bytes(&v), NOW).unwrap_err(), Error::Malformed);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bounded_two_hundred_consumer_load_and_scope_isolation() {
    let mut s = signer();
    let v = feed(&mut s, 10, 1);
    let wire = bytes(&v);
    let mut consumers: Vec<_> = (0..200)
        .map(|_| new_charter(ORIGIN, "alpha").unwrap())
        .collect();
    for consumer in &mut consumers {
        consumer.install(&wire, NOW).unwrap();
    }
    assert!(matches!(
        new_charter(ORIGIN, "beta"),
        Err(Error::Unauthenticated)
    ));
    let next = bytes(&feed(&mut s, 11, 2));
    for consumer in &mut consumers {
        consumer.install(&next, NOW).unwrap();
        assert_eq!(consumer.current(NOW).unwrap().policy_epoch(), 2);
        assert_eq!(consumer.install(&wire, NOW).unwrap_err(), Error::Rollback);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn higher_feed_revision_cannot_rewrite_a_retained_schema() {
    let mut s = signer();
    let old = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&old), NOW).unwrap();
    let mut candidate = feed(&mut s, 11, 2);
    let schema = json!({"community":"alpha","version":1,"public":[{"id":"changed","label":"Changed","kind":{"type":"yes_no"},"required":false,"filterable":false,"change_preset":"free","no_contact_details":false}],"private":[]});
    replace(
        &mut s,
        &mut candidate,
        "schema",
        CoseKind::SchemaSnapshot,
        |p| p["content"] = schema.clone(),
    );
    replace(
        &mut s,
        &mut candidate,
        "schema_versions",
        CoseKind::SchemaSnapshot,
        |p| p["content"]["versions"][0]["schema"] = schema,
    );
    assert_eq!(
        c.install(&bytes(&candidate), NOW).unwrap_err(),
        Error::Equivocation
    );
    assert_eq!(c.current(NOW).unwrap().revision(), 10);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn one_expired_snapshot_refuses_the_entire_candidate_at_its_deadline() {
    let mut s = signer();
    let old = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&old), NOW).unwrap();
    let mut candidate = feed(&mut s, 11, 2);
    let cose: Vec<u8> = serde_json::from_value(candidate["revocations"].clone()).unwrap();
    let payload = s
        .key_ring()
        .verify(&cose, CoseKind::RevocationListSnapshot, NOW)
        .unwrap()
        .payload()
        .to_vec();
    candidate["revocations"] = json!(
        s.sign(CoseKind::RevocationListSnapshot, &payload, NOW, NOW + 50)
            .unwrap()
    );
    let mut fresh = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(
        fresh
            .install(&bytes(&candidate), NOW + 49)
            .unwrap()
            .valid_until(),
        NOW + 50
    );
    assert_eq!(
        c.install(&bytes(&candidate), NOW + 50).unwrap_err(),
        Error::Signature
    );
    assert_eq!(c.current(NOW + 50).unwrap().revision(), 10);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn configured_origin_and_readiness_reject_invalid_boundaries() {
    let configured = new_charter("https://ALPHA.example.test:443/", "alpha").unwrap();
    assert_eq!(configured.origin(), ORIGIN);
    for case in 0..3 {
        let mut config = configuration(&signer());
        match case {
            0 => config.community = "beta".into(),
            1 => config.minimum_revision = 0,
            _ => config.key_ring = b"broken".to_vec(),
        }
        assert!(matches!(Charter::new(config), Err(Error::Unauthenticated)));
    }
    for origin in [
        "invalid",
        "http://alpha.example.test",
        "https://u:p@alpha.example.test",
        "https://alpha.example.test/path",
        "https://alpha.example.test?query",
        "https://:secret@alpha.example.test",
        "https://alpha.example.test/#fragment",
    ] {
        assert!(new_charter(origin, "alpha").is_err());
    }
    for community in [String::new(), "x".repeat(257), "a\0b".into()] {
        assert!(new_charter(ORIGIN, &community).is_err());
    }
    let mut s = signer();
    let feed = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(c.current(NOW).unwrap_err(), Error::Unavailable);
    assert_eq!(c.state(NOW - 1), State::Unavailable);
    let mut early = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(
        early.install(&bytes(&feed), NOW - 1).unwrap_err(),
        Error::Signature
    );
    let view = c.install(&bytes(&feed), NOW).unwrap();
    assert_eq!(view.community(), "alpha");
    assert_eq!(view.schema().version, 1);
    assert_eq!(view.schema_history().len(), 1);
    assert_eq!(view.publication(Kind::Settings).revision(), 10);
    assert!(view.publication(Kind::Settings).content().is_object());
    assert_eq!(
        view.manifest_bytes(),
        serde_json::from_value::<Vec<u8>>(feed["manifest"].clone()).unwrap()
    );
    assert_eq!(c.state(NOW), State::Current);
    assert_eq!(c.changes_since(11, NOW).unwrap_err(), Error::Rollback);
    assert_eq!(Error::Unauthenticated.to_string(), "Unauthenticated");
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn every_manifest_binding_and_snapshot_shape_is_enforced() {
    let mut s = signer();
    for (field, value) in [
        ("community", json!("beta")),
        ("revision", json!(11)),
        ("policy_epoch", json!(2)),
        ("key_ring", json!([])),
        ("schema_version", json!(0)),
    ] {
        let mut candidate = feed(&mut s, 10, 1);
        replace(
            &mut s,
            &mut candidate,
            "manifest",
            CoseKind::SettingsSnapshot,
            |p| p[field] = value,
        );
        assert!(
            new_charter(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), NOW)
                .is_err()
        );
    }
    for (revision, epoch) in [
        (0, 1),
        (i64::MAX as u64 + 1, 1),
        (10, 0),
        (10, i64::MAX as u64 + 1),
    ] {
        let candidate = feed(&mut s, revision, epoch);
        assert_eq!(
            new_charter(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), NOW)
                .unwrap_err(),
            Error::Incoherent
        );
    }
    for revision in [0, 11] {
        let mut candidate = feed(&mut s, 10, 1);
        replace(
            &mut s,
            &mut candidate,
            "settings",
            CoseKind::SettingsSnapshot,
            |p| p["revision"] = json!(revision),
        );
        assert_eq!(
            new_charter(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), NOW)
                .unwrap_err(),
            Error::Incoherent
        );
    }
    for (name, kind, content) in [
        ("settings", CoseKind::SettingsSnapshot, json!([])),
        ("schema", CoseKind::SchemaSnapshot, json!(null)),
        ("schema_versions", CoseKind::SchemaSnapshot, json!(null)),
        ("communities", CoseKind::CommunitiesSnapshot, json!(null)),
        ("revocations", CoseKind::RevocationListSnapshot, json!(null)),
        ("communities", CoseKind::CommunitiesSnapshot, json!([""])),
        (
            "communities",
            CoseKind::CommunitiesSnapshot,
            json!(["x".repeat(257)]),
        ),
        (
            "communities",
            CoseKind::CommunitiesSnapshot,
            json!(["same", "same"]),
        ),
        (
            "communities",
            CoseKind::CommunitiesSnapshot,
            json!((0..257).map(|n| format!("c{n}")).collect::<Vec<_>>()),
        ),
    ] {
        let mut candidate = feed(&mut s, 10, 1);
        replace(&mut s, &mut candidate, name, kind, |p| {
            p["content"] = content
        });
        assert!(
            new_charter(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), NOW)
                .is_err()
        );
    }
    let mut huge = feed(&mut s, 10, 1);
    huge["settings"] = json!(vec![0u8; (1 << 20) + 8193]);
    assert_eq!(
        new_charter(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&huge), NOW)
            .unwrap_err(),
        Error::Limit
    );
    let mut scalar = feed(&mut s, 10, 1);
    replace(
        &mut s,
        &mut scalar,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| {
            p["content"] = json!({"boolean":true,"negative":-1,"fraction":1.5,"null":null});
        },
    );
    assert!(
        new_charter(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&scalar), NOW)
            .is_ok()
    );
}

fn history_feed(s: &mut Signer, revision: u64, epoch: u64) -> Value {
    let mut value = feed(s, revision, epoch);
    let first = json!({"community":"alpha","version":1,"public":[],"private":[]});
    let second = json!({"community":"alpha","version":2,"public":[],"private":[]});
    let changes = cshm::classify_changes(
        &serde_json::from_value(first.clone()).unwrap(),
        &serde_json::from_value(second.clone()).unwrap(),
    )
    .unwrap();
    replace(s, &mut value, "manifest", CoseKind::SettingsSnapshot, |p| {
        p["schema_version"] = json!(2)
    });
    replace(s, &mut value, "schema", CoseKind::SchemaSnapshot, |p| {
        p["content"] = second.clone()
    });
    replace(
        s,
        &mut value,
        "schema_versions",
        CoseKind::SchemaSnapshot,
        |p| {
            p["content"] = json!({"purpose":"cplc.schema-versions.v1","current":2,"versions":[
                {"schema":first,"changes":null}, {"schema":second,"changes":changes}
            ]});
        },
    );
    value
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn history_classification_and_retention_are_verified() {
    let mut s = signer();
    let original = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&original), NOW).unwrap();
    let next = history_feed(&mut s, 11, 2);
    c.install(&bytes(&next), NOW).unwrap();
    assert_eq!(c.current(NOW).unwrap().schema_history().len(), 2);
    for case in 0..13 {
        let mut candidate = history_feed(&mut s, 12, 2);
        replace(
            &mut s,
            &mut candidate,
            "schema_versions",
            CoseKind::SchemaSnapshot,
            |p| {
                let h = &mut p["content"];
                match case {
                    0 => h["purpose"] = json!("foreign"),
                    1 => h["versions"] = json!(vec![h["versions"][0].clone(); 257]),
                    2 => h["versions"][0]["schema"]["community"] = json!("beta"),
                    3 => h["versions"][0]["schema"]["version"] = json!(0),
                    4 => h["versions"][0]["changes"] = h["versions"][1]["changes"].clone(),
                    5 => h["versions"][1]["schema"]["version"] = json!(1),
                    6 => h["versions"][1]["changes"] = json!(null),
                    7 => h["versions"][1]["schema"]["version"] = json!(3),
                    8 => {
                        h["versions"] = json!([h["versions"][1].clone()]);
                        h["versions"][0]["changes"] = json!(null);
                    }
                    9 => h["versions"][0]["schema"]["private"] = json!([{"id":"x"}]),
                    10 => h["versions"][1]["schema"]["community"] = json!("beta"),
                    11 => h["versions"][1]["schema"]["public"] = json!([{"id":"x"}]),
                    _ => h["versions"][0]["schema"]["version"] = json!(3),
                }
            },
        );
        let error = c.install(&bytes(&candidate), NOW).unwrap_err();
        if matches!(case, 5 | 12) {
            assert_eq!(
                error,
                Error::Incoherent,
                "nonincreasing history case {case}"
            );
        }
        assert_eq!(c.current(NOW).unwrap().revision(), 11);
    }
    let rollback = feed(&mut s, 12, 2);
    assert_eq!(
        c.install(&bytes(&rollback), NOW).unwrap_err(),
        Error::Rollback
    );
    let old_epoch = history_feed(&mut s, 12, 1);
    assert_eq!(
        c.install(&bytes(&old_epoch), NOW).unwrap_err(),
        Error::Rollback
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn equal_manifest_revision_cannot_change_any_signed_bytes() {
    let mut s = signer();
    let mut original = feed(&mut s, 10, 1);
    replace(
        &mut s,
        &mut original,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| p["revision"] = json!(9),
    );
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&original), NOW).unwrap();
    let mut candidate = original.clone();
    let cose: Vec<u8> = serde_json::from_value(candidate["manifest"].clone()).unwrap();
    let payload = s
        .key_ring()
        .verify(&cose, CoseKind::SettingsSnapshot, NOW)
        .unwrap()
        .payload()
        .to_vec();
    candidate["manifest"] = json!(
        s.sign(CoseKind::SettingsSnapshot, &payload, NOW, NOW + 499)
            .unwrap()
    );
    assert_eq!(
        c.install(&bytes(&candidate), NOW).unwrap_err(),
        Error::Equivocation
    );
    let mut candidate = original.clone();
    replace(
        &mut s,
        &mut candidate,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| p["revision"] = json!(10),
    );
    assert_eq!(
        c.install(&bytes(&candidate), NOW).unwrap_err(),
        Error::Equivocation
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn schema_scope_and_history_definition_match_exactly() {
    let mut s = signer();
    let mut invalid = feed(&mut s, 10, 1);
    replace(
        &mut s,
        &mut invalid,
        "schema",
        CoseKind::SchemaSnapshot,
        |p| p["content"]["version"] = json!(0),
    );
    assert_eq!(
        new_charter(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&invalid), NOW)
            .unwrap_err(),
        Error::Incoherent
    );
    let mut candidate = feed(&mut s, 10, 1);
    replace(
        &mut s,
        &mut candidate,
        "schema",
        CoseKind::SchemaSnapshot,
        |p| p["content"]["community"] = json!("beta"),
    );
    assert_eq!(
        new_charter(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&candidate), NOW)
            .unwrap_err(),
        Error::Incoherent
    );
    let mut candidate = feed(&mut s, 10, 1);
    replace(
        &mut s,
        &mut candidate,
        "schema_versions",
        CoseKind::SchemaSnapshot,
        |p| {
            p["content"]["versions"][0]["schema"]["public"] = json!([{"id":"bio","label":"About","kind":{"type":"short_text","min_length":0,"max_length":30},"required":false,"filterable":false,"change_preset":"free","no_contact_details":false}]);
        },
    );
    assert_eq!(
        new_charter(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&candidate), NOW)
            .unwrap_err(),
        Error::Incoherent
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn retained_schema_cannot_gain_a_different_predecessor() {
    let mut s = signer();
    let mut original = history_feed(&mut s, 10, 1);
    replace(
        &mut s,
        &mut original,
        "schema_versions",
        CoseKind::SchemaSnapshot,
        |p| {
            let mut current = p["content"]["versions"][1].clone();
            current["changes"] = json!(null);
            p["content"]["versions"] = json!([current]);
        },
    );
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&original), NOW).unwrap();
    let candidate = history_feed(&mut s, 11, 2);
    assert_eq!(
        c.install(&bytes(&candidate), NOW).unwrap_err(),
        Error::Equivocation
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authenticated_rich_feed_requires_real_device_and_profile_evidence() {
    use ed25519_dalek::{Signer as _, SigningKey};
    let device = SigningKey::from_bytes(&[19; 32]);
    for group in ["all_of", "any_of", "k_of_n"] {
        let mut s = signer();
        let mut candidate = feed(&mut s, 10, 1);
        let schema = json!({"community":"alpha","version":1,"public":[{"id":"available","label":"Available","kind":{"type":"yes_no"},"required":true,"filterable":true,"change_preset":"free","no_contact_details":false}],"private":[]});
        replace(
            &mut s,
            &mut candidate,
            "schema",
            CoseKind::SchemaSnapshot,
            |p| p["content"] = schema.clone(),
        );
        replace(
            &mut s,
            &mut candidate,
            "schema_versions",
            CoseKind::SchemaSnapshot,
            |p| p["content"]["versions"][0]["schema"] = schema,
        );
        let requirement = json!({"gate":"voucher","level":"community","provider":"community"});
        let mut action = json!({"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]});
        action[group] = if group == "k_of_n" {
            json!({"k":1,"of":[requirement]})
        } else {
            json!([requirement])
        };
        replace(
            &mut s,
            &mut candidate,
            "settings",
            CoseKind::SettingsSnapshot,
            |p| p["content"] = json!({"action/admission":action,"gate/community/voucher":true,"provider/community/voucher/community":true}),
        );
        let mut charter = new_charter(ORIGIN, "alpha").unwrap();
        let current = charter.install(&bytes(&candidate), NOW).unwrap();
        let policy = current.admission_policy("admission", NOW, 500).unwrap();
        let credential = sign(
            &mut s,
            CoseKind::Credential,
            json!({"purpose":"cplc.community-credential.v2","issuance_action":"admission","community":"alpha","member":"person","handle":"mountain","schema_version":1,"policy_epoch":1,"gates":[{"gate":"voucher","provider":"community","valid_until":NOW+500}],"pins":[],"devices":[device.verifying_key().to_bytes()]}),
        );
        let body = json!({"community":"alpha","member":"person","device":device.verifying_key().to_bytes(),"credential":credential,"profile":{"scope":"public","profile":{"community":"alpha","schema_version":1,"public":{"available":true}}},"openings":[]});
        let present = |body: &Value| {
            let payload = bytes(body);
            cgrd::Bundle {
                signature: device
                    .sign(&cgrd::binding_bytes(&payload))
                    .to_bytes()
                    .to_vec(),
                payload,
            }
        };
        let signed = present(&body);
        let schema = current.publication(Kind::Schema).signed_bytes();
        assert!(cgrd::check_published(&signed, &policy, schema).is_admitted());
        assert_eq!(policy.policy.expected_issuance_action, "admission");
        for field in ["purpose", "issuance_action"] {
            let mut unsigned: Value = serde_json::from_slice(
                s.key_ring()
                    .verify(&credential, CoseKind::Credential, NOW)
                    .unwrap()
                    .payload(),
            )
            .unwrap();
            unsigned.as_object_mut().unwrap().remove(field);
            let unbound = sign(&mut s, CoseKind::Credential, unsigned);
            let mut changed = body.clone();
            changed["credential"] = json!(unbound);
            assert!(!cgrd::check_published(&present(&changed), &policy, schema).is_admitted());
        }
        let mut wrong_action: Value = serde_json::from_slice(
            s.key_ring()
                .verify(&credential, CoseKind::Credential, NOW)
                .unwrap()
                .payload(),
        )
        .unwrap();
        wrong_action["issuance_action"] = json!("another.admission");
        let mut changed = body.clone();
        changed["credential"] = json!(sign(&mut s, CoseKind::Credential, wrong_action));
        assert_eq!(
            cgrd::check_published(&present(&changed), &policy, schema),
            cgrd::Admission::Refused {
                reasons: vec![cgrd::Refusal::Credential]
            }
        );
        let mut broken = signed.clone();
        broken.signature[0] ^= 1;
        assert!(!cgrd::check_published(&broken, &policy, schema).is_admitted());
        let mut absent = body.clone();
        absent["profile"]["profile"]["public"] = json!({});
        assert!(!cgrd::check_published(&present(&absent), &policy, schema).is_admitted());
        let mut wrong = body.clone();
        wrong["device"] = json!(vec![0; 32]);
        assert!(!cgrd::check_published(&present(&wrong), &policy, schema).is_admitted());
        for case in 0..5 {
            let mut restricted = candidate.clone();
            let expected = if case < 2 {
                replace(
                    &mut s,
                    &mut restricted,
                    "revocations",
                    CoseKind::RevocationListSnapshot,
                    |p| {
                        if case == 0 {
                            p["content"]["members"] = json!(["person"]);
                        } else {
                            p["content"]["devices"] = json!([device.verifying_key().to_bytes()]);
                        }
                    },
                );
                Some(cgrd::Refusal::Revoked)
            } else {
                replace(
                    &mut s,
                    &mut restricted,
                    "settings",
                    CoseKind::SettingsSnapshot,
                    |p| {
                        let content = &mut p["content"];
                        match case {
                            2 => {
                                content["action/admission"]["all_of"] = json!([{"gate":"voucher","level":"global","provider":"community"}]);
                                content["gate/global/voucher"] = json!(true);
                                content["provider/global/voucher/community"] = json!(true);
                            }
                            3 => content["action/admission"]["maximum_proof_age"] = json!(300),
                            _ => {
                                content["action/admission"]["k_of_n"] = json!({"k":2,"of":[{"gate":"voucher","level":"community","provider":"community"}]})
                            }
                        }
                    },
                );
                if case == 4 {
                    Some(cgrd::Refusal::Gate)
                } else {
                    None
                }
            };
            let mut restricted_charter = new_charter(ORIGIN, "alpha").unwrap();
            let current = restricted_charter
                .install(&bytes(&restricted), NOW)
                .unwrap();
            let policy = current.admission_policy("admission", NOW, 500).unwrap();
            let result = cgrd::check_published(
                &signed,
                &policy,
                current.publication(Kind::Schema).signed_bytes(),
            );
            match expected {
                Some(expected) => assert_eq!(
                    result,
                    cgrd::Admission::Refused {
                        reasons: vec![expected]
                    },
                    "authenticated refusal case {case}"
                ),
                // A v2 issuer decision binds the exact action/epoch. Its private
                // global proofs and proof times are intentionally not exported.
                None => assert!(result.is_admitted(), "issuer decision case {case}"),
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signed_ring_chains_are_bounded_ordered_and_installed_atomically() {
    let mut s = signer();
    let original = feed(&mut s, 10, 1);
    let proof1 = s
        .rotate_with_proof(SecretKey::from_seed(&mut [72; 32]), NOW, NOW + 500)
        .unwrap();
    let first = json!({"revision":s.ring_revision(),"proof":proof1});
    s.acknowledge_transition(s.ring_revision()).unwrap();
    let proof2 = s
        .rotate_with_proof(SecretKey::from_seed(&mut [73; 32]), NOW, NOW + 500)
        .unwrap();
    let second = json!({"revision":s.ring_revision(),"proof":proof2});
    let mut valid = feed(&mut s, 11, 1);
    valid["key_transitions"] = json!([first, second]);
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    charter.install(&bytes(&original), NOW).unwrap();
    for case in 0..5 {
        let mut bad = valid.clone();
        let expected = match case {
            0 => {
                bad["key_transitions"] = json!(vec![first.clone(); 257]);
                Error::Limit
            }
            1 => {
                bad["key_transitions"] = json!([first, first]);
                Error::Rollback
            }
            2 => {
                bad["key_transitions"][0]["revision"] = json!(10);
                Error::Incoherent
            }
            3 => {
                let proof = bad["key_transitions"][0]["proof"].as_array_mut().unwrap();
                let last = proof.last_mut().unwrap();
                *last = json!(last.as_u64().unwrap() ^ 1);
                Error::Signature
            }
            _ => {
                bad["manifest"] = json!([]);
                Error::Signature
            }
        };
        assert_eq!(charter.install(&bytes(&bad), NOW).unwrap_err(), expected);
        assert_eq!(charter.current(NOW).unwrap().revision(), 10);
    }
    // Every failed chain above left the original ring and revision available.
    charter.install(&bytes(&valid), NOW).unwrap();
    assert_eq!(charter.current(NOW).unwrap().key_ring(), s.key_ring());
    assert!(charter.install(&bytes(&original), NOW).is_err());
    // Installed proofs can expire without weakening the retained ring floor.
    let mut later = feed(&mut s, 12, 1);
    later["key_transitions"] = json!([{"revision":1,"proof":[]},{"revision":2,"proof":[]}]);
    charter.install(&bytes(&later), NOW).unwrap();
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn matching_signing_keys_do_not_replace_exact_ring_continuity() {
    use coset::{CborSerializable, cbor::value::Value as Cbor};
    let mut different =
        Signer::new("alpha", SecretKey::from_seed(&mut [71; 32]), NOW - 2, 1000).unwrap();
    let proof = different
        .rotate_with_proof(SecretKey::from_seed(&mut [72; 32]), NOW, NOW + 500)
        .unwrap();
    let mut v = feed(&mut different, 10, 1);
    v["key_transitions"] = json!([{"revision":1,"proof":proof}]);
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(
        charter.install(&bytes(&v), NOW).unwrap_err(),
        Error::Incoherent
    );

    let mut producer = signer();
    let original_ring = producer.key_ring().clone();
    let proof = producer
        .rotate_with_proof(SecretKey::from_seed(&mut [72; 32]), NOW, NOW + 500)
        .unwrap();
    let verified = original_ring
        .verify(&proof, CoseKind::KeyRingTransition, NOW)
        .unwrap();
    let Cbor::Map(mut fields) = Cbor::from_slice(verified.payload()).unwrap() else {
        panic!()
    };
    for (key, value) in &mut fields {
        if *key == Cbor::Integer(5.into()) {
            *value = Cbor::Bytes(original_ring.to_cbor());
        }
    }
    let mut attester = signer();
    let self_proof = attester
        .sign(
            CoseKind::KeyRingTransition,
            &Cbor::Map(fields).to_vec().unwrap(),
            NOW,
            NOW + 500,
        )
        .unwrap();
    let mut v = feed(&mut attester, 10, 1);
    v["key_transitions"] = json!([{"revision":1,"proof":self_proof}]);
    assert_eq!(
        charter.install(&bytes(&v), NOW).unwrap_err(),
        Error::Incoherent
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn configuration_requires_a_valid_scoped_publishing_root_and_floor() {
    let mut config = configuration(&signer());
    config.key_ring.clear();
    assert!(matches!(Charter::new(config), Err(Error::Unauthenticated)));
    let mut config = configuration(&signer());
    config.minimum_revision = 0;
    assert!(matches!(Charter::new(config), Err(Error::Unauthenticated)));
    let mut config = configuration(&signer());
    config.community = "different".into();
    assert!(matches!(Charter::new(config), Err(Error::Unauthenticated)));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn two_hop_chain_is_atomic_with_later_snapshot_checks() {
    let mut s = signer();
    let original = feed(&mut s, 10, 1);
    let root_cbor = s.key_ring().to_cbor();
    let root_manifest: Vec<u8> = serde_json::from_value(original["manifest"].clone()).unwrap();
    let root_settings: Vec<u8> = serde_json::from_value(original["settings"].clone()).unwrap();
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    charter.install(&bytes(&original), NOW).unwrap();
    let proof1 = s
        .rotate_with_proof(SecretKey::from_seed(&mut [72; 32]), NOW, NOW + 500)
        .unwrap();
    let first = json!({"revision": s.ring_revision(), "proof": proof1});
    s.acknowledge_transition(s.ring_revision()).unwrap();
    let proof2 = s
        .rotate_with_proof(SecretKey::from_seed(&mut [73; 32]), NOW, NOW + 500)
        .unwrap();
    let second = json!({"revision": s.ring_revision(), "proof": proof2});
    s.acknowledge_transition(s.ring_revision()).unwrap();
    let mut valid = feed(&mut s, 11, 1);
    valid["key_transitions"] = json!([first.clone(), second.clone()]);
    let mut bad = valid.clone();
    replace(
        &mut s,
        &mut bad,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| {
            p["revision"] = json!(9);
        },
    );
    assert_eq!(
        charter.install(&bytes(&bad), NOW).unwrap_err(),
        Error::Rollback
    );
    assert_eq!(charter.current(NOW).unwrap().revision(), 10);
    assert_eq!(
        charter.current(NOW).unwrap().key_ring().to_cbor(),
        root_cbor
    );
    assert_eq!(
        charter.current(NOW).unwrap().manifest_bytes(),
        root_manifest
    );
    assert_eq!(
        charter
            .current(NOW)
            .unwrap()
            .publication(Kind::Settings)
            .signed_bytes(),
        root_settings
    );
    assert_eq!(charter.changes_since(10, NOW).unwrap(), Changes::Unchanged);
    charter.install(&bytes(&valid), NOW).unwrap();
    assert_eq!(charter.current(NOW).unwrap().revision(), 11);
    assert_eq!(charter.current(NOW).unwrap().key_ring(), s.key_ring());
    let mut next = feed(&mut s, 12, 1);
    next["key_transitions"] = json!([first, second]);
    charter.install(&bytes(&next), NOW).unwrap();
    assert_eq!(charter.current(NOW).unwrap().revision(), 12);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn retained_prefix_is_skipped_without_granting_attacker_authority() {
    let mut s = signer();
    let original = feed(&mut s, 10, 1);
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    charter.install(&bytes(&original), NOW).unwrap();
    let proof1 = s
        .rotate_with_proof(SecretKey::from_seed(&mut [72; 32]), NOW, NOW + 500)
        .unwrap();
    let first = json!({"revision": s.ring_revision(), "proof": proof1});
    s.acknowledge_transition(s.ring_revision()).unwrap();
    let proof2 = s
        .rotate_with_proof(SecretKey::from_seed(&mut [73; 32]), NOW, NOW + 500)
        .unwrap();
    let second = json!({"revision": s.ring_revision(), "proof": proof2});
    s.acknowledge_transition(s.ring_revision()).unwrap();
    let mut valid = feed(&mut s, 11, 1);
    valid["key_transitions"] = json!([first.clone(), second.clone()]);
    charter.install(&bytes(&valid), NOW).unwrap();
    let proof3 = s
        .rotate_with_proof(SecretKey::from_seed(&mut [74; 32]), NOW, NOW + 500)
        .unwrap();
    let third = s.ring_revision();
    s.acknowledge_transition(third).unwrap();
    let base = feed(&mut s, 12, 1);
    let mut attacker =
        Signer::new("alpha", SecretKey::from_seed(&mut [90; 32]), NOW - 1, 1000).unwrap();
    let evil = attacker
        .rotate_with_proof(SecretKey::from_seed(&mut [91; 32]), NOW, NOW + 500)
        .unwrap();
    let mut forged = base.clone();
    forged["key_transitions"] =
        json!([first.clone(), second.clone(), {"revision": third, "proof": evil}]);
    assert!(charter.install(&bytes(&forged), NOW).is_err());
    assert_eq!(charter.current(NOW).unwrap().revision(), 11);
    let mut replayed = base.clone();
    replayed["key_transitions"] = json!([first.clone(), second.clone(), {"revision": third, "proof": first["proof"].clone()}]);
    assert!(charter.install(&bytes(&replayed), NOW).is_err());
    assert_eq!(charter.current(NOW).unwrap().revision(), 11);
    let mut good = base.clone();
    good["key_transitions"] = json!([{"revision": 1, "proof": []}, {"revision": 2, "proof": []}, {"revision": third, "proof": proof3}]);
    charter.install(&bytes(&good), NOW).unwrap();
    assert_eq!(charter.current(NOW).unwrap().revision(), 12);
    assert_eq!(charter.current(NOW).unwrap().key_ring(), s.key_ring());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn failed_candidate_preserves_exact_deadline_and_floors() {
    let mut s = signer();
    let original = feed(&mut s, 10, 1);
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    charter.install(&bytes(&original), NOW).unwrap();
    assert_eq!(charter.current(NOW).unwrap().valid_until(), NOW + 500);
    let proof = s
        .rotate_with_proof(SecretKey::from_seed(&mut [72; 32]), NOW, NOW + 500)
        .unwrap();
    let transition = json!({"revision": s.ring_revision(), "proof": proof});
    s.acknowledge_transition(s.ring_revision()).unwrap();
    let mut shortened = feed(&mut s, 11, 1);
    shortened["key_transitions"] = json!([transition.clone()]);
    let cose: Vec<u8> = serde_json::from_value(shortened["revocations"].clone()).unwrap();
    let payload = s
        .key_ring()
        .verify(&cose, CoseKind::RevocationListSnapshot, NOW)
        .unwrap()
        .payload()
        .to_vec();
    shortened["revocations"] = json!(
        s.sign(CoseKind::RevocationListSnapshot, &payload, NOW, NOW + 50)
            .unwrap()
    );
    charter.install(&bytes(&shortened), NOW).unwrap();
    assert_eq!(charter.current(NOW).unwrap().valid_until(), NOW + 50);
    let mut bad = feed(&mut s, 12, 2);
    bad["key_transitions"] = json!([transition.clone()]);
    replace(
        &mut s,
        &mut bad,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| {
            p["revision"] = json!(9);
        },
    );
    assert_eq!(
        charter.install(&bytes(&bad), NOW).unwrap_err(),
        Error::Rollback
    );
    assert_eq!(charter.current(NOW).unwrap().revision(), 11);
    assert_eq!(charter.current(NOW).unwrap().valid_until(), NOW + 50);
    assert_eq!(charter.current(NOW).unwrap().policy_epoch(), 1);
    assert_eq!(charter.current(NOW + 49).unwrap().revision(), 11);
    assert_eq!(charter.current(NOW + 50).unwrap_err(), Error::Expired);
    let mut next = feed(&mut s, 12, 2);
    next["key_transitions"] = json!([{"revision": 1, "proof": []}]);
    charter.install(&bytes(&next), NOW + 50).unwrap();
    assert_eq!(charter.current(NOW + 50).unwrap().revision(), 12);
    assert_eq!(
        charter.install(&bytes(&shortened), NOW + 50).unwrap_err(),
        Error::Rollback
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn original_passkey_revocations_are_explicit_and_bounded() {
    let mut signer = signer();
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    let first = feed(&mut signer, 1, 1);
    let original = charter.install(&bytes(&first), NOW).unwrap();
    assert_eq!(
        original.revocations().passkey_revoked(&[9; 64]),
        Err(Error::Unavailable)
    );
    let mut next = feed(&mut signer, 2, 1);
    replace(
        &mut signer,
        &mut next,
        "revocations",
        CoseKind::RevocationListSnapshot,
        |v| v["content"]["passkeys"] = json!([vec![9; 64]]),
    );
    let current = charter.install(&bytes(&next), NOW).unwrap();
    assert_eq!(current.revocations().passkey_revoked(&[9; 64]), Ok(true));
    assert_eq!(current.revocations().passkey_revoked(&[8; 64]), Ok(false));
    assert_eq!(
        current.revocations().passkey_revoked(&[]),
        Err(Error::Malformed)
    );
    for invalid in [Vec::new(), vec![9; 1025]] {
        let mut bad = feed(&mut signer, 3, 1);
        replace(
            &mut signer,
            &mut bad,
            "revocations",
            CoseKind::RevocationListSnapshot,
            |v| v["content"]["passkeys"] = json!([invalid]),
        );
        assert!(charter.install(&bytes(&bad), NOW).is_err());
        assert_eq!(charter.current(NOW).unwrap().revision(), 2);
    }
}

fn with_root_board(signer: &mut Signer, revision: u64, board_revision: u64) -> Value {
    let mut value = feed(signer, revision, 1);
    let descriptor: Vec<u8> = include_bytes!("fixtures/root-board-public.bin").to_vec();
    let material = json!({"purpose":"cplc.root-board.v1","community":"alpha","revision":board_revision,"policy_epoch":1,"descriptor":descriptor});
    value["root_board"] = json!(sign(signer, CoseKind::SettingsSnapshot, material));
    replace(
        signer,
        &mut value,
        "manifest",
        CoseKind::SettingsSnapshot,
        |v| v["root_board_revision"] = json!(board_revision),
    );
    value
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn root_board_is_atomic_original_signed_material_with_independent_floors() {
    let mut signer = signer();
    let first = with_root_board(&mut signer, 10, 2);
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(
        charter
            .install(&bytes(&first), NOW)
            .unwrap()
            .root_board()
            .unwrap()
            .signed_bytes(),
        serde_json::from_value::<Vec<u8>>(first["root_board"].clone()).unwrap()
    );
    charter.install(&bytes(&first), NOW).unwrap();
    for case in 0..9 {
        let mut bad = with_root_board(&mut signer, 11, 2);
        let expected = match case {
            0 => {
                bad.as_object_mut().unwrap().remove("root_board");
                Error::Incoherent
            }
            1 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "manifest",
                    CoseKind::SettingsSnapshot,
                    |v| {
                        v.as_object_mut().unwrap().remove("root_board_revision");
                    },
                );
                Error::Incoherent
            }
            2 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "manifest",
                    CoseKind::SettingsSnapshot,
                    |v| v["root_board_revision"] = json!(12),
                );
                Error::Incoherent
            }
            3 => {
                bad = feed(&mut signer, 11, 1);
                Error::Rollback
            }
            4 => {
                bad = with_root_board(&mut signer, 11, 1);
                Error::Rollback
            }
            5 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "root_board",
                    CoseKind::SettingsSnapshot,
                    |v| v["descriptor"] = json!(vec![7; 32]),
                );
                Error::Equivocation
            }
            6 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "root_board",
                    CoseKind::SettingsSnapshot,
                    |v| v["purpose"] = json!("settings"),
                );
                Error::Incoherent
            }
            7 => {
                replace(
                    &mut signer,
                    &mut bad,
                    "root_board",
                    CoseKind::SettingsSnapshot,
                    |v| v["community"] = json!("beta"),
                );
                Error::Incoherent
            }
            _ => {
                replace(
                    &mut signer,
                    &mut bad,
                    "root_board",
                    CoseKind::SettingsSnapshot,
                    |v| v["policy_epoch"] = json!(2),
                );
                Error::Incoherent
            }
        };
        assert_eq!(
            charter.install(&bytes(&bad), NOW).unwrap_err(),
            expected,
            "case {case}"
        );
        assert_eq!(charter.current(NOW).unwrap().revision(), 10);
    }
    let next = with_root_board(&mut signer, 11, 3);
    assert_eq!(
        charter
            .install(&bytes(&next), NOW)
            .unwrap()
            .root_board()
            .unwrap()
            .revision(),
        3
    );
    assert_eq!(charter.current(NOW + 500).unwrap_err(), Error::Expired);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn root_board_deadline_kind_signature_duplicates_and_floor_survives_expiry() {
    let mut signer = signer();
    let mut value = with_root_board(&mut signer, 10, 2);
    let cose: Vec<u8> = serde_json::from_value(value["root_board"].clone()).unwrap();
    let payload = signer
        .key_ring()
        .verify(&cose, CoseKind::SettingsSnapshot, NOW)
        .unwrap()
        .payload()
        .to_vec();
    value["root_board"] = json!(
        signer
            .sign(CoseKind::SettingsSnapshot, &payload, NOW, NOW + 10)
            .unwrap()
    );
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    assert_eq!(
        charter.install(&bytes(&value), NOW).unwrap().valid_until(),
        NOW + 10
    );
    assert_eq!(charter.current(NOW + 10).unwrap_err(), Error::Expired);
    let mut bad_kind = with_root_board(&mut signer, 11, 3);
    let raw: Vec<u8> = serde_json::from_value(bad_kind["root_board"].clone()).unwrap();
    let inner = signer
        .key_ring()
        .verify(&raw, CoseKind::SettingsSnapshot, NOW)
        .unwrap()
        .payload()
        .to_vec();
    bad_kind["root_board"] = json!(
        signer
            .sign(CoseKind::SchemaSnapshot, &inner, NOW, NOW + 500)
            .unwrap()
    );
    assert_eq!(
        charter.install(&bytes(&bad_kind), NOW + 10).unwrap_err(),
        Error::Signature
    );
    let mut tampered = with_root_board(&mut signer, 11, 3);
    tampered["root_board"][0] = json!(0);
    assert_eq!(
        charter.install(&bytes(&tampered), NOW + 10).unwrap_err(),
        Error::Signature
    );
    let duplicate = String::from_utf8(payload).unwrap().replace(
        "\"purpose\":",
        "\"purpose\":\"cplc.root-board.v1\",\"purpose\":",
    );
    value["root_board"] = json!(
        signer
            .sign(
                CoseKind::SettingsSnapshot,
                duplicate.as_bytes(),
                NOW,
                NOW + 500
            )
            .unwrap()
    );
    assert_eq!(
        charter.install(&bytes(&value), NOW + 10).unwrap_err(),
        Error::Incoherent
    );
    let dropped = feed(&mut signer, 11, 1);
    assert_eq!(
        charter.install(&bytes(&dropped), NOW + 10).unwrap_err(),
        Error::Rollback
    );
    let next = with_root_board(&mut signer, 11, 3);
    charter.install(&bytes(&next), NOW + 10).unwrap();
    assert_eq!(
        charter
            .current(NOW + 10)
            .unwrap()
            .root_board()
            .unwrap()
            .revision(),
        3
    );
    assert_eq!(
        charter
            .install(&bytes(&with_root_board(&mut signer, 12, 2)), NOW + 10)
            .unwrap_err(),
        Error::Rollback
    );
}

fn ohttp_config(id: u8) -> Vec<u8> {
    ohttp::KeyConfig::derive(
        id,
        ohttp::hpke::Kem::X25519Sha256,
        vec![ohttp::SymmetricSuite::new(
            ohttp::hpke::Kdf::HkdfSha256,
            ohttp::hpke::Aead::ChaCha20Poly1305,
        )],
        &[id; 32],
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn with_ohttp(s: &mut Signer, directory: Value) -> Value {
    let mut value = feed(s, 10, 1);
    replace(s, &mut value, "manifest", CoseKind::SettingsSnapshot, |m| {
        m["ohttp"] = directory
    });
    value
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signed_ohttp_directory_reaches_the_verified_charter_and_malformed_ones_do_not() {
    let mut s = signer();
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    let plain = feed(&mut s, 10, 1);
    assert!(
        charter
            .install(&bytes(&plain), NOW)
            .unwrap()
            .ohttp()
            .is_none()
    );
    let entry = |id: u8| {
        json!({"service":"api.alpha.example","key_id":id,"config":ohttp_config(id),
            "not_before":NOW - 10,"not_after":NOW + 100})
    };
    let good = with_ohttp(
        &mut s,
        json!({"relay":"https://relay.alpha.example","keys":[entry(1),entry(2)]}),
    );
    let mut charter = new_charter(ORIGIN, "alpha").unwrap();
    let verified = charter.install(&bytes(&good), NOW).unwrap();
    let (relay, key) = verified
        .ohttp()
        .unwrap()
        .current("api.alpha.example", NOW)
        .unwrap();
    assert_eq!(relay, "https://relay.alpha.example");
    assert_eq!(key.key_id, 2);
    for bad in [
        json!({"relay":"http://relay.alpha.example","keys":[entry(1)]}),
        json!({"relay":"https://relay.alpha.example","keys":[entry(1),entry(1)]}),
        json!({"relay":"https://relay.alpha.example","keys":[],"extra":1}),
    ] {
        let candidate = with_ohttp(&mut s, bad);
        assert!(
            new_charter(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), NOW)
                .is_err()
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_fingerprint_anchors_the_whole_chain_with_no_configured_key() {
    let mut s = signer();
    let genesis = s.genesis().unwrap();
    let fingerprint = csgn::verify_genesis(&genesis).unwrap().fingerprint();
    let link = |s: &mut Signer, seed: u8| {
        let proof = s
            .rotate_with_proof(SecretKey::from_seed(&mut [seed; 32]), NOW, NOW + 500)
            .unwrap();
        let link = json!({"revision": s.ring_revision(), "proof": proof});
        s.acknowledge_transition(s.ring_revision()).unwrap();
        link
    };
    let first = link(&mut s, 72);
    let second = link(&mut s, 73);
    let mut full = feed(&mut s, 10, 1);
    full["genesis"] = json!(genesis);
    full["key_transitions"] = json!([first.clone(), second.clone()]);
    let start = || Charter::from_fingerprint(ORIGIN.into(), "alpha".into(), fingerprint, 1);
    // The whole chain from the genesis installs, and the head is the current ring.
    let mut charter = start().unwrap();
    assert_eq!(charter.state(NOW), State::Unbootstrapped);
    charter.install(&bytes(&full), NOW).unwrap();
    assert_eq!(
        charter.current(NOW).unwrap().key_ring().to_cbor(),
        s.key_ring().to_cbor()
    );
    assert_eq!(
        charter.current(NOW).unwrap().fingerprint(),
        Some(&fingerprint)
    );
    // Later feeds need no genesis and no repeated links.
    let mut later = feed(&mut s, 11, 1);
    later["key_transitions"] = json!([second.clone()]);
    charter.install(&bytes(&later), NOW).unwrap();
    // A wrong fingerprint, a missing genesis, a gap, a missing link and a
    // different community's genesis are all refused.
    let wrong = Charter::from_fingerprint(ORIGIN.into(), "alpha".into(), [9; 32], 1).unwrap();
    let mut wrong = wrong;
    assert_eq!(
        wrong.install(&bytes(&full), NOW).unwrap_err(),
        Error::Unauthenticated
    );
    let mut missing = full.clone();
    missing.as_object_mut().unwrap().remove("genesis");
    assert_eq!(
        start().unwrap().install(&bytes(&missing), NOW).unwrap_err(),
        Error::Unauthenticated
    );
    let mut gap = full.clone();
    gap["key_transitions"] = json!([second.clone()]);
    assert_eq!(
        start().unwrap().install(&bytes(&gap), NOW).unwrap_err(),
        Error::Incoherent
    );
    let mut short = full.clone();
    short["key_transitions"] = json!([first.clone()]);
    assert_eq!(
        start().unwrap().install(&bytes(&short), NOW).unwrap_err(),
        Error::Unauthenticated
    );
    let mut bogus = full;
    bogus["genesis"] = json!(
        Signer::new("alpha", SecretKey::from_seed(&mut [5; 32]), NOW - 1, 1000)
            .unwrap()
            .genesis()
            .unwrap()
    );
    assert_eq!(
        start().unwrap().install(&bytes(&bogus), NOW).unwrap_err(),
        Error::Unauthenticated
    );
    assert!(Charter::from_fingerprint(ORIGIN.into(), "".into(), fingerprint, 1).is_err());
}

fn start_with(fingerprint: [u8; 32], pin: cchr::ChainPin) -> Charter {
    Charter::from_fingerprint(ORIGIN.into(), "alpha".into(), fingerprint, 1)
        .unwrap()
        .with_pin(pin)
        .unwrap()
}
fn old_chain(seeds: &[u8]) -> (Signer, Vec<u8>, Vec<Value>) {
    // Founded long ago; every rotation proof has long expired at NOW.
    let mut s = Signer::new(
        "alpha",
        SecretKey::from_seed(&mut [71; 32]),
        NOW - 100_000,
        1000,
    )
    .unwrap();
    let genesis = s.genesis().unwrap();
    let mut links = Vec::new();
    for (i, seed) in seeds.iter().enumerate() {
        let at = NOW - 50_000 + i as u64 * 100;
        let proof = s
            .rotate_with_proof(SecretKey::from_seed(&mut [*seed; 32]), at, at + 500)
            .unwrap();
        links.push(json!({"revision": s.ring_revision(), "proof": proof}));
        s.acknowledge_transition(s.ring_revision()).unwrap();
    }
    (s, genesis, links)
}
fn old_feed(seeds: &[u8], with_genesis: bool) -> (Value, [u8; 32], Charter) {
    let (mut s, genesis, links) = old_chain(seeds);
    let fingerprint = csgn::verify_genesis(&genesis).unwrap().fingerprint();
    let mut v = feed(&mut s, 10, 1);
    if with_genesis {
        v["genesis"] = json!(genesis);
    }
    v["key_transitions"] = json!(links);
    let charter = Charter::from_fingerprint(ORIGIN.into(), "alpha".into(), fingerprint, 1).unwrap();
    (v, fingerprint, charter)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_chain_of_expired_proofs_verifies_and_only_the_head_is_checked_against_now() {
    let (v, _, mut charter) = old_feed(&[72, 73], true);
    charter.install(&bytes(&v), NOW).unwrap();
    assert_eq!(charter.current(NOW).unwrap().chain_pin().ring_revision, 2);
    // The head's own signatures still expire: far later the same feed is stale.
    let (v, _, mut late) = old_feed(&[72, 73], true);
    assert!(late.install(&bytes(&v), NOW + 10_000).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn a_pinned_head_must_be_extended_exactly_and_never_rolled_back_or_forked() {
    let (v, fingerprint, mut charter) = old_feed(&[72, 73], true);
    charter.install(&bytes(&v), NOW).unwrap();
    let pin = charter.current(NOW).unwrap().chain_pin();
    let start = || {
        Charter::from_fingerprint(ORIGIN.into(), "alpha".into(), fingerprint, 1)
            .unwrap()
            .with_pin(pin)
            .unwrap()
    };
    // The same chain, and one that extends it, are accepted.
    start().install(&bytes(&v), NOW).unwrap();
    let (longer, _, _) = old_feed(&[72, 73, 74], true);
    start().install(&bytes(&longer), NOW).unwrap();
    // A shorter chain is a rollback.
    let (shorter, _, _) = old_feed(&[72], true);
    assert_eq!(
        start().install(&bytes(&shorter), NOW).unwrap_err(),
        Error::Rollback
    );
    // A different transition at the pinned revision is a fork, even if longer.
    let (fork, _, _) = old_feed(&[72, 75, 76], true);
    assert_eq!(
        start().install(&bytes(&fork), NOW).unwrap_err(),
        Error::Equivocation
    );
    // A pin on the genesis ring itself is extended by any chain.
    let head = csgn::verify_genesis(&old_chain(&[]).1)
        .unwrap()
        .ring()
        .digest();
    let (one, _, _) = old_feed(&[72], true);
    start_with(
        fingerprint,
        cchr::ChainPin {
            ring_revision: 0,
            head,
        },
    )
    .install(&bytes(&one), NOW)
    .unwrap();
    // A pin only makes sense before bootstrap and on a fingerprint charter.
    assert!(new_charter(ORIGIN, "alpha").unwrap().with_pin(pin).is_err());
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn ended_chains_come_only_from_the_signed_communities_snapshot() {
    let mut s = signer();
    let mut v = feed(&mut s, 10, 1);
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    assert!(c.install(&bytes(&v), NOW).unwrap().ended().is_empty());

    let hex = "ab".repeat(32);
    replace(
        &mut s,
        &mut v,
        "communities",
        CoseKind::CommunitiesSnapshot,
        |p| {
            p["content"] = json!({"communities":["alpha"],"ended":[
            {"fingerprint":hex,"reason_class":"banned","ended_at":5},
            {"fingerprint":"cd".repeat(32),"reason_class":"dissolved","ended_at":6}]});
        },
    );
    let mut c = new_charter(ORIGIN, "alpha").unwrap();
    let ended = c.install(&bytes(&v), NOW).unwrap().ended().to_vec();
    assert_eq!(ended.len(), 2);
    assert_eq!(ended[0].fingerprint, [0xab; 32]);
    assert_eq!(ended[0].reason_class, cchr::EndReason::Banned);
    assert_eq!(ended[1].ended_at, 6);

    // Duplicates, bad fingerprints and oversized lists are refused.
    for content in [
        json!({"communities":[],"ended":[
            {"fingerprint":hex,"reason_class":"banned","ended_at":1},
            {"fingerprint":hex,"reason_class":"dissolved","ended_at":2}]}),
        json!({"communities":[],"ended":[{"fingerprint":"AB","reason_class":"banned","ended_at":1}]}),
    ] {
        let mut bad = v.clone();
        replace(
            &mut s,
            &mut bad,
            "communities",
            CoseKind::CommunitiesSnapshot,
            |p| p["content"] = content,
        );
        assert!(
            new_charter(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&bad), NOW)
                .is_err()
        );
    }
    let many: Vec<Value> = (0..=cchr::MAX_ENDED as u32)
        .map(|i| {
            let mut f = [0u8; 32];
            f[..4].copy_from_slice(&i.to_be_bytes());
            let text: String = f.iter().map(|b| format!("{b:02x}")).collect();
            json!({"fingerprint":text,"reason_class":"banned","ended_at":1})
        })
        .collect();
    let mut big = v.clone();
    replace(
        &mut s,
        &mut big,
        "communities",
        CoseKind::CommunitiesSnapshot,
        |p| {
            p["content"] = json!({"communities":[],"ended":many});
        },
    );
    assert!(
        new_charter(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&big), NOW)
            .is_err()
    );

    // Unsigned edits to the snapshot are refused: the entries are not outside the signature.
    let mut forged = feed(&mut s, 10, 1);
    forged["communities"] = v["communities"].clone();
    forged["communities"][0] = json!(0);
    assert!(
        new_charter(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&forged), NOW)
            .is_err()
    );
}
