use cchr::{AuthenticatedOrigin, Changes, Charter, Error, Kind, State};
use csgn::{Kind as CoseKind, SecretKey, Signer};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;
const ORIGIN: &str = "https://alpha.example.test";

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
fn authority(s: &Signer) -> AuthenticatedOrigin {
    AuthenticatedOrigin::from_authenticated_response(
        ORIGIN,
        "alpha",
        &s.key_ring().to_cbor(),
        1,
        NOW,
        NOW + 100,
    )
    .unwrap()
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
    let a = authority(&s);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    assert_eq!(c.state(NOW), State::Unbootstrapped);
    let current = c.install(&bytes(&v), &a, NOW).unwrap();
    assert_eq!(current.revision(), 10);
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
    let a = authority(&s);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&old), &a, NOW).unwrap();
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
        assert!(c.install(&bytes(&candidate), &a, NOW).is_err(), "case {i}");
        assert_eq!(c.current(NOW).unwrap().revision(), 10);
    }
    let next = feed(&mut s, 11, 2);
    c.install(&bytes(&next), &a, NOW).unwrap();
    assert_eq!(
        c.install(&bytes(&old), &a, NOW).unwrap_err(),
        Error::Rollback
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn same_revision_requires_exact_original_signed_bytes() {
    let mut s = signer();
    let mut v = feed(&mut s, 10, 1);
    let a = authority(&s);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&v), &a, NOW).unwrap();
    c.install(&bytes(&v), &a, NOW).unwrap();
    replace(
        &mut s,
        &mut v,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| p["content"] = json!({"changed":true}),
    );
    assert_eq!(
        c.install(&bytes(&v), &a, NOW).unwrap_err(),
        Error::Equivocation
    );
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
    assert_eq!(
        c.install(&bytes(&v), &a, NOW).unwrap_err(),
        Error::Equivocation
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bootstrap_scope_freshness_and_rotation_are_explicit() {
    let mut s = signer();
    let old = feed(&mut s, 10, 1);
    let a = authority(&s);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    let foreign = AuthenticatedOrigin::from_authenticated_response(
        "https://beta.example.test",
        "alpha",
        &s.key_ring().to_cbor(),
        1,
        NOW,
        NOW + 100,
    )
    .unwrap();
    assert_eq!(
        c.install(&bytes(&old), &foreign, NOW).unwrap_err(),
        Error::Unauthenticated
    );
    c.install(&bytes(&old), &a, NOW).unwrap();
    s.rotate(SecretKey::from_seed(&mut [72; 32]), NOW).unwrap();
    let new = feed(&mut s, 11, 1);
    assert_eq!(
        c.install(&bytes(&new), &a, NOW).unwrap_err(),
        Error::Unauthenticated
    );
    let approved = authority(&s);
    c.install(&bytes(&new), &approved, NOW).unwrap();
    // Retired keys still validate their original snapshots in the newly authenticated ring.
    let old_schema: Vec<u8> = serde_json::from_value(old["schema"].clone()).unwrap();
    assert!(
        c.current(NOW)
            .unwrap()
            .key_ring()
            .verify(&old_schema, CoseKind::SchemaSnapshot, NOW)
            .is_ok()
    );
    let floor = AuthenticatedOrigin::from_authenticated_response(
        ORIGIN,
        "alpha",
        &s.key_ring().to_cbor(),
        12,
        NOW,
        NOW + 100,
    )
    .unwrap();
    let mut restarted = Charter::new(ORIGIN, "alpha").unwrap();
    assert_eq!(
        restarted.install(&bytes(&new), &floor, NOW).unwrap_err(),
        Error::Rollback
    );
    assert_eq!(
        c.install(&bytes(&new), &approved, NOW + 100).unwrap_err(),
        Error::Unauthenticated
    );
    for bad in [
        "http://alpha.example.test",
        "https://u:p@alpha.example.test",
        "https://alpha.example.test/path",
        "https://alpha.example.test?query",
    ] {
        assert!(Charter::new(bad, "alpha").is_err());
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn duplicate_fields_unknown_fields_trailing_bytes_and_limits_fail() {
    let mut s = signer();
    let mut v = feed(&mut s, 10, 1);
    let a = authority(&s);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    let original = bytes(&v);
    let mut duplicate = original.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"revision\":10}");
    assert_eq!(
        c.install(&duplicate, &a, NOW).unwrap_err(),
        Error::Malformed
    );
    let mut trailing = original;
    trailing.push(b'x');
    assert_eq!(c.install(&trailing, &a, NOW).unwrap_err(), Error::Malformed);
    let payload =
        br#"{"community":"alpha","revision":10,"policy_epoch":1,"content":{"x":1,"x":2}}"#;
    v["settings"] = json!(
        s.sign(CoseKind::SettingsSnapshot, payload, NOW, NOW + 500)
            .unwrap()
    );
    assert_eq!(
        c.install(&bytes(&v), &a, NOW).unwrap_err(),
        Error::Malformed
    );
    let huge = vec![b' '; cchr::MAX_FEED_BYTES + 1];
    assert_eq!(c.install(&huge, &a, NOW).unwrap_err(), Error::Limit);
    v["unknown"] = json!(true);
    assert_eq!(
        c.install(&bytes(&v), &a, NOW).unwrap_err(),
        Error::Malformed
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bounded_two_hundred_consumer_load_and_scope_isolation() {
    let mut s = signer();
    let v = feed(&mut s, 10, 1);
    let a = authority(&s);
    let wire = bytes(&v);
    let mut consumers: Vec<_> = (0..200)
        .map(|_| Charter::new(ORIGIN, "alpha").unwrap())
        .collect();
    for consumer in &mut consumers {
        consumer.install(&wire, &a, NOW).unwrap();
    }
    let mut foreign = Charter::new(ORIGIN, "beta").unwrap();
    assert_eq!(
        foreign.install(&wire, &a, NOW).unwrap_err(),
        Error::Unauthenticated
    );
    let next = bytes(&feed(&mut s, 11, 2));
    for consumer in &mut consumers {
        consumer.install(&next, &a, NOW).unwrap();
        assert_eq!(consumer.current(NOW).unwrap().policy_epoch(), 2);
        assert_eq!(
            consumer.install(&wire, &a, NOW).unwrap_err(),
            Error::Rollback
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn higher_feed_revision_cannot_rewrite_a_retained_schema() {
    let mut s = signer();
    let old = feed(&mut s, 10, 1);
    let a = authority(&s);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&old), &a, NOW).unwrap();
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
        c.install(&bytes(&candidate), &a, NOW).unwrap_err(),
        Error::Equivocation
    );
    assert_eq!(c.current(NOW).unwrap().revision(), 10);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn one_expired_snapshot_refuses_the_entire_candidate_at_its_deadline() {
    let mut s = signer();
    let old = feed(&mut s, 10, 1);
    let a = authority(&s);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&old), &a, NOW).unwrap();
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
    let mut fresh = Charter::new(ORIGIN, "alpha").unwrap();
    assert_eq!(
        fresh
            .install(&bytes(&candidate), &a, NOW + 49)
            .unwrap()
            .valid_until(),
        NOW + 50
    );
    assert_eq!(
        c.install(&bytes(&candidate), &a, NOW + 50).unwrap_err(),
        Error::Signature
    );
    assert_eq!(c.current(NOW + 50).unwrap().revision(), 10);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn origin_receipts_and_readiness_reject_invalid_boundaries() {
    let configured = Charter::new("https://ALPHA.example.test:443/", "alpha").unwrap();
    assert_eq!(configured.origin(), ORIGIN);
    let mut s = signer();
    let ring = s.key_ring().to_cbor();
    for (community, minimum, observed, until) in [
        ("beta", 1, NOW, NOW + 1),
        ("alpha", 0, NOW, NOW + 1),
        ("alpha", 1, NOW, NOW),
    ] {
        assert!(
            AuthenticatedOrigin::from_authenticated_response(
                ORIGIN, community, &ring, minimum, observed, until,
            )
            .is_err()
        );
    }
    assert!(
        AuthenticatedOrigin::from_authenticated_response(
            ORIGIN,
            "alpha",
            b"broken",
            1,
            NOW,
            NOW + 1,
        )
        .is_err()
    );
    for origin in [
        "invalid",
        "https://:secret@alpha.example.test",
        "https://alpha.example.test/#fragment",
    ] {
        assert!(Charter::new(origin, "alpha").is_err());
    }
    for community in [String::new(), "x".repeat(257), "a\0b".into()] {
        assert!(Charter::new(ORIGIN, &community).is_err());
    }
    let feed = feed(&mut s, 10, 1);
    let receipt = authority(&s);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    assert_eq!(c.current(NOW).unwrap_err(), Error::Unavailable);
    assert_eq!(c.state(NOW - 1), State::Unavailable);
    let mut early = Charter::new(ORIGIN, "alpha").unwrap();
    assert_eq!(
        early.install(&bytes(&feed), &receipt, NOW - 1).unwrap_err(),
        Error::Unauthenticated
    );
    let view = c.install(&bytes(&feed), &receipt, NOW).unwrap();
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
    let receipt = authority(&s);
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
            Charter::new(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), &receipt, NOW)
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
            Charter::new(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), &receipt, NOW)
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
            Charter::new(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), &receipt, NOW)
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
            Charter::new(ORIGIN, "alpha")
                .unwrap()
                .install(&bytes(&candidate), &receipt, NOW)
                .is_err()
        );
    }
    let mut huge = feed(&mut s, 10, 1);
    huge["settings"] = json!(vec![0u8; (1 << 20) + 8193]);
    assert_eq!(
        Charter::new(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&huge), &receipt, NOW)
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
        Charter::new(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&scalar), &receipt, NOW)
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
    let receipt = authority(&s);
    let original = feed(&mut s, 10, 1);
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&original), &receipt, NOW).unwrap();
    let next = history_feed(&mut s, 11, 2);
    c.install(&bytes(&next), &receipt, NOW).unwrap();
    assert_eq!(c.current(NOW).unwrap().schema_history().len(), 2);
    for case in 0..12 {
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
                    _ => h["versions"][1]["schema"]["public"] = json!([{"id":"x"}]),
                }
            },
        );
        assert!(
            c.install(&bytes(&candidate), &receipt, NOW).is_err(),
            "history case {case}"
        );
        assert_eq!(c.current(NOW).unwrap().revision(), 11);
    }
    let rollback = feed(&mut s, 12, 2);
    assert_eq!(
        c.install(&bytes(&rollback), &receipt, NOW).unwrap_err(),
        Error::Rollback
    );
    let old_epoch = history_feed(&mut s, 12, 1);
    assert_eq!(
        c.install(&bytes(&old_epoch), &receipt, NOW).unwrap_err(),
        Error::Rollback
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn equal_manifest_revision_cannot_change_any_signed_bytes() {
    let mut s = signer();
    let receipt = authority(&s);
    let mut original = feed(&mut s, 10, 1);
    replace(
        &mut s,
        &mut original,
        "settings",
        CoseKind::SettingsSnapshot,
        |p| p["revision"] = json!(9),
    );
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&original), &receipt, NOW).unwrap();
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
        c.install(&bytes(&candidate), &receipt, NOW).unwrap_err(),
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
        c.install(&bytes(&candidate), &receipt, NOW).unwrap_err(),
        Error::Equivocation
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn schema_scope_and_history_definition_match_exactly() {
    let mut s = signer();
    let receipt = authority(&s);
    let mut invalid = feed(&mut s, 10, 1);
    replace(
        &mut s,
        &mut invalid,
        "schema",
        CoseKind::SchemaSnapshot,
        |p| p["content"]["version"] = json!(0),
    );
    assert_eq!(
        Charter::new(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&invalid), &receipt, NOW)
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
        Charter::new(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&candidate), &receipt, NOW)
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
        Charter::new(ORIGIN, "alpha")
            .unwrap()
            .install(&bytes(&candidate), &receipt, NOW)
            .unwrap_err(),
        Error::Incoherent
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn retained_schema_cannot_gain_a_different_predecessor() {
    let mut s = signer();
    let receipt = authority(&s);
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
    let mut c = Charter::new(ORIGIN, "alpha").unwrap();
    c.install(&bytes(&original), &receipt, NOW).unwrap();
    let candidate = history_feed(&mut s, 11, 2);
    assert_eq!(
        c.install(&bytes(&candidate), &receipt, NOW).unwrap_err(),
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
        let receipt = authority(&s);
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
        let mut charter = Charter::new(ORIGIN, "alpha").unwrap();
        let current = charter.install(&bytes(&candidate), &receipt, NOW).unwrap();
        let policy = current.admission_policy("admission", NOW, 500).unwrap();
        let credential = sign(
            &mut s,
            CoseKind::Credential,
            json!({"community":"alpha","member":"person","handle":"mountain","schema_version":1,"policy_epoch":1,"gates":[{"gate":"voucher","provider":"community","valid_until":NOW+500}],"pins":[],"devices":[device.verifying_key().to_bytes()]}),
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
        let mut broken = signed.clone();
        broken.signature[0] ^= 1;
        assert!(!cgrd::check_published(&broken, &policy, schema).is_admitted());
        let mut absent = body.clone();
        absent["profile"]["profile"]["public"] = json!({});
        assert!(!cgrd::check_published(&present(&absent), &policy, schema).is_admitted());
        let mut wrong = body.clone();
        wrong["device"] = json!(vec![0; 32]);
        assert!(!cgrd::check_published(&present(&wrong), &policy, schema).is_admitted());
    }
}
