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
    assert_eq!(current.admission_policy(), Err(Error::UnsupportedPolicy));
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
