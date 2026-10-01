#![cfg(feature = "door-vectors")]
use cchr::{AuthenticatedOrigin, Charter, Error, Kind};
use serde_json::Value;
const INITIAL: &[u8] = include_bytes!("../.build/fixtures/initial.json");
const ORDINARY: &[u8] = include_bytes!("../.build/fixtures/ordinary.json");
const ALL: &[u8] = include_bytes!("../.build/fixtures/all.json");
const ANY: &[u8] = include_bytes!("../.build/fixtures/any.json");
const THRESHOLD: &[u8] = include_bytes!("../.build/fixtures/threshold.json");
const SCHEMA: &[u8] = include_bytes!("../.build/fixtures/schema.json");
const REVOKED: &[u8] = include_bytes!("../.build/fixtures/revoked.json");
const NOW: u64 = 1_800_000_003;
fn configured_authority() -> AuthenticatedOrigin {
    let config: Value =
        serde_json::from_slice(include_bytes!("../.build/fixtures/publishing-root.json")).unwrap();
    let ring: Vec<u8> = serde_json::from_value(config["key_ring"].clone()).unwrap();
    AuthenticatedOrigin::from_authenticated_response(
        "https://alpha.example.test",
        "alpha",
        &ring,
        config["minimum_revision"].as_u64().unwrap(),
        NOW,
        NOW + 60,
    )
    .unwrap()
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn running_door_publications_install_without_translation() {
    assert_eq!(INITIAL, ORDINARY);
    let origin = "https://alpha.example.test";
    let authority = configured_authority();
    let mut charter = Charter::new(origin, "alpha").unwrap();
    let mut epoch = 0;
    for bytes in [INITIAL, ALL, ANY, THRESHOLD, SCHEMA, REVOKED] {
        let current = charter.install(bytes, &authority, NOW).unwrap();
        assert!(current.policy_epoch() > epoch);
        epoch = current.policy_epoch();
        let raw: Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(
            current.publication(Kind::Settings).signed_bytes(),
            serde_json::from_value::<Vec<u8>>(raw["settings"].clone()).unwrap()
        );
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
    }
    assert_eq!(charter.current(NOW).unwrap().schema().version, 2);
    assert_eq!(charter.current(NOW).unwrap().schema_history().len(), 2);
    assert_eq!(
        charter.install(INITIAL, &authority, NOW).unwrap_err(),
        Error::Rollback
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn current_door_issued_device_bundles_follow_full_policy_and_revocation() {
    let captures: &[(&[u8], &[u8])] = &[
        (ALL, include_bytes!("../.build/fixtures/all-bundle.json")),
        (ANY, include_bytes!("../.build/fixtures/any-bundle.json")),
        (
            THRESHOLD,
            include_bytes!("../.build/fixtures/threshold-bundle.json"),
        ),
        (
            SCHEMA,
            include_bytes!("../.build/fixtures/schema-bundle.json"),
        ),
    ];
    let origin = "https://alpha.example.test";
    let mut last = None;
    for (feed_bytes, capture_bytes) in captures {
        let capture: Value = serde_json::from_slice(capture_bytes).unwrap();
        let authority = configured_authority();
        let mut charter = Charter::new(origin, "alpha").unwrap();
        let current = charter.install(feed_bytes, &authority, NOW).unwrap();
        let bundle: cgrd::Bundle = serde_json::from_value(capture["bundle"].clone()).unwrap();
        let action = capture["action"].as_str().unwrap();
        let policy = current.admission_policy(action, NOW, 86400).unwrap();
        let result = cgrd::check_published(
            &bundle,
            &policy,
            current.publication(Kind::Schema).signed_bytes(),
        );
        assert!(
            result.is_admitted(),
            "current door credential and authorized device must pass Guard"
        );
        let mut tampered = bundle.clone();
        tampered.payload.push(b' ');
        assert!(
            !cgrd::check_published(
                &tampered,
                &policy,
                current.publication(Kind::Schema).signed_bytes()
            )
            .is_admitted()
        );
        last = Some((bundle, action.to_owned(), charter));
    }
    let (bundle, action, mut charter) = last.unwrap();
    let authority = configured_authority();
    let revoked = charter.install(REVOKED, &authority, NOW).unwrap();
    let policy = revoked.admission_policy(&action, NOW, 86400).unwrap();
    assert!(
        !cgrd::check_published(
            &bundle,
            &policy,
            revoked.publication(Kind::Schema).signed_bytes()
        )
        .is_admitted()
    );
}
