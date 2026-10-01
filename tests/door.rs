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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn running_door_publications_install_without_translation() {
    assert_eq!(INITIAL, ORDINARY);
    let feed: Value = serde_json::from_slice(INITIAL).unwrap();
    let ring: Vec<u8> = serde_json::from_value(feed["key_ring"].clone()).unwrap();
    let origin = "https://alpha.example.test";
    let authority = AuthenticatedOrigin::from_authenticated_response(
        origin,
        "alpha",
        &ring,
        feed["revision"].as_u64().unwrap(),
        NOW,
        NOW + 60,
    )
    .unwrap();
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
