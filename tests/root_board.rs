#![cfg(not(target_arch = "wasm32"))]
//! Original root-board producer and authenticated consumer scenarios.
#[path = "root_board/support.rs"]
mod support;
use cplc::*;
use cpsd::rand::{SeedableRng, rngs::StdRng};
use cpsd::{IssuerKey, ROOT_BOARD_COHORT_SECONDS, RootBoardPublicKey};
use serde_json::json;
use support::*;

const ROOT: &str = "root";
fn issuer(seed: u64) -> IssuerKey {
    IssuerKey::generate(
        &mut StdRng::seed_from_u64(seed),
        cpsd::KeyId::new("common-root").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap()
}

fn descriptor(key: &IssuerKey, epoch: u64, cohort: u64) -> RootBoardPublicKey {
    RootBoardPublicKey::from_authenticated_beacon(
        key.public_key().clone(),
        cpsd::CommunityId::new(ROOT.as_bytes()).unwrap(),
        epoch,
        cohort,
    )
    .unwrap()
}

async fn setup() -> (tempfile::TempDir, crlt::Db, crlt::Db, SqlPolicy) {
    let directory = tempfile::tempdir().unwrap();
    let url = format!("file://{}", directory.path().join("policy.db").display());
    let (db, rules) = databases(&url, "").await;
    let mut policy = sql_policy(&db, &rules, ROOT).await;
    policy
        .schedule_rules(None, change(book(admission()), 1, NOW as i64))
        .await
        .unwrap();
    let mut definition = schema(1);
    definition.community = ROOT.into();
    policy.set_schema(definition).await.unwrap();
    (directory, db, rules, policy)
}

async fn reopen(db: &crlt::Db, rules: crlt::Db, key_seed: u8, now: u64) -> SqlPolicy {
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(ROOT).unwrap()),
        ROOT,
        key(key_seed),
        day(now),
    )
    .await
    .unwrap();
    Policy::open(
        crbk::LibsqlStore::new(rules),
        LibsqlStore::new(db, ROOT).unwrap(),
        signer,
    )
    .await
    .unwrap()
}

fn charter(ring: &csgn::KeyRing) -> cchr::Charter {
    cchr::Charter::new(cchr::Configuration {
        origin: "https://root.example.test".into(),
        community: ROOT.into(),
        key_ring: ring.to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap()
}

fn decoded(view: &cchr::VerifiedCharter, now: u64) -> RootBoardPublicKey {
    assert!(now < view.valid_until());
    let material = view.root_board().unwrap();
    let payload: cbcn::root_board::Payload = serde_json::from_slice(material.payload()).unwrap();
    let descriptor = RootBoardPublicKey::from_bytes(&payload.descriptor).unwrap();
    assert_eq!(descriptor.to_bytes(), payload.descriptor);
    assert_eq!(
        descriptor.community().as_bytes(),
        view.community().as_bytes()
    );
    assert_eq!(descriptor.policy_epoch(), view.policy_epoch());
    assert!(descriptor.cohort_start() <= now && now < descriptor.expires_at());
    assert!(material.valid_until() <= descriptor.expires_at());
    descriptor
}

#[tokio::test]
async fn actual_signer_beacon_charter_and_original_codec_survive_sql_reopen() {
    let (_directory, db, rules, mut policy) = setup().await;
    assert!(policy.root_board_publication(NOW).await.unwrap().is_none());
    assert!(policy.root_board_descriptor(NOW).await.unwrap().is_none());
    let before = policy.trust_feed(NOW).await.unwrap();
    assert!(before.root_board.is_none());
    assert!(
        serde_json::to_value(&*before)
            .unwrap()
            .get("root_board")
            .is_none()
    );
    let ring = policy.key_ring().unwrap().clone();
    let common = descriptor(&issuer(801), policy.epoch(NOW).await.unwrap(), 0);
    let original = policy.publish_root_board(&common, NOW).await.unwrap();
    let (current, until) = policy.root_board_descriptor(NOW).await.unwrap().unwrap();
    assert!(current == common);
    assert_eq!(
        until,
        policy
            .key_ring()
            .unwrap()
            .verify(&original, csgn::Kind::SettingsSnapshot, NOW)
            .unwrap()
            .valid_until()
    );
    assert!(policy.root_board_descriptor(until).await.is_err());
    let feed = policy.trust_feed(NOW).await.unwrap();
    assert_eq!(feed.root_board.as_ref(), Some(&original));
    assert_eq!(policy.trust_feed(NOW + 1).await.unwrap(), feed);
    let mut device = charter(&ring);
    let view = device
        .install(&serde_json::to_vec(&*feed).unwrap(), NOW)
        .unwrap();
    assert!(decoded(view, NOW) == common);
    assert_eq!(view.root_board().unwrap().signed_bytes(), original);
    assert_eq!(view.root_board().unwrap().revision(), 1);
    let manifest: TrustManifest = serde_json::from_slice(
        ring.verify(&feed.manifest, csgn::Kind::SettingsSnapshot, NOW)
            .unwrap()
            .payload(),
    )
    .unwrap();
    assert_eq!(manifest.root_board_revision, Some(1));
    // Export only real public material for replay by the device-side CI suites.
    if let Ok(directory) = std::env::var("CPLC_ROOT_BOARD_VECTOR_DIR") {
        let directory = std::path::Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join("root-board-public.bin"), common.to_bytes()).unwrap();
        std::fs::write(
            directory.join("root-board-feed.json"),
            serde_json::to_vec(&*feed).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join("root-board-anchor.json"),
            serde_json::to_vec(&json!({
            "community":ROOT,"key_ring":ring.to_cbor(),"now":NOW}))
            .unwrap(),
        )
        .unwrap();
    }
    let mut reopened = reopen(&db, rules, 1, NOW).await;
    assert!(policy.root_board_publication(NOW).await.is_err());
    assert_eq!(
        reopened.root_board_publication(NOW).await.unwrap(),
        Some(original.clone())
    );
    let reopened_feed = reopened.trust_feed(NOW).await.unwrap();
    assert_eq!(reopened_feed.root_board, Some(original));
    assert!(
        decoded(
            device
                .install(&serde_json::to_vec(&*reopened_feed).unwrap(), NOW)
                .unwrap(),
            NOW
        ) == common
    );
}

#[tokio::test]
async fn signing_rotation_and_epoch_invalidation_preserve_the_common_issuer() {
    let (_directory, db, rules, mut policy) = setup().await;
    let key = issuer(804);
    let common = descriptor(&key, policy.epoch(NOW).await.unwrap(), 0);
    policy.publish_root_board(&common, NOW).await.unwrap();
    let ring = policy.key_ring().unwrap().clone();
    let mut device = charter(&ring);
    device
        .install(
            &serde_json::to_vec(&*policy.trust_feed(NOW).await.unwrap()).unwrap(),
            NOW,
        )
        .unwrap();
    policy.rotate(common::key(2), NOW).await.unwrap();
    let rotated = policy.trust_feed(NOW).await.unwrap();
    assert_eq!(rotated.key_transitions.len(), 1);
    let view = device
        .install(&serde_json::to_vec(&*rotated).unwrap(), NOW)
        .unwrap();
    assert!(decoded(view, NOW) == common);
    policy.bump_epoch().await.unwrap();
    assert!(policy.root_board_publication(NOW).await.is_err());
    assert!(policy.trust_feed(NOW).await.is_err());
    assert!(policy.publish_root_board(&common, NOW).await.is_err());
    let next = descriptor(&key, policy.epoch(NOW).await.unwrap(), 0);
    policy.publish_root_board(&next, NOW).await.unwrap();
    let mut reopened = reopen(&db, rules, 2, NOW).await;
    let updated = reopened.trust_feed(NOW).await.unwrap();
    assert!(
        decoded(
            device
                .install(&serde_json::to_vec(&*updated).unwrap(), NOW)
                .unwrap(),
            NOW
        ) == next
    );
    assert!(
        reopened
            .publish_root_board(&descriptor(&issuer(805), next.policy_epoch(), 0), NOW)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn fixed_cohort_clips_deadline_and_rollover_retains_the_issuer_and_floor() {
    let (_directory, db, rules, mut policy) = setup().await;
    let key = issuer(806);
    let epoch = policy.epoch(NOW).await.unwrap();
    let first = descriptor(&key, epoch, 0);
    let late = ROOT_BOARD_COHORT_SECONDS - 10;
    policy.publish_root_board(&first, late).await.unwrap();
    let mut device = charter(policy.key_ring().unwrap());
    let feed = policy.trust_feed(late).await.unwrap();
    assert_eq!(
        device
            .install(&serde_json::to_vec(&*feed).unwrap(), late)
            .unwrap()
            .valid_until(),
        ROOT_BOARD_COHORT_SECONDS
    );
    assert!(
        policy
            .root_board_publication(ROOT_BOARD_COHORT_SECONDS)
            .await
            .is_err()
    );
    assert_eq!(
        device.current(ROOT_BOARD_COHORT_SECONDS).unwrap_err(),
        cchr::Error::Expired
    );
    let second = descriptor(&key, epoch, ROOT_BOARD_COHORT_SECONDS);
    policy
        .publish_root_board(&second, ROOT_BOARD_COHORT_SECONDS)
        .await
        .unwrap();
    policy.bump_epoch().await.unwrap();
    let epoch = policy.epoch(ROOT_BOARD_COHORT_SECONDS).await.unwrap();
    let mut reopened = reopen(&db, rules, 1, ROOT_BOARD_COHORT_SECONDS).await;
    // A caller's regressed time makes the old cohort live, but cannot lower its durable floor.
    assert!(
        reopened
            .publish_root_board(&descriptor(&key, epoch, 0), NOW)
            .await
            .is_err()
    );
    let second = descriptor(&key, epoch, ROOT_BOARD_COHORT_SECONDS);
    reopened
        .publish_root_board(&second, ROOT_BOARD_COHORT_SECONDS)
        .await
        .unwrap();
    let feed = reopened
        .trust_feed(ROOT_BOARD_COHORT_SECONDS)
        .await
        .unwrap();
    assert!(
        decoded(
            device
                .install(
                    &serde_json::to_vec(&*feed).unwrap(),
                    ROOT_BOARD_COHORT_SECONDS
                )
                .unwrap(),
            ROOT_BOARD_COHORT_SECONDS
        ) == second
    );
}

#[path = "root_board/refusals.rs"]
mod refusals;
