use super::*;

#[tokio::test]
async fn authenticated_transport_is_not_a_decoded_credential_capability() {
    let (_directory, _db, _rules, mut policy) = setup().await;
    let common = descriptor(&issuer(807), policy.epoch(NOW).await.unwrap(), 0);
    policy.publish_root_board(&common, NOW).await.unwrap();
    let feed = policy.trust_feed(NOW).await.unwrap();
    let ring = policy.key_ring().unwrap().clone();
    let mut value = serde_json::to_value(&*feed).unwrap();
    let signed = ring
        .verify(
            feed.root_board.as_ref().unwrap(),
            csgn::Kind::SettingsSnapshot,
            NOW,
        )
        .unwrap();
    let mut payload: cbcn::root_board::Payload = serde_json::from_slice(signed.payload()).unwrap();
    payload.descriptor = vec![0xff];
    let mut fixture_signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        ROOT,
        key(1),
        day(NOW),
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    assert_eq!(fixture_signer.key_ring().unwrap(), &ring);
    value["root_board"] = json!(
        fixture_signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&payload).unwrap(),
                day(NOW),
                signed.valid_until()
            )
            .await
            .unwrap()
    );
    let mut device = charter(&ring);
    let view = device
        .install(&serde_json::to_vec(&value).unwrap(), NOW)
        .unwrap();
    let authenticated: cbcn::root_board::Payload =
        serde_json::from_slice(view.root_board().unwrap().payload()).unwrap();
    assert_eq!(authenticated.descriptor, vec![0xff]);
    assert!(RootBoardPublicKey::from_bytes(&authenticated.descriptor).is_err());
}

#[tokio::test]
async fn failed_actual_sql_cas_requires_reopen_and_preserves_prior_publication() {
    let (directory, db, rules, mut policy) = setup().await;
    let common = descriptor(&issuer(810), policy.epoch(NOW).await.unwrap(), 0);
    let original = policy.publish_root_board(&common, NOW).await.unwrap();
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    let connection = raw.connect().unwrap();
    connection.execute_batch("CREATE TRIGGER stop_root BEFORE UPDATE ON cplc_policy WHEN json_extract(NEW.document, '$.root_board.revision') > 1 BEGIN SELECT RAISE(ABORT, 'fault'); END;").await.unwrap();
    assert!(policy.publish_root_board(&common, NOW).await.is_err());
    assert!(matches!(
        policy.root_board_publication(NOW).await,
        Err(Error::ReloadRequired)
    ));
    assert!(policy.trust_feed(NOW).await.is_err());
    connection
        .execute_batch("DROP TRIGGER stop_root;")
        .await
        .unwrap();
    let mut reopened = reopen(&db, rules, 1, NOW).await;
    assert_eq!(
        reopened.root_board_publication(NOW).await.unwrap(),
        Some(original)
    );
    reopened.publish_root_board(&common, NOW).await.unwrap();
    let feed = reopened.trust_feed(NOW).await.unwrap();
    let mut device = charter(reopened.key_ring().unwrap());
    assert!(
        decoded(
            device
                .install(&serde_json::to_vec(&*feed).unwrap(), NOW)
                .unwrap(),
            NOW
        ) == common
    );
}
