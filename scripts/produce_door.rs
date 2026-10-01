//! CI-only example inserted in the current cvld main checkout.
#[path = "../tests/support/mod.rs"]
mod support;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use support::*;
fn save(name: &str, value: &Value) {
    let dir = std::env::var("CHARTER_FIXTURES").unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        format!("{dir}/{name}.json"),
        serde_json::to_vec(value).unwrap(),
    )
    .unwrap();
}
fn unchanged(stage: &str, initial: &Value, current: Value) {
    save(stage, &current);
    let changed: Vec<_> = initial.as_object().unwrap().keys().filter(|key| initial[*key] != current[*key]).collect();
    assert!(changed.is_empty(), "public feed changed after {stage}; sections {changed:?}");
}
fn save_bundle(name: &str, credential: Vec<u8>, member: &str, schema_version: u32) {
    // Match the actual signer authorized by the current door's enrollment helper.
    let device = SigningKey::from_bytes(&[13; 32]);
    let payload = serde_json::to_vec(&cgrd::BundleContent {
        community: "alpha".into(),
        member: member.into(),
        device: device.verifying_key().to_bytes(),
        credential,
        profile: cgrd::Profile::Public(cmty::cplc::cshm::PublicProfile {
            community: "alpha".into(),
            schema_version,
            public: Default::default(),
        }),
        openings: vec![],
    })
    .unwrap();
    let signature = device.sign(&cgrd::binding_bytes(&payload)).to_bytes().to_vec();
    save(name, &json!({"action":cmty::ADMISSION_ACTION,"bundle":{"payload":payload,"signature":signature}}));
}
#[tokio::main]
async fn main() {
    let global = global(1000).await;
    let (_, passport, public) = wallet_passport(&global).await;
    let community = community_with_burst("alpha", &public, 1000).await;
    // Provision verification from the actual deployment configuration before any response.
    let config: cvld::config::CommunityConfig = serde_json::from_slice(
        &std::fs::read(community.dir.path().join("config.json")).unwrap(),
    ).unwrap();
    let mut seed: [u8; 32] = std::fs::read(&config.signing_seed_file).unwrap().try_into().unwrap();
    let configured = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "alpha",
        csgn::SecretKey::from_seed(&mut seed),
        cmty::cplc::day(NOW),
        config.signer_max_seconds,
    ).await.unwrap();
    save("publishing-root", &json!({"key_ring":configured.key_ring().unwrap().to_cbor(),"minimum_revision":1}));
    let host = "api.alpha.example.test";
    let public_client = client(&community, host, None);
    let initial = public_client.call("trust_feed", json!({})).await.unwrap();
    save("initial", &initial);
    let member = enrol_community(&community, host, &passport).await;
    assert_eq!(member.signing_key, SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes());
    unchanged("after-enrollment", &initial, public_client.call("trust_feed", json!({})).await.unwrap());
    let member_client = client(&community, host, Some(&member.session));
    member_client.call("lobby", json!({})).await.unwrap();
    unchanged("after-lobby", &initial, public_client.call("trust_feed", json!({})).await.unwrap());
    member_client
        .call("handle_reserve", json!({"handle":"charter_member"}))
        .await
        .unwrap();
    let pseudonym = passport
        .pseudonym(&cpsd::CommunityId::new(b"alpha").unwrap())
        .to_hex();
    member_client
        .call(
            "gate_voucher",
            voucher("alpha", &pseudonym, "charter-voucher", NOW + 172800),
        )
        .await
        .unwrap();
    unchanged("after-voucher", &initial, public_client.call("trust_feed", json!({})).await.unwrap());
    for _ in 0..2 {
        let issued = issue_community(&community, host, &member, &passport).await;
        assert!(
            issued.credential.is_some(),
            "real admission and renewal must succeed"
        );
    }
    let ordinary = public_client.call("trust_feed", json!({})).await.unwrap();
    unchanged("ordinary", &initial, ordinary);
    let admin = enrol(
        &community,
        "api.admin.alpha.example.test",
        Some("synthetic-admin-enrolment-capability"),
    )
    .await;
    let admin_client = client(
        &community,
        "api.admin.alpha.example.test",
        Some(&admin.session),
    );
    for (offset, shape) in [(1, "all"), (2, "any"), (3, "threshold")] {
        community.clock.set(NOW + offset);
        let req = json!({"gate":"cvch","level":"community","provider":null});
        let mut policy =
            json!({"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":[]});
        match shape {
            "all" => policy["all_of"] = json!([req]),
            "any" => policy["any_of"] = json!([req]),
            _ => policy["k_of_n"] = json!({"k":1,"of":[req]}),
        }
        let current = admin_client.call("setting_set",json!({"key":cmty::cplc::crbk::action_key(cmty::ADMISSION_ACTION),"value":policy,"inherit":false,"effective_at":NOW+offset})).await.unwrap();
        save(shape, &current);
        let issued = issue_community(&community, host, &member, &passport).await;
        save_bundle(&format!("{shape}-bundle"), issued.credential.unwrap(), &pseudonym, 1);
        let change = public_client
            .call("trust_changes", json!({"revision":initial["revision"]}))
            .await
            .unwrap();
        assert_eq!(change["changed"], true);
        assert_eq!(change["revision"], current["revision"]);
        save(&format!("{shape}-announcement"), &change);
    }
    let schema = admin_client
        .call("schema_set", json!({"schema":community_schema("alpha",2)}))
        .await
        .unwrap();
    save("schema", &schema);
    let renewed = issue_community(&community, host, &member, &passport).await;
    save_bundle("schema-bundle", renewed.credential.unwrap(), &pseudonym, 2);
    let announcement = public_client
        .call("trust_changes", json!({"revision":initial["revision"]}))
        .await
        .unwrap();
    save("schema-announcement", &announcement);
    member_client
        .call("passkey_revoke", json!({"credential":member.credential}))
        .await
        .unwrap();
    let revoked = public_client.call("trust_feed", json!({})).await.unwrap();
    assert!(revoked["policy_epoch"].as_u64().unwrap() > schema["policy_epoch"].as_u64().unwrap());
    save("revoked", &revoked);
    let announcement = public_client
        .call("trust_changes", json!({"revision":schema["revision"]}))
        .await
        .unwrap();
    save("revoked-announcement", &announcement);
    println!(
        "Real cvld HTTP: ordinary activity stable; all/any/threshold, schema and revocation publications captured"
    );
}
