//! Original Policy test construction using real SQL and signer owners.
use cplc::{crbk, crlt, csgn, cshm, *};
use serde_json::json;
pub const COMMUNITY: &str = "example";
pub const NOW: u64 = 100;
pub type SqlPolicy = Policy<crbk::LibsqlStore, LibsqlStore, csgn::LibsqlStore>;
pub fn key(seed: u8) -> csgn::SecretKey {
    csgn::SecretKey::from_seed(&mut [seed; 32])
}

pub fn config() -> Config {
    Config {
        credential_action: "admit".into(),
        snapshot_validity: DAY,
    }
}

pub fn schema(version: u32) -> cshm::Schema {
    serde_json::from_value(json!({"community": COMMUNITY, "version": version,
        "public": [{"id": "weekends", "label": "Do weekends suit you?", "kind": {"type":"yes_no"}, "required": true,
        "filterable": true, "change_preset": "stable", "no_contact_details": false}], "private": []})).unwrap()
}

pub fn requirement(gate: &str, level: crbk::GateLevel) -> crbk::Requirement {
    crbk::Requirement {
        gate: gate.into(),
        level,
        provider: None,
    }
}

pub fn admission() -> crbk::ActionPolicy {
    crbk::ActionPolicy {
        all_of: vec![requirement("development", crbk::GateLevel::Community)],
        ..Default::default()
    }
}

pub fn book(policy: crbk::ActionPolicy) -> crbk::Rulebook {
    use crbk::*;
    let mut book = Rulebook::default();
    for (gate, level) in [
        ("development", GateLevel::Community),
        ("voucher", GateLevel::Community),
        ("phone", GateLevel::Global),
    ] {
        for key in [gate_key(level, gate), provider_key(level, gate, "test")] {
            book.define(
                key,
                Setting {
                    value_type: SettingType::Boolean,
                    nullable: true,
                    default: json!(true),
                    bounds: Bounds::default(),
                    lowest_layer: Layer::Community,
                    kind: SettingKind::Technical,
                },
            )
            .unwrap();
        }
    }
    book.define(
        action_key("admit"),
        Setting {
            value_type: SettingType::Policy,
            nullable: true,
            default: serde_json::to_value(policy).unwrap(),
            bounds: Bounds::default(),
            lowest_layer: Layer::Community,
            kind: SettingKind::Technical,
        },
    )
    .unwrap();
    book.define(
        "quota",
        Setting {
            value_type: SettingType::Integer,
            nullable: true,
            default: json!(10),
            bounds: Bounds {
                min: Some(0.into()),
                max: Some(100.into()),
            },
            lowest_layer: Layer::Member,
            kind: SettingKind::Template,
        },
    )
    .unwrap();
    book
}

pub fn change(rulebook: crbk::Rulebook, epoch: u64, effective_at: i64) -> crbk::Change {
    crbk::Change {
        rulebook,
        announced_at: NOW as i64,
        effective_at,
        notice_seconds: 0,
        policy_epoch: epoch,
    }
}

pub fn migrations() -> Vec<crlt::Migration<'static>> {
    vec![
        crlt::Migration::new(1, "rulebook", crbk::SCHEMA),
        crlt::Migration::new(2, "signing", csgn::SCHEMA),
        crlt::Migration::new(3, "policy", SCHEMA),
    ]
}

pub async fn databases(url: &str, token: &str) -> (crlt::Db, crlt::Db) {
    let db = crlt::Db::open(crlt::Config::new(url, token)).await.unwrap();
    db.migrate(&migrations()).await.unwrap();
    let rules_db = db.clone();
    (db, rules_db)
}

pub async fn sql_policy(db: &crlt::Db, rules_db: &crlt::Db, community: &str) -> SqlPolicy {
    let signer = csgn::PersistentSigner::create(
        csgn::LibsqlStore::new(db.community(community).unwrap()),
        community,
        key(1),
        day(NOW),
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    Policy::create(
        crbk::LibsqlStore::new(rules_db.clone()),
        LibsqlStore::new(db, community).unwrap(),
        signer,
        config(),
    )
    .await
    .unwrap()
}
