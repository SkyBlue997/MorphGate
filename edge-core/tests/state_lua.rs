//! The Lua scripts on a real Valkey (spec §9.7; WP-C3 tests in §15):
//! `mg_gcra` agrees with `mg_core::gcra_check` on every case of
//! `core/testdata/gcra-cases.json` (explicit `now_us`); `mg_nonce_issue` v2
//! is tested in `state_phase2.rs`.
//!
//! Skipped (with `SKIPPED: …`) without a Valkey server; see
//! `mg_edge_core::testkit::valkey::ValkeyFixture`.

use mg_core::gcra::{GcraOutcome, GcraParams, gcra_check};
use mg_edge_core::state::{MG_GCRA_LUA, MG_JTI_LUA, MG_NONCE_ISSUE_V2_LUA};
use mg_edge_core::testkit::valkey::ValkeyFixture;
use redis::aio::MultiplexedConnection;
use redis::{Script, Value};
use serde_json::Value as Json;

const CASES: &str = include_str!("../../core/testdata/gcra-cases.json");

async fn connect(fx: &ValkeyFixture) -> MultiplexedConnection {
    redis::Client::open(fx.url())
        .expect("fixture url")
        .get_multiplexed_async_connection()
        .await
        .expect("connect to valkey")
}

fn ints(v: Value) -> Vec<i64> {
    match v {
        Value::Array(items) => items
            .into_iter()
            .map(|i| match i {
                Value::Int(n) => n,
                other => panic!("non-integer item {other:?}"),
            })
            .collect(),
        other => panic!("not an array: {other:?}"),
    }
}

fn triple(o: &GcraOutcome) -> [i64; 3] {
    [
        i64::from(o.allowed),
        o.retry_after_us as i64,
        o.tat_minus_now_us as i64,
    ]
}

async fn get(conn: &mut MultiplexedConnection, key: &str) -> Option<String> {
    redis::cmd("GET").arg(key).query_async(conn).await.unwrap()
}

async fn pttl(conn: &mut MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("PTTL").arg(key).query_async(conn).await.unwrap()
}

async fn set_state(conn: &mut MultiplexedConnection, key: &str, tat: Option<u64>) {
    match tat {
        Some(t) => redis::cmd("SET")
            .arg(key)
            .arg(t.to_string())
            .arg("PX")
            .arg(600_000)
            .exec_async(conn)
            .await
            .unwrap(),
        None => redis::cmd("DEL").arg(key).exec_async(conn).await.unwrap(),
    }
}

/// §9.7: `mg_gcra` and `gcra_check` agree bit for bit on the shared table,
/// for write 1 and write 0, and the stored TAT is a plain decimal integer
/// (`string.format('%d')`, never scientific notation) with a matching `PX`.
#[tokio::test]
async fn mg_gcra_matches_gcra_check_on_every_case() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let mut conn = connect(&fx).await;
    let script = Script::new(MG_GCRA_LUA);
    let doc: Json = serde_json::from_str(CASES).unwrap();
    let cases = doc["checks"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for (i, c) in cases.iter().enumerate() {
        let name = c["name"].as_str().unwrap();
        let p = GcraParams {
            interval_us: c["interval_us"].as_u64().unwrap(),
            burst: c["burst"].as_u64().unwrap() as u32,
        };
        let cost = c["cost"].as_u64().unwrap() as u32;
        let stored = c["stored_tat_us"].as_u64();
        let now = c["now_us"].as_u64().unwrap();
        assert_ne!(now, 0, "{name}: 0 means the server clock");
        let expected = gcra_check(&p, stored, now, cost);
        assert_eq!(expected.allowed, c["allowed"].as_bool().unwrap(), "{name}");
        for write in [0u8, 1] {
            let key = format!("mg:rl:{}:case{i}:{write}", fx.site());
            set_state(&mut conn, &key, stored).await;
            let out: Value = script
                .key(&key)
                .arg(now)
                .arg(p.interval_us)
                .arg(p.burst)
                .arg(cost)
                .arg(write)
                .invoke_async(&mut conn)
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(ints(out), triple(&expected), "{name} write={write}");
            let after = get(&mut conn, &key).await;
            match (write, expected.new_tat_us) {
                (1, Some(new_tat)) => {
                    assert_eq!(
                        after.as_deref(),
                        Some(new_tat.to_string().as_str()),
                        "{name}"
                    );
                    let ttl_ms = (new_tat - now).div_ceil(1000).max(1) as i64;
                    let left = pttl(&mut conn, &key).await;
                    assert!(
                        left > 0 && left <= ttl_ms,
                        "{name}: PTTL {left} vs {ttl_ms}"
                    );
                }
                _ => assert_eq!(
                    after,
                    stored.map(|t| t.to_string()),
                    "{name}: state unchanged"
                ),
            }
        }
    }
}

/// One invocation with every case as a separate key returns the same
/// triples in order (the multi-key ARGV layout of §9.7).
#[tokio::test]
async fn mg_gcra_multi_key_layout() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let mut conn = connect(&fx).await;
    let doc: Json = serde_json::from_str(CASES).unwrap();
    // One shared `now` per invocation: take the cases with the common now.
    let now = 1_790_000_000_000_000u64;
    let cases: Vec<&Json> = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["now_us"].as_u64() == Some(now))
        .collect();
    assert!(cases.len() >= 5);
    let script = Script::new(MG_GCRA_LUA);
    let mut inv = script.prepare_invoke();
    let mut expected = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let key = format!("mg:rl:{}:multi{i}", fx.site());
        set_state(&mut conn, &key, c["stored_tat_us"].as_u64()).await;
        inv.key(key);
        let p = GcraParams {
            interval_us: c["interval_us"].as_u64().unwrap(),
            burst: c["burst"].as_u64().unwrap() as u32,
        };
        expected.extend(triple(&gcra_check(
            &p,
            c["stored_tat_us"].as_u64(),
            now,
            c["cost"].as_u64().unwrap() as u32,
        )));
    }
    inv.arg(now);
    for c in &cases {
        inv.arg(c["interval_us"].as_u64().unwrap())
            .arg(c["burst"].as_u64().unwrap())
            .arg(c["cost"].as_u64().unwrap())
            .arg(1);
    }
    let out: Value = inv.invoke_async(&mut conn).await.unwrap();
    assert_eq!(ints(out), expected);
}

/// `now_us = 0` uses the server clock (production calls).
#[tokio::test]
async fn mg_gcra_zero_now_uses_server_time() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let mut conn = connect(&fx).await;
    let key = format!("mg:rl:{}:clock", fx.site());
    let out: Value = Script::new(MG_GCRA_LUA)
        .key(&key)
        .arg(0)
        .arg(1_000_000)
        .arg(5)
        .arg(1)
        .arg(1)
        .invoke_async(&mut conn)
        .await
        .unwrap();
    assert_eq!(ints(out), [1, 0, 1_000_000]);
    let (secs, micros): (u64, u64) = redis::cmd("TIME").query_async(&mut conn).await.unwrap();
    let server_now = secs * 1_000_000 + micros;
    let tat: u64 = get(&mut conn, &key).await.unwrap().parse().unwrap();
    assert!(
        tat > server_now && tat <= server_now + 1_000_000 + 1_000,
        "tat {tat} server {server_now}"
    );
}

// `mg_nonce_issue` v1 was removed with the stage 2 switch (Phase 2 spec
// §2.3, ruling I-52); v2 is tested in `state_phase2.rs`.

/// The SHA-1s the Edge uses for `EVALSHA` are the ones `SCRIPT LOAD` returns.
#[tokio::test]
async fn script_load_returns_the_expected_sha() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let mut conn = connect(&fx).await;
    for src in [MG_GCRA_LUA, MG_NONCE_ISSUE_V2_LUA, MG_JTI_LUA] {
        let sha: String = redis::cmd("SCRIPT")
            .arg("LOAD")
            .arg(src)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(sha, Script::new(src).get_hash());
    }
}
