//! The Edge's Valkey ACL user (docs/impl/phase1-spec.md §17 step 2, §19,
//! docs/10 VK-02 / VK-06; WP-E1b): with exactly the selectors of §17,
//!
//! ```text
//! ACL SETUSER edge on >… resetkeys resetchannels -@all +get +set +mget +evalsha
//!   +script|load +ping +xadd +time +select +client|setinfo +client|setname
//!   %R~mg:v:* ~mg:rl:* ~mg:n:* %W~mg:ev
//! ```
//!
//! every operation of the Edge's state layer works (connect: `PING` +
//! `SCRIPT LOAD`; round trip 1: `MGET` verdicts + `EVALSHA mg_gcra`; round
//! trip 2: `EVALSHA mg_nonce_issue`; `XADD mg:ev`), and each forbidden
//! operation is refused: writing `mg:v:*` (also from inside a script),
//! reading `mg:rev:*` or `mg:ev`, `PUBLISH`, `SCRIPT FLUSH` / `KILL`,
//! `FLUSHALL`, `CONFIG`, `EVAL`, `KEYS`, `DEL`. This answers the §19 open
//! question for Valkey 9: the `%R~` / `%W~` selectors also hold for the keys
//! an `EVALSHA` script is called with (`mg_gcra` on a read-only `mg:v:*`
//! key is refused with "No permissions to access a key"), and the scripts'
//! own `TIME` needs `+time`.
//!
//! Skipped without a Valkey server. The user name, password and keys are
//! random per run; the user is deleted at the end.

mod common;

use common::valkey::Valkey;
use mg_core::gcra::GcraParams;
use mg_edge_core::state::{
    EVENT_STREAM_KEY, LimitCheck, LimiterKey, MG_GCRA_LUA, NonceIssue, NonceResult, RoundTrip1,
    StateConfig, StateHandle, StateMode, StateService, entity_key, verdict_key,
};
use redis::Commands;
use std::time::Duration;

/// The §17 selectors, verbatim.
const RULES: &str = "on resetkeys resetchannels -@all +get +set +mget +evalsha +script|load \
                     +ping +xadd +time +select +client|setinfo +client|setname \
                     %R~mg:v:* ~mg:rl:* ~mg:n:* %W~mg:ev";

const K: [u8; 32] = [9; 32];

/// Deletes the test user whatever happens.
struct User<'a> {
    vk: &'a Valkey,
    name: String,
}

impl Drop for User<'_> {
    fn drop(&mut self) {
        let mut admin = self.vk.admin();
        let _: redis::RedisResult<()> = redis::cmd("ACL")
            .arg("DELUSER")
            .arg(&self.name)
            .query(&mut admin);
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Valkey's `NOPERM` refusal (redis-rs shows it as `NoPerm: …`).
fn is_noperm(e: &redis::RedisError) -> bool {
    let text = e.to_string().to_ascii_lowercase();
    text.contains("noperm") || text.contains("no permissions")
}

async fn wait_valkey(h: &StateHandle) {
    for _ in 0..200 {
        if h.mode() == StateMode::Valkey {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the state service never connected with the ACL user: {h:?}");
}

#[test]
fn edge_acl_user_can_do_exactly_what_the_edge_needs() {
    let Some(vk) = Valkey::start() else { return };
    let name = format!("mg-edge-{}", vk.tag);
    let password = format!("pw-{}-{}", vk.tag, vk.tag);
    let mut admin = vk.admin();
    let mut setuser = redis::cmd("ACL");
    setuser.arg("SETUSER").arg(&name);
    for part in RULES.split_whitespace() {
        setuser.arg(part);
    }
    setuser.arg(format!(">{password}"));
    let () = setuser.query(&mut admin).expect("ACL SETUSER");
    let _user = User {
        vk: &vk,
        name: name.clone(),
    };

    // The Edge's URL carries the user, never the password (§8.1).
    let url = vk
        .proxy_url()
        .replacen("redis://", &format!("redis://{name}@"), 1);
    let site = vk.tag.clone();
    let config = |url: &str| {
        let mut c = StateConfig::valkey(url, K);
        c.password = Some(password.clone());
        c.timeout_ms = 1_000;
        c.connect_timeout_ms = 1_000;
        c
    };

    // A verdict the owner wrote (the Edge may only read it).
    let ip_key = verdict_key(&site, "ip", &entity_key(&K, "ip", "192.0.2.1"));
    let verdict = r#"{"type":"ip","risk":90,"expires_at_ms":9999999999999,"site_id":"x"}"#;
    let _: () = admin.pset_ex(&ip_key, verdict, 60_000).unwrap();
    let gcra = LimitCheck {
        key: LimiterKey::new(site.as_str(), "acl-test", "ip=192.0.2.1"),
        params: GcraParams::new(10, 60, 10).unwrap(),
        cost: 1,
        write: true,
    };
    let rl_key = gcra.key.redis_key(&K);

    let rt = runtime();
    rt.block_on(async {
        let (service, handle) = StateService::new(config(&url));
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(service.run(stopped));
        wait_valkey(&handle).await;

        // Round trip 1: MGET + EVALSHA mg_gcra (GET / SET mg:rl:*).
        let r = handle
            .round_trip1(RoundTrip1 {
                verdict_keys: vec![ip_key.clone()],
                limits: vec![gcra.clone()],
            })
            .await;
        assert_eq!(r.mode, StateMode::Valkey, "{r:?}");
        assert_eq!(r.verdicts[0].as_deref(), Some(verdict));
        assert!(r.limits[0].allowed);

        // Round trip 2: EVALSHA mg_nonce_issue (SET NX mg:n:*, mg:rl:*).
        let nonce = NonceIssue {
            site: site.clone(),
            nonce: [7; 16],
            ttl_ms: 60_000,
            limits: vec![LimitCheck {
                key: LimiterKey::new(site.as_str(), "acl-issue", "ip_prefix=192.0.2.0/24"),
                ..gcra.clone()
            }],
        };
        let now = 1_790_000_000_000;
        assert!(matches!(
            handle.nonce_issue(nonce.clone(), now, now).await,
            NonceResult::Fresh { .. }
        ));
        // XADD mg:ev.
        handle
            .xadd_batch(
                100_000,
                vec![vec![
                    ("v", "1".to_string()),
                    ("kind", "acl-test".to_string()),
                ]],
            )
            .await
            .expect("XADD mg:ev");

        // A second Edge (fresh local replay set) learns the reuse from
        // Valkey itself.
        let (service2, handle2) = StateService::new(config(&url));
        let (stop2, stopped2) = tokio::sync::watch::channel(false);
        let task2 = tokio::spawn(service2.run(stopped2));
        wait_valkey(&handle2).await;
        assert_eq!(
            handle2.nonce_issue(nonce, now, now).await,
            NonceResult::Reused
        );
        stop.send_replace(true);
        stop2.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), task2).await;
    });
    let exists: bool = admin.exists(&rl_key).unwrap();
    assert!(exists, "the script wrote the limiter state");

    // Forbidden operations, as the Edge's user.
    let user_url = vk
        .proxy_url()
        .replacen("redis://", &format!("redis://{name}:{password}@"), 1);
    let mut edge = redis::Client::open(user_url)
        .unwrap()
        .get_connection()
        .unwrap();
    let _: String = redis::cmd("PING").query(&mut edge).unwrap();
    let gcra_sha = redis::Script::new(MG_GCRA_LUA).get_hash().to_owned();
    let forbidden: Vec<(&str, redis::Cmd)> = vec![
        ("SET mg:v:*", {
            let mut c = redis::cmd("SET");
            c.arg(&ip_key).arg("{}");
            c
        }),
        ("script write to mg:v:*", {
            let mut c = redis::cmd("EVALSHA");
            c.arg(&gcra_sha)
                .arg(1)
                .arg(&ip_key)
                .arg(1)
                .arg(1_000_000)
                .arg(1)
                .arg(1)
                .arg(1);
            c
        }),
        ("GET mg:rev:*", {
            let mut c = redis::cmd("GET");
            c.arg(format!("mg:rev:{site}"));
            c
        }),
        ("GET mg:ev", {
            let mut c = redis::cmd("GET");
            c.arg(EVENT_STREAM_KEY);
            c
        }),
        ("XRANGE mg:ev", {
            let mut c = redis::cmd("XRANGE");
            c.arg(EVENT_STREAM_KEY).arg("-").arg("+");
            c
        }),
        ("XADD elsewhere", {
            let mut c = redis::cmd("XADD");
            c.arg(format!("mg:other:{site}")).arg("*").arg("a").arg("b");
            c
        }),
        ("PUBLISH", {
            let mut c = redis::cmd("PUBLISH");
            c.arg("mg:pub:cfg").arg("x");
            c
        }),
        ("SCRIPT FLUSH", {
            let mut c = redis::cmd("SCRIPT");
            c.arg("FLUSH");
            c
        }),
        ("SCRIPT KILL", {
            let mut c = redis::cmd("SCRIPT");
            c.arg("KILL");
            c
        }),
        ("FLUSHALL", redis::cmd("FLUSHALL")),
        ("CONFIG GET", {
            let mut c = redis::cmd("CONFIG");
            c.arg("GET").arg("maxmemory");
            c
        }),
        ("EVAL", {
            let mut c = redis::cmd("EVAL");
            c.arg("return 1").arg(0);
            c
        }),
        ("KEYS", {
            let mut c = redis::cmd("KEYS");
            c.arg("mg:*");
            c
        }),
        ("DEL mg:rl:*", {
            let mut c = redis::cmd("DEL");
            c.arg(&rl_key);
            c
        }),
    ];
    for (what, cmd) in forbidden {
        let r: redis::RedisResult<redis::Value> = cmd.query(&mut edge);
        match r {
            Err(e) => assert!(is_noperm(&e), "{what}: {e}"),
            Ok(v) => panic!("{what} was allowed: {v:?}"),
        }
    }
    // The verdict is unchanged and the limiter state still exists.
    let v: String = admin.get(&ip_key).unwrap();
    assert_eq!(v, verdict);
    let exists: bool = admin.exists(&rl_key).unwrap();
    assert!(exists);
    let _: () = admin.del(&[ip_key.as_str(), rl_key.as_str()]).unwrap();
}
