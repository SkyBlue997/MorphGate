//! Phase 2 state layer (docs/impl/phase2-spec.md §9.2, §14; WP-C5 tests in
//! §17): `mg_nonce_issue` v2 and `mg_jti` v1 byte-for-byte as specified and
//! on a real Valkey under the Edge's §14.5 ACL user, `StateHandle`'s new
//! entry points (`round_trip1_v2`, `nonce_issue_v2`) across two Edges and
//! with Valkey down, and the local-mode rules (D-35, the start-time rule of
//! the local `jti` verdict).
//!
//! Valkey tests are skipped (with `SKIPPED: …`) without a server; the
//! local-mode tests always run.

use std::time::{Duration, Instant};

use mg_core::gcra::GcraParams;
use mg_edge_core::state::{
    JTI_PER_KEY_LIMIT, JtiCheck, JtiOutcome, LimitCheck, LimiterKey, MG_JTI_LUA,
    MG_NONCE_ISSUE_V2_LUA, NonceIssueV2, NonceResultV2, RoundTrip1V2, StateConfig, StateHandle,
    StateMode, StateService, TokenReplay, jti_count_key, jti_key, jti_key_hash, replay_key,
    token_hash,
};
use mg_edge_core::testkit::valkey::{FaultMode, FaultProxy, ValkeyFixture};
use redis::aio::MultiplexedConnection;
use redis::{Script, Value};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const SPEC: &str = include_str!("../../docs/impl/phase2-spec.md");

/// `K_pseudo` of `testdata/phase1/kat.json` (bytes 0x00..0x1f).
const K: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// The Edge's ACL rules of §14.5 (after `ACL SETUSER edge`, without the
/// password), verbatim.
const EDGE_ACL: &str = "on resetkeys resetchannels -@all +get +set +mget +evalsha +script|load \
                        +ping +xadd +time +select +client|setinfo +client|setname \
                        %R~mg:v:* ~mg:rl:* ~mg:n:* ~mg:jti:* ~mg:jc:* ~mg:rp:* %W~mg:ev";

/// A 43-character thumbprint (only its `kh` is used).
const JKT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

// ---------------------------------------------------------------------------
// The scripts are the spec's, byte for byte

/// The code block of the spec that starts with `first_line`.
fn spec_block(first_line: &str) -> String {
    let start = SPEC
        .find(&format!("```lua\n{first_line}\n"))
        .unwrap_or_else(|| panic!("no lua block starting with {first_line:?}"));
    let body = &SPEC[start + "```lua\n".len()..];
    let end = body.find("\n```").expect("closed block");
    format!("{}\n", &body[..end])
}

/// §14.2: "三个脚本都按本文逐字节实现".
#[test]
fn scripts_are_the_spec_bytes() {
    assert_eq!(MG_NONCE_ISSUE_V2_LUA, spec_block("-- mg_nonce_issue v2"));
    assert_eq!(MG_JTI_LUA, spec_block("-- mg_jti v1"));
}

#[test]
fn key_builders() {
    let kj = jti_key_hash(&K, JKT);
    assert_eq!(kj.len(), 32);
    assert!(!kj.contains(JKT));
    assert_eq!(
        jti_key("blog", &kj, "AAAAAAAAAAAAAAAAAAAAAA"),
        format!("mg:jti:blog:{kj}:AAAAAAAAAAAAAAAAAAAAAA")
    );
    assert_eq!(jti_count_key("blog", &kj), format!("mg:jc:blog:{kj}"));
    // th = lower_hex(SHA-256(token))[0..32]; SHA-256("abc") is the FIPS 180-2 vector.
    assert_eq!(token_hash("abc"), "ba7816bf8f01cfea414140de5dae2223");
    assert_eq!(
        replay_key("blog", "turnstile", &token_hash("abc")),
        "mg:rp:blog:turnstile:ba7816bf8f01cfea414140de5dae2223"
    );
    let c = JtiCheck::new("blog", &K, JKT, "AAAAAAAAAAAAAAAAAAAAAA", 5);
    assert_eq!(c.kj, kj);
    // §2.4 item 10: never the thumbprint, the jti or the token in Debug.
    let dbg = format!("{c:?}");
    assert!(!dbg.contains(JKT) && !dbg.contains(&kj) && !dbg.contains("AAAAAAAA"));
    let r = TokenReplay::new("turnstile", "secret-token-value");
    let dbg = format!("{r:?}");
    assert!(!dbg.contains("secret-token") && !dbg.contains(&r.token_hash));
    let issue = NonceIssueV2 {
        site: "blog".into(),
        nonce: [0xcd; 16],
        ttl_ms: 1,
        replay: Some(r),
        limits: vec![],
    };
    assert!(!format!("{issue:?}").contains("cdcd"));
}

// ---------------------------------------------------------------------------
// Real Valkey, Edge ACL user

/// An ACL user with the §14.5 rules, deleted on drop.
struct AclUser {
    admin_url: String,
    name: String,
    password: String,
}

impl AclUser {
    async fn create(fx: &ValkeyFixture) -> Self {
        let tag = fx.site().to_owned();
        let user = Self {
            admin_url: fx.url().to_owned(),
            name: format!("mg-edge-{tag}"),
            password: format!("pw-{tag}-{tag}"),
        };
        let mut admin = connect(fx.url()).await;
        let mut cmd = redis::cmd("ACL");
        cmd.arg("SETUSER").arg(&user.name);
        for part in EDGE_ACL.split_whitespace() {
            cmd.arg(part);
        }
        cmd.arg(format!(">{}", user.password));
        cmd.exec_async(&mut admin).await.expect("ACL SETUSER");
        user
    }

    /// The fixture URL with this user (the password goes separately).
    fn url(&self, base: &str) -> String {
        if base.starts_with("unix://") {
            let sep = if base.contains('?') { '&' } else { '?' };
            format!("{base}{sep}user={}", self.name)
        } else {
            base.replacen("redis://", &format!("redis://{}@", self.name), 1)
        }
    }

    /// A raw connection authenticated as this user.
    async fn connect(&self) -> MultiplexedConnection {
        let mut conn = connect(&self.admin_url).await;
        redis::cmd("AUTH")
            .arg(&self.name)
            .arg(&self.password)
            .exec_async(&mut conn)
            .await
            .expect("AUTH as the edge user");
        conn
    }
}

impl Drop for AclUser {
    fn drop(&mut self) {
        if let Ok(client) = redis::Client::open(self.admin_url.as_str())
            && let Ok(mut conn) = client.get_connection()
        {
            let _: redis::RedisResult<()> = redis::cmd("ACL")
                .arg("DELUSER")
                .arg(&self.name)
                .query(&mut conn);
        }
    }
}

async fn connect(url: &str) -> MultiplexedConnection {
    redis::Client::open(url)
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

async fn get(conn: &mut MultiplexedConnection, key: &str) -> Option<String> {
    redis::cmd("GET").arg(key).query_async(conn).await.unwrap()
}

async fn pttl(conn: &mut MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("PTTL").arg(key).query_async(conn).await.unwrap()
}

/// One `mg_nonce_issue` v2 call (§14.2 layout), cost 1 per limiter.
async fn nonce_v2(
    conn: &mut MultiplexedConnection,
    nonce_key: &str,
    replay: Option<&str>,
    limiters: &[(&str, u64, u32)],
    now: u64,
) -> Vec<i64> {
    let script = Script::new(MG_NONCE_ISSUE_V2_LUA);
    let mut inv = script.prepare_invoke();
    inv.key(nonce_key);
    if let Some(r) = replay {
        inv.key(r);
    }
    for (k, _, _) in limiters {
        inv.key(*k);
    }
    inv.arg(180_000)
        .arg(now)
        .arg(u8::from(replay.is_some()))
        .arg(300_000);
    for (_, interval, burst) in limiters {
        inv.arg(*interval).arg(*burst).arg(1);
    }
    ints(inv.invoke_async(conn).await.expect("mg_nonce_issue v2"))
}

/// §14.2 on a real Valkey as the Edge user: nonce reused `{0}`; a used
/// provider token `{2}` with the nonce consumed and no quota spent; quotas
/// all-or-nothing; the renewal form (R = 0, no limiters).
#[tokio::test]
async fn mg_nonce_issue_v2_semantics() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let user = AclUser::create(&fx).await;
    let mut conn = user.connect().await;
    // Inspection (PTTL) is not the Edge's to do.
    let mut admin = connect(fx.url()).await;
    let site = fx.site();
    let now = 1_790_000_000_000_000u64;
    let ip = format!("mg:rl:{site}:mg.a11y.issue:k1");
    let ipp = format!("mg:rl:{site}:mg.a11y.issue.ipp:k2");
    // ip: burst 1 per 60 s; ipp: burst 2 per 60 s.
    let limiters = [(ip.as_str(), 60_000_000, 1), (ipp.as_str(), 30_000_000, 2)];
    let n = |b: u8| format!("mg:n:{site}:{}", format!("{b:02x}").repeat(16));
    let rp = |t: &str| replay_key(site, "turnstile", &token_hash(t));

    // First use: nonce, token and both quotas written.
    let out = nonce_v2(&mut conn, &n(1), Some(&rp("tok-1")), &limiters, now).await;
    assert_eq!(out, [1, 1, 0, 60_000_000, 1, 0, 30_000_000]);
    assert_eq!(get(&mut admin, &n(1)).await.as_deref(), Some("1"));
    let left = pttl(&mut admin, &rp("tok-1")).await;
    assert!(left > 290_000 && left <= 300_000, "replay PTTL {left}");
    assert_eq!(
        get(&mut admin, &ip).await,
        Some((now + 60_000_000).to_string())
    );

    // Nonce reused: {0}; the replay key and quotas are untouched.
    let out = nonce_v2(&mut conn, &n(1), Some(&rp("tok-9")), &limiters, now).await;
    assert_eq!(out, [0]);
    assert_eq!(get(&mut admin, &rp("tok-9")).await, None);

    // Token reused with a fresh nonce: {2}, the nonce IS consumed, no quota.
    let ipp_before = get(&mut admin, &ipp).await;
    let out = nonce_v2(&mut conn, &n(2), Some(&rp("tok-1")), &limiters, now).await;
    assert_eq!(out, [2]);
    assert_eq!(get(&mut admin, &n(2)).await.as_deref(), Some("1"));
    assert_eq!(get(&mut admin, &ipp).await, ipp_before);
    assert_eq!(
        nonce_v2(&mut conn, &n(2), Some(&rp("tok-2")), &limiters, now).await,
        [0]
    );

    // ip exhausted: ipp allows but is not written (all-or-nothing).
    let out = nonce_v2(&mut conn, &n(3), Some(&rp("tok-3")), &limiters, now).await;
    assert_eq!(out, [1, 0, 60_000_000, 60_000_000, 1, 0, 60_000_000]);
    assert_eq!(get(&mut admin, &ipp).await, ipp_before);

    // The renewal form: only the nonce (R = 0, no limiters).
    assert_eq!(nonce_v2(&mut conn, &n(4), None, &[], now).await, [1]);
    assert_eq!(nonce_v2(&mut conn, &n(4), None, &[], now).await, [0]);
    drop(user);
}

/// §14.2: concurrent double submissions of one nonce (and of one token with
/// different nonces) succeed exactly once.
#[tokio::test]
async fn mg_nonce_issue_v2_concurrent_double_submit() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let user = AclUser::create(&fx).await;
    let site = fx.site().to_owned();
    let now = 1_790_000_000_000_000u64;
    let mut tasks = Vec::new();
    for i in 0..16u8 {
        let mut conn = user.connect().await;
        let site = site.clone();
        tasks.push(tokio::spawn(async move {
            let same_nonce = format!("mg:n:{site}:{}", "ab".repeat(16));
            let other_nonce = format!("mg:n:{site}:{}", format!("{i:02x}").repeat(16));
            let token = replay_key(&site, "turnstile", &token_hash("shared-token"));
            let a = nonce_v2(&mut conn, &same_nonce, None, &[], now).await;
            let b = nonce_v2(&mut conn, &other_nonce, Some(&token), &[], now).await;
            (a, b)
        }));
    }
    let mut nonce_wins = 0;
    let mut token_wins = 0;
    for t in tasks {
        let (a, b) = t.await.unwrap();
        match a.as_slice() {
            [1] => nonce_wins += 1,
            [0] => {}
            other => panic!("unexpected {other:?}"),
        }
        match b.as_slice() {
            [1] => token_wins += 1,
            [2] => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!((nonce_wins, token_wins), (1, 1));
    drop(user);
}

async fn jti(conn: &mut MultiplexedConnection, key: &str, count_key: &str) -> Vec<i64> {
    let out = Script::new(MG_JTI_LUA)
        .key(key)
        .key(count_key)
        .arg(JTI_PER_KEY_LIMIT)
        .arg(60_000)
        .arg(40)
        .invoke_async(conn)
        .await
        .expect("mg_jti");
    ints(out)
}

/// §9.2 / §14.2 `mg_jti` v1 as the Edge user: fresh, replay, the per-key
/// quota of 600 per window (only that key), and the TTLs.
#[tokio::test]
async fn mg_jti_semantics() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let user = AclUser::create(&fx).await;
    let mut conn = user.connect().await;
    let mut admin = connect(fx.url()).await;
    let site = fx.site();
    let kj = jti_key_hash(&K, JKT);
    let other = jti_key_hash(&K, "another-thumbprint-of-43-characters-xxxxxxx");
    let count = jti_count_key(site, &kj);
    let key = |i: u32| jti_key(site, &kj, &format!("jti{i:019}"));

    assert_eq!(jti(&mut conn, &key(0), &count).await, [0]);
    let left = pttl(&mut admin, &key(0)).await;
    assert!(left > 39_000 && left <= 40_000, "jti PTTL {left}");
    let left = pttl(&mut admin, &count).await;
    assert!(left > 59_000 && left <= 60_000, "counter PTTL {left}");
    assert_eq!(jti(&mut conn, &key(0), &count).await, [1], "replay");
    // The replay counted: 2 so far; 598 more fit.
    for i in 1..=598 {
        assert_eq!(jti(&mut conn, &key(i), &count).await, [0], "jti {i}");
    }
    assert_eq!(get(&mut admin, &count).await.as_deref(), Some("600"));
    let left = pttl(&mut admin, &count).await;
    assert!(
        left > 0 && left <= 60_000,
        "KEEPTTL kept the window: {left}"
    );
    // 601st proof of this key: quota, nothing recorded.
    assert_eq!(jti(&mut conn, &key(599), &count).await, [2]);
    assert_eq!(get(&mut admin, &key(599)).await, None);
    // Another key is not affected.
    let other_count = jti_count_key(site, &other);
    let other_key = jti_key(site, &other, "jti0000000000000000000");
    assert_eq!(jti(&mut conn, &other_key, &other_count).await, [0]);
    drop(user);
}

/// The Edge user may not use the Phase 2 keys for anything else: a script
/// call with a key outside its patterns is refused.
#[tokio::test]
async fn edge_user_is_limited_to_its_key_patterns() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let user = AclUser::create(&fx).await;
    let mut conn = user.connect().await;
    let site = fx.site();
    let err = Script::new(MG_JTI_LUA)
        .key(format!("mg:rev:{site}:x"))
        .key(jti_count_key(site, "kj"))
        .arg(600)
        .arg(60_000)
        .arg(40)
        .invoke_async::<Value>(&mut conn)
        .await
        .expect_err("mg:rev:* is not the edge's");
    let text = err.to_string().to_ascii_lowercase();
    assert!(
        text.contains("noperm") || text.contains("no permissions"),
        "{text}"
    );
    drop(user);
}

// ---------------------------------------------------------------------------
// StateHandle

struct Running {
    handle: StateHandle,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Running {
    fn start(cfg: StateConfig) -> Self {
        let (service, handle) = StateService::new(cfg);
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(service.run(rx));
        Self { handle, stop, task }
    }

    async fn shutdown(self) {
        self.stop.send_replace(true);
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("service stops on shutdown")
            .expect("service task");
    }
}

async fn wait_mode(h: &StateHandle, mode: StateMode, within: Duration) -> bool {
    let end = Instant::now() + within;
    while Instant::now() < end {
        if h.mode() == mode {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    h.mode() == mode
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn limit(site: &str, limiter: &str, dims: &str, rate: u32, period: u32, burst: u32) -> LimitCheck {
    LimitCheck {
        key: LimiterKey::new(site, limiter, dims),
        params: GcraParams::new(rate, period, burst).unwrap(),
        cost: 1,
        write: true,
    }
}

fn issue(site: &str, nonce: u8, token: Option<&str>, limits: Vec<LimitCheck>) -> NonceIssueV2 {
    NonceIssueV2 {
        site: site.to_owned(),
        nonce: [nonce; 16],
        ttl_ms: 660_000,
        replay: token.map(|t| TokenReplay::new("turnstile", t)),
        limits,
    }
}

fn proof(site: &str, jti: &str, iat_s: i64) -> RoundTrip1V2 {
    RoundTrip1V2 {
        verdict_keys: vec![],
        limits: vec![],
        jti: Some(JtiCheck::new(site, &K, JKT, jti, iat_s)),
    }
}

/// Two Edges sharing one Valkey through the §14.5 ACL user: the second Edge
/// learns of a nonce, a token and a `jti` used at the first one from Valkey
/// (`mg_nonce_issue` v2 `{0}` / `{2}`, `mg_jti` `{1}`); with Valkey down
/// nothing is authoritative.
#[tokio::test]
async fn handles_across_edges_and_when_valkey_is_down() {
    let Some(fx) = ValkeyFixture::start().await else {
        return;
    };
    let user = AclUser::create(&fx).await;
    let proxy = FaultProxy::start(fx.url()).await.unwrap();
    let cfg = || {
        let mut c = StateConfig::valkey(user.url(&proxy.url()), K);
        c.password = Some(user.password.clone());
        c.timeout_ms = 1_000;
        c.connect_timeout_ms = 1_000;
        c
    };
    let a = Running::start(cfg());
    let b = Running::start(cfg());
    assert!(wait_mode(&a.handle, StateMode::Valkey, Duration::from_secs(5)).await);
    assert!(wait_mode(&b.handle, StateMode::Valkey, Duration::from_secs(5)).await);
    let site = fx.site();
    let now = now_ms();
    let quota = || vec![limit(site, "mg.a11y.issue", "ip=203.0.113.7", 6, 3600, 6)];

    // Nonce + token at A.
    let r = a
        .handle
        .nonce_issue_v2(issue(site, 1, Some("tok-a"), quota()), now, now)
        .await;
    assert!(
        matches!(&r, NonceResultV2::Fresh { limits } if limits[0].allowed),
        "{r:?}"
    );
    // B: the same nonce -> Reused; the same token, new nonce -> TokenReused.
    assert_eq!(
        b.handle
            .nonce_issue_v2(issue(site, 1, Some("tok-b"), quota()), now, now)
            .await,
        NonceResultV2::Reused
    );
    assert_eq!(
        b.handle
            .nonce_issue_v2(issue(site, 2, Some("tok-a"), quota()), now, now)
            .await,
        NonceResultV2::TokenReused
    );
    // ... and that nonce is consumed at Valkey as well.
    assert_eq!(
        a.handle
            .nonce_issue_v2(issue(site, 2, None, vec![]), now, now)
            .await,
        NonceResultV2::Reused
    );
    // Locally known replays need no round trip.
    let base = proxy.round_trips();
    assert_eq!(
        a.handle
            .nonce_issue_v2(issue(site, 3, Some("tok-a"), quota()), now, now)
            .await,
        NonceResultV2::TokenReused
    );
    assert_eq!(proxy.round_trips(), base);

    // jti: fresh at A, replay at B (from Valkey), replay at A (locally).
    let iat = now / 1000;
    let r = a
        .handle
        .round_trip1_v2(proof(site, "jti-one", iat), now)
        .await;
    assert_eq!(
        (r.mode, r.jti),
        (StateMode::Valkey, Some(JtiOutcome::Fresh))
    );
    let r = b
        .handle
        .round_trip1_v2(proof(site, "jti-one", iat), now)
        .await;
    assert_eq!(r.jti, Some(JtiOutcome::Replayed));
    let base = proxy.round_trips();
    let r = a
        .handle
        .round_trip1_v2(proof(site, "jti-one", iat), now)
        .await;
    assert_eq!(r.jti, Some(JtiOutcome::Replayed));
    assert_eq!(proxy.round_trips(), base, "the local set answers");
    // Verdicts, limiters and mg_jti travel in ONE round trip.
    let base = proxy.round_trips();
    let mut req = proof(site, "jti-two", iat);
    req.verdict_keys = vec![format!("mg:v:{site}:ip:none")];
    req.limits = vec![limit(site, "rt1", "ip=1", 10, 60, 10)];
    let r = b.handle.round_trip1_v2(req, now).await;
    assert_eq!(r.mode, StateMode::Valkey);
    assert_eq!(r.verdicts, vec![None]);
    assert!(r.limits[0].allowed);
    assert_eq!(r.jti, Some(JtiOutcome::Fresh));
    assert_eq!(proxy.round_trips(), base + 1);

    // Valkey down: no authoritative answer (local_replay_authoritative is
    // off), replays still detected locally.
    proxy.set_mode(FaultMode::Refuse);
    let r = a
        .handle
        .round_trip1_v2(proof(site, "jti-3", iat), now)
        .await;
    assert_eq!(
        (r.mode, r.jti),
        (StateMode::Local, Some(JtiOutcome::Unavailable))
    );
    let r = a
        .handle
        .round_trip1_v2(proof(site, "jti-3", iat), now)
        .await;
    assert_eq!(r.jti, Some(JtiOutcome::Replayed));
    let r = a
        .handle
        .nonce_issue_v2(issue(site, 9, Some("tok-9"), vec![]), now, now)
        .await;
    assert_eq!(r, NonceResultV2::Unavailable { limits: vec![] });
    proxy.set_mode(FaultMode::Pass);
    a.shutdown().await;
    b.shutdown().await;
    drop(user);
}

// ---------------------------------------------------------------------------
// Local mode

fn local(start_ms: i64, authoritative: bool) -> StateHandle {
    let mut cfg = StateConfig::local(K);
    cfg.local_replay_authoritative = authoritative;
    cfg.process_start_ms = start_ms;
    StateService::new(cfg).1
}

/// §9.2 "结论" without Valkey: authoritative only with
/// `local_replay_authoritative`, for proofs with `iat − 5 ≥` the process
/// start, and never while (or for proofs from before) the set was full.
#[tokio::test]
async fn local_jti_rules() {
    let start = 1_790_000_000_000;
    let now = start + 60_000;
    let iat = now / 1000;

    let h = local(start, false);
    let r = h.round_trip1_v2(proof("blog", "a", iat), now).await;
    assert_eq!(r.jti, Some(JtiOutcome::Unavailable));
    let r = h.round_trip1_v2(proof("blog", "a", iat), now).await;
    assert_eq!(
        r.jti,
        Some(JtiOutcome::Replayed),
        "replays are still caught"
    );

    let h = local(start, true);
    let r = h.round_trip1_v2(proof("blog", "a", iat), now).await;
    assert_eq!((r.mode, r.jti), (StateMode::Local, Some(JtiOutcome::Fresh)));
    let r = h.round_trip1_v2(proof("blog", "a", iat), now).await;
    assert_eq!(r.jti, Some(JtiOutcome::Replayed));
    // iat - 5 exactly at the start: still fine; one second earlier: not.
    let at_start = start / 1000 + 5;
    let r = h.round_trip1_v2(proof("blog", "b", at_start), now).await;
    assert_eq!(r.jti, Some(JtiOutcome::Fresh));
    let r = h
        .round_trip1_v2(proof("blog", "c", at_start - 1), now)
        .await;
    assert_eq!(
        r.jti,
        Some(JtiOutcome::Unavailable),
        "the proof could have been accepted before this process started"
    );
    // No proof, no jti result.
    let r = h.round_trip1_v2(RoundTrip1V2::default(), now).await;
    assert_eq!(r.jti, None);
}

#[tokio::test]
async fn local_jti_per_key_quota_and_overflow() {
    let start = 1_790_000_000_000;
    let now = start + 60_000;
    let iat = now / 1000;
    let h = local(start, true);
    for i in 0..JTI_PER_KEY_LIMIT {
        let r = h
            .round_trip1_v2(proof("blog", &format!("q{i}"), iat), now)
            .await;
        assert_eq!(r.jti, Some(JtiOutcome::Fresh), "{i}");
    }
    let r = h.round_trip1_v2(proof("blog", "q-over", iat), now).await;
    assert_eq!(r.jti, Some(JtiOutcome::KeyQuota));
    assert!(r.jti.unwrap().is_replay());
    // Another session key of the same site is unaffected.
    let mut other = proof("blog", "q-other", iat);
    other.jti = Some(JtiCheck::new("blog", &K, "other-key", "q-other", iat));
    assert_eq!(
        h.round_trip1_v2(other, now).await.jti,
        Some(JtiOutcome::Fresh)
    );

    // D-35: a full set never evicts; what it could not record is not judged.
    let mut cfg = StateConfig::local(K);
    cfg.local_replay_authoritative = true;
    cfg.process_start_ms = start;
    cfg.local_jti_capacity = 2;
    let (_s, h) = StateService::new(cfg);
    for j in ["x1", "x2"] {
        let r = h.round_trip1_v2(proof("blog", j, iat), now).await;
        assert_eq!(r.jti, Some(JtiOutcome::Fresh));
    }
    let r = h.round_trip1_v2(proof("blog", "x3", iat), now + 1).await;
    assert_eq!(r.jti, Some(JtiOutcome::Unavailable), "full");
    let r = h.round_trip1_v2(proof("blog", "x1", iat), now + 2).await;
    assert_eq!(r.jti, Some(JtiOutcome::Replayed), "live entries kept");
    // After the entries expired (40 s), proofs whose iat - 5 s predates the
    // overflow are still not judged; later ones are.
    let later = now + 41_000;
    let r = h.round_trip1_v2(proof("blog", "x3", iat), later).await;
    assert_eq!(r.jti, Some(JtiOutcome::Unavailable));
    let r = h
        .round_trip1_v2(proof("blog", "x4", later / 1000), later)
        .await;
    assert_eq!(r.jti, Some(JtiOutcome::Fresh));
}

/// §14.4: the local form of `mg_nonce_issue` v2: nonce first, then the
/// token, then the quotas (all-or-nothing); the token set follows D-35.
#[tokio::test]
async fn local_nonce_issue_v2_rules() {
    let start = 1_000_000;
    let now = 2_000_000;
    let fresh = NonceResultV2::Fresh { limits: vec![] };
    let unavailable = NonceResultV2::Unavailable { limits: vec![] };

    let h = local(start, false);
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 1, Some("t1"), vec![]), now, now)
            .await,
        unavailable
    );

    let mut cfg = StateConfig::local(K);
    cfg.local_replay_authoritative = true;
    cfg.process_start_ms = start;
    cfg.local_rp_capacity = 2;
    let (_s, h) = StateService::new(cfg);
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 1, Some("t1"), vec![]), now, 1_500_000)
            .await,
        fresh
    );
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 1, Some("t2"), vec![]), now, 1_500_000)
            .await,
        NonceResultV2::Reused
    );
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 2, Some("t1"), vec![]), now, 1_500_000)
            .await,
        NonceResultV2::TokenReused
    );
    // The nonce of the token replay is consumed.
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 2, None, vec![]), now, 1_500_000)
            .await,
        NonceResultV2::Reused
    );
    // Before the process started: not judged.
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 3, Some("t3"), vec![]), now, 999_999)
            .await,
        unavailable
    );
    // Token set full (t1, t3): t4 not recorded -> Unavailable; t1 still caught.
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 4, Some("t4"), vec![]), now + 10, 1_500_000)
            .await,
        unavailable
    );
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 5, Some("t1"), vec![]), now + 20, 1_500_000)
            .await,
        NonceResultV2::TokenReused
    );
    // A renewal (no token) is unaffected by the full token set.
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 6, None, vec![]), now + 30, 1_500_000)
            .await,
        fresh
    );
    // After the token entries expired: challenges from before the overflow
    // stay unjudged, later ones are judged again.
    let later = now + 300_001;
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 7, Some("t7"), vec![]), later, 1_500_000)
            .await,
        unavailable
    );
    assert_eq!(
        h.nonce_issue_v2(issue("blog", 8, Some("t8"), vec![]), later, now + 11)
            .await,
        fresh
    );

    // Quotas: all-or-nothing, nothing consumed on a replay.
    let quotas = || {
        vec![
            limit("blog", "mg.a11y.issue", "ip=1", 1, 3600, 1),
            limit("blog", "mg.a11y.issue.ipp", "ip_prefix=1", 2, 3600, 2),
        ]
    };
    let r = h
        .nonce_issue_v2(issue("blog", 20, None, quotas()), later, later)
        .await;
    assert!(
        matches!(&r, NonceResultV2::Fresh { limits } if limits.iter().all(|l| l.allowed)),
        "{r:?}"
    );
    let r = h
        .nonce_issue_v2(issue("blog", 21, None, quotas()), later, later)
        .await;
    assert!(
        matches!(&r, NonceResultV2::Fresh { limits } if !limits[0].allowed && limits[1].allowed),
        "{r:?}"
    );
    // ipp was not written by the refused issuance: one more ipp use fits
    // after the ip limiter is out of the way.
    let r = h
        .nonce_issue_v2(
            issue(
                "blog",
                22,
                None,
                vec![limit(
                    "blog",
                    "mg.a11y.issue.ipp",
                    "ip_prefix=1",
                    2,
                    3600,
                    2,
                )],
            ),
            later,
            later,
        )
        .await;
    assert!(
        matches!(&r, NonceResultV2::Fresh { limits } if limits[0].allowed),
        "{r:?}"
    );
}
