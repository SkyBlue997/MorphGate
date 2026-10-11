//! Valkey commands and reply parsing (spec §9.7). Everything here runs on the
//! `mg-state` runtime only.

use std::time::Duration;

use mg_core::gcra::GcraOutcome;
use redis::aio::{ConnectionLike, ConnectionManager, ConnectionManagerConfig};
use redis::{Cmd, ConnectionInfo, IntoConnectionInfo, Pipeline, Value};

use super::local::PreparedLimit;
use super::{
    EVENT_STREAM_KEY, JTI_COUNTER_WINDOW_MS, JTI_PER_KEY_LIMIT, JTI_TTL_S, JtiOutcome,
    MAX_VERDICT_BYTES, MG_GCRA_LUA, MG_JTI_LUA, MG_NONCE_ISSUE_V2_LUA, StateConfig, StateError,
    TOKEN_REPLAY_TTL_MS, metrics,
};

/// Stream entries of one `xadd_batch` call.
pub(crate) type StreamBatch = Vec<Vec<(&'static str, String)>>;

/// SHA-1 of every script, as `SCRIPT LOAD` returns them.
#[derive(Debug, Clone)]
pub(crate) struct Scripts {
    pub gcra: String,
    /// `mg_nonce_issue` v2 (Phase 2 spec §14.2; v1 was removed with the
    /// stage 2 switch, ruling I-52).
    pub nonce_v2: String,
    /// `mg_jti` v1 (Phase 2 spec §14.2).
    pub jti: String,
}

/// Every script the Edge loads, in `SCRIPT LOAD` order (Phase 2 spec §14.2:
/// only `mg_nonce_issue` v2 since the stage 2 switch, I-52).
const SCRIPT_SOURCES: [&str; 3] = [MG_GCRA_LUA, MG_NONCE_ISSUE_V2_LUA, MG_JTI_LUA];

impl Scripts {
    pub fn new() -> Self {
        let sha = |src| redis::Script::new(src).get_hash().to_owned();
        Self {
            gcra: sha(MG_GCRA_LUA),
            nonce_v2: sha(MG_NONCE_ISSUE_V2_LUA),
            jti: sha(MG_JTI_LUA),
        }
    }

    fn in_load_order(&self) -> [&str; 3] {
        [&self.gcra, &self.nonce_v2, &self.jti]
    }
}

/// Parses the configured URL and adds the password. The URL itself must not
/// carry a password (`edge.toml` keeps it in a credential file).
pub(crate) fn connection_info(cfg: &StateConfig) -> Result<ConnectionInfo, StateError> {
    let url = cfg
        .url
        .as_deref()
        .ok_or_else(|| StateError::Config("[valkey] url is required in valkey mode".into()))?;
    // The error text of the URL parser can quote the URL; keep it out.
    let info = url
        .into_connection_info()
        .map_err(|_| StateError::Config("[valkey] url is not a valid redis URL".into()))?;
    if info.redis_settings().password().is_some() {
        return Err(StateError::Config(
            "[valkey] url must not contain a password; use [valkey] password".into(),
        ));
    }
    Ok(match &cfg.password {
        Some(pw) => {
            let settings = info.redis_settings().clone().set_password(pw);
            info.set_redis_settings(settings)
        }
        None => info,
    })
}

/// Connects, checks `PING` and loads both scripts. The connection manager
/// does not retry by itself: the breaker schedules new attempts.
pub(crate) async fn connect(
    info: &ConnectionInfo,
    connect_timeout: Duration,
    response_timeout: Duration,
    scripts: &Scripts,
) -> Result<ConnectionManager, StateError> {
    let client = redis::Client::open(info.clone()).map_err(redis_err)?;
    let cfg = ConnectionManagerConfig::new()
        .set_connection_timeout(Some(connect_timeout))
        .set_response_timeout(Some(response_timeout))
        .set_number_of_retries(0);
    let mut conn = ConnectionManager::new_with_config(client, cfg)
        .await
        .map_err(redis_err)?;
    let pong = redis::cmd("PING")
        .query_async::<Value>(&mut conn)
        .await
        .map_err(redis_err)?;
    if !matches!(&pong, Value::SimpleString(s) if s == "PONG") {
        return Err(StateError::Reply("PING"));
    }
    load_scripts(&mut conn, scripts).await?;
    Ok(conn)
}

async fn load_scripts(conn: &mut ConnectionManager, scripts: &Scripts) -> Result<(), StateError> {
    let mut pipe = redis::pipe();
    for src in SCRIPT_SOURCES {
        pipe.cmd("SCRIPT").arg("LOAD").arg(src);
    }
    let result = async {
        let values = exec_raw(conn, &pipe).await?;
        let shas: Vec<String> = values
            .into_iter()
            .map(|v| match v {
                Value::BulkString(b) => {
                    String::from_utf8(b).map_err(|_| StateError::Reply("SCRIPT LOAD"))
                }
                Value::SimpleString(s) => Ok(s),
                _ => Err(StateError::Reply("SCRIPT LOAD")),
            })
            .collect::<Result<_, _>>()?;
        if shas.iter().map(String::as_str).eq(scripts.in_load_order()) {
            Ok(())
        } else {
            Err(StateError::Reply(
                "SCRIPT LOAD returned an unexpected SHA-1",
            ))
        }
    }
    .await;
    if result.is_err() {
        metrics::get().valkey_error("script_load");
    }
    result
}

fn redis_err(e: redis::RedisError) -> StateError {
    if e.is_timeout() {
        StateError::Timeout
    } else {
        StateError::Valkey(truncate(&e.to_string()))
    }
}

fn truncate(s: &str) -> String {
    const MAX: usize = 200;
    if s.len() <= MAX {
        return s.to_owned();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Sends a pipeline and returns one value per command (server errors
/// included as [`Value::ServerError`]).
async fn exec_raw(conn: &mut ConnectionManager, pipe: &Pipeline) -> Result<Vec<Value>, StateError> {
    let values = conn
        .req_packed_commands(pipe, 0, pipe.len())
        .await
        .map_err(redis_err)?;
    if values.len() != pipe.len() {
        return Err(StateError::Reply("pipeline reply count"));
    }
    Ok(values)
}

/// Sends a pipeline whose `EVALSHA`s may hit `NOSCRIPT` (Valkey restarted or
/// `SCRIPT FLUSH`ed): reloads both scripts and retries once. Any server error
/// fails the whole pipeline.
async fn exec_scripted(
    conn: &mut ConnectionManager,
    pipe: &Pipeline,
    scripts: &Scripts,
) -> Result<Vec<Value>, StateError> {
    let mut values = exec_raw(conn, pipe).await?;
    if values.iter().any(is_noscript) {
        load_scripts(conn, scripts).await?;
        values = exec_raw(conn, pipe).await?;
    }
    for v in &values {
        if let Value::ServerError(e) = v {
            let detail = e.details().map(truncate).unwrap_or_default();
            return Err(StateError::Valkey(format!("{} {detail}", e.code())));
        }
    }
    Ok(values)
}

fn is_noscript(v: &Value) -> bool {
    matches!(v, Value::ServerError(e) if e.code() == "NOSCRIPT")
}

/// `EVALSHA mg_gcra` (ARGV layout of §9.7).
pub(crate) fn gcra_cmd(sha: &str, limits: &[PreparedLimit], now_us: u64) -> Cmd {
    let mut c = redis::cmd("EVALSHA");
    c.arg(sha).arg(limits.len());
    for l in limits {
        c.arg(&l.key);
    }
    c.arg(now_us);
    for l in limits {
        c.arg(l.params.interval_us)
            .arg(l.params.burst)
            .arg(l.cost)
            .arg(u8::from(l.write));
    }
    c
}

/// `EVALSHA mg_nonce_issue` v2 (KEYS / ARGV layout of Phase 2 spec §14.2).
pub(crate) fn nonce_v2_cmd(
    sha: &str,
    nonce_key: &str,
    replay_key: Option<&str>,
    ttl_ms: u64,
    limits: &[PreparedLimit],
    now_us: u64,
) -> Cmd {
    let r = usize::from(replay_key.is_some());
    let mut c = redis::cmd("EVALSHA");
    c.arg(sha).arg(1 + r + limits.len()).arg(nonce_key);
    if let Some(k) = replay_key {
        c.arg(k);
    }
    for l in limits {
        c.arg(&l.key);
    }
    c.arg(ttl_ms.max(1))
        .arg(now_us)
        .arg(r)
        .arg(TOKEN_REPLAY_TTL_MS);
    for l in limits {
        c.arg(l.params.interval_us).arg(l.params.burst).arg(l.cost);
    }
    c
}

/// `EVALSHA mg_jti` v1 (Phase 2 spec §9.2, §14.2).
pub(crate) fn jti_cmd(sha: &str, jti_key: &str, count_key: &str) -> Cmd {
    let mut c = redis::cmd("EVALSHA");
    c.arg(sha)
        .arg(2)
        .arg(jti_key)
        .arg(count_key)
        .arg(JTI_PER_KEY_LIMIT)
        .arg(JTI_COUNTER_WINDOW_MS)
        .arg(JTI_TTL_S);
    c
}

fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        _ => None,
    }
}

/// Parses `n` triples `allowed, retry_after_us, tat_minus_now_us`.
/// `edge_now_us` places `new_tat_us` of allowed outcomes on the Edge clock.
pub(crate) fn parse_triples(
    items: &[Value],
    n: usize,
    edge_now_us: u64,
) -> Result<Vec<GcraOutcome>, StateError> {
    if items.len() != n * 3 {
        return Err(StateError::Reply("GCRA reply length"));
    }
    items
        .chunks_exact(3)
        .map(|t| {
            let (Some(allowed), Some(retry), Some(tat)) =
                (as_int(&t[0]), as_int(&t[1]), as_int(&t[2]))
            else {
                return Err(StateError::Reply("GCRA reply type"));
            };
            let (Ok(retry), Ok(tat)) = (u64::try_from(retry), u64::try_from(tat)) else {
                return Err(StateError::Reply("GCRA reply sign"));
            };
            match (allowed, retry) {
                (1, 0) => Ok(GcraOutcome {
                    allowed: true,
                    retry_after_us: 0,
                    tat_minus_now_us: tat,
                    new_tat_us: Some(edge_now_us.saturating_add(tat)),
                }),
                (0, r) if r > 0 => Ok(GcraOutcome {
                    allowed: false,
                    retry_after_us: r,
                    tat_minus_now_us: tat,
                    new_tat_us: None,
                }),
                _ => Err(StateError::Reply("GCRA reply values")),
            }
        })
        .collect()
}

/// `mg_gcra` reply.
pub(crate) fn parse_gcra(
    v: &Value,
    n: usize,
    edge_now_us: u64,
) -> Result<Vec<GcraOutcome>, StateError> {
    match v {
        Value::Array(items) => parse_triples(items, n, edge_now_us),
        _ => Err(StateError::Reply("GCRA reply type")),
    }
}

/// `mg_nonce_issue` v2 reply (Phase 2 spec §14.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NonceV2Reply {
    /// `{0}`: the nonce was already used.
    Reused,
    /// `{2}`: the provider token was already used (the nonce is consumed).
    TokenReused,
    /// `{1, …}`: one outcome per limiter.
    Fresh(Vec<GcraOutcome>),
}

/// Parses an `mg_nonce_issue` v2 reply for `n` limiters.
pub(crate) fn parse_nonce_v2(
    v: &Value,
    n: usize,
    edge_now_us: u64,
) -> Result<NonceV2Reply, StateError> {
    let Value::Array(items) = v else {
        return Err(StateError::Reply("nonce reply type"));
    };
    match items.split_first() {
        Some((first, [])) if as_int(first) == Some(0) => Ok(NonceV2Reply::Reused),
        Some((first, [])) if as_int(first) == Some(2) => Ok(NonceV2Reply::TokenReused),
        Some((first, rest)) if as_int(first) == Some(1) => {
            parse_triples(rest, n, edge_now_us).map(NonceV2Reply::Fresh)
        }
        _ => Err(StateError::Reply("nonce reply values")),
    }
}

/// Parses an `mg_jti` v1 reply: `{0}` fresh, `{1}` replay, `{2}` per-key
/// quota exceeded.
pub(crate) fn parse_jti(v: &Value) -> Result<JtiOutcome, StateError> {
    let Value::Array(items) = v else {
        return Err(StateError::Reply("jti reply type"));
    };
    match items.as_slice() {
        [first] => match as_int(first) {
            Some(0) => Ok(JtiOutcome::Fresh),
            Some(1) => Ok(JtiOutcome::Replayed),
            Some(2) => Ok(JtiOutcome::KeyQuota),
            _ => Err(StateError::Reply("jti reply values")),
        },
        _ => Err(StateError::Reply("jti reply values")),
    }
}

/// `MGET` reply. Values that are too long or not UTF-8 are ignored and
/// counted as verdict parse errors.
pub(crate) fn parse_mget(v: &Value, n: usize) -> Result<Vec<Option<String>>, StateError> {
    let Value::Array(items) = v else {
        return Err(StateError::Reply("MGET reply type"));
    };
    if items.len() != n {
        return Err(StateError::Reply("MGET reply length"));
    }
    items
        .iter()
        .map(|item| match item {
            Value::Nil => Ok(None),
            Value::BulkString(b) => {
                if b.len() > MAX_VERDICT_BYTES {
                    metrics::get().verdict_parse_errors.inc();
                    return Ok(None);
                }
                match std::str::from_utf8(b) {
                    Ok(s) => Ok(Some(s.to_owned())),
                    Err(_) => {
                        metrics::get().verdict_parse_errors.inc();
                        Ok(None)
                    }
                }
            }
            _ => Err(StateError::Reply("MGET item type")),
        })
        .collect()
}

/// Round trip 1: `MGET` (if any key) + `EVALSHA mg_gcra` (if any limiter),
/// sent as one pipeline.
pub(crate) async fn round_trip1(
    conn: &mut ConnectionManager,
    scripts: &Scripts,
    mget: &[String],
    limits: &[PreparedLimit],
) -> Result<(Vec<Option<String>>, Vec<GcraOutcome>), StateError> {
    let mut pipe = redis::pipe();
    if !mget.is_empty() {
        pipe.cmd("MGET").arg(mget);
    }
    if !limits.is_empty() {
        pipe.add_command(gcra_cmd(&scripts.gcra, limits, 0));
    }
    if pipe.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let values = exec_scripted(conn, &pipe, scripts).await?;
    let edge_now = super::unix_now_us();
    let mut it = values.iter();
    let verdicts = if mget.is_empty() {
        Vec::new()
    } else {
        parse_mget(
            it.next().ok_or(StateError::Reply("pipeline reply count"))?,
            mget.len(),
        )?
    };
    let outcomes = if limits.is_empty() {
        Vec::new()
    } else {
        parse_gcra(
            it.next().ok_or(StateError::Reply("pipeline reply count"))?,
            limits.len(),
            edge_now,
        )?
    };
    Ok((verdicts, outcomes))
}

/// The reply of [`round_trip1_v2`]: verdicts, limiter outcomes and the
/// `mg_jti` outcome (if a proof was checked).
pub(crate) type RoundTrip1V2Reply = (Vec<Option<String>>, Vec<GcraOutcome>, Option<JtiOutcome>);

/// Phase 2 round trip 1 (Phase 2 spec §14.3): `MGET` (if any key) +
/// `EVALSHA mg_gcra` (if any limiter) + `EVALSHA mg_jti` (if a proof is
/// checked; `jti` = its key and counter key), sent as one pipeline.
pub(crate) async fn round_trip1_v2(
    conn: &mut ConnectionManager,
    scripts: &Scripts,
    mget: &[String],
    limits: &[PreparedLimit],
    jti: Option<&(String, String)>,
) -> Result<RoundTrip1V2Reply, StateError> {
    let mut pipe = redis::pipe();
    if !mget.is_empty() {
        pipe.cmd("MGET").arg(mget);
    }
    if !limits.is_empty() {
        pipe.add_command(gcra_cmd(&scripts.gcra, limits, 0));
    }
    if let Some((key, count_key)) = jti {
        pipe.add_command(jti_cmd(&scripts.jti, key, count_key));
    }
    if pipe.is_empty() {
        return Ok((Vec::new(), Vec::new(), None));
    }
    let values = exec_scripted(conn, &pipe, scripts).await?;
    let edge_now = super::unix_now_us();
    let mut it = values.iter();
    let mut next = || it.next().ok_or(StateError::Reply("pipeline reply count"));
    let verdicts = if mget.is_empty() {
        Vec::new()
    } else {
        parse_mget(next()?, mget.len())?
    };
    let outcomes = if limits.is_empty() {
        Vec::new()
    } else {
        parse_gcra(next()?, limits.len(), edge_now)?
    };
    let jti = match jti {
        Some(_) => Some(parse_jti(next()?)?),
        None => None,
    };
    Ok((verdicts, outcomes, jti))
}

/// Round trip 2 with `mg_nonce_issue` v2.
pub(crate) async fn nonce_issue_v2(
    conn: &mut ConnectionManager,
    scripts: &Scripts,
    nonce_key: &str,
    replay_key: Option<&str>,
    ttl_ms: u64,
    limits: &[PreparedLimit],
) -> Result<NonceV2Reply, StateError> {
    let mut pipe = redis::pipe();
    pipe.add_command(nonce_v2_cmd(
        &scripts.nonce_v2,
        nonce_key,
        replay_key,
        ttl_ms,
        limits,
        0,
    ));
    let values = exec_scripted(conn, &pipe, scripts).await?;
    let edge_now = super::unix_now_us();
    let reply = values
        .first()
        .ok_or(StateError::Reply("pipeline reply count"))?;
    parse_nonce_v2(reply, limits.len(), edge_now)
}

/// `EVALSHA mg_gcra` alone (async failure counting).
pub(crate) async fn gcra(
    conn: &mut ConnectionManager,
    scripts: &Scripts,
    limits: &[PreparedLimit],
) -> Result<Vec<GcraOutcome>, StateError> {
    round_trip1(conn, scripts, &[], limits)
        .await
        .map(|(_, o)| o)
}

/// One pipeline of `XADD mg:ev MAXLEN ~ <maxlen> * f v ...` (§13.6).
pub(crate) async fn xadd(
    conn: &mut ConnectionManager,
    maxlen: u64,
    entries: &StreamBatch,
) -> Result<(), StateError> {
    let mut pipe = redis::pipe();
    for fields in entries {
        let c = pipe
            .cmd("XADD")
            .arg(EVENT_STREAM_KEY)
            .arg("MAXLEN")
            .arg("~")
            .arg(maxlen)
            .arg("*");
        for (name, value) in fields {
            c.arg(*name).arg(value);
        }
    }
    if pipe.is_empty() {
        return Ok(());
    }
    let values = exec_raw(conn, &pipe).await?;
    match values
        .iter()
        .find(|v| !matches!(v, Value::BulkString(_) | Value::SimpleString(_)))
    {
        None => Ok(()),
        Some(Value::ServerError(e)) => Err(StateError::Valkey(e.code().to_owned())),
        Some(_) => Err(StateError::Reply("XADD reply type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{LimitCheck, LimiterKey};
    use mg_core::gcra::GcraParams;

    fn limits() -> Vec<PreparedLimit> {
        ["a", "b"]
            .iter()
            .map(|d| {
                PreparedLimit::new(
                    &LimitCheck {
                        key: LimiterKey::new("blog", "l", *d),
                        params: GcraParams::new(20, 60, 5).unwrap(),
                        cost: 1,
                        write: *d == "a",
                    },
                    &[0u8; 32],
                )
            })
            .collect()
    }

    fn args(c: &Cmd) -> Vec<String> {
        c.args_iter()
            .map(|a| match a {
                redis::Arg::Simple(b) => String::from_utf8(b.to_vec()).unwrap(),
                _ => "<other>".into(),
            })
            .collect()
    }

    #[test]
    fn gcra_argv_layout() {
        let l = limits();
        let a = args(&gcra_cmd("sha", &l, 0));
        assert_eq!(a[..3], ["EVALSHA", "sha", "2"]);
        assert_eq!(a[3], l[0].key);
        assert_eq!(a[4], l[1].key);
        assert_eq!(
            a[5..],
            ["0", "3000000", "5", "1", "1", "3000000", "5", "1", "0"]
        );
    }

    #[test]
    fn scripts_hashes_are_sha1_hex() {
        let s = Scripts::new();
        let all = s.in_load_order();
        for (i, sha) in all.iter().enumerate() {
            assert_eq!(sha.len(), 40);
            assert!(all[..i].iter().all(|other| other != sha));
        }
    }

    #[test]
    fn nonce_v2_argv_layout() {
        let l = limits();
        let replay = Some("mg:rp:blog:turnstile:ab");
        let a = args(&nonce_v2_cmd("sha", "mg:n:blog:00", replay, 0, &l, 7));
        assert_eq!(
            a[..5],
            [
                "EVALSHA",
                "sha",
                "4",
                "mg:n:blog:00",
                "mg:rp:blog:turnstile:ab"
            ]
        );
        assert_eq!(a[5], l[0].key);
        assert_eq!(a[6], l[1].key);
        assert_eq!(
            a[7..],
            [
                "1", "7", "1", "300000", "3000000", "5", "1", "3000000", "5", "1"
            ]
        );
        let a = args(&nonce_v2_cmd("sha", "mg:n:blog:00", None, 660_000, &[], 0));
        assert_eq!(
            a,
            [
                "EVALSHA",
                "sha",
                "1",
                "mg:n:blog:00",
                "660000",
                "0",
                "0",
                "300000"
            ]
        );
    }

    #[test]
    fn jti_argv_layout() {
        let a = args(&jti_cmd("sha", "mg:jti:blog:kj:j", "mg:jc:blog:kj"));
        assert_eq!(
            a,
            [
                "EVALSHA",
                "sha",
                "2",
                "mg:jti:blog:kj:j",
                "mg:jc:blog:kj",
                "600",
                "60000",
                "40"
            ]
        );
    }

    #[test]
    fn v2_reply_parsing() {
        let arr = |v: Vec<i64>| Value::Array(v.into_iter().map(Value::Int).collect());
        assert_eq!(
            parse_nonce_v2(&arr(vec![0]), 1, 0).unwrap(),
            NonceV2Reply::Reused
        );
        assert_eq!(
            parse_nonce_v2(&arr(vec![2]), 1, 0).unwrap(),
            NonceV2Reply::TokenReused
        );
        assert_eq!(
            parse_nonce_v2(&arr(vec![1]), 0, 0).unwrap(),
            NonceV2Reply::Fresh(vec![])
        );
        let fresh = parse_nonce_v2(&arr(vec![1, 1, 0, 5]), 1, 100).unwrap();
        assert!(matches!(fresh, NonceV2Reply::Fresh(o) if o[0].new_tat_us == Some(105)));
        assert!(parse_nonce_v2(&arr(vec![2, 1]), 0, 0).is_err());
        assert!(parse_nonce_v2(&arr(vec![3]), 0, 0).is_err());
        assert!(parse_nonce_v2(&arr(vec![1, 1, 0]), 1, 0).is_err());
        assert!(parse_nonce_v2(&Value::Nil, 0, 0).is_err());
        assert_eq!(parse_jti(&arr(vec![0])).unwrap(), JtiOutcome::Fresh);
        assert_eq!(parse_jti(&arr(vec![1])).unwrap(), JtiOutcome::Replayed);
        assert_eq!(parse_jti(&arr(vec![2])).unwrap(), JtiOutcome::KeyQuota);
        for bad in [
            arr(vec![]),
            arr(vec![3]),
            arr(vec![0, 0]),
            Value::Int(0),
            Value::Nil,
        ] {
            assert!(parse_jti(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn reply_parsing() {
        let int = Value::Int;
        let ok = Value::Array(vec![int(1), int(0), int(5), int(0), int(7), int(9)]);
        let out = parse_gcra(&ok, 2, 100).unwrap();
        assert!(out[0].allowed && out[0].new_tat_us == Some(105));
        assert!(!out[1].allowed && out[1].retry_after_us == 7 && out[1].new_tat_us.is_none());
        assert!(parse_gcra(&ok, 1, 0).is_err());
        let bad = Value::Array(vec![int(1), int(3), int(5)]);
        assert!(parse_gcra(&bad, 1, 0).is_err(), "allowed with a retry time");
        let neg = Value::Array(vec![int(0), int(-1), int(5)]);
        assert!(parse_gcra(&neg, 1, 0).is_err());
        let mget = Value::Array(vec![
            Value::Nil,
            Value::BulkString(b"{}".to_vec()),
            Value::BulkString(vec![0xff, 0xfe]),
            Value::BulkString(vec![b'x'; MAX_VERDICT_BYTES + 1]),
        ]);
        assert_eq!(
            parse_mget(&mget, 4).unwrap(),
            vec![None, Some("{}".to_owned()), None, None]
        );
        assert!(parse_mget(&mget, 3).is_err());
        assert!(parse_mget(&Value::Array(vec![int(1)]), 1).is_err());
    }

    #[test]
    fn url_with_password_is_rejected_without_quoting_it() {
        let cfg = StateConfig::valkey("redis://u:s3cr3t@127.0.0.1/", [0; 32]);
        let err = connection_info(&cfg).unwrap_err().to_string();
        assert!(!err.contains("s3cr3t"));
        let mut cfg = StateConfig::valkey("redis://edge@127.0.0.1:6379/2", [0; 32]);
        cfg.password = Some("pw".into());
        let info = connection_info(&cfg).unwrap();
        assert_eq!(info.redis_settings().password(), Some("pw"));
        assert_eq!(info.redis_settings().username(), Some("edge"));
    }

    /// §2.4 item 3: random reply trees never panic the parsers.
    #[test]
    fn random_replies_never_panic() {
        struct XorShift(u64);
        impl XorShift {
            fn next(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
        }
        fn value(r: &mut XorShift, depth: u32) -> Value {
            match r.next() % if depth > 2 { 4 } else { 6 } {
                0 => Value::Nil,
                1 => Value::Int(match r.next() % 4 {
                    0 => 0,
                    1 => 1,
                    2 => -(r.next() as i64 & 0xff),
                    _ => r.next() as i64,
                }),
                2 => Value::BulkString((0..r.next() % 8).map(|_| r.next() as u8).collect()),
                3 => Value::Okay,
                _ => Value::Array((0..r.next() % 10).map(|_| value(r, depth + 1)).collect()),
            }
        }
        let mut r = XorShift(0x1234_5678_9abc_def1);
        for _ in 0..10_000 {
            let v = value(&mut r, 0);
            let n = (r.next() % 4) as usize;
            let _ = parse_gcra(&v, n, r.next());
            let _ = parse_mget(&v, n);
            let _ = parse_nonce_v2(&v, n, r.next());
            let _ = parse_jti(&v);
        }
    }

    #[test]
    fn truncate_is_char_safe() {
        let s = "é".repeat(300);
        assert!(truncate(&s).len() <= 204);
    }
}
