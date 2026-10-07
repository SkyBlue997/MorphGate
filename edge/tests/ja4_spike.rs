//! The `direct_tls` JA4 spike end to end (docs/impl/phase1-spec.md §15
//! WP-J1; ADR-0002 decision 4 and its 2026-09-28 erratum). Loopback only;
//! test certificates from `tests/fixtures/tls/`.
//!
//! One Edge serves site "blog" (a `direct_tls` bundle, monitor) on two
//! `direct_tls` listeners: `tls` with `ja4_spike = true` and `tls-plain`
//! without. Decision events go to the file sink, every one kept. The bundle
//! has two rules that would block on JA4 (`has(tls.ja4)` and
//! `tls.ja4.value == <the expected JA4>`): the spike must never let the
//! policy see the value (D-07).
//!
//! Clients: BoringSSL (`pingora::tls`, blocking) with fixed parameters, and
//! rustls (reqwest) as a second, independent TLS stack. A TCP relay in
//! front of the Edge records each connection's plaintext ClientHello records,
//! so the JA4 of the bytes on the wire can be compared with the one the Edge
//! computed from BoringSSL's `ClientHello::as_bytes()`.
//!
//! Recorded behaviour (asserted below):
//!
//! * **Session resumption**: BoringSSL runs the select-certificate callback
//!   before it decides on resumption, so resumed handshakes carry a JA4 too.
//!   A TLS 1.3 resumption adds `pre_shared_key` (0029), so `c` changes
//!   while `b` stays. The count depends on the stack: Chromium keeps its
//!   other extensions and counts one more (FoxIO's published pair
//!   `t13d1516h2_…_02713d6af862` / `t13d1517h2_…_b0da82dd1658`); rustls
//!   (0.23, locked) drops `session_ticket` (0023) at the same time, so its
//!   count stays 11 (`t13d1011h1_61a7ad8aa9b6_0d308c48d2a3` →
//!   `…_053248755fe4`). A TLS 1.2 ticket resumption keeps the extension
//!   types, so its JA4 does not change.
//! * **Size-dependent padding**: BoringSSL pads a ClientHello of 256-511
//!   bytes to 512 with the RFC 7685 `padding` extension (0015), so the same
//!   client gets another JA4 when only its host name is longer.
//! * **HelloRetryRequest**: only the first ClientHello is fingerprinted
//!   (`hello_retry_request_fingerprints_the_first_client_hello`).
//! * **HTTP/2**: the JA4 belongs to the connection (`SslDigest.extension`);
//!   every stream of an h2 connection carries the same value.
//! * **Hostile and 16 KiB ClientHellos** never break the listener
//!   (`hostile_client_hellos_leave_the_listener_working`).
//! * **Overhead**: see `handshake_and_parser_overhead` (numbers printed with
//!   `--nocapture`; the release-build measurement is in the ADR erratum).

mod common;

use common::policy::{default_route, eq, field, rule, string};
use common::{Edge, TestEnv, blog_bundle, fixture, free_addr, read_response, sign, with_events};
use mg_edge::tls::client_hello::{self, ClientHello, EXT_PRE_SHARED_KEY};
use mg_edge::tls::ja4;
use mg_proto::v1::{self as pb, EventConfig, SiteBundle, UpstreamProfileKind};
use pingora::tls::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The JA4 of the BoringSSL client below (TLS 1.3, SNI, ALPN `http/1.1`, no
/// GREASE), computed by hand from its ClientHello (see [`BORING_TLS13_R`]);
/// the two hashes were computed with Python's `hashlib`, not with mg-edge.
const BORING_TLS13: &str = "t13d0611h1_d9a339d1b048_0c936b6b1637";
/// `JA4_r` of [`BORING_TLS13`]: the three TLS 1.3 suites and the three TLS 1.2
/// suites of `CIPHERS`, sorted; BoringSSL's client extensions without SNI and
/// ALPN, sorted (supported_groups, ec_point_formats, signature_algorithms,
/// extended_master_secret, session_ticket, supported_versions,
/// psk_key_exchange_modes, key_share, renegotiation_info: nine, plus SNI and
/// ALPN = 11); the signature algorithms of `SIGALGS` in order.
const BORING_TLS13_R: &str = "t13d0611h1_1301,1302,1303,c02b,c02f,cca8_\
     000a,000b,000d,0017,0023,002b,002d,0033,ff01_0403,0804,0401";

/// The same client limited to TLS 1.2, without SNI and ALPN: three suites,
/// six extensions (no supported_versions, psk_key_exchange_modes, key_share);
/// hashes again from `hashlib`.
const BORING_TLS12: &str = "t12i030600_d00c593a278a_909ab965658b";
const BORING_TLS12_R: &str =
    "t12i030600_c02b,c02f,cca8_000a,000b,000d,0017,0023,ff01_0403,0804,0401";
/// [`BORING_TLS13`] offering `h2` first: only the ALPN pair changes (ALPN is
/// not part of `c`).
const BORING_TLS13_H2: &str = "t13d0611h2_d9a339d1b048_0c936b6b1637";
/// [`BORING_TLS13`] when BoringSSL pads its ClientHello (RFC 7685 `padding`,
/// 0015): one more extension and another `c` (`hashlib` again).
const BORING_TLS13_PADDED: &str = "t13d0612h1_d9a339d1b048_303605e647f4";

/// TLS 1.2 suites offered by the BoringSSL client (TLS 1.3 suites are fixed:
/// 1301, 1302, 1303).
const CIPHERS: &str =
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305";
/// 0403, 0804, 0401.
const SIGALGS: &str = "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256";

const WAIT: Duration = Duration::from_secs(10);

fn tls_listener(name: &str, bind: SocketAddr, extra: &str) -> String {
    format!(
        "[[listeners]]\nname = \"{name}\"\nbind = \"{bind}\"\nprofile = \"direct_tls\"\n{extra}tls_cert = \"{}\"\ntls_key = \"{}\"\n",
        fixture("tls/edge.pem").display(),
        fixture("tls/edge.key").display()
    )
}

fn has(path: &str) -> pb::Expr {
    pb::Expr {
        kind: Some(pb::expr::Kind::Has(path.into())),
    }
}

/// A `direct_tls` bundle for both listeners, monitor, every decision kept,
/// with the two JA4 rules.
fn bundle() -> SiteBundle {
    let mut b = blog_bundle(1);
    b.upstream.as_mut().unwrap().kind = UpstreamProfileKind::DirectTls as i32;
    b.cloudflare = None;
    b.allowed_listeners = vec!["tls".into(), "tls-plain".into()];
    b.monitor_only = true;
    b.events = Some(EventConfig {
        allow_sample_rate: 1.0,
        access_log: false,
        stream: false,
    });
    let env = &mut b.environments[0];
    env.routes = vec![default_route()];
    env.rules = vec![
        rule(
            "ja4-present",
            "custom",
            pb::Action::Block,
            has("tls.ja4"),
            &[],
        ),
        rule(
            "ja4-value",
            "custom",
            pb::Action::Block,
            eq(field("tls.ja4.value"), string(BORING_TLS13)),
            &[],
        ),
    ];
    b
}

/// A running Edge (killed on drop) and its environment.
struct Spike {
    _env: TestEnv,
    _edge: Edge,
    /// The `ja4_spike` listener.
    spike: SocketAddr,
    /// The listener without the spike.
    plain: SocketAddr,
    events: PathBuf,
}

fn start(tag: &str) -> Spike {
    let env = TestEnv::new(tag);
    let (spike, plain) = (free_addr(), free_addr());
    let listeners = format!(
        "{}{}",
        tls_listener("tls", spike, "ja4_spike = true\n"),
        tls_listener("tls-plain", plain, "")
    );
    let site = env.site("").replace(
        "listeners = [\"cf-tunnel\"]",
        "listeners = [\"tls\", \"tls-plain\"]",
    );
    let events = env.dir.join("events.jsonl");
    let config = with_events(
        &env.config(&listeners, &site),
        &format!("file = \"{}\"\nflush_interval_ms = 50\n", events.display()),
    );
    let path = env.write_config(&config);
    env.write_lkg("blog", &sign(&bundle()));
    let out = env.check(&path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let edge = env.spawn(&path);
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    Spike {
        _env: env,
        _edge: edge,
        spike,
        plain,
        events,
    }
}

/// The decision event of the request for `path` (waits for the sink).
fn decision(events: &Path, path: &str) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let text = std::fs::read_to_string(events).unwrap_or_default();
        let found = text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["kind"] == "decision" && v["ctx"]["http"]["path"] == path);
        if let Some(v) = found {
            return v;
        }
        assert!(
            Instant::now() < deadline,
            "no decision event for {path} in:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `ctx.tls.ja4` of a decision event, checked for its provenance.
fn event_ja4(event: &Value) -> Option<String> {
    let j = event["ctx"]["tls"].get("ja4")?;
    assert_eq!(j["source"], "self", "{j}");
    assert_eq!(j["authenticated"], true, "{j}");
    Some(j["value"].as_str().unwrap().to_owned())
}

/// D-07: neither JA4 rule matched; the value rule read a MISSING field.
fn assert_policy_saw_missing(event: &Value) {
    let hits = event["hits"].as_array().cloned().unwrap_or_default();
    assert!(
        hits.iter().all(|h| h["outcome"] != "matched"),
        "a JA4 rule matched: {hits:?}"
    );
    let value = hits
        .iter()
        .find(|h| h["rule_id"] == "ja4-value")
        .unwrap_or_else(|| panic!("no ja4-value hit: {hits:?}"));
    assert_eq!(value["outcome"], "missing_input", "{value}");
    assert!(
        hits.iter().all(|h| h["rule_id"] != "ja4-present"),
        "{hits:?}"
    );
}

// ---------------------------------------------------------------------------
// A relay that records the first TLS record of every connection.

struct Relay {
    addr: SocketAddr,
    /// Per connection, in the order their first records arrived: the
    /// plaintext ClientHello records the client sent (one, or two after a
    /// HelloRetryRequest).
    records: Arc<Mutex<Vec<Vec<Vec<u8>>>>>,
}

impl Relay {
    fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let records = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&records);
        std::thread::spawn(move || {
            for client in listener.incoming().flatten() {
                let rec = Arc::clone(&rec);
                std::thread::spawn(move || {
                    let _ = pipe(client, upstream, &rec);
                });
            }
        });
        Self { addr, records }
    }

    /// The (first) ClientHello body of the `i`-th connection.
    fn hello(&self, i: usize) -> Vec<u8> {
        self.hellos(i).swap_remove(0)
    }

    /// Every ClientHello body the `i`-th connection has sent so far.
    fn hellos(&self, i: usize) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(r) = self.records.lock().unwrap().get(i) {
                return r
                    .iter()
                    .map(|r| client_hello::body_from_record(r).unwrap().to_vec())
                    .collect();
            }
            assert!(Instant::now() < deadline, "no connection {i}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// One TLS record (header and fragment).
fn read_record(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut rec = vec![0u8; 5];
    s.read_exact(&mut rec)?;
    rec.resize(5 + usize::from(u16::from_be_bytes([rec[3], rec[4]])), 0);
    s.read_exact(&mut rec[5..])?;
    Ok(rec)
}

/// A plaintext handshake record that starts a ClientHello.
fn is_client_hello(rec: &[u8]) -> bool {
    rec.first() == Some(&22) && rec.get(5) == Some(&1)
}

fn pipe(
    mut client: TcpStream,
    upstream: SocketAddr,
    rec: &Mutex<Vec<Vec<Vec<u8>>>>,
) -> std::io::Result<()> {
    let mut up = TcpStream::connect(upstream)?;
    let first = read_record(&mut client)?;
    let slot = {
        let mut r = rec.lock().unwrap();
        r.push(vec![first.clone()]);
        r.len() - 1
    };
    up.write_all(&first)?;
    let (mut c2, mut u2) = (client.try_clone()?, up.try_clone()?);
    let back = std::thread::spawn(move || {
        let _ = std::io::copy(&mut u2, &mut c2);
        let _ = c2.shutdown(Shutdown::Write);
    });
    // Record by record while the client is still in plaintext: a second
    // ClientHello (after a HelloRetryRequest) is recorded, a
    // ChangeCipherSpec is skipped, anything else (TLS 1.2
    // ClientKeyExchange, encrypted records) ends the recording.
    while let Ok(r) = read_record(&mut client) {
        up.write_all(&r)?;
        if is_client_hello(&r) {
            rec.lock().unwrap()[slot].push(r);
        } else if r[0] != 20 {
            break;
        }
    }
    let _ = std::io::copy(&mut client, &mut up);
    let _ = up.shutdown(Shutdown::Write);
    let _ = back.join();
    Ok(())
}

// ---------------------------------------------------------------------------
// The BoringSSL client.

#[derive(Debug, Clone, Copy)]
struct Params {
    max: SslVersion,
    /// The SNI host name; the certificate is checked against it only when
    /// it is `edge.test`.
    sni: Option<&'static str>,
    alpn: Option<&'static [u8]>,
    grease: bool,
    /// Supported groups in preference order; BoringSSL sends a key share
    /// for the first one only.
    curves: &'static str,
}

const TLS13: Params = Params {
    max: SslVersion::TLS1_3,
    sni: Some("edge.test"),
    alpn: Some(b"\x08http/1.1"),
    grease: false,
    curves: "X25519:P-256",
};

fn connector(p: Params) -> SslConnector {
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_ca_file(fixture("tls/server-ca.pem")).unwrap();
    b.set_verify(SslVerifyMode::PEER);
    b.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    b.set_max_proto_version(Some(p.max)).unwrap();
    b.set_cipher_list(CIPHERS).unwrap();
    b.set_sigalgs_list(SIGALGS).unwrap();
    b.set_curves_list(p.curves).unwrap();
    b.set_grease_enabled(p.grease);
    if let Some(a) = p.alpn {
        b.set_alpn_protos(a).unwrap();
    }
    b.build()
}

/// A TLS connection with `p`.
fn tls_connect(
    addr: SocketAddr,
    c: &SslConnector,
    p: Params,
) -> pingora::tls::ssl::SslStream<TcpStream> {
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut cfg = c.configure().unwrap();
    cfg.set_use_server_name_indication(p.sni.is_some());
    cfg.set_verify_hostname(p.sni == Some("edge.test"));
    cfg.connect(p.sni.unwrap_or("edge.test"), tcp)
        .unwrap_or_else(|e| panic!("handshake with {p:?}: {e}"))
}

/// `GET path` on an established connection; the status.
fn get(s: &mut pingora::tls::ssl::SslStream<TcpStream>, path: &str) -> u16 {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: morphgate-dev-tooling\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    read_response(s).unwrap().status
}

/// `GET path` over one BoringSSL connection; the status.
fn boring_get(addr: SocketAddr, p: Params, path: &str) -> u16 {
    get(&mut tls_connect(addr, &connector(p), p), path)
}

// ---------------------------------------------------------------------------
// Tests

/// §15: a BoringSSL client with fixed parameters; the JA4 in the decision
/// event equals the hand-computed value and the JA4 of the bytes on the
/// wire; the policy still sees `tls.ja4` as MISSING.
#[test]
fn boringssl_client_fixed_parameters() {
    let s = start("ja4-boring");
    let relay = Relay::start(s.spike);

    assert_eq!(boring_get(relay.addr, TLS13, "/ja4/tls13"), 200);
    let wire = relay.hello(0);
    eprintln!(
        "JA4_r of the BoringSSL client: {}",
        ja4::ja4_r(&wire).unwrap()
    );
    eprintln!("JA4 of the BoringSSL client: {}", ja4::ja4(&wire).unwrap());
    assert_eq!(ja4::ja4_r(&wire).unwrap(), BORING_TLS13_R);
    assert_eq!(ja4::ja4(&wire).unwrap().as_str(), BORING_TLS13);
    let ev = decision(&s.events, "/ja4/tls13");
    assert_eq!(event_ja4(&ev).as_deref(), Some(BORING_TLS13));
    assert_eq!(ev["ctx"]["tls"]["sni"], "edge.test");
    assert_policy_saw_missing(&ev);

    // BoringSSL's GREASE (ciphers, extensions, groups, versions, key shares)
    // does not change the JA4.
    let grease = Params {
        grease: true,
        ..TLS13
    };
    assert_eq!(boring_get(relay.addr, grease, "/ja4/grease"), 200);
    let wire = relay.hello(1);
    let parsed = ClientHello::parse(&wire).unwrap();
    assert!(
        parsed.cipher_suites().any(ja4::is_grease)
            && parsed.extensions().any(|(t, _)| ja4::is_grease(t)),
        "the client sent no GREASE"
    );
    let ev = decision(&s.events, "/ja4/grease");
    assert_eq!(event_ja4(&ev).as_deref(), Some(BORING_TLS13));

    // TLS 1.2 only, no SNI, no ALPN.
    let tls12 = Params {
        max: SslVersion::TLS1_2,
        sni: None,
        alpn: None,
        ..TLS13
    };
    assert_eq!(boring_get(relay.addr, tls12, "/ja4/tls12"), 200);
    let wire = relay.hello(2);
    assert_eq!(ja4::ja4_r(&wire).unwrap(), BORING_TLS12_R);
    assert_eq!(ja4::ja4(&wire).unwrap().as_str(), BORING_TLS12);
    let ev = decision(&s.events, "/ja4/tls12");
    assert_eq!(event_ja4(&ev).as_deref(), Some(BORING_TLS12));
    assert!(
        ev["ctx"]["tls"].get("sni").is_none(),
        "{}",
        ev["ctx"]["tls"]
    );
    assert_policy_saw_missing(&ev);

    // The same client with a longer host name: its ClientHello grows past 255
    // bytes and BoringSSL pads it to 512 (RFC 7685 `padding`, 0015), so one
    // more extension and another `c` for an unchanged client.
    let long = Params {
        sni: Some("a-host-name-long-enough-to-pad-the-client-hello.edge.test"),
        ..TLS13
    };
    assert_eq!(boring_get(relay.addr, long, "/ja4/long-sni"), 200);
    let wire = relay.hello(3);
    assert_eq!(
        wire.len(),
        512 - 4,
        "padded to 512 bytes with the handshake header"
    );
    let raw = ja4::ja4_r(&wire).unwrap();
    assert_eq!(
        raw,
        BORING_TLS13_R
            .replace("t13d0611h1", "t13d0612h1")
            .replace("0017,0023", "0015,0017,0023")
    );
    assert_eq!(ja4::ja4(&wire).unwrap().as_str(), BORING_TLS13_PADDED);
    let ev = decision(&s.events, "/ja4/long-sni");
    assert_eq!(event_ja4(&ev).as_deref(), Some(BORING_TLS13_PADDED));

    // A listener without the spike computes nothing.
    assert_eq!(boring_get(s.plain, TLS13, "/ja4/plain"), 200);
    let ev = decision(&s.events, "/ja4/plain");
    assert_eq!(event_ja4(&ev), None, "{}", ev["ctx"]["tls"]);
    assert_eq!(ev["ctx"]["tls"]["available"], true);
}

/// Recorded behaviour, HelloRetryRequest: BoringSSL runs the
/// select-certificate callback for the first ClientHello only (its one call
/// site; `tls13_server.cc` negotiates "based on the first ClientHello (for
/// consistency with what |select_certificate_cb| observed)"), so the JA4 is
/// the first ClientHello's. The client prefers P-521, which the Edge does not
/// accept (BoringSSL's default server groups are X25519, P-256 and P-384), and
/// sends a key share for it only, so the Edge asks again for X25519. The
/// 133-byte P-521 share makes the first ClientHello 256-511 bytes long and
/// BoringSSL pads it; the second, with a 32-byte X25519 share, is not
/// padded. The two ClientHellos therefore have different JA4s and the
/// assertion tells them apart.
#[test]
fn hello_retry_request_fingerprints_the_first_client_hello() {
    let s = start("ja4-hrr");
    let relay = Relay::start(s.spike);
    let p = Params {
        curves: "P-521:X25519",
        ..TLS13
    };
    let mut conn = tls_connect(relay.addr, &connector(p), p);
    assert!(
        conn.ssl().used_hello_retry_request(),
        "no HelloRetryRequest"
    );
    assert_eq!(get(&mut conn, "/ja4/hrr"), 200);
    let hellos = relay.hellos(0);
    assert_eq!(hellos.len(), 2, "two ClientHellos on one connection");
    let first = ja4::ja4(&hellos[0]).unwrap();
    let second = ja4::ja4(&hellos[1]).unwrap();
    assert_eq!(first.as_str(), BORING_TLS13_PADDED);
    assert_eq!(second.as_str(), BORING_TLS13);
    let ev = decision(&s.events, "/ja4/hrr");
    assert_eq!(event_ja4(&ev).as_deref(), Some(first.as_str()));
    assert_policy_saw_missing(&ev);
}

/// Hostile ClientHellos on the wire, each on its own connection: one the
/// parser rejects although BoringSSL passes it to the callback (an ALPN list
/// longer than its body; BoringSSL refuses it only later), the largest one
/// BoringSSL accepts (16 KiB of cipher suites), one whose cipher suites,
/// extra extension and versions are all GREASE, and one BoringSSL refuses
/// before the callback (a truncated extension block). The Edge answers or closes each promptly and keeps serving: a
/// normal client afterwards still gets its JA4, and so does a client whose
/// ClientHello is 16 KiB long.
#[test]
fn hostile_client_hellos_leave_the_listener_working() {
    let s = start("ja4-hostile");
    let suites = [0x1301, 0x1302, 0xc02b];
    let tls13 = (0x002b, vec![2, 3, 4]);
    let mut truncated = hello_body(&suites, Some(std::slice::from_ref(&tls13)));
    truncated.pop();
    let hellos = [
        hello_body(
            &suites,
            Some(&[tls13.clone(), (0x0010, vec![0, 9, 2, b'h', b'2'])]),
        ),
        largest_hello(),
        hello_body(
            &[0x0a0a, 0x1a1a],
            Some(&[(0x2a2a, vec![]), (0x002b, vec![2, 0x3a, 0x3a])]),
        ),
        truncated,
    ];
    assert_eq!(mg_edge::tls::compute_ja4(&hellos[0]), None);
    for (i, body) in hellos.iter().enumerate() {
        let mut tcp = TcpStream::connect_timeout(&s.spike, Duration::from_secs(2)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tcp.write_all(&hello_record(body)).unwrap();
        // An alert, a ServerHello, EOF or a reset: anything but a timeout.
        match tcp.read(&mut [0u8; 1]) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) => panic!("hostile ClientHello {i}: {e}"),
        }
    }
    assert_eq!(boring_get(s.spike, TLS13, "/ja4/after-hostile"), 200);
    let ev = decision(&s.events, "/ja4/after-hostile");
    assert_eq!(event_ja4(&ev).as_deref(), Some(BORING_TLS13));

    // A real client can reach that size too: ~1,770 ALPN names after
    // `http/1.1` make a 16 KiB ClientHello. The callback still runs and,
    // since only the first name counts, the JA4 is the plain client's.
    let mut names = b"\x08http/1.1".to_vec();
    while names.len() < 15_900 {
        names.extend(b"\x08mg-pad-x");
    }
    let big = Params {
        alpn: Some(names.leak()),
        ..TLS13
    };
    let relay = Relay::start(s.spike);
    assert_eq!(boring_get(relay.addr, big, "/ja4/16k"), 200);
    let wire = relay.hello(0);
    assert!(
        (16_000..=16 * 1024 - 4).contains(&wire.len()),
        "{}",
        wire.len()
    );
    let ev = decision(&s.events, "/ja4/16k");
    assert_eq!(event_ja4(&ev).as_deref(), Some(BORING_TLS13));
}

/// `ja4_spike` is a `direct_tls` key: `--check-config` refuses it elsewhere.
#[test]
fn ja4_spike_only_on_direct_tls() {
    let env = TestEnv::new("ja4-config");
    let config = env.default_config("").replacen(
        "profile = \"cloudflare\"\n",
        "profile = \"cloudflare\"\nja4_spike = true\n",
        1,
    );
    let out = env.check(&env.write_config(&config));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(
        err.contains("ja4_spike is only used by direct_tls"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// rustls (reqwest): a second TLS stack, and session resumption.

/// A rustls client trusting the test CA, with `edge.test` resolved to
/// `addr`; no connection pool, so every request opens a new connection and
/// the second one offers the first one's session.
fn rustls_client(addr: SocketAddr, max: Option<reqwest::tls::Version>) -> reqwest::Client {
    let pem = std::fs::read(fixture("tls/server-ca.pem")).unwrap();
    let mut b = reqwest::Client::builder()
        .user_agent("morphgate-dev-tooling")
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_pem(&pem).unwrap()])
        .resolve("edge.test", addr)
        .pool_max_idle_per_host(0)
        .http1_only();
    if let Some(v) = max {
        b = b.tls_version_max(v);
    }
    b.build().unwrap()
}

/// Two sequential requests through the relay; the captured ClientHellos and
/// the JA4 of both decision events.
fn rustls_pair(s: &Spike, max: Option<reqwest::tls::Version>, tag: &str) -> [(Vec<u8>, String); 2] {
    let relay = Relay::start(s.spike);
    let client = rustls_client(relay.addr, max);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let paths = [format!("/ja4/{tag}-full"), format!("/ja4/{tag}-resumed")];
    for p in &paths {
        let status = rt.block_on(async {
            client
                .get(format!("https://edge.test:{}{p}", relay.addr.port()))
                .header("host", "example.com")
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });
        assert_eq!(status, 200, "{p}");
    }
    [0, 1].map(|i| {
        let ev = decision(&s.events, &paths[i]);
        assert_policy_saw_missing(&ev);
        (
            relay.hello(i),
            event_ja4(&ev).expect("the spike listener computed a JA4"),
        )
    })
}

fn has_ext(body: &[u8], ty: u16) -> Option<Vec<u8>> {
    ClientHello::parse(body)
        .unwrap()
        .extensions()
        .find(|(t, _)| *t == ty)
        .map(|(_, d)| d.to_vec())
}

/// §15 session resumption, with rustls: a TLS 1.3 resumption offers
/// `pre_shared_key` and changes `c` (rustls also drops `session_ticket`, so
/// the count is unchanged); a TLS 1.2 ticket resumption keeps the JA4. The
/// Edge's value is always the JA4 of the bytes on the wire.
#[test]
fn rustls_client_and_session_resumption() {
    let s = start("ja4-rustls");

    let [(full, full_ja4), (resumed, resumed_ja4)] = rustls_pair(&s, None, "tls13");
    eprintln!(
        "rustls TLS 1.3 full:    {full_ja4}  {}",
        ja4::ja4_r(&full).unwrap()
    );
    eprintln!(
        "rustls TLS 1.3 resumed: {resumed_ja4}  {}",
        ja4::ja4_r(&resumed).unwrap()
    );
    assert_eq!(ja4::ja4(&full).unwrap().as_str(), full_ja4);
    assert_eq!(ja4::ja4(&resumed).unwrap().as_str(), resumed_ja4);
    assert!(
        full_ja4.starts_with("t13d") && &full_ja4[8..10] == "h1",
        "{full_ja4}"
    );
    assert!(has_ext(&full, EXT_PRE_SHARED_KEY).is_none());
    assert!(
        has_ext(&resumed, EXT_PRE_SHARED_KEY).is_some(),
        "the second connection did not offer the session"
    );
    assert!(has_ext(&full, 0x0023).is_some());
    assert!(
        has_ext(&resumed, 0x0023).is_none(),
        "rustls offers no TLS 1.2 ticket next to a TLS 1.3 PSK"
    );
    assert_eq!(
        full_ja4[..10],
        resumed_ja4[..10],
        "same version, counts and ALPN"
    );
    assert_eq!(full_ja4[10..23], resumed_ja4[10..23], "same cipher part");
    assert_ne!(
        full_ja4[24..],
        resumed_ja4[24..],
        "the extension part changes"
    );

    let tls12 = Some(reqwest::tls::Version::TLS_1_2);
    let [(full, full_ja4), (resumed, resumed_ja4)] = rustls_pair(&s, tls12, "tls12");
    eprintln!(
        "rustls TLS 1.2 full:    {full_ja4}  {}",
        ja4::ja4_r(&full).unwrap()
    );
    eprintln!(
        "rustls TLS 1.2 resumed: {resumed_ja4}  {}",
        ja4::ja4_r(&resumed).unwrap()
    );
    assert!(full_ja4.starts_with("t12d"), "{full_ja4}");
    assert_eq!(
        has_ext(&full, 0x0023).as_deref(),
        Some(&[][..]),
        "empty session_ticket"
    );
    assert!(
        has_ext(&resumed, 0x0023).is_some_and(|t| !t.is_empty()),
        "the second connection did not offer the ticket"
    );
    assert_eq!(full_ja4, resumed_ja4);
    assert_eq!(ja4::ja4(&resumed).unwrap().as_str(), resumed_ja4);
}

// ---------------------------------------------------------------------------
// HTTP/2

/// An HTTP/2 frame (RFC 9113 §4.1).
fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut f = len[1..].to_vec();
    f.extend([ty, flags]);
    f.extend(stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// HPACK "literal header field without indexing, indexed name" (RFC 7541
/// §6.2.2) for a static-table name index below 15, without Huffman coding.
fn literal(name_index: u8, value: &[u8]) -> Vec<u8> {
    let mut v = vec![name_index, u8::try_from(value.len()).unwrap()];
    v.extend_from_slice(value);
    v
}

/// Two GET requests on streams 1 and 3 of one h2 connection; asserts both
/// answered `:status 200`.
fn h2_two_requests(addr: SocketAddr, paths: [&str; 2]) {
    let p = Params {
        alpn: Some(b"\x02h2"),
        ..TLS13
    };
    let mut s = tls_connect(addr, &connector(p), p);
    assert_eq!(s.ssl().selected_alpn_protocol(), Some(&b"h2"[..]));
    let mut out = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    out.extend(frame(0x4, 0, 0, &[]));
    for (stream, path) in [1u32, 3].into_iter().zip(paths) {
        // :method GET (static 2), :scheme https (static 7), :path, :authority.
        let mut block = vec![0x82, 0x87];
        block.extend(literal(4, path.as_bytes()));
        block.extend(literal(1, b"example.com"));
        out.extend(frame(0x1, 0x4 | 0x1, stream, &block));
    }
    s.write_all(&out).unwrap();

    let mut done = [false; 2];
    let mut status = [0u8; 2];
    while done != [true, true] {
        let mut h = [0u8; 9];
        s.read_exact(&mut h).unwrap();
        let len = usize::try_from(u32::from_be_bytes([0, h[0], h[1], h[2]])).unwrap();
        let (ty, flags) = (h[3], h[4]);
        let stream = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).unwrap();
        let slot = match stream {
            1 => Some(0),
            3 => Some(1),
            _ => None,
        };
        match (ty, slot) {
            (0x4, _) if flags & 0x1 == 0 => s.write_all(&frame(0x4, 0x1, 0, &[])).unwrap(),
            (0x3 | 0x7, _) => panic!("h2 frame type {ty} on stream {stream}: {payload:x?}"),
            (0x1, Some(k)) => {
                status[k] = status[k].max(payload.first().copied().unwrap_or(0));
                done[k] |= flags & 0x1 != 0;
            }
            (0x0, Some(k)) => done[k] |= flags & 0x1 != 0,
            _ => {}
        }
    }
    // `:status 200` is the indexed static entry 8.
    assert_eq!(status, [0x88, 0x88]);
}

/// §15 HTTP/2: the JA4 belongs to the connection; both streams carry it.
#[test]
fn http2_streams_share_the_connection_ja4() {
    let s = start("ja4-h2");
    h2_two_requests(s.spike, ["/ja4/h2-a", "/ja4/h2-b"]);
    for path in ["/ja4/h2-a", "/ja4/h2-b"] {
        let ev = decision(&s.events, path);
        assert_eq!(ev["ctx"]["http"]["version"], "HTTP/2", "{path}");
        assert_eq!(ev["ctx"]["tls"]["alpn"], "h2", "{path}");
        assert_eq!(event_ja4(&ev).as_deref(), Some(BORING_TLS13_H2), "{path}");
        assert_policy_saw_missing(&ev);
    }
}

// ---------------------------------------------------------------------------
// Overhead (§15: "normal timing test, order of magnitude").

fn percentile(v: &mut [Duration], p: usize) -> Duration {
    v.sort_unstable();
    v[(v.len() - 1) * p / 100]
}

/// Full handshakes against the two listeners of one Edge, interleaved, and
/// the callback's own work (`compute_ja4`, which is what the
/// select-certificate callback runs) on a real ClientHello. Prints the
/// numbers; asserts only a loose bound (debug builds, shared CI machines).
#[test]
fn handshake_and_parser_overhead() {
    let s = start("ja4-overhead");
    let c = connector(TLS13);
    for addr in [s.spike, s.plain] {
        drop(tls_connect(addr, &c, TLS13));
    }
    const N: usize = 200;
    let (mut spike, mut plain) = (Vec::with_capacity(N), Vec::with_capacity(N));
    for i in 0..2 * N {
        let (addr, into) = if i % 2 == 0 {
            (s.spike, &mut spike)
        } else {
            (s.plain, &mut plain)
        };
        let t = Instant::now();
        let conn = tls_connect(addr, &c, TLS13);
        into.push(t.elapsed());
        drop(conn);
    }
    let (sp50, pl50) = (percentile(&mut spike, 50), percentile(&mut plain, 50));
    let (sp90, pl90) = (percentile(&mut spike, 90), percentile(&mut plain, 90));
    eprintln!(
        "TLS 1.3 handshake over loopback, {N} each (debug build): \
         ja4_spike p50 {sp50:?} p90 {sp90:?}; plain p50 {pl50:?} p90 {pl90:?}"
    );

    let relay = Relay::start(s.spike);
    assert_eq!(boring_get(relay.addr, TLS13, "/ja4/overhead"), 200);
    let body = relay.hello(0);
    const M: u32 = 20_000;
    let t = Instant::now();
    for _ in 0..M {
        std::hint::black_box(mg_edge::tls::compute_ja4(std::hint::black_box(&body)));
    }
    let per = t.elapsed() / M;
    eprintln!(
        "compute_ja4 on a {}-byte ClientHello (debug build): {per:?} per call",
        body.len()
    );
    assert!(per < Duration::from_millis(1), "{per:?}");

    // The worst case a client can send: BoringSSL accepts a ClientHello of up
    // to 16 KiB (`ssl_max_handshake_message_len` when the server does not ask
    // for a certificate) and runs the callback before it looks at the cipher
    // list. The longest list to sort and hash is ~8,100 cipher suites.
    let largest = largest_hello();
    assert!(largest.len() <= 16 * 1024);
    let v = mg_edge::tls::compute_ja4(&largest).expect("parses");
    assert!(v.as_str().starts_with("t12i9900"), "{v}");
    const L: u32 = 20;
    let t = Instant::now();
    for _ in 0..L {
        std::hint::black_box(mg_edge::tls::compute_ja4(std::hint::black_box(&largest)));
    }
    let per_largest = t.elapsed() / L;
    eprintln!(
        "compute_ja4 on a {}-byte ClientHello with 8100 suites (debug build): {per_largest:?} per call",
        largest.len()
    );
    assert!(per_largest < Duration::from_millis(500), "{per_largest:?}");
}

/// A ClientHello body of 8,100 pseudo-random cipher suites and no
/// extensions, just under BoringSSL's 16 KiB limit: the slowest input of the
/// parser (the longest list to sort and hash).
fn largest_hello() -> Vec<u8> {
    let mut x: u16 = 0x1234;
    let ciphers: Vec<u16> = (0..8100)
        .map(|_| {
            x = x.wrapping_mul(25173).wrapping_add(13849);
            x
        })
        .collect();
    hello_body(&ciphers, None)
}

/// A ClientHello body: `legacy_version` TLS 1.2, `ciphers`, null
/// compression and, unless `None`, the extension block `exts` (bodies
/// written as given).
fn hello_body(ciphers: &[u16], exts: Option<&[(u16, Vec<u8>)]>) -> Vec<u8> {
    let mut b = vec![3, 3];
    b.extend([0x42; 32]);
    b.push(0);
    b.extend(u16::try_from(2 * ciphers.len()).unwrap().to_be_bytes());
    b.extend(ciphers.iter().flat_map(|c| c.to_be_bytes()));
    b.extend([1, 0]);
    if let Some(exts) = exts {
        let block: Vec<u8> = exts
            .iter()
            .flat_map(|(ty, data)| {
                let mut e = ty.to_be_bytes().to_vec();
                e.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
                e.extend_from_slice(data);
                e
            })
            .collect();
        b.extend(u16::try_from(block.len()).unwrap().to_be_bytes());
        b.extend(block);
    }
    b
}

/// `body` in one handshake record, as a client sends it.
fn hello_record(body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(body.len()).unwrap().to_be_bytes();
    let mut rec = vec![22, 3, 1];
    rec.extend(u16::try_from(body.len() + 4).unwrap().to_be_bytes());
    rec.extend([1, len[1], len[2], len[3]]);
    rec.extend_from_slice(body);
    rec
}
