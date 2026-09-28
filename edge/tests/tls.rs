//! TLS listeners (docs/impl/phase1-spec.md §9.2): `direct_tls` hands SNI and
//! ALPN from `EdgeTlsAccept` to the request; `origin_mtls` requires a client
//! certificate from `client_ca` and counts one `untrusted_ca` per failed
//! handshake, whatever the length of the rejected chain. Certificates:
//! `tests/fixtures/tls/` (test-only keys, `gen.sh`). Loopback only.

mod common;

use common::{TestEnv, fixture, free_addr, read_response};
use pingora::tls::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn tls_listener(name: &str, bind: SocketAddr, extra: &str) -> String {
    format!(
        "[[listeners]]\nname = \"{name}\"\nbind = \"{bind}\"\n{extra}tls_cert = \"{}\"\ntls_key = \"{}\"\n",
        fixture("tls/edge.pem").display(),
        fixture("tls/edge.key").display()
    )
}

/// A TLS client trusting the test server CA; `client` = (chain, key).
fn connector(alpn: &[u8], client: Option<(&str, &str)>) -> SslConnector {
    let mut b = SslConnector::builder(SslMethod::tls()).unwrap();
    b.set_ca_file(fixture("tls/server-ca.pem")).unwrap();
    b.set_verify(SslVerifyMode::PEER);
    b.set_alpn_protos(alpn).unwrap();
    if let Some((chain, key)) = client {
        b.set_certificate_chain_file(fixture(chain)).unwrap();
        b.set_private_key_file(fixture(key), SslFiletype::PEM)
            .unwrap();
    }
    b.build()
}

/// One HTTP/1.1 request over TLS; `Err` if the handshake or exchange fails.
fn https(
    addr: SocketAddr,
    connector: &SslConnector,
    request: &str,
) -> Result<(common::Response, Option<String>), String> {
    let tcp =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut s = connector
        .connect("edge.test", tcp)
        .map_err(|e| format!("handshake: {e}"))?;
    let alpn = s
        .ssl()
        .selected_alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    if alpn.as_deref() == Some("h2") {
        return Ok((
            common::Response {
                status: 0,
                head: String::new(),
                body: String::new(),
            },
            alpn,
        ));
    }
    s.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    let r = read_response(&mut s).map_err(|e| e.to_string())?;
    if r.status == 0 {
        return Err("no HTTP response".into());
    }
    Ok((r, alpn))
}

const REQUEST: &str = "GET /tls HTTP/1.1\r\nHost: example.com\r\nCF-Connecting-IP: 198.51.100.7\r\nConnection: close\r\n\r\n";

#[test]
fn direct_tls_hands_sni_and_alpn_to_the_request() {
    let env = TestEnv::new("tls-direct");
    let bind = free_addr();
    let config = env.config(
        &tls_listener("tls", bind, "profile = \"direct_tls\"\n"),
        &env.site("")
            .replace("listeners = [\"cf-tunnel\"]", "listeners = [\"tls\"]"),
    );
    let path = env.write_config(&config);
    let out = env.check(&path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let edge = env.spawn(&path);

    let (r, alpn) = https(bind, &connector(b"\x08http/1.1", None), REQUEST).unwrap();
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(alpn.as_deref(), Some("http/1.1"));
    let seen = env.origin.last("/tls").unwrap();
    // direct_tls: the TCP peer is the client, every upstream family is stripped.
    assert_eq!(seen.header("mg-client-ip"), Some("127.0.0.1"));
    assert_eq!(seen.header("x-forwarded-proto"), Some("https"));
    assert!(!seen.has("cf-connecting-ip"));
    assert_eq!(
        edge.metric("mg_upstream_headers_stripped_total{profile=\"direct_tls\"}"),
        1.0
    );
    let id = seen.header("mg-request-id").unwrap().to_owned();
    let line = edge.request_log(&id).expect("request log line");
    assert!(
        line.contains("tls_sni=edge.test tls_alpn=http/1.1"),
        "TlsFacts did not reach the request: {line}"
    );

    // A failed handshake is logged by Pingora without the peer's address
    // (D-31); the Edge's log filter redacts it.
    let mut plain = std::net::TcpStream::connect(bind).unwrap();
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .unwrap();
    drop(plain);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let line = loop {
        if let Some(l) = edge
            .log_text()
            .lines()
            .find(|l| l.contains("Downstream handshake error"))
        {
            break l.to_owned();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no handshake error logged"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        line.contains("<redacted>") && !line.contains("127.0.0.1"),
        "{line}"
    );

    // ALPN offers h2 first (§9.2).
    let (_, alpn) = https(bind, &connector(b"\x02h2\x08http/1.1", None), REQUEST).unwrap();
    assert_eq!(alpn.as_deref(), Some("h2"));
}

#[test]
fn origin_mtls_requires_a_trusted_client_certificate() {
    let env = TestEnv::new("tls-mtls");
    let bind = free_addr();
    let extra = format!(
        "profile = \"cloudflare\"\nauth = \"origin_mtls\"\nclient_ca = \"{}\"\n",
        fixture("tls/client-ca.pem").display()
    );
    let config = env.config(
        &tls_listener("aop", bind, &extra),
        &env.site("")
            .replace("listeners = [\"cf-tunnel\"]", "listeners = [\"aop\"]"),
    );
    let edge = env.spawn(&env.write_config(&config));
    let untrusted = "mg_upstream_auth_failures_total{listener=\"aop\",profile=\"cloudflare\",reason=\"untrusted_ca\"}";

    let good = connector(b"\x08http/1.1", Some(("tls/client.pem", "tls/client.key")));
    let (r, _) = https(bind, &good, REQUEST).unwrap();
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/tls").unwrap();
    assert_eq!(
        seen.header("mg-client-ip"),
        Some("198.51.100.7"),
        "cloudflare headers are trusted"
    );
    let id = seen.header("mg-request-id").unwrap().to_owned();
    assert!(
        edge.request_log(&id)
            .unwrap()
            .contains(" auth=origin_mtls ")
    );

    // A two-certificate chain from another CA: one failed handshake, one count.
    let rogue = connector(
        b"\x08http/1.1",
        Some(("tls/rogue-chain.pem", "tls/rogue.key")),
    );
    assert!(
        https(bind, &rogue, REQUEST).is_err(),
        "an untrusted client got a response"
    );
    edge.wait_metric(untrusted, 5, |v| v >= 1.0);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        edge.metric(untrusted),
        1.0,
        "one failed handshake, one count"
    );

    // No client certificate: the handshake fails too.
    let anonymous = connector(b"\x08http/1.1", None);
    assert!(https(bind, &anonymous, REQUEST).is_err());
    assert_eq!(
        env.origin.seen().len(),
        1,
        "only the trusted client reached the origin"
    );
}

/// `cloudflare_ip_filter` (§9.2): TCP peers outside every site's
/// `cloudflare-ips` artifact are dropped before the TLS handshake; with no
/// artifact yet the filter accepts everything and reports itself inactive.
#[test]
fn cloudflare_ip_filter_drops_peers_outside_the_ranges() {
    let aop = |env: &TestEnv, bind: SocketAddr| {
        let extra = format!(
            "profile = \"cloudflare\"\nauth = \"origin_mtls\"\nclient_ca = \"{}\"\ncloudflare_ip_filter = true\n",
            fixture("tls/client-ca.pem").display()
        );
        env.config(
            &tls_listener("aop", bind, &extra),
            &env.site("")
                .replace("listeners = [\"cf-tunnel\"]", "listeners = [\"aop\"]"),
        )
    };
    let good = connector(b"\x08http/1.1", Some(("tls/client.pem", "tls/client.key")));
    let active = "mg_cf_ip_filter_active{listener=\"aop\"}";

    // No bundle, no ranges: accepted, filter inactive.
    let env = TestEnv::new("tls-filter-open");
    let bind = free_addr();
    let edge = env.spawn(&env.write_config(&aop(&env, bind)));
    let (r, _) = https(bind, &good, REQUEST).unwrap();
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(edge.metric(active), 0.0);
    drop(edge);

    // A bundle with Cloudflare's ranges: a loopback peer is not Cloudflare.
    let env = TestEnv::new("tls-filter");
    let bind = free_addr();
    let ranges = std::fs::read(common::repo(
        "testdata/phase1/artifacts/cloudflare-ips.json",
    ))
    .unwrap();
    let sha = env.cache_artifact(&ranges);
    let mut b = common::blog_bundle(1);
    b.allowed_listeners = vec!["aop".into()];
    b.artifacts.push(mg_proto::v1::ArtifactRef {
        name: "cloudflare-ips".into(),
        uri: format!("artifacts/{sha}"),
        sha256: sha,
        version: String::new(),
        size: ranges.len() as u64,
    });
    env.write_lkg("blog", &common::sign(&b));
    let edge = env.spawn(&env.write_config(&aop(&env, bind)));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    // Active from the start (the LKG has the ranges), not only once the
    // first connection has been checked.
    assert_eq!(edge.metric(active), 1.0);
    assert!(
        https(bind, &good, REQUEST).is_err(),
        "a non-Cloudflare peer got through"
    );
    assert_eq!(edge.metric(active), 1.0);
    assert!(env.origin.seen().is_empty());
}
