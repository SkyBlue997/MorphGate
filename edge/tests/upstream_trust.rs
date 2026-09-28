//! Upstream trust through the real binary (docs/impl/phase1-spec.md §9.2,
//! §9.3, §9.3.2, §9.9; WP-E1a test list). Loopback only.
//!
//! The `non_loopback_peer` rejection cannot be exercised here: a loopback
//! `cloudflare` listener must bind a loopback address, so every peer that
//! can reach it in a test is a loopback peer. `listener::tests` covers the
//! peer check itself.

mod common;

use common::{Edge, TestEnv, blog_bundle, cf, get, raw, sign};

/// An active monitor-mode site from an LKG bundle (no poll wait).
fn active(
    env: &TestEnv,
    site_extra: &str,
    edit: impl FnOnce(&mut mg_proto::v1::SiteBundle),
) -> Edge {
    let mut b = blog_bundle(1);
    edit(&mut b);
    env.write_lkg("blog", &sign(&b));
    let edge = env.spawn(&env.write_config(&env.default_config(site_extra)));
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    edge
}

#[test]
fn upstream_families_are_stripped_including_underscore_spellings() {
    let env = TestEnv::new("families");
    let _edge = active(&env, "", |_| {});
    let spoofed = "CF_Connecting_IP: 10.9.9.9\r\nX_MG_CF_ASN: 1\r\nx-mg-cf-asn: 64500\r\n\
        X-Forwarded-For: 10.0.0.1\r\nX-Forwarded-Host: evil.example\r\nX_Forwarded_Proto: http\r\n\
        Forwarded: for=10.0.0.1\r\nTrue-Client-IP: 10.0.0.2\r\nX-Real-IP: 10.0.0.3\r\n\
        mg-bot-score: 0\r\nMG_Bot_Class: human\r\nMG-Client-IP: 10.0.0.4\r\n\
        CloudFront-Viewer-Address: 10.0.0.5\r\nTLS-JA4: x\r\nx-mg-cf-t1: snippet\r\n\
        x-mg-cf-priority: u=1\r\nx-mg-upstream-key: guess\r\nX-Other: kept\r\n";
    let r = get(
        env.listen,
        "example.com",
        "/families",
        &format!("{}{spoofed}", cf("198.51.100.7")),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/families").unwrap();
    for (name, _) in &seen.headers {
        let lower = name.to_ascii_lowercase().replace('_', "-");
        let family = ["cf-", "x-mg-", "cloudfront-", "x-forwarded-", "mg-", "tls-"]
            .iter()
            .any(|p| lower.starts_with(p))
            || ["forwarded", "true-client-ip", "x-real-ip"].contains(&lower.as_str());
        let rewritten = [
            "cf-connecting-ip",
            "cf-ray",
            "cf-visitor",
            "x-forwarded-for",
            "x-forwarded-proto",
            "mg-client-ip",
            "mg-request-id",
            // The decision headers (WP-E1b), written by the Edge.
            "mg-bot-score",
            "mg-bot-class",
        ]
        .contains(&lower.as_str());
        assert!(
            !family || rewritten,
            "{name} reached the origin: {:?}",
            seen.headers
        );
        assert!(!name.contains('_'), "{name} reached the origin");
    }
    // Only the Edge's own values, each exactly once.
    assert_eq!(seen.all("cf-connecting-ip"), ["198.51.100.7"]);
    assert_eq!(seen.all("x-forwarded-for"), ["198.51.100.7"]);
    assert_eq!(seen.all("mg-client-ip"), ["198.51.100.7"]);
    assert_eq!(seen.all("x-forwarded-proto"), ["https"]);
    // The client's MG-Bot-Score / MG_Bot_Class never survive: only the
    // Edge's decision headers arrive, once each.
    let score = seen.all("mg-bot-score");
    assert_eq!(score.len(), 1, "{:?}", seen.headers);
    assert!(score[0].parse::<u8>().is_ok_and(|s| s <= 100));
    let class = seen.all("mg-bot-class");
    assert_eq!(class.len(), 1);
    assert_ne!(class[0], "human", "the forged value");
    assert_eq!(seen.all("cf-ray"), ["8f00aa11bb22cc33-HKG"]);
    assert_eq!(seen.header("x-other"), Some("kept"));
    assert!(!seen.has("cf-ipcountry"), "location headers are off");

    // The underscore spelling is never parsed as the client address.
    let r = get(
        env.listen,
        "example.com",
        "/underscore",
        "CF_Connecting_IP: 198.51.100.8\r\n",
    );
    assert_eq!(r.status, 200);
    let seen = env.origin.last("/underscore").unwrap();
    assert_eq!(seen.header("mg-client-ip"), Some("unknown"));
    assert!(!seen.has("cf-connecting-ip") && !seen.has("x-forwarded-for"));
}

/// I-29: the client-IP, URL-rewrite and method-override headers, in their
/// canonical form, upper case, underscore spellings and when the client
/// nominates them in `Connection`.
const I29: [&str; 12] = [
    "client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "fastly-client-ip",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "x-original-url",
    "x-rewrite-url",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// I-29 header lines: every name in three spellings, each value a unique
/// `spoof-*` marker, plus a `Connection` field that nominates some of them.
fn i29_spoofed() -> String {
    let mut lines = String::new();
    for (i, name) in I29.iter().enumerate() {
        let title: Vec<String> = name
            .split('-')
            .map(|p| p[..1].to_ascii_uppercase() + &p[1..])
            .collect();
        lines += &format!("{}: spoof-{i}-a\r\n", title.join("-"));
        lines += &format!("{}: spoof-{i}-b\r\n", name.to_ascii_uppercase());
        lines += &format!("{}: spoof-{i}-c\r\n", title.join("_"));
    }
    lines += "Connection: X-Original-URL, x_http_method_override, CLIENT-IP, X_Rewrite_Url\r\n";
    lines
}

/// I-29: none of the extra client-IP, URL-rewrite and method-override
/// headers reaches the origin, whatever the spelling and whether or not
/// `Connection` nominates them; the origin sees the Edge's path, method and
/// client address only.
#[test]
fn i29_client_ip_rewrite_and_override_headers_never_reach_the_origin() {
    let env = TestEnv::new("i29");
    let _edge = active(&env, "", |_| {});
    let r = get(
        env.listen,
        "example.com",
        "/i29",
        &format!("{}{}X-Other: kept\r\n", cf("198.51.100.7"), i29_spoofed()),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/i29").unwrap();
    assert!(seen.line.starts_with("GET /i29 "), "{}", seen.line);
    for (name, value) in &seen.headers {
        let normalized = name.to_ascii_lowercase().replace('_', "-");
        assert!(
            !I29.contains(&normalized.as_str()),
            "{name} reached the origin: {:?}",
            seen.headers
        );
        assert!(!value.contains("spoof-"), "{name}: {value}");
    }
    assert_eq!(seen.header("x-other"), Some("kept"));
    assert_eq!(seen.all("mg-client-ip"), ["198.51.100.7"]);
    assert_eq!(seen.all("x-forwarded-for"), ["198.51.100.7"]);
}

/// I-29 against framing tricks: an I-29 name hidden in an obs-fold
/// continuation or spelled with whitespace before the colon is a malformed
/// request (400, nothing reaches the origin; Pingora's request parser
/// rejects both, and a Pingora bump must keep it that way). Several
/// `Connection` lines in any case and repeated names in mixed spellings are
/// all stripped, and a chunked request's trailer section never reaches the
/// origin (its reader accepts no trailers, so it would drop the request).
#[test]
fn i29_names_survive_no_framing_trick() {
    let env = TestEnv::new("i29-framing");
    let _edge = active(&env, "", |_| {});
    let head = |method: &str, path: &str| {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n{}",
            cf("198.51.100.7")
        )
    };
    for (path, lines) in [
        (
            "/i29-fold-line",
            "X-Other: a\r\n X-Original-URL: /spoof\r\n",
        ),
        ("/i29-fold-value", "X-Original-URL:\r\n /spoof\r\n"),
        ("/i29-space", "X-Original-URL : /spoof\r\n"),
        ("/i29-tab", "X-HTTP-Method-Override\t: DELETE\r\n"),
    ] {
        let req = format!("{}{lines}\r\n", head("GET", path));
        let r = raw(env.listen, req.as_bytes()).unwrap();
        assert_eq!(r.status, 400, "{path}: {}", r.head);
        assert!(env.origin.last(path).is_none(), "{path} reached the origin");
    }

    let assert_clean = |path: &str| {
        let seen = env.origin.last(path).unwrap_or_else(|| panic!("{path}"));
        for (name, value) in &seen.headers {
            let normalized = name.to_ascii_lowercase().replace('_', "-");
            assert!(!I29.contains(&normalized.as_str()), "{path}: {name}");
            assert!(!value.contains("spoof"), "{path}: {name}: {value}");
        }
        seen
    };
    let conn = "CONNECTION: X-Client-IP\r\nconnection: x_remote_addr, X-HTTP-Method\r\n\
                X-Client-IP: spoof-a\r\nx_remote_addr: spoof-b\r\nX-HTTP-METHOD: spoof-c\r\n\
                x-client-ip: spoof-d\r\nX_CLIENT_IP: spoof-e\r\nx-Client_Ip: spoof-f\r\n";
    let r = raw(
        env.listen,
        format!("{}{conn}\r\n", head("GET", "/i29-conn")).as_bytes(),
    )
    .unwrap();
    assert_eq!(r.status, 200, "{}", r.head);
    assert_clean("/i29-conn");

    let chunked = format!(
        "{}Transfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n\
         3\r\nabc\r\n0\r\nX-Original-URL: /spoof\r\nX-HTTP-Method-Override: spoof\r\n\r\n",
        head("POST", "/i29-trailer")
    );
    let r = raw(env.listen, chunked.as_bytes()).unwrap();
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = assert_clean("/i29-trailer");
    assert!(seen.line.starts_with("POST /i29-trailer "), "{}", seen.line);
    assert_eq!(seen.body, b"abc");
}

#[test]
fn client_ip_unknown_is_never_more_permissive() {
    let env = TestEnv::new("ipunknown");
    let edge = active(&env, "", |_| {});
    let missing = "mg_cf_connecting_ip_missing_total{site=\"blog\"}";
    for (i, headers) in [
        String::new(),
        "CF-Connecting-IP: not-an-ip\r\n".to_string(),
        "CF-Connecting-IP: 198.51.100.7:443\r\n".to_string(),
        "CF-Connecting-IP: [2001:db8::1]\r\n".to_string(),
        "CF-Connecting-IP: 198.51.100.7\r\nCF-Connecting-IP: 198.51.100.8\r\n".to_string(),
    ]
    .iter()
    .enumerate()
    {
        let path = format!("/unknown-{i}");
        let r = get(
            env.listen,
            "example.com",
            &path,
            &format!("{headers}X-Forwarded-For: 10.1.1.1\r\n"),
        );
        assert_eq!(r.status, 200, "{headers}");
        let seen = env.origin.last(&path).unwrap();
        assert_eq!(seen.header("mg-client-ip"), Some("unknown"), "{headers}");
        assert!(!seen.has("cf-connecting-ip"), "{headers}");
        assert!(!seen.has("x-forwarded-for"), "{headers}");
    }
    assert_eq!(edge.metric(missing), 5.0);

    // IPv4-mapped addresses are the IPv4 client.
    let r = get(
        env.listen,
        "example.com",
        "/mapped",
        &cf("::ffff:198.51.100.9"),
    );
    assert_eq!(r.status, 200);
    let seen = env.origin.last("/mapped").unwrap();
    assert_eq!(seen.header("mg-client-ip"), Some("198.51.100.9"));
    assert_eq!(edge.metric(missing), 5.0);
}

#[test]
fn foreign_zone_workers_are_rejected_and_counted() {
    let env = TestEnv::new("worker");
    let edge = active(&env, "", |_| {});
    let counter = "mg_cf_foreign_worker_total{site=\"blog\"}";

    let own = get(
        env.listen,
        "example.com",
        "/own",
        &format!("{}CF-Worker: example.com\r\n", cf("198.51.100.7")),
    );
    assert_eq!(own.status, 200, "an owner-zone Worker is served");
    assert_eq!(edge.metric(counter), 0.0);

    for worker in [
        "CF-Worker: evil.example\r\n",
        "CF-Worker: EXAMPLE!\r\n",
        "CF-Worker: example.com\r\nCF-Worker: evil.example\r\n",
        // Connection must not hide the header from the check (I-12).
        "Connection: CF-Worker\r\nCF-Worker: evil.example\r\n",
    ] {
        let r = get(
            env.listen,
            "example.com",
            "/foreign",
            &format!("{}{worker}", cf("198.51.100.7")),
        );
        assert_eq!(r.status, 403, "{worker}");
        assert_eq!(r.body, "forbidden");
        assert_eq!(r.header("cache-control"), Some("no-store, private"));
    }
    assert_eq!(edge.metric(counter), 4.0);
    assert!(env.origin.last("/foreign").is_none());
}

#[test]
fn bootstrap_owner_zones_decide_workers_before_the_first_bundle() {
    // No bundle: every Worker is foreign...
    let env = TestEnv::new("bootworker");
    let edge = env.spawn(&env.write_config(&env.default_config("")));
    let r = get(
        env.listen,
        "example.com",
        "/w",
        &format!("{}CF-Worker: example.com\r\n", cf("198.51.100.7")),
    );
    assert_eq!(r.status, 403);
    assert_eq!(
        edge.metric("mg_cf_foreign_worker_total{site=\"blog\"}"),
        1.0
    );
    drop(edge);

    // ... unless edge.toml names the owner's zones (I-4).
    let env = TestEnv::new("bootworker2");
    let _edge = env
        .spawn(&env.write_config(&env.default_config("bootstrap_owner_zones = [\"example.com\"]")));
    let r = get(
        env.listen,
        "example.com",
        "/w",
        &format!("{}CF-Worker: example.com\r\n", cf("198.51.100.7")),
    );
    assert_eq!(r.status, 200);
    let r = get(
        env.listen,
        "example.com",
        "/w",
        &format!("{}CF-Worker: other.example\r\n", cf("198.51.100.7")),
    );
    assert_eq!(r.status, 403);
}

#[test]
fn secret_header_is_required_when_configured() {
    let env = TestEnv::new("secret");
    let config = env.default_config("").replace(
        "profile = \"cloudflare\"\n",
        "profile = \"cloudflare\"\nupstream_keys = \"cred://mg-upstream-keys\"\n",
    );
    let edge = env.spawn(&env.write_config(&config));
    let reason = "mg_upstream_auth_failures_total{listener=\"cf-tunnel\",profile=\"cloudflare\",reason=\"bad_secret_header\"}";
    let current = "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
    let previous = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8";

    for (i, h) in [
        String::new(),
        "x-mg-upstream-key: wrong\r\n".into(),
        format!("x-mg-upstream-key: {}\r\n", &current[..42]),
        format!("x-mg-upstream-key: {current}\r\nx-mg-upstream-key: {current}\r\n"),
        format!("X_MG_Upstream_Key: {current}\r\n"),
    ]
    .iter()
    .enumerate()
    {
        let r = get(
            env.listen,
            "example.com",
            "/secret",
            &format!("{}{h}", cf("198.51.100.7")),
        );
        assert_eq!(r.status, 403, "{h}");
        assert_eq!(r.body, "forbidden");
        assert_eq!(edge.metric(reason), (i + 1) as f64);
    }
    assert!(env.origin.last("/secret").is_none());

    for key in [current, previous] {
        let r = get(
            env.listen,
            "example.com",
            "/secret-ok",
            &format!("{}x-mg-upstream-key: {key}\r\n", cf("198.51.100.7")),
        );
        assert_eq!(r.status, 200, "{key}");
    }
    let seen = env.origin.last("/secret-ok").unwrap();
    assert!(
        !seen.has("x-mg-upstream-key"),
        "the secret is never forwarded"
    );
}

#[test]
fn edge_headers_survive_connection_listings_and_mg_headers_are_stripped_both_ways() {
    let env = TestEnv::new("mgheaders");
    let _edge = active(&env, "", |_| {});
    let r = get(
        env.listen,
        "example.com",
        "/conn",
        &format!(
            "{}Connection: keep-alive, MG-Client-IP, X-Forwarded-For, MG-Request-Id, X-Other\r\n\
             X-Other: dropped\r\nKeep-Alive: timeout=5\r\nX-Forwarded-For: 10.0.0.1\r\n\
             X-Forwarded-For: 10.0.0.2\r\n",
            cf("198.51.100.7")
        ),
    );
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/conn").unwrap();
    assert_eq!(seen.all("mg-client-ip"), ["198.51.100.7"]);
    assert_eq!(seen.all("mg-request-id").len(), 1);
    assert_eq!(seen.all("x-forwarded-for"), ["198.51.100.7"]);
    assert!(
        !seen.has("x-other"),
        "a Connection-listed header is hop-by-hop"
    );
    assert!(!seen.has("keep-alive"));
    assert!(
        seen.all("connection")
            .iter()
            .all(|v| !v.to_ascii_lowercase().contains("mg-")),
        "{:?}",
        seen.headers
    );

    // Origin -> client: MG-* and MG_* never leave the Edge.
    let r = get(
        env.listen,
        "example.com",
        "/mg-response",
        &cf("198.51.100.7"),
    );
    assert_eq!(r.status, 200);
    assert!(
        !r.has_header_prefix("mg-") && !r.has_header_prefix("mg_"),
        "{}",
        r.head
    );
    assert_eq!(r.header("x-origin"), Some("kept"));
}

#[test]
fn upstream_host_is_the_normalized_host_and_targets_are_origin_form() {
    let env = TestEnv::new("host");
    let edge = active(&env, "", |_| {});
    let r = get(env.listen, "Example.COM.:8080", "/h1", &cf("198.51.100.7"));
    assert_eq!(r.status, 200, "{}", r.head);
    assert_eq!(env.origin.last("/h1").unwrap().all("host"), ["example.com"]);

    // Absolute-form: the authority takes part in the Host check, the origin
    // gets origin-form.
    let req = "GET http://www.example.com/abs?q=1 HTTP/1.1\r\nHost: www.example.com\r\n\
               CF-Connecting-IP: 198.51.100.7\r\nConnection: close\r\n\r\n";
    let r = raw(env.listen, req.as_bytes()).unwrap();
    assert_eq!(r.status, 200, "{}", r.head);
    let seen = env.origin.last("/abs").unwrap();
    assert_eq!(seen.line, "GET /abs?q=1 HTTP/1.1");
    assert_eq!(seen.all("host"), ["www.example.com"]);

    let bad_host = "mg_protocol_rejected_total{listener=\"cf-tunnel\",reason=\"bad_host\"}";
    for req in [
        // Absolute-form authority and Host disagree.
        "GET http://staging.example.com/x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        // Two Host field lines.
        "GET /x HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        // No Host at all.
        "GET /x HTTP/1.0\r\n\r\n",
        // Not a host name.
        "GET /x HTTP/1.1\r\nHost: exa mple.com\r\nConnection: close\r\n\r\n",
    ] {
        let r = raw(env.listen, req.as_bytes()).unwrap();
        assert_eq!(r.status, 400, "{req:?}: {}", r.head);
        assert!(
            r.head.to_ascii_lowercase().contains("no-store"),
            "{}",
            r.head
        );
        assert!(env.origin.last("/x").is_none());
    }
    // Pingora 0.9's HTTP/1 parser already answers the first two itself (400
    // before any filter runs, so they are not counted); the Edge's own check
    // covers the rest and HTTP/2 `:authority`.
    assert_eq!(edge.metric(bad_host), 2.0);
}

#[test]
fn location_headers_are_forwarded_only_when_trusted() {
    let env = TestEnv::new("location");
    let _edge = active(&env, "", |b| {
        b.cloudflare.as_mut().unwrap().location_headers = true;
    });
    let r = get(
        env.listen,
        "example.com",
        "/loc",
        &format!(
            "{}CF-IPCountry: HK\r\nCF-IPCity: Kowloon\r\n",
            cf("198.51.100.7")
        ),
    );
    assert_eq!(r.status, 200);
    let seen = env.origin.last("/loc").unwrap();
    assert_eq!(seen.all("cf-ipcountry"), ["HK"]);
    assert!(
        !seen.has("cf-ipcity"),
        "only the §9.9 headers are re-written"
    );
    assert_eq!(seen.header("cf-visitor"), Some("{\"scheme\":\"https\"}"));
}

/// §9.3 step 3 removes the headers a `Connection` field lists, but it must
/// never remove the message framing of the downstream request: Pingora
/// frames the request body from the (filtered) request header, so a
/// `Connection: Content-Length` (or `Transfer-Encoding`) would make the Edge
/// read the body as a second request on the same connection, with a forged
/// `CF-Connecting-IP` that the loopback listener trusts.
#[test]
fn connection_listed_framing_headers_cannot_smuggle_a_request() {
    use std::io::{Read as _, Write as _};
    use std::net::{Shutdown, TcpStream};
    use std::time::Duration;

    let env = TestEnv::new("smuggle");
    let _edge = active(&env, "", |_| {});
    let smuggled = "GET /smuggled HTTP/1.1\r\nHost: example.com\r\n\
                    CF-Connecting-IP: 203.0.113.66\r\n\r\n";
    for (i, (listed, framing, body)) in [
        (
            "Content-Length",
            format!("Content-Length: {}\r\n", smuggled.len()),
            smuggled.to_string(),
        ),
        (
            "Transfer-Encoding",
            "Transfer-Encoding: chunked\r\n".to_string(),
            format!("{:x}\r\n{smuggled}\r\n0\r\n\r\n", smuggled.len()),
        ),
    ]
    .iter()
    .enumerate()
    {
        let path = format!("/outer-{i}");
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: example.com\r\n{}Connection: keep-alive, {listed}\r\n{framing}\r\n",
            cf("198.51.100.7")
        );
        let mut s = TcpStream::connect(env.listen).unwrap();
        // Keep-alive: read whatever arrives until the Edge goes quiet.
        s.set_read_timeout(Some(Duration::from_millis(1500)))
            .unwrap();
        s.write_all(head.as_bytes()).unwrap();
        // The body in a later segment, as a slow client (or a proxy that
        // streams) sends it.
        std::thread::sleep(Duration::from_millis(300));
        s.write_all(body.as_bytes()).unwrap();
        let mut answer = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = s.read(&mut buf) {
            if n == 0 {
                break;
            }
            answer.extend_from_slice(&buf[..n]);
        }
        let _ = s.shutdown(Shutdown::Both);
        let answer = String::from_utf8_lossy(&answer);
        assert_eq!(
            answer.matches("HTTP/1.1 ").count(),
            1,
            "{listed}: one request, one response: {answer}"
        );
        assert!(
            env.origin.last("/smuggled").is_none(),
            "{listed}: the body was parsed as a request: {:?}",
            env.origin.seen()
        );
        let outer = env.origin.last(&path).expect("the outer request");
        assert_eq!(outer.body, smuggled.as_bytes(), "{listed}: body forwarded");
    }
}

/// D-31 / §2.4 item 5: application logs never contain a client address,
/// cookie or upstream key, at any level. Pingora's own debug output dumps
/// raw request bytes (the rejected header buffer, the parsed request), so
/// even `RUST_LOG=trace` must not let it through.
#[test]
fn logs_never_contain_client_secrets_even_at_trace_level() {
    let env = TestEnv::new("logsecrets");
    let mut b = blog_bundle(1);
    b.monitor_only = true;
    env.write_lkg("blog", &sign(&b));
    let edge = env.spawn_logging(&env.write_config(&env.default_config("")), "trace");
    edge.wait_metric("mg_config_version{site=\"blog\"}", 10, |v| v == 1.0);
    let ip = "198.51.100.77";
    let cookie = "session=cookie-marker-5f2d";
    let key = "upstream-key-marker-9c1e";
    let secrets =
        format!("CF-Connecting-IP: {ip}\r\nCookie: {cookie}\r\nx-mg-upstream-key: {key}\r\n");
    // Proxied, and rejected by Pingora's own parser (a header line without
    // a colon), which logs the raw buffer at debug level.
    let r = get(env.listen, "example.com", "/logged", &secrets);
    assert_eq!(r.status, 200, "{}", r.head);
    let bad = format!(
        "GET /bad HTTP/1.1\r\nHost: example.com\r\n{secrets}no colon here\r\nConnection: close\r\n\r\n"
    );
    let r = raw(env.listen, bad.as_bytes()).unwrap();
    assert_eq!(r.status, 400, "{}", r.head);
    // Let the logger flush.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let log = edge.log_text();
    assert!(!log.is_empty());
    for secret in [ip, "cookie-marker-5f2d", key] {
        assert!(!log.contains(secret), "{secret} in the log:\n{log}");
    }
}
