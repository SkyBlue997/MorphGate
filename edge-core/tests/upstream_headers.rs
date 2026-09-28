//! Header families and hop-by-hop headers (docs/impl/phase1-spec.md §9.3
//! steps 3 and 5; WP-C1).

use mg_edge_core::upstream::{
    FAMILY_NAMES, FAMILY_PREFIXES, FRAMING, HOP_BY_HOP, connection_listed, hop_by_hop,
    is_upstream_family,
};

fn headers<'a>(pairs: &'a [(&'a str, &'a str)]) -> Vec<(&'a str, &'a [u8])> {
    pairs.iter().map(|(n, v)| (*n, v.as_bytes())).collect()
}

/// §9.3: every prefix and full name of the family list, in the canonical
/// spelling.
#[test]
fn family_list_is_exactly_the_spec_list() {
    assert_eq!(
        FAMILY_PREFIXES,
        [
            "cf-",
            "x-mg-",
            "cloudfront-",
            "ali-",
            "esa-",
            "eo-",
            "x-forwarded-",
            "mg-"
        ]
    );
    assert_eq!(
        FAMILY_NAMES,
        [
            "tls-ja3",
            "tls-ja4",
            "tls-hash",
            "x-forward-port",
            "forwarded",
            "true-client-ip",
            "x-real-ip",
            // I-29.
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
        ]
    );
}

/// The I-29 names in their canonical spelling.
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

/// I-29: the client-IP, URL-rewrite and method-override headers belong to
/// the families in any case and in their underscore spellings (the CGI
/// variable `HTTP_X_ORIGINAL_URL` is the same for all of them).
#[test]
fn i29_names_match_in_any_case_and_with_underscores() {
    for name in I29 {
        let upper = name.to_ascii_uppercase();
        let title: String = name
            .split('-')
            .map(|part| {
                let mut c = part.chars();
                c.next()
                    .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join("-");
        let underscore = name.replace('-', "_");
        let mixed = title.replacen('-', "_", 1);
        for spelling in [
            name.to_owned(),
            upper.clone(),
            title.clone(),
            underscore.clone(),
            underscore.to_ascii_uppercase(),
            mixed,
        ] {
            assert!(is_upstream_family(&spelling), "{spelling}");
        }
    }
    for name in [
        "X-Original-URL",
        "X_Original_Url",
        "X-HTTP-Method-Override",
        "x_http_method",
        "Fastly-Client-IP",
        "CLIENT_IP",
        "X-Cluster-Client-Ip",
    ] {
        assert!(is_upstream_family(name), "{name}");
    }
}

/// I-29 names are whole names, not prefixes: neighbours stay ordinary.
#[test]
fn i29_names_match_whole_names_only() {
    for name in [
        "client-ip2",
        "client",
        "x-client",
        "x-client-ips",
        "x-original-uri",
        "x-original-urls",
        "x-rewrite",
        "x-http-methods",
        "x-http-method-overrides",
        "x-method",
        "x-remote-address",
        "x-remote",
        "fastly-client",
        "x-originating",
        "original-url",
        "method-override",
    ] {
        assert!(!is_upstream_family(name), "{name}");
    }
}

/// I-29 with §9.3 steps 3-5: a `Connection` listing of an I-29 name is
/// left to step 5 like every family name (step 5 strips it and counts it),
/// so the header is removed whether or not the client nominated it.
#[test]
fn connection_listed_i29_names_are_left_to_step_5() {
    let h = headers(&[
        (
            "Connection",
            "X-Original-URL, x_http_method_override, CLIENT-IP, X-Custom",
        ),
        ("X-Original-URL", "/admin"),
        ("x_http_method_override", "DELETE"),
        ("Client-IP", "10.0.0.1"),
    ]);
    let listed = connection_listed(&h);
    assert_eq!(
        listed,
        [
            "x-original-url",
            "x_http_method_override",
            "client-ip",
            "x-custom"
        ]
    );
    let hop = hop_by_hop(&h);
    assert_eq!(
        hop,
        [
            "connection",
            "x-custom",
            "keep-alive",
            "proxy-connection",
            "te",
            "upgrade"
        ]
    );
    for name in &listed {
        assert!(hop.contains(name) || is_upstream_family(name), "{name}");
    }
    for (name, _) in &h[1..] {
        assert!(is_upstream_family(name), "{name}");
    }
}

/// §9.3: a representative member of every prefix family, in several
/// spellings.
#[test]
fn prefix_families_match_in_any_case() {
    for name in [
        "cf-connecting-ip",
        "CF-Connecting-IP",
        "Cf-Ray",
        "cf-",
        "x-mg-cf-asn",
        "X-MG-Upstream-Key",
        "x-mg-",
        "CloudFront-Viewer-Address",
        "cloudfront-is-mobile-viewer",
        "Ali-Cdn-Real-Ip",
        "ali-swift-log-host",
        "Esa-User-Risk",
        "EO-Connecting-IP",
        "eo-client-ip",
        "X-Forwarded-For",
        "x-forwarded-proto",
        "X-Forwarded-Host",
        "MG-Client-IP",
        "mg-bot-score",
        "mg-",
    ] {
        assert!(is_upstream_family(name), "{name}");
    }
}

/// §9.3: names are lower-cased and `_` becomes `-` before matching, so the
/// CGI-equivalent underscore spellings are stripped too.
#[test]
fn underscore_variants_match() {
    for name in [
        "CF_Connecting_IP",
        "cf_ray",
        "X_MG_CF_ASN",
        "x_mg_upstream_key",
        "x-mg_cf-tls-random",
        "CLOUDFRONT_VIEWER_ADDRESS",
        "ali_cdn_real_ip",
        "ESA_USER_RISK",
        "eo_connecting_ip",
        "X_Forwarded_For",
        "MG_Client_IP",
        "mg_bot_score",
        "TLS_JA3",
        "Tls_Ja4",
        "tls_hash",
        "X_Forward_Port",
        "True_Client_IP",
        "X_REAL_IP",
    ] {
        assert!(is_upstream_family(name), "{name}");
    }
}

/// §9.3: the full names match exactly, not as prefixes.
#[test]
fn full_names_match_whole_names_only() {
    for name in [
        "Tls-Ja3",
        "TLS-JA4",
        "tls-hash",
        "X-Forward-Port",
        "Forwarded",
        "True-Client-IP",
        "X-Real-IP",
    ] {
        assert!(is_upstream_family(name), "{name}");
    }
    for name in [
        "tls-ja3-extra",
        "tls-ja",
        "forwarded-by",
        "x-forward-portal",
        "true-client-ip2",
        "x-real-ipv6",
        "x-real",
    ] {
        assert!(!is_upstream_family(name), "{name}");
    }
}

#[test]
fn ordinary_headers_are_not_upstream_family() {
    for name in [
        "",
        "c",
        "cf",
        "cfx-foo",
        "Accept",
        "User-Agent",
        "Cookie",
        "Host",
        "Connection",
        "x-mgx",
        "x-mg",
        "xmg-foo",
        "x-forwarded",
        "x-forwardedfor",
        "mg",
        "mgx-foo",
        "eox-foo",
        "Sec-CH-UA",
        "cdn-loop",
        "Via",
        "Referer",
        "Ümlaut-cf-",
    ] {
        assert!(!is_upstream_family(name), "{name}");
    }
}

/// §9.3 step 3: names listed by `Connection`, lower-cased, trimmed,
/// distinct, across repeated fields.
#[test]
fn connection_lists_names_lower_cased_and_distinct() {
    let h = headers(&[
        ("Host", "example.com"),
        ("Connection", "MG-Client-IP, X-Forwarded-For"),
        ("Accept", "*/*"),
        ("connection", " keep-alive ,\tMG-Client-IP,, ,x_mg_cf_asn"),
        ("CONNECTION", "Upgrade"),
    ]);
    assert_eq!(
        connection_listed(&h),
        [
            "mg-client-ip",
            "x-forwarded-for",
            "keep-alive",
            "x_mg_cf_asn",
            "upgrade"
        ]
    );
}

#[test]
fn connection_skips_non_token_entries() {
    let h: Vec<(&str, &[u8])> = vec![(
        "Connection",
        b"close, bad name, a\"b, \xff\xfe, ok-token, (x), a/b",
    )];
    assert_eq!(connection_listed(&h), ["close", "ok-token"]);
    assert!(connection_listed(&headers(&[("Accept", "a, b")])).is_empty());
    assert!(connection_listed(&headers(&[("Connection", "")])).is_empty());
    // Only the exact field name `Connection` lists hop-by-hop headers.
    assert!(connection_listed(&headers(&[("Connection_", "mg-client-ip")])).is_empty());
    assert!(connection_listed(&headers(&[("Proxy-Connection", "mg-client-ip")])).is_empty());
}

/// §9.3 step 3 and D-34: the attack `Connection: MG-Client-IP,
/// X-Forwarded-For` only ever removes the client's own copies, because the
/// `Connection` field itself is removed at step 3 and the listed family
/// names at step 5, all before the Edge writes its origin headers.
#[test]
fn hop_by_hop_covers_connection_listed_and_fixed_names() {
    let h = headers(&[
        (
            "Connection",
            "MG-Client-IP, X-Forwarded-For, X-Custom, keep-alive",
        ),
        ("Keep-Alive", "timeout=5"),
        ("TE", "trailers"),
    ]);
    assert_eq!(
        hop_by_hop(&h),
        [
            "connection",
            "x-custom",
            "keep-alive",
            "proxy-connection",
            "te",
            "upgrade"
        ]
    );
    assert!(is_upstream_family("mg-client-ip") && is_upstream_family("x-forwarded-for"));
    // Without a Connection field the fixed names are still removed.
    let mut expected = vec!["connection"];
    expected.extend(HOP_BY_HOP);
    assert_eq!(hop_by_hop(&[]), expected);
    // `Connection: connection` does not duplicate the entry.
    assert_eq!(
        hop_by_hop(&headers(&[("Connection", "Connection, TE")])),
        [
            "connection",
            "te",
            "keep-alive",
            "proxy-connection",
            "upgrade"
        ]
    );
}

/// §9.3 steps 3–5, D-23: listed upstream-family names are left to step 5
/// (which strips them all), so `Connection` can never hide a trusted
/// Cloudflare header such as `CF-Worker` from the step-4 parser.
#[test]
fn hop_by_hop_leaves_family_names_to_step_5() {
    let h = headers(&[(
        "Connection",
        "CF-Worker, cf_connecting_ip, X-MG-CF-ASN, MG-Client-IP, X-Forwarded-For, Forwarded, \
         X-Real-IP, X-Custom",
    )]);
    let listed = connection_listed(&h);
    assert_eq!(listed.len(), 8);
    assert_eq!(
        hop_by_hop(&h),
        [
            "connection",
            "x-custom",
            "keep-alive",
            "proxy-connection",
            "te",
            "upgrade"
        ]
    );
    // Every listed name is removed at step 3 or step 5.
    let hop = hop_by_hop(&h);
    for name in &listed {
        assert!(hop.contains(name) || is_upstream_family(name), "{name}");
    }
}

/// §9.3 step 3 never removes the message framing: a `Connection` listing of
/// `Content-Length` or `Transfer-Encoding` would otherwise make the proxy
/// read the body as empty and parse it as a second (smuggled) request.
#[test]
fn hop_by_hop_never_removes_the_message_framing() {
    let h = headers(&[
        (
            "Connection",
            "keep-alive, Content-Length, transfer-encoding, TRANSFER-ENCODING, X-Custom",
        ),
        ("Content-Length", "10"),
    ]);
    let listed = connection_listed(&h);
    assert!(listed.contains(&"content-length".to_owned()));
    assert!(listed.contains(&"transfer-encoding".to_owned()));
    let hop = hop_by_hop(&h);
    for name in FRAMING {
        assert!(!hop.contains(&name.to_owned()), "{name}: {hop:?}");
    }
    assert!(hop.contains(&"x-custom".to_owned()), "{hop:?}");
    assert_eq!(FRAMING, ["content-length", "transfer-encoding"]);
}

/// §9.3 step 3: `Upgrade` is kept only for a WebSocket upgrade.
#[test]
fn upgrade_is_kept_only_for_websocket() {
    let websocket = headers(&[("Connection", "Upgrade"), ("Upgrade", "websocket")]);
    let names = hop_by_hop(&websocket);
    assert!(names.contains(&"connection".to_owned()));
    assert!(!names.contains(&"upgrade".to_owned()), "{names:?}");

    let versioned = headers(&[
        ("Connection", "keep-alive, Upgrade"),
        ("Upgrade", "WebSocket/13"),
    ]);
    assert!(!hop_by_hop(&versioned).contains(&"upgrade".to_owned()));

    let h2c = headers(&[
        ("Connection", "Upgrade, HTTP2-Settings"),
        ("Upgrade", "h2c"),
    ]);
    let names = hop_by_hop(&h2c);
    assert!(names.contains(&"upgrade".to_owned()));
    assert!(names.contains(&"http2-settings".to_owned()));

    // `Upgrade: websocket` without `Connection: upgrade` is not an upgrade.
    let not_listed = headers(&[("Upgrade", "websocket")]);
    assert!(hop_by_hop(&not_listed).contains(&"upgrade".to_owned()));
}
