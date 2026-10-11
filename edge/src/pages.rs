//! The challenge answers the Edge writes (docs/impl/phase1-spec.md §10.2,
//! §10.3, §11.2, §9.9, D-11, D-32).
//!
//! * [`challenge_page`]: 403 HTML rendered from the SDK directory's
//!   `challenge.html` ([`crate::sdk::Template`]) with a per-response CSP
//!   nonce: `default-src 'none'; script-src 'nonce-<N>'; style-src
//!   'nonce-<N>'; worker-src 'self'; connect-src 'self'; img-src 'self'
//!   data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`.
//!   Every value is HTML-escaped by the template renderer.
//! * [`challenge_json`] / [`failed_json`]: the JSON forms of §10.2 / §10.3,
//!   serialized with `serde_json` (never by string formatting of client
//!   input).
//! * [`https_redirect`] (308, D-32), [`submit_redirect`] (303 + cookie,
//!   D-11), [`submit_ok_json`] (200 + cookie), [`too_early_json`] (425).
//!
//! Phase 2 (WP-E2a, docs/impl/phase2-spec.md §7.3, §11.2, §12.3): every
//! JSON answer carries `"v": 2`, every JSON error `MG-Error: <error>` (the
//! SDK takes only a 403 / 429 with `MG-Error` or `MG-Challenge` for the
//! Edge's), an interactive challenge carries its plain parameters `ix`
//! instead of `pow`, the template v2 placeholders `{{ix}}`, `{{help_href}}`
//! and `{{privacy_href}}` are filled, and the page language falls back to
//! the bundle's `challenge.default_lang`.
//!
//! The Edge's `MG-*` answer headers are `MG-Challenge` and `MG-Error`
//! (§9.9; the origin's are stripped).

use crate::enforce::{EdgeResponse, HTML, JSON, TEXT, safe_id};
use crate::sdk::{Placeholder, SdkDir};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mg_challenge::{POW_ALG, Rng, RngError};
use mg_core::ChallengeType;
use serde_json::{Value, json};

/// The endpoint prefix the page hands to the SDK (§11.2 `{{prefix}}`).
pub const PREFIX: &str = "/__mg/";

/// The challenge page's CSP for `nonce` (§10.2).
pub fn csp(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
         worker-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; \
         base-uri 'none'; frame-ancestors 'none'"
    )
}

/// A fresh CSP nonce: 128 bits from the OS CSPRNG, base64 (§10.2).
pub fn csp_nonce(rng: &dyn Rng) -> Result<String, RngError> {
    let mut raw = [0u8; 16];
    rng.fill(&mut raw)?;
    Ok(STANDARD.encode(raw))
}

/// `{{lang}}` (Phase 2 spec §7.3): `zh-CN` when the first `Accept-Language`
/// tag starts with `zh`, `en` when it starts with `en`, otherwise the
/// bundle's `default_lang` (`en` in schema 1 bundles, as Phase 1 §11.2).
pub fn page_lang(accept_language: Option<&str>, default_lang: &'static str) -> &'static str {
    let first = accept_language
        .and_then(|v| v.split(',').next())
        .and_then(|t| t.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    let starts = |p: &str| first.get(..2).is_some_and(|f| f.eq_ignore_ascii_case(p));
    if starts("zh") {
        "zh-CN"
    } else if starts("en") {
        "en"
    } else {
        default_lang
    }
}

/// `{{state}}` of the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    /// A fresh challenge (`state = challenge`).
    Challenge,
    /// A failed submission (`state = failed`), with or without a new `C`.
    Failed,
}

impl PageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "challenge",
            Self::Failed => "failed",
        }
    }
}

/// A sealed challenge as the page and the JSON answers show it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Shown<'a> {
    pub c: &'a str,
    pub ty: ChallengeType,
    pub bits: u32,
    /// The plain parameters of an interactive `C` (§7.2); `None` otherwise.
    pub ix: Option<&'a Value>,
}

impl Shown<'_> {
    /// The JSON members that describe the challenge: `challenge`, `type`
    /// and `pow` (invisible / pow) or `ix` (interactive).
    fn describe(&self, body: &mut Value) {
        body["challenge"] = json!(self.c);
        body["type"] = json!(self.ty.as_str());
        match self.ix {
            Some(ix) => body["ix"] = ix.clone(),
            None => body["pow"] = json!({"alg": POW_ALG, "bits": self.bits}),
        }
    }
}

/// Everything a rendered page needs.
#[derive(Debug, Clone, Copy)]
pub struct Page<'a> {
    pub lang: &'static str,
    /// From [`csp_nonce`].
    pub nonce: &'a str,
    pub request_id: &'a str,
    /// A validated return path (§6.4).
    pub ret: &'a str,
    pub state: PageState,
    /// `None`: a failed page without a new `C` (the SDK shows the retry link).
    pub challenge: Option<Shown<'a>>,
    /// Template v2 `{{help_href}}` / `{{privacy_href}}` (`challenge.help_path`
    /// / `privacy_path`, `/` by default).
    pub help_href: &'a str,
    pub privacy_href: &'a str,
}

/// The 403 challenge page (§10.2, §11.2).
pub fn challenge_page(sdk: &SdkDir, page: &Page<'_>) -> EdgeResponse {
    let sdk_src = sdk.sdk_src();
    let bits = page
        .challenge
        .map(|c| c.bits.to_string())
        .unwrap_or_default();
    // `{{ix}}`: the JSON of `ix`, escaped as an attribute value by the
    // renderer; empty on non-interactive pages (§12.3).
    let ix = page
        .challenge
        .and_then(|c| c.ix)
        .map(Value::to_string)
        .unwrap_or_default();
    let html = sdk.template.render(|p| match p {
        Placeholder::Lang => page.lang,
        Placeholder::Nonce => page.nonce,
        Placeholder::SdkSrc => &sdk_src,
        Placeholder::Prefix => PREFIX,
        Placeholder::C => page.challenge.map_or("", |c| c.c),
        Placeholder::Type => page.challenge.map_or("", |c| c.ty.as_str()),
        Placeholder::PowBits => &bits,
        Placeholder::Ret => page.ret,
        Placeholder::RequestId => safe_id(page.request_id),
        Placeholder::State => page.state.as_str(),
        Placeholder::Ix => &ix,
        Placeholder::HelpHref => page.help_href,
        Placeholder::PrivacyHref => page.privacy_href,
    });
    let mut resp = EdgeResponse::new(403, HTML, html);
    resp.csp = Some(csp(page.nonce));
    resp
}

/// The JSON version of every Edge answer (Phase 2 spec §11.2).
pub const JSON_V: u32 = 2;

/// A JSON error answer: `status`, the body and `MG-Error: <error>` (§11.2).
pub fn json_error(status: u16, error: &str, body: &Value) -> EdgeResponse {
    EdgeResponse::new(status, JSON, body.to_string()).with("MG-Error", error)
}

/// The 403 JSON challenge (§10.2, Phase 2 spec §7.3) with `MG-Challenge:
/// <type>`.
pub fn challenge_json(request_id: &str, shown: Shown<'_>, ret: &str) -> EdgeResponse {
    let mut body = json!({
        "v": JSON_V,
        "error": "mg_challenge",
        "ret": ret,
        "retry": true,
        "request_id": safe_id(request_id),
    });
    shown.describe(&mut body);
    json_error(403, "mg_challenge", &body).with("MG-Challenge", shown.ty.as_str())
}

/// The 403 JSON uniform failure of a fetch submission or a renewal (§10.3,
/// Phase 2 spec §7.4, §7.5); `challenge`, `type` and `pow` / `ix` only with
/// a new `C`.
pub fn failed_json(request_id: &str, new: Option<Shown<'_>>) -> EdgeResponse {
    let mut body = json!({
        "v": JSON_V,
        "error": "mg_challenge_failed",
        "retry": true,
        "request_id": safe_id(request_id),
    });
    if let Some(n) = new {
        n.describe(&mut body);
    }
    json_error(403, "mg_challenge_failed", &body)
}

/// 200 `{"v": 2, "challenge": …, "ix": …}`: a renewed interactive `C`
/// (Phase 2 spec §7.4 step 9).
pub fn renewed_json(shown: Shown<'_>) -> EdgeResponse {
    let mut body = json!({"v": JSON_V});
    shown.describe(&mut body);
    if let Some(o) = body.as_object_mut() {
        o.remove("type");
    }
    EdgeResponse::new(200, JSON, body.to_string())
}

/// A `Location` / URL value: bytes outside visible ASCII percent-encoded,
/// so the header value is always valid (a request target or a validated
/// `ret` has no other bytes to worry about).
pub fn url_safe(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if (0x21..=0x7e).contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// 308 to `https://<host><origin-form target>` for an http visitor (D-32).
/// `host` is §9.4-normalized: no port, and an IPv6 literal keeps its
/// brackets (`mg_edge_core::request::resolve_host`), as a URL needs.
pub fn https_redirect(host: &str, origin_form: &[u8]) -> EdgeResponse {
    let target = if origin_form.first() == Some(&b'/') {
        url_safe(origin_form)
    } else {
        "/".to_owned()
    };
    EdgeResponse::new(308, TEXT, "use https").with(
        "Location",
        format!("https://{}{target}", url_safe(host.as_bytes())),
    )
}

/// 303 to `ret` with the clearance cookie (navigation submission, D-11).
pub fn submit_redirect(ret: &str, set_cookie: String) -> EdgeResponse {
    EdgeResponse::new(303, TEXT, "")
        .with("Location", url_safe(ret.as_bytes()))
        .with("Set-Cookie", set_cookie)
}

/// 200 `{"ok": true, "ret": "<ret>", "v": 2, "now_ms": …}` with the
/// clearance cookie (fetch submission; Phase 2 spec §7.5).
pub fn submit_ok_json(ret: &str, set_cookie: String, now_ms: i64) -> EdgeResponse {
    let body = json!({"ok": true, "ret": ret, "v": JSON_V, "now_ms": now_ms});
    EdgeResponse::new(200, JSON, body.to_string()).with("Set-Cookie", set_cookie)
}

/// 425 `{"v": 2, "error": "mg_too_early"}` (`Early-Data`, §10.3 step 1).
pub fn too_early_json() -> EdgeResponse {
    json_error(
        425,
        "mg_too_early",
        &json!({"v": JSON_V, "error": "mg_too_early"}),
    )
}

/// 429 JSON `mg_rate_limited` with `Retry-After` (§11.2), for the endpoints
/// whose every answer is JSON (`/__mg/c/renew`).
pub fn rate_limited_json(request_id: &str, retry_after_s: u32) -> EdgeResponse {
    EdgeResponse::rate_limited(request_id, retry_after_s, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn sdk() -> SdkDir {
        SdkDir::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk")).unwrap()
    }

    fn sdk_v1() -> SdkDir {
        crate::test_support::sdk(false)
    }

    #[test]
    fn languages() {
        for default in ["en", "zh-CN"] {
            assert_eq!(page_lang(Some("zh-CN,zh;q=0.9,en;q=0.8"), default), "zh-CN");
            assert_eq!(page_lang(Some("ZH-tw"), default), "zh-CN");
            assert_eq!(page_lang(Some("zh;q=0.5"), default), "zh-CN");
            assert_eq!(page_lang(Some("en-US,zh;q=0.9"), default), "en");
            assert_eq!(page_lang(Some("EN"), default), "en");
            // Phase 2 spec §7.3: neither zh nor en -> challenge.default_lang.
            assert_eq!(page_lang(Some(""), default), default);
            assert_eq!(page_lang(Some("z"), default), default);
            assert_eq!(page_lang(Some("é"), default), default);
            assert_eq!(page_lang(Some("ja-JP,zh;q=0.8"), default), default);
            assert_eq!(page_lang(None, default), default);
        }
    }

    #[test]
    fn nonces_are_random_base64() {
        let a = csp_nonce(&crate::rng::OsRng).unwrap();
        let b = csp_nonce(&crate::rng::OsRng).unwrap();
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
        assert_eq!(STANDARD.decode(&a).unwrap().len(), 16);
    }

    /// §10.2: 403, CSP with the nonce, every placeholder replaced, the §9.9
    /// HTML headers; template v2 and the frozen v1 directory alike.
    #[test]
    fn page_rendering() {
        for sdk in [sdk(), sdk_v1()] {
            page_rendering_with(&sdk);
        }
    }

    fn page_rendering_with(sdk: &SdkDir) {
        let nonce = "q83vEjRWeJq83vEjRWeJqw==";
        let r = challenge_page(
            sdk,
            &Page {
                lang: "zh-CN",
                nonce,
                request_id: ID,
                ret: "/account/login?a=1&b=\"2\"",
                state: PageState::Challenge,
                challenge: Some(Shown {
                    c: "AAEC",
                    ty: ChallengeType::Pow,
                    bits: 16,
                    ix: None,
                }),
                help_href: "/help",
                privacy_href: "/privacy?x=\"1\"",
            },
        );
        assert_eq!(r.status, 403);
        let html = r.body_text();
        assert!(!html.contains("{{") && !html.contains("}}"), "{html}");
        assert!(html.contains("<html lang=\"zh-CN\">"));
        assert!(html.contains("data-mg-c=\"AAEC\""));
        assert!(html.contains("data-mg-type=\"pow\""));
        assert!(html.contains("data-mg-pow-bits=\"16\""));
        assert!(html.contains("data-mg-state=\"challenge\""));
        assert!(html.contains("data-mg-prefix=\"/__mg/\""));
        assert!(html.contains("data-mg-ret=\"/account/login?a=1&amp;b=&quot;2&quot;\""));
        assert!(html.contains(&format!("src=\"/__mg/s/{}\"", sdk.sdk)));
        assert!(html.contains(&format!("nonce=\"{nonce}\"")));
        assert!(html.contains(ID));
        let h = r.header().unwrap();
        let policy = h.headers["content-security-policy"].to_str().unwrap();
        assert_eq!(policy, csp(nonce));
        assert!(policy.contains(&format!("script-src 'nonce-{nonce}'")));
        assert!(policy.contains("worker-src 'self'") && policy.contains("form-action 'self'"));
        assert_eq!(h.headers["cache-control"], "no-store, private");
        assert_eq!(h.headers["x-frame-options"], "DENY");
        assert!(h.headers.keys().all(|k| !k.as_str().starts_with("mg-")));

        if sdk.is_v2() {
            // §12.3: the links and an empty `ix` on a non-interactive page.
            assert!(html.contains("href=\"/help\""));
            assert!(html.contains("href=\"/privacy?x=&quot;1&quot;\""));
            assert!(html.contains("data-mg-ix=\"\""));
        }

        // A failed page without a new C.
        let r = challenge_page(
            sdk,
            &Page {
                lang: "en",
                nonce,
                request_id: ID,
                ret: "/",
                state: PageState::Failed,
                challenge: None,
                help_href: "/",
                privacy_href: "/",
            },
        );
        let html = r.body_text();
        assert!(html.contains("data-mg-state=\"failed\"") && html.contains("data-mg-c=\"\""));
    }

    /// §7.3: an interactive page carries `ix` as the escaped JSON of
    /// `data-mg-ix`.
    #[test]
    fn interactive_page_carries_ix() {
        let sdk = sdk();
        let ix = json!({"v": 1, "providers": ["self_hold", "pow_a11y"], "x": "<\"'&>"});
        let r = challenge_page(
            &sdk,
            &Page {
                lang: "en",
                nonce: "q83vEjRWeJq83vEjRWeJqw==",
                request_id: ID,
                ret: "/",
                state: PageState::Challenge,
                challenge: Some(Shown {
                    c: "AAEC",
                    ty: ChallengeType::Interactive,
                    bits: 18,
                    ix: Some(&ix),
                }),
                help_href: "/",
                privacy_href: "/",
            },
        );
        let html = r.body_text();
        assert!(html.contains("data-mg-type=\"interactive\""));
        let attr = html
            .split("data-mg-ix=\"")
            .nth(1)
            .and_then(|t| t.split('"').next())
            .unwrap();
        assert!(!attr.contains('<') && !attr.contains('\''));
        let decoded = attr
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        assert_eq!(serde_json::from_str::<Value>(&decoded).unwrap(), ix);
    }

    #[test]
    fn json_answers() {
        let shown = Shown {
            c: "AAEC",
            ty: ChallengeType::Invisible,
            bits: 14,
            ix: None,
        };
        let r = challenge_json(ID, shown, "/a");
        assert_eq!(r.status, 403);
        assert!(
            r.headers
                .contains(&("MG-Challenge", "invisible".to_string()))
        );
        // Phase 2 spec §11.2: every JSON error names itself in MG-Error.
        assert!(
            r.headers
                .contains(&("MG-Error", "mg_challenge".to_string()))
        );
        let v: serde_json::Value = serde_json::from_str(r.body_text()).unwrap();
        assert_eq!(
            v,
            json!({"v": 2, "error": "mg_challenge", "type": "invisible", "challenge": "AAEC",
                   "pow": {"alg": "sha256-hashcash-v1", "bits": 14}, "ret": "/a",
                   "retry": true, "request_id": ID})
        );
        let failed = failed_json(ID, None);
        assert!(
            failed
                .headers
                .contains(&("MG-Error", "mg_challenge_failed".to_string()))
        );
        let v: serde_json::Value = serde_json::from_str(failed.body_text()).unwrap();
        assert_eq!(
            v,
            json!({"v": 2, "error": "mg_challenge_failed", "retry": true, "request_id": ID})
        );
        let new = Shown {
            c: "BBB",
            ty: ChallengeType::Pow,
            bits: 18,
            ix: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(failed_json(ID, Some(new)).body_text()).unwrap();
        assert_eq!(v["challenge"], "BBB");
        assert_eq!(v["type"], "pow");
        assert_eq!(v["pow"]["bits"], 18);
        // §7.3: an interactive C travels with `ix`, never `pow`.
        let ix = json!({"v": 1});
        let interactive = Shown {
            c: "CCC",
            ty: ChallengeType::Interactive,
            bits: 16,
            ix: Some(&ix),
        };
        let r = challenge_json(ID, interactive, "/b");
        assert!(
            r.headers
                .contains(&("MG-Challenge", "interactive".to_string()))
        );
        let v: serde_json::Value = serde_json::from_str(r.body_text()).unwrap();
        assert_eq!((v["ix"].clone(), v.get("pow")), (ix.clone(), None));
        let v: serde_json::Value =
            serde_json::from_str(failed_json(ID, Some(interactive)).body_text()).unwrap();
        assert_eq!(
            (v["type"].as_str(), v["ix"].clone()),
            (Some("interactive"), ix.clone())
        );
        let v: serde_json::Value =
            serde_json::from_str(renewed_json(interactive).body_text()).unwrap();
        assert_eq!(v, json!({"v": 2, "challenge": "CCC", "ix": {"v": 1}}));
        let r = submit_ok_json("/a?b=\"", "c=1".into(), 1_790_000_000_123);
        let v: serde_json::Value = serde_json::from_str(r.body_text()).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "ret": "/a?b=\"", "v": 2, "now_ms": 1_790_000_000_123i64})
        );
        let r = too_early_json();
        assert_eq!(r.status, 425);
        assert!(
            r.headers
                .contains(&("MG-Error", "mg_too_early".to_string()))
        );
    }

    /// D-32 and D-11 redirects: the Location value is always a valid
    /// header value.
    #[test]
    fn redirects() {
        let r = https_redirect("example.com", b"/a b?x=\xe9");
        assert_eq!(r.status, 308);
        let h = r.header().unwrap();
        assert_eq!(h.headers["location"], "https://example.com/a%20b?x=%E9");
        let r = https_redirect("example.com", b"*");
        assert_eq!(
            r.header().unwrap().headers["location"],
            "https://example.com/"
        );
        // §9.4 allows IP-literal hosts; the normalized IPv6 form keeps the
        // brackets a URL needs.
        let host =
            mg_edge_core::request::resolve_host(Some("[2001:DB8::1]:80"), None, None).unwrap();
        let r = https_redirect(&host, b"/a?b=1");
        assert_eq!(
            r.header().unwrap().headers["location"],
            "https://[2001:db8::1]/a?b=1"
        );
        let r = https_redirect("192.0.2.1", b"/");
        assert_eq!(
            r.header().unwrap().headers["location"],
            "https://192.0.2.1/"
        );
        let r = submit_redirect("/caf\u{e9}?q=1", "__Host-mg_clr=x".into());
        let h = r.header().unwrap();
        assert_eq!(h.status.as_u16(), 303);
        assert_eq!(h.headers["location"], "/caf%C3%A9?q=1");
        assert_eq!(h.headers["set-cookie"], "__Host-mg_clr=x");
        assert_eq!(h.headers["cache-control"], "no-store, private");
    }
}
