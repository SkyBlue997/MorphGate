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
//! Only `MG-Challenge` of a JSON challenge is an `MG-*` header (§9.9).

use crate::enforce::{EdgeResponse, HTML, JSON, TEXT, safe_id};
use crate::sdk::{Placeholder, SdkDir};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mg_challenge::{POW_ALG, Rng, RngError};
use mg_core::ChallengeType;
use serde_json::json;

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

/// `{{lang}}`: `zh-CN` when the first `Accept-Language` tag starts with
/// `zh`, otherwise `en` (§11.2).
pub fn page_lang(accept_language: Option<&str>) -> &'static str {
    let first = accept_language
        .and_then(|v| v.split(',').next())
        .and_then(|t| t.split(';').next())
        .map(str::trim)
        .unwrap_or_default();
    if first.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("zh")) {
        "zh-CN"
    } else {
        "en"
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shown<'a> {
    pub c: &'a str,
    pub ty: ChallengeType,
    pub bits: u32,
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
}

/// The 403 challenge page (§10.2, §11.2).
pub fn challenge_page(sdk: &SdkDir, page: &Page<'_>) -> EdgeResponse {
    let sdk_src = sdk.sdk_src();
    let bits = page
        .challenge
        .map(|c| c.bits.to_string())
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
    });
    let mut resp = EdgeResponse::new(403, HTML, html);
    resp.csp = Some(csp(page.nonce));
    resp
}

/// The 403 JSON challenge (§10.2) with `MG-Challenge: <type>`.
pub fn challenge_json(request_id: &str, shown: Shown<'_>, ret: &str) -> EdgeResponse {
    let body = json!({
        "error": "mg_challenge",
        "type": shown.ty.as_str(),
        "challenge": shown.c,
        "pow": {"alg": POW_ALG, "bits": shown.bits},
        "ret": ret,
        "retry": true,
        "request_id": safe_id(request_id),
    });
    EdgeResponse::new(403, JSON, body.to_string()).with("MG-Challenge", shown.ty.as_str())
}

/// The 403 JSON uniform failure of a fetch submission (§10.3); the last
/// three fields only with a new `C`.
pub fn failed_json(request_id: &str, new: Option<Shown<'_>>) -> EdgeResponse {
    let mut body = json!({
        "error": "mg_challenge_failed",
        "retry": true,
        "request_id": safe_id(request_id),
    });
    if let Some(n) = new {
        body["challenge"] = json!(n.c);
        body["type"] = json!(n.ty.as_str());
        body["pow"] = json!({"alg": POW_ALG, "bits": n.bits});
    }
    EdgeResponse::new(403, JSON, body.to_string())
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

/// 200 `{"ok":true,"ret":"<ret>"}` with the clearance cookie (fetch
/// submission).
pub fn submit_ok_json(ret: &str, set_cookie: String) -> EdgeResponse {
    let body = json!({"ok": true, "ret": ret});
    EdgeResponse::new(200, JSON, body.to_string()).with("Set-Cookie", set_cookie)
}

/// 425 `{"error":"mg_too_early"}` (`Early-Data: 1`, §10.3 step 1).
pub fn too_early_json() -> EdgeResponse {
    EdgeResponse::new(425, JSON, "{\"error\":\"mg_too_early\"}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn sdk() -> SdkDir {
        SdkDir::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sdk")).unwrap()
    }

    #[test]
    fn languages() {
        assert_eq!(page_lang(Some("zh-CN,zh;q=0.9,en;q=0.8")), "zh-CN");
        assert_eq!(page_lang(Some("ZH-tw")), "zh-CN");
        assert_eq!(page_lang(Some("zh;q=0.5")), "zh-CN");
        assert_eq!(page_lang(Some("en-US,zh;q=0.9")), "en");
        assert_eq!(page_lang(Some("")), "en");
        assert_eq!(page_lang(Some("z")), "en");
        assert_eq!(page_lang(Some("é")), "en");
        assert_eq!(page_lang(None), "en");
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
    /// HTML headers.
    #[test]
    fn page_rendering() {
        let sdk = sdk();
        let nonce = "q83vEjRWeJq83vEjRWeJqw==";
        let r = challenge_page(
            &sdk,
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
                }),
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

        // A failed page without a new C.
        let r = challenge_page(
            &sdk,
            &Page {
                lang: "en",
                nonce,
                request_id: ID,
                ret: "/",
                state: PageState::Failed,
                challenge: None,
            },
        );
        let html = r.body_text();
        assert!(html.contains("data-mg-state=\"failed\"") && html.contains("data-mg-c=\"\""));
    }

    #[test]
    fn json_answers() {
        let shown = Shown {
            c: "AAEC",
            ty: ChallengeType::Invisible,
            bits: 14,
        };
        let r = challenge_json(ID, shown, "/a");
        assert_eq!(r.status, 403);
        assert!(
            r.headers
                .contains(&("MG-Challenge", "invisible".to_string()))
        );
        let v: serde_json::Value = serde_json::from_str(r.body_text()).unwrap();
        assert_eq!(
            v,
            json!({"error": "mg_challenge", "type": "invisible", "challenge": "AAEC",
                   "pow": {"alg": "sha256-hashcash-v1", "bits": 14}, "ret": "/a",
                   "retry": true, "request_id": ID})
        );
        let v: serde_json::Value = serde_json::from_str(failed_json(ID, None).body_text()).unwrap();
        assert_eq!(
            v,
            json!({"error": "mg_challenge_failed", "retry": true, "request_id": ID})
        );
        let new = Shown {
            c: "BBB",
            ty: ChallengeType::Pow,
            bits: 18,
        };
        let v: serde_json::Value =
            serde_json::from_str(failed_json(ID, Some(new)).body_text()).unwrap();
        assert_eq!(v["challenge"], "BBB");
        assert_eq!(v["type"], "pow");
        assert_eq!(v["pow"]["bits"], 18);
        let r = submit_ok_json("/a?b=\"", "c=1".into());
        let v: serde_json::Value = serde_json::from_str(r.body_text()).unwrap();
        assert_eq!(v, json!({"ok": true, "ret": "/a?b=\""}));
        assert_eq!(too_early_json().status, 425);
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
