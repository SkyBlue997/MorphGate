//! Normative User-Agent family / major-version parser
//! (docs/impl/phase1-spec.md §5.7 "UA 解析").
//!
//! It feeds the HTTP detectors and the clearance binding `bind.uah =
//! hash("uah", family + "/" + major)`, so its output is part of the token
//! contract: the Edge that issues a token and the Edge that verifies it must
//! parse identically. Keep the marker order exactly as specified.

/// Parsed User-Agent facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaInfo {
    /// `headless_chrome`, `edge`, `opera`, `samsung`, `firefox_ios`,
    /// `firefox`, `chrome_ios`, `chrome`, `safari` or `other`.
    pub family: &'static str,
    /// Decimal major version after the family marker (0 when absent).
    pub major: u32,
    /// The UA contains `Mobile`.
    pub mobile: bool,
    /// Starts with `Mozilla/5.0` and the family is a real browser (not
    /// `other` or `headless_chrome`).
    pub claims_browser: bool,
    /// An HTTP library or automation framework marker is present.
    pub library: bool,
    /// The UA declares itself a bot (`bot/`, `crawler`, `+http`, ...).
    pub declared_bot: bool,
}

impl UaInfo {
    /// `family + "/" + major`, the input of `bind.uah`.
    pub fn bind_key(&self) -> String {
        format!("{}/{}", self.family, self.major)
    }
}

/// Family markers in priority order: the first marker contained in the UA
/// wins. `(marker, family)`.
const FAMILY_MARKERS: &[(&str, &str)] = &[
    ("HeadlessChrome/", "headless_chrome"),
    ("Edg/", "edge"),
    ("EdgA/", "edge"),
    ("EdgiOS/", "edge"),
    ("OPR/", "opera"),
    ("SamsungBrowser/", "samsung"),
    ("FxiOS/", "firefox_ios"),
    ("Firefox/", "firefox"),
    ("CriOS/", "chrome_ios"),
    ("Chrome/", "chrome"),
    ("Chromium/", "chrome"),
];

/// Lower-case substrings of HTTP libraries and automation frameworks.
const LIBRARY_MARKERS: &[&str] = &[
    "curl/",
    "wget/",
    "python-requests",
    "python-urllib",
    "aiohttp",
    "httpx",
    "go-http-client",
    "okhttp",
    "java/",
    "apache-httpclient",
    "libwww-perl",
    "node-fetch",
    "axios/",
    "undici",
    "scrapy",
    "headlesschrome",
    "phantomjs",
    "puppeteer",
    "playwright",
];

/// Lower-case substrings of self-declared bots. A bare `bot` is deliberately
/// absent: it would match device names such as `CUBOT`.
const BOT_MARKERS: &[&str] = &[
    "bot/", "bot;", "bot)", "crawler", "spider", "slurp", "+http",
];

/// Parses a User-Agent header value.
pub fn parse(ua: &str) -> UaInfo {
    let (family, major) = family_and_major(ua);
    let lower = ua.to_ascii_lowercase();
    UaInfo {
        family,
        major,
        mobile: ua.contains("Mobile"),
        claims_browser: ua.starts_with("Mozilla/5.0")
            && family != "other"
            && family != "headless_chrome",
        library: LIBRARY_MARKERS.iter().any(|m| lower.contains(m)),
        declared_bot: BOT_MARKERS.iter().any(|m| lower.contains(m)),
    }
}

fn family_and_major(ua: &str) -> (&'static str, u32) {
    for &(marker, family) in FAMILY_MARKERS {
        if let Some(major) = major_after(ua, marker) {
            return (family, major);
        }
    }
    match major_after(ua, "Version/") {
        Some(major) if ua.contains("Safari/") => ("safari", major),
        _ => ("other", 0),
    }
}

/// `Some(major)` if `marker` occurs in `ua`: the decimal digits right after
/// its first occurrence (saturating), 0 when there are none.
pub(crate) fn major_after(ua: &str, marker: &str) -> Option<u32> {
    let start = ua.find(marker)? + marker.len();
    let mut major: u32 = 0;
    for b in ua[start..].bytes() {
        if !b.is_ascii_digit() {
            break;
        }
        major = major.saturating_mul(10).saturating_add(u32::from(b - b'0'));
    }
    Some(major)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    const EDGE: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.51";
    const EDGE_ANDROID: &str = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36 EdgA/124.0.2478.64";
    const EDGE_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/124.2478.50 Mobile/15E148 Safari/605.1.15";
    const OPERA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0";
    const SAMSUNG: &str = "Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36";
    const FIREFOX: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0";
    const FIREFOX_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/125.0 Mobile/15E148 Safari/605.1.15";
    const CHROME_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.88 Mobile/15E148 Safari/604.1";
    const SAFARI: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15";
    const HEADLESS: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36";
    const CHROMIUM: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/99.0.4844.51 Safari/537.36";
    const GOOGLEBOT: &str =
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    const GOOGLEBOT_SMARTPHONE: &str = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.201 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

    #[test]
    fn families_and_majors() {
        for (ua, family, major, mobile) in [
            (CHROME, "chrome", 124, false),
            (EDGE, "edge", 124, false),
            (EDGE_ANDROID, "edge", 124, true),
            (EDGE_IOS, "edge", 124, true),
            (OPERA, "opera", 109, false),
            (SAMSUNG, "samsung", 24, true),
            (FIREFOX, "firefox", 125, false),
            (FIREFOX_IOS, "firefox_ios", 125, true),
            (CHROME_IOS, "chrome_ios", 124, true),
            (SAFARI, "safari", 17, false),
            (HEADLESS, "headless_chrome", 124, false),
            (CHROMIUM, "chrome", 99, false),
            (GOOGLEBOT_SMARTPHONE, "chrome", 124, true),
            (GOOGLEBOT, "other", 0, false),
            ("curl/8.5.0", "other", 0, false),
            ("", "other", 0, false),
        ] {
            let info = parse(ua);
            assert_eq!(
                (info.family, info.major, info.mobile),
                (family, major, mobile),
                "{ua}"
            );
        }
    }

    #[test]
    fn claims_browser_needs_mozilla_prefix_and_a_browser_family() {
        assert!(parse(CHROME).claims_browser);
        assert!(parse(SAFARI).claims_browser);
        assert!(
            !parse(HEADLESS).claims_browser,
            "headless is not a browser claim"
        );
        assert!(!parse(GOOGLEBOT).claims_browser, "family other");
        assert!(
            !parse("Chrome/124.0").claims_browser,
            "no Mozilla/5.0 prefix"
        );
        assert!(!parse("Mozilla/4.0 (compatible; MSIE 6.0) Chrome/124").claims_browser);
    }

    #[test]
    fn library_markers() {
        for ua in [
            "curl/8.5.0",
            "Wget/1.21.4",
            "python-requests/2.31.0",
            "Python-urllib/3.12",
            "Python/3.12 aiohttp/3.9.5",
            "python-httpx/0.27.0",
            "Go-http-client/2.0",
            "okhttp/4.12.0",
            "Java/21.0.2",
            "Apache-HttpClient/5.3",
            "libwww-perl/6.72",
            "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)",
            "axios/1.6.8",
            "undici",
            "Scrapy/2.11.1 (+https://scrapy.org)",
            HEADLESS,
            "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1",
            "Mozilla/5.0 Puppeteer",
            "Mozilla/5.0 Playwright/1.43",
        ] {
            assert!(parse(ua).library, "{ua}");
        }
        for ua in [CHROME, SAFARI, FIREFOX, GOOGLEBOT, ""] {
            assert!(!parse(ua).library, "{ua}");
        }
    }

    #[test]
    fn declared_bot_markers_avoid_device_names() {
        for ua in [
            GOOGLEBOT,
            GOOGLEBOT_SMARTPHONE,
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            "Baiduspider-render/2.0",
            "SomeCrawler",
            "ExampleBot; v1",
            "(ExampleBot)",
        ] {
            assert!(parse(ua).declared_bot, "{ua}");
        }
        for ua in [
            "Mozilla/5.0 (Linux; Android 11; CUBOT KINGKONG 5 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
            CHROME,
            "curl/8.5.0",
            "robotics-client",
        ] {
            assert!(!parse(ua).declared_bot, "{ua}");
        }
    }

    #[test]
    fn major_version_edge_cases() {
        assert_eq!(parse("Mozilla/5.0 Chrome/").major, 0);
        assert_eq!(parse("Mozilla/5.0 Chrome/x").major, 0);
        assert_eq!(parse("Mozilla/5.0 Chrome/007.1").major, 7);
        assert_eq!(
            parse("Mozilla/5.0 Chrome/99999999999999999999").major,
            u32::MAX
        );
        // Safari needs both Safari/ and Version/; Version/ gives the major.
        assert_eq!(parse("Mozilla/5.0 Safari/605.1.15").family, "other");
        assert_eq!(parse("Mozilla/5.0 Version/16.6 Safari/605").major, 16);
        assert_eq!(parse(CHROME).bind_key(), "chrome/124");
    }

    /// Spec §2.4: deterministic random input never panics.
    #[test]
    fn random_inputs_do_not_panic() {
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let pieces = [
            "Mozilla/5.0 ",
            "Chrome/",
            "Edg/",
            "Safari/",
            "Version/",
            "9",
            "12",
            ".",
            "é",
            "bot/",
            "curl/",
            "Mobile",
            " ",
            "\u{0}",
            "OPR/",
            "HeadlessChrome/",
        ];
        for _ in 0..10_000 {
            let mut s = String::new();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            for i in 0..(state % 12) {
                s.push_str(pieces[((state >> (i * 4)) % pieces.len() as u64) as usize]);
            }
            let info = parse(&s);
            assert!(!info.family.is_empty());
        }
    }
}
