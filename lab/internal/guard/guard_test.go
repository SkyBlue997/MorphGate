package guard

import (
	"errors"
	"strings"
	"testing"
)

func mustGuard(t *testing.T, cfg Config, opts ...Option) *Guard {
	t.Helper()
	g, err := New(cfg, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

// ownerConfig is the default allowlist plus one owner staging host.
func ownerConfig() Config {
	cfg := DefaultConfig()
	cfg.OwnerTargets = []OwnerTarget{{Host: "staging.example.com", ExpectedCIDRs: []string{"203.0.113.0/28"}}}
	return cfg
}

func TestCheckURL(t *testing.T) {
	g := mustGuard(t, ownerConfig())
	cases := []struct {
		name     string
		raw      string
		allow    bool
		canon    string    // canonical URL when allowed
		kind     MatchKind // when allowed
		reasonIn string    // substring of the deny reason
	}{
		// Plainly allowed targets.
		{"localhost", "http://localhost:8080/path?q=1", true, "http://localhost:8080/path?q=1", MatchHost, ""},
		{"suffix .test", "https://app.test/login", true, "https://app.test/login", MatchSuffix, ""},
		{"suffix .localhost", "http://api.localhost/", true, "http://api.localhost/", MatchSuffix, ""},
		{"nested suffix", "http://a.b.c.test/", true, "http://a.b.c.test/", MatchSuffix, ""},
		{"loopback IPv4", "http://127.0.0.1:18081/", true, "http://127.0.0.1:18081/", MatchIP, ""},
		{"loopback IPv6", "http://[::1]:8080/", true, "http://[::1]:8080/", MatchIP, ""},
		{"owner target", "https://staging.example.com/", true, "https://staging.example.com/", MatchOwner, ""},
		{"fragment dropped", "http://localhost/#frag", true, "http://localhost/", MatchHost, ""},
		{"uppercase scheme and host", "HTTP://LOCALHOST:8080/X", true, "http://localhost:8080/X", MatchHost, ""},
		{"trailing dot", "http://localhost./", true, "http://localhost/", MatchHost, ""},
		{"trailing dot suffix", "http://app.test./", true, "http://app.test/", MatchSuffix, ""},
		{"fullwidth maps to ASCII", "http://ｌｏｃａｌｈｏｓｔ/", true, "http://localhost/", MatchHost, ""},

		// Classic confusion attacks.
		{"allowed name as subdomain", "http://localhost.evil.com/", false, "", 0, `host "localhost.evil.com" is not in the lab allowlist`},
		{"fragment fake authority", "http://evil.com#@localhost", false, "", 0, `host "evil.com" is not in the lab allowlist`},
		{"query fake authority", "http://evil.com?@localhost", false, "", 0, `host "evil.com" is not in the lab allowlist`},
		{"userinfo", "http://localhost@evil.com/", false, "", 0, "userinfo"},
		{"userinfo with password", "http://localhost:8080@evil.com/", false, "", 0, "userinfo"},
		{"empty userinfo", "http://@localhost/", false, "", 0, "userinfo"},
		{"backslash", `http://evil.com\@localhost/`, false, "", 0, "backslash"},
		{"wildcard DNS to loopback", "http://127.0.0.1.nip.io/", false, "", 0, `host "127.0.0.1.nip.io" is not in the lab allowlist`},
		{"owner lookalike", "https://staging.example.com.evil.net/", false, "", 0, "not in the lab allowlist"},
		{"owner sibling", "https://www.example.com/", false, "", 0, "not in the lab allowlist"},
		{"bare suffix", "http://test/", false, "", 0, `host "test" is not in the lab allowlist`},
		{"suffix without dot boundary", "http://evil-test/", false, "", 0, "not in the lab allowlist"},

		// Numeric host tricks: judged by the address they denote.
		{"decimal IPv4", "http://2130706433/", true, "http://127.0.0.1/", MatchIP, ""},
		{"hex IPv4 short", "http://0x7f.1/", true, "http://127.0.0.1/", MatchIP, ""},
		{"octal IPv4", "http://017700000001:8080/", true, "http://127.0.0.1:8080/", MatchIP, ""},
		{"short IPv4", "http://127.1/", true, "http://127.0.0.1/", MatchIP, ""},
		{"leading zeros IPv4", "http://127.000.000.001/", true, "http://127.0.0.1/", MatchIP, ""},
		{"IPv4-mapped IPv6 loopback", "http://[::ffff:7f00:1]/", true, "http://127.0.0.1/", MatchIP, ""},
		{"IPv4-mapped IPv6 dotted", "http://[::ffff:127.0.0.1]:9000/", true, "http://127.0.0.1:9000/", MatchIP, ""},
		{"decimal private IPv4", "http://3232235521/", false, "", 0, `non-canonical IPv4 form "3232235521" of 192.168.0.1 is not inside allow_cidrs`},
		{"hex public IPv4", "http://0x08080808/", false, "", 0, "of 8.8.8.8 is not inside allow_cidrs"},
		{"IPv4-mapped metadata", "http://[::ffff:a9fe:a9fe]/", false, "", 0, "IPv4-mapped IPv6 form of 169.254.169.254 is never a lab target: link-local"},
		{"metadata IP", "http://169.254.169.254/latest/meta-data/", false, "", 0, "link-local"},
		{"private IP not listed", "http://10.0.0.1/", false, "", 0, "IP 10.0.0.1 is not inside allow_cidrs"},
		{"public IP", "http://93.184.216.34/", false, "", 0, "not inside allow_cidrs"},
		{"unspecified IPv4", "http://0/", false, "", 0, "is never a lab target: unspecified"},
		{"unspecified IPv6", "http://[::]/", false, "", 0, "is never a lab target: unspecified"},
		{"invalid IPv4 too many parts", "http://1.2.3.4.5/", false, "", 0, "more than four parts"},
		{"invalid IPv4 overflow", "http://256.0.0.1/", false, "", 0, "part out of range"},
		{"invalid octal digit", "http://08.0.0.1/", false, "", 0, "looks like an IPv4 address"},
		{"name ending in number", "http://foo.123/", false, "", 0, "looks like an IPv4 address"},
		{"IPv6 zone", "http://[fe80::1%25en0]/", false, "", 0, "percent-encoding"},

		// Host name normalisation failures.
		{"unicode homoglyph", "http://lоcalhost/", false, "", 0, `host "xn--lcalhost-nbh" is not in the lab allowlist`},
		{"homoglyph in suffix", "http://app.tеst/", false, "", 0, "not in the lab allowlist"},
		{"double trailing dot", "http://localhost../", false, "", 0, "empty label"},
		{"empty label", "http://a..test/", false, "", 0, "empty label"},
		{"underscore", "http://a_b.test/", false, "", 0, "invalid host name"},
		{"bad punycode", "http://xn--lcalhost-9sg/", false, "", 0, "invalid host name"},

		// Scheme and syntax.
		{"ftp", "ftp://localhost/", false, "", 0, `scheme "ftp" is not allowed`},
		{"file", "file:///etc/passwd", false, "", 0, `scheme "file" is not allowed`},
		{"javascript", "javascript:alert(1)", false, "", 0, `scheme "javascript"`},
		{"websocket", "ws://localhost/", false, "", 0, `scheme "ws"`},
		{"scheme relative", "//localhost/", false, "", 0, `scheme ""`},
		{"opaque", "http:localhost", false, "", 0, "opaque"},
		{"missing host", "http:///path", false, "", 0, "missing host"},
		{"empty port", "http://localhost:/", false, "", 0, "empty port"},
		{"port zero", "http://localhost:0/", false, "", 0, "invalid port"},
		{"port too large", "http://localhost:99999/", false, "", 0, "invalid port"},
		{"leading space", " http://localhost/", false, "", 0, "whitespace"},
		{"tab in host", "http://local\thost/", false, "", 0, "whitespace"},
		{"newline", "http://localhost/\r\nHost: evil.com", false, "", 0, "whitespace"},
		{"percent in host", "http://local%68ost/", false, "", 0, "unparsable"},
		{"empty", "", false, "", 0, `scheme ""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, err := g.CheckURL(tc.raw)
			if tc.allow {
				if err != nil {
					t.Fatalf("CheckURL(%q) denied: %v", tc.raw, err)
				}
				if got := target.URL.String(); got != tc.canon {
					t.Errorf("canonical URL = %q, want %q", got, tc.canon)
				}
				if target.Kind != tc.kind {
					t.Errorf("kind = %v, want %v", target.Kind, tc.kind)
				}
				if target.Reason == "" {
					t.Error("allowed target without a reason")
				}
				// The canonical form must itself be allowed, unchanged.
				again, err := g.CheckURL(target.URL.String())
				if err != nil || again.URL.String() != target.URL.String() {
					t.Errorf("canonical URL not stable: %v, %v", again, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckURL(%q) allowed (%s); want deny", tc.raw, target.Reason)
			}
			if !errors.Is(err, ErrDenied) {
				t.Errorf("error %v is not ErrDenied", err)
			}
			if !strings.Contains(err.Error(), tc.reasonIn) {
				t.Errorf("reason %q does not contain %q", err.Error(), tc.reasonIn)
			}
		})
	}
}

func TestNumericTricksDeniedWithoutLoopbackCIDR(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowCIDRs = []string{"::1/128"}
	g := mustGuard(t, cfg)
	for _, raw := range []string{
		"http://2130706433/", "http://0x7f.1/", "http://017700000001/", "http://127.1/",
		"http://127.0.0.1/", "http://[::ffff:7f00:1]/",
	} {
		if _, err := g.CheckURL(raw); !errors.Is(err, ErrDenied) {
			t.Errorf("CheckURL(%q) = %v, want denied", raw, err)
		}
	}
	if _, err := g.CheckURL("http://[::1]/"); err != nil {
		t.Errorf("[::1] denied: %v", err)
	}
}

func TestDefaultDeny(t *testing.T) {
	g := mustGuard(t, Config{})
	for _, raw := range []string{"http://localhost/", "http://app.test/", "http://127.0.0.1/", "http://[::1]/"} {
		if _, err := g.CheckURL(raw); !errors.Is(err, ErrDenied) {
			t.Errorf("empty config allowed %q", raw)
		}
	}
}

func TestLongURL(t *testing.T) {
	g := mustGuard(t, DefaultConfig())
	_, err := g.CheckURL("http://localhost/" + strings.Repeat("a", MaxURLLength))
	if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("long URL: %v", err)
	}
}
