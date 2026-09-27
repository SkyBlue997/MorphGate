package intelsync

import (
	"strings"
	"testing"
)

// §12.3 per-CIDR rules (D-36) for the crawler registry.
func TestCrawlerCIDRRules(t *testing.T) {
	cases := []struct {
		in     string
		test   bool   // "test": true registry
		want   string // canonical output of the lenient (fetch) parse; "" = rejected
		errHas string
	}{
		{in: "66.249.64.0/27", want: "66.249.64.0/27"},
		{in: "2001:4860:4801:10::/64", want: "2001:4860:4801:10::/64"},
		{in: "66.249.64.7", want: "66.249.64.7/32"}, // a single address is the one accepted non-CIDR form
		{in: "2001:4860:4801:10::7", want: "2001:4860:4801:10::7/128"},
		{in: "2001:4860:4801:0010::/64", want: "2001:4860:4801:10::/64"},
		{in: "2620:0:9C0::/48", want: "2620:0:9c0::/48"},
		{in: "66.249.0.0/16", want: "66.249.0.0/16"},
		{in: "2600::/32", want: "2600::/32"},
		// Too broad (D-36 examples).
		{in: "0.0.0.0/0", errHas: "prefix length"},
		{in: "66.0.0.0/8", errHas: "prefix length"},
		{in: "66.248.0.0/15", errHas: "prefix length"},
		{in: "2600::/16", errHas: "prefix length"},
		{in: "::/0", errHas: "prefix length"},
		// Host bits.
		{in: "66.249.64.1/27", errHas: "host bits"},
		{in: "2001:4860:4801:10::1/64", errHas: "host bits"},
		// Special-purpose ranges, including overlaps from a wider prefix.
		{in: "10.1.0.0/16", errHas: "private"},
		{in: "172.20.0.0/16", errHas: "private"},
		{in: "192.168.1.0/24", errHas: "private"},
		{in: "127.0.0.0/16", errHas: "loopback"},
		{in: "169.254.0.0/16", errHas: "link-local"},
		{in: "224.1.0.0/16", errHas: "multicast"},
		{in: "100.64.0.0/16", errHas: "CGNAT"},
		{in: "100.127.0.0/16", errHas: "CGNAT"},
		{in: "240.0.0.0/16", errHas: "reserved"},
		{in: "255.255.255.255", errHas: "reserved"},
		{in: "0.0.0.0/16", errHas: "unspecified"},
		{in: "198.18.0.0/16", errHas: "reserved"},
		{in: "192.0.0.0/24", errHas: "reserved"},
		{in: "::1", errHas: "global unicast"},
		{in: "fd00::/32", errHas: "global unicast"},
		{in: "fe80::/64", errHas: "global unicast"},
		{in: "ff02::/32", errHas: "global unicast"},
		{in: "::ffff:66.249.64.0/120", errHas: "IPv4-mapped"},
		{in: "2001::/32", errHas: "reserved"},
		// Documentation ranges only in test registries.
		{in: "192.0.2.0/25", errHas: "documentation"},
		{in: "198.51.100.0/24", errHas: "documentation"},
		{in: "203.0.113.0/24", errHas: "documentation"},
		{in: "2001:db8:4860::/48", errHas: "documentation"},
		{in: "3fff::/32", errHas: "documentation"},
		{in: "192.0.2.0/25", test: true, want: "192.0.2.0/25"},
		{in: "2001:db8:4860::/48", test: true, want: "2001:db8:4860::/48"},
		{in: "127.0.0.0/16", test: true, errHas: "loopback"}, // test registries still reject the rest
		// Garbage.
		{in: "", errHas: "empty"},
		{in: "66.249.64.0/27 ", errHas: "invalid"},
		{in: "066.249.64.0/27", errHas: "invalid"},
		{in: "fe80::1%eth0", errHas: "zoned"},
		{in: "66.249.64.0/33", errHas: "invalid"},
		{in: strings.Repeat("1", 100), errHas: "too long"},
	}
	for _, tc := range cases {
		rules := crawlerRules
		rules.allowDocumentation = tc.test
		p, err := parseCIDR(tc.in, rules, false)
		if tc.want == "" {
			if err == nil {
				t.Errorf("parseCIDR(%q, test=%v) = %s, want error containing %q", tc.in, tc.test, p, tc.errHas)
			} else if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("parseCIDR(%q) error %q, want it to contain %q", tc.in, err, tc.errHas)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseCIDR(%q, test=%v): %v", tc.in, tc.test, err)
			continue
		}
		if p.String() != tc.want {
			t.Errorf("parseCIDR(%q) = %s, want %s", tc.in, p, tc.want)
		}
	}
}

// Artifacts must already hold the canonical text; only fetched lists are
// normalised.
func TestStrictTextRejectsNonCanonical(t *testing.T) {
	for _, s := range []string{"2001:4860:4801:0010::/64", "2620:0:9C0::/48"} {
		if _, err := parseCIDR(s, crawlerRules, true); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Errorf("strict parseCIDR(%q) = %v, want a canonical-form error", s, err)
		}
	}
	if _, err := parseCIDR("66.249.64.7", crawlerRules, true); err != nil {
		t.Errorf("a canonical single address must be accepted: %v", err)
	}
}

// §12.2: Cloudflare ranges are CIDRs of /8-/32 and /16-/128.
func TestCloudflareCIDRRules(t *testing.T) {
	ok := []string{"173.245.48.0/20", "104.16.0.0/13", "2a06:98c0::/29", "2400:cb00::/32", "8.0.0.0/8"}
	bad := map[string]string{
		"96.0.0.0/7":      "prefix length",
		"2000::/15":       "prefix length",
		"173.245.48.1/20": "host bits",
		"10.0.0.0/8":      "private",
		"198.51.100.0/24": "documentation",
		"173.245.48.1":    "not a CIDR",
		"fc00::/16":       "global unicast",
	}
	for _, s := range ok {
		if _, err := parseCIDR(s, cloudflareIPRules, true); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for s, want := range bad {
		if _, err := parseCIDR(s, cloudflareIPRules, true); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want %q", s, err, want)
		}
	}
}
