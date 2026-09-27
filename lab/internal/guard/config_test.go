package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	base := DefaultConfig
	cases := []struct {
		name string
		mut  func(*Config)
		want string // "" = valid
	}{
		{"default", func(*Config) {}, ""},
		{"zero rate uses default", func(c *Config) { c.RateRPS = 0 }, ""},
		{"max rate", func(c *Config) { c.RateRPS = 50 }, ""},
		{"rate above hard max", func(c *Config) { c.RateRPS = 51 }, "exceeds the hard maximum of 50"},
		{"negative rate", func(c *Config) { c.RateRPS = -1 }, "positive"},
		{"suffix without dot", func(c *Config) { c.AllowSuffixes = []string{"test"} }, "must start with a dot"},
		{"public suffix com", func(c *Config) { c.AllowSuffixes = []string{".com"} }, "is a public suffix"},
		{"public suffix co.uk", func(c *Config) { c.AllowSuffixes = []string{".co.uk"} }, "is a public suffix"},
		{"home.arpa allowed", func(c *Config) { c.AllowSuffixes = []string{".home.arpa"} }, ""},
		{"internal allowed", func(c *Config) { c.AllowSuffixes = []string{".internal"} }, ""},
		{"IP in allow_hosts", func(c *Config) { c.AllowHosts = []string{"127.0.0.1"} }, "use allow_cidrs"},
		{"bad host", func(c *Config) { c.AllowHosts = []string{"a b"} }, "invalid character"},
		{"bad CIDR", func(c *Config) { c.AllowCIDRs = []string{"10.0.0.0/33"} }, "invalid CIDR"},
		{"world CIDR", func(c *Config) { c.AllowCIDRs = []string{"0.0.0.0/0"} }, "overlaps 0.0.0.0/8"},
		{"world v6 CIDR", func(c *Config) { c.AllowCIDRs = []string{"::/0"} }, "overlaps"},
		{"metadata", func(c *Config) { c.AllowCIDRs = []string{"169.254.169.254"} }, "link-local/metadata"},
		{"broad public", func(c *Config) { c.AllowCIDRs = []string{"8.0.0.0/8"} }, "too broad"},
		{"broad public v6", func(c *Config) { c.AllowCIDRs = []string{"2001:db8::/32"} }, "too broad"},
		{"whole private range ok", func(c *Config) { c.AllowCIDRs = []string{"10.0.0.0/8", "fc00::/7"} }, ""},
		{"public /28 ok", func(c *Config) { c.AllowCIDRs = []string{"203.0.113.0/28"} }, ""},
		{"owner without CIDRs", func(c *Config) { c.OwnerTargets = []OwnerTarget{{Host: "stg.example.com"}} }, "expected_cidrs is required"},
		{"owner broad CIDR", func(c *Config) {
			c.OwnerTargets = []OwnerTarget{{Host: "stg.example.com", ExpectedCIDRs: []string{"203.0.0.0/16"}}}
		}, "too broad"},
		{"owner duplicate", func(c *Config) {
			c.OwnerTargets = []OwnerTarget{
				{Host: "stg.example.com", ExpectedCIDRs: []string{"203.0.113.1"}},
				{Host: "STG.example.com.", ExpectedCIDRs: []string{"203.0.113.2"}},
			}
		}, "duplicate host"},
		{"owner also in allow_hosts", func(c *Config) {
			c.AllowHosts = []string{"stg.example.com"}
			c.OwnerTargets = []OwnerTarget{{Host: "stg.example.com", ExpectedCIDRs: []string{"203.0.113.1"}}}
		}, "also in allow_hosts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mut(&cfg)
			_, err := New(cfg)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cfg, err := LoadConfig("../../config/lab.example.yaml")
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatalf("example config invalid: %v", err)
	}
	if g.RateRPS() != DefaultRateRPS {
		t.Errorf("example rate = %v", g.RateRPS())
	}

	if _, err := LoadConfig(write("typo.yaml", "allow_host: [localhost]\n")); err == nil ||
		!strings.Contains(err.Error(), "field allow_host not found") {
		t.Errorf("unknown field accepted: %v", err)
	}
	if _, err := LoadConfig(write("empty.yaml", "")); err == nil {
		t.Error("empty config accepted")
	}
}

// The allowlist mounted into the isolated compose network (profile "lab")
// admits only in-network `.lab.test` services, not even localhost.
func TestComposeConfig(t *testing.T) {
	cfg, err := LoadConfig("../../config/lab.compose.yaml")
	if err != nil {
		t.Fatalf("compose config: %v", err)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatalf("compose config invalid: %v", err)
	}
	if _, err := g.CheckURL("http://origin.lab.test:8081/health"); err != nil {
		t.Errorf("in-network origin denied: %v", err)
	}
	for _, raw := range []string{
		"http://example.com/",
		"http://localhost:8080/",
		"http://lab.test/",
		"http://169.254.169.254/",
	} {
		if _, err := g.CheckURL(raw); err == nil {
			t.Errorf("%s allowed by the compose config", raw)
		}
	}
}
