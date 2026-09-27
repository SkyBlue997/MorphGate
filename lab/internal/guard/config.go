package guard

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/net/publicsuffix"
)

// Rate limits for all traffic sent through one Guard.
const (
	DefaultRateRPS = 5.0
	MaxRateRPS     = 50.0
)

// Config is the Validation Lab target allowlist. Everything not listed is
// denied. See lab/config/lab.example.yaml.
type Config struct {
	// AllowHosts are exact host names, e.g. "localhost" or a compose service
	// name. They may only resolve to loopback or private (RFC 1918 / ULA)
	// addresses.
	AllowHosts []string `yaml:"allow_hosts"`
	// AllowSuffixes are label-aligned suffixes such as ".test" or
	// ".localhost". Matching hosts may only resolve to loopback or private
	// addresses.
	AllowSuffixes []string `yaml:"allow_suffixes"`
	// AllowCIDRs admit URLs whose host is an IP literal inside one of them.
	AllowCIDRs []string `yaml:"allow_cidrs"`
	// OwnerTargets are the owner's own staging hosts on public addresses; each
	// may only resolve into its expected CIDRs.
	OwnerTargets []OwnerTarget `yaml:"owner_targets"`
	// RateRPS caps requests per second across the whole process (token
	// bucket, burst 1). 0 means DefaultRateRPS; values above MaxRateRPS are
	// rejected.
	RateRPS float64 `yaml:"rate_rps"`
}

// OwnerTarget is one explicitly registered staging host of the owner.
type OwnerTarget struct {
	Host          string   `yaml:"host"`
	ExpectedCIDRs []string `yaml:"expected_cidrs"`
}

// DefaultConfig allows only loopback and the reserved local suffixes.
func DefaultConfig() Config {
	return Config{
		AllowHosts:    []string{"localhost"},
		AllowSuffixes: []string{".test", ".localhost"},
		AllowCIDRs:    []string{"127.0.0.0/8", "::1/128"},
		RateRPS:       DefaultRateRPS,
	}
}

// LoadConfig reads a YAML config. Unknown fields are errors.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, fmt.Errorf("%s: empty config", path)
		}
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// neverTarget is an address range the lab never sends traffic to, whatever
// the config says. CheckURL, Resolve and the connect-time hook all deny it.
type neverTarget struct {
	prefix netip.Prefix
	what   string
	// inside selects how config prefixes are judged. false: a config prefix
	// that overlaps the range is rejected. true: only a config prefix that
	// lies inside the range is rejected, so a broad private range that merely
	// contains one endpoint (fc00::/7 contains fd00:ec2::254) stays valid;
	// the endpoint itself is still denied at check and connect time.
	inside bool
}

var neverTargets = []neverTarget{
	{netip.MustParsePrefix("0.0.0.0/8"), `unspecified ("this network")`, false},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local/metadata (169.254.169.254)", false},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast", false},
	{netip.MustParsePrefix("255.255.255.255/32"), "broadcast", false},
	{netip.MustParsePrefix("::/128"), "unspecified", false},
	{netip.MustParsePrefix("fe80::/10"), "link-local", false},
	{netip.MustParsePrefix("ff00::/8"), "multicast", false},

	// IPv6 transition prefixes embed an IPv4 destination that a NAT64 gateway
	// or relay forwards to. They look narrow (64:ff9b::/96 passes a /48 width
	// check) but stand for the whole IPv4 Internet.
	{netip.MustParsePrefix("64:ff9b::/96"), "NAT64 well-known prefix (RFC 6052), reaches any IPv4 address", false},
	{netip.MustParsePrefix("64:ff9b:1::/48"), "NAT64 local-use prefix (RFC 8215), reaches any IPv4 address", false},
	{netip.MustParsePrefix("2002::/16"), "6to4 (RFC 3056), reaches any IPv4 address", false},
	{netip.MustParsePrefix("2001::/32"), "Teredo (RFC 4380), reaches any IPv4 address", false},

	// Cloud instance-metadata endpoints outside link-local. AWS and GCP put
	// their IPv6 endpoints inside fc00::/7, which isLocal treats as private.
	{netip.MustParsePrefix("fd00:ec2::/32"), "AWS instance metadata / link services over IPv6 (fd00:ec2::254)", true},
	{netip.MustParsePrefix("fd20:ce::254/128"), "GCP metadata server over IPv6", true},
	{netip.MustParsePrefix("100.100.100.200/32"), "Alibaba Cloud ECS metadata", true},
	{netip.MustParsePrefix("192.0.0.192/32"), "Oracle Cloud metadata", true},
}

// localPrefixes are loopback, RFC 1918 and ULA ranges.
var localPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
}

// Special-use suffixes that are ICANN public suffixes yet reserved for local
// networks (RFC 8375).
var localPublicSuffixes = []string{"home.arpa"}

// neverTargetFor returns the neverTargets entry that contains a, if any.
func neverTargetFor(a netip.Addr) (neverTarget, bool) {
	a = a.Unmap().WithZone("")
	for _, n := range neverTargets {
		if n.prefix.Contains(a) {
			return n, true
		}
	}
	return neverTarget{}, false
}

func isForbidden(a netip.Addr) bool {
	_, ok := neverTargetFor(a)
	return ok
}

func isLocal(a netip.Addr) bool {
	a = a.Unmap()
	return !isForbidden(a) && (a.IsLoopback() || a.IsPrivate())
}

// compiled is a validated Config.
type compiled struct {
	hosts    map[string]bool
	suffixes []string // with leading dot
	cidrs    []netip.Prefix
	owners   map[string][]netip.Prefix
	rps      float64
}

func (cfg Config) compile() (*compiled, error) {
	c := &compiled{
		hosts:  map[string]bool{},
		owners: map[string][]netip.Prefix{},
		rps:    cfg.RateRPS,
	}
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	switch {
	case c.rps == 0:
		c.rps = DefaultRateRPS
	case c.rps < 0 || math.IsNaN(c.rps) || math.IsInf(c.rps, 0):
		fail("rate_rps must be a positive finite number")
	case c.rps > MaxRateRPS:
		fail("rate_rps %.1f exceeds the hard maximum of %.0f requests per second", c.rps, MaxRateRPS)
	}

	for _, h := range cfg.AllowHosts {
		name, err := configHostName(h)
		if err != nil {
			fail("allow_hosts: %v", err)
			continue
		}
		c.hosts[name] = true
	}

	for _, s := range cfg.AllowSuffixes {
		if !strings.HasPrefix(s, ".") {
			fail("allow_suffixes: %q must start with a dot, e.g. \".test\"", s)
			continue
		}
		name, err := configHostName(s[1:])
		if err != nil {
			fail("allow_suffixes: %v", err)
			continue
		}
		if ps, icann := publicsuffix.PublicSuffix(name); icann && ps == name && !slices.Contains(localPublicSuffixes, name) {
			fail("allow_suffixes: %q is a public suffix; list your own hosts or a reserved local suffix instead", s)
			continue
		}
		c.suffixes = append(c.suffixes, "."+name)
	}

	for _, s := range cfg.AllowCIDRs {
		p, err := parseConfigPrefix(s)
		if err != nil {
			fail("allow_cidrs: %v", err)
			continue
		}
		c.cidrs = append(c.cidrs, p)
	}

	for i, o := range cfg.OwnerTargets {
		name, err := configHostName(o.Host)
		if err != nil {
			fail("owner_targets[%d].host: %v", i, err)
			continue
		}
		if c.hosts[name] {
			fail("owner_targets[%d].host: %q is also in allow_hosts", i, name)
			continue
		}
		if _, dup := c.owners[name]; dup {
			fail("owner_targets[%d].host: duplicate host %q", i, name)
			continue
		}
		if len(o.ExpectedCIDRs) == 0 {
			fail("owner_targets[%d] (%s): expected_cidrs is required", i, name)
			continue
		}
		var prefixes []netip.Prefix
		for _, s := range o.ExpectedCIDRs {
			p, err := parseConfigPrefix(s)
			if err != nil {
				fail("owner_targets[%d] (%s).expected_cidrs: %v", i, name, err)
				continue
			}
			prefixes = append(prefixes, p)
		}
		c.owners[name] = prefixes
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid lab config: %w", errors.Join(errs...))
	}
	return c, nil
}

// configHostName normalises a host name from the config; IP addresses are
// rejected here because they belong in allow_cidrs.
func configHostName(h string) (string, error) {
	info, err := normalizeHost(h, false)
	if err != nil {
		return "", err
	}
	if info.addr.IsValid() {
		return "", fmt.Errorf("%q is an IP address; use allow_cidrs", h)
	}
	return info.name, nil
}

// parseConfigPrefix parses a CIDR or single address and rejects ranges that
// are never acceptable targets or are implausibly broad for an owner's own
// infrastructure (shorter than /24 for IPv4 or /48 for IPv6 outside local
// ranges).
func parseConfigPrefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, fmt.Errorf("invalid CIDR %q", s)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return p, fmt.Errorf("invalid CIDR %q", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return p, fmt.Errorf("invalid IP address %q", s)
		}
		a = a.Unmap()
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = p.Masked()
	for _, n := range neverTargets {
		switch {
		case n.inside && n.prefix.Bits() <= p.Bits() && n.prefix.Contains(p.Addr()):
			return p, fmt.Errorf("%s is inside %s (%s), which is never allowed", p, n.prefix, n.what)
		case !n.inside && p.Overlaps(n.prefix):
			return p, fmt.Errorf("%s overlaps %s (%s), which is never allowed", p, n.prefix, n.what)
		}
	}
	for _, l := range localPrefixes {
		if l.Bits() <= p.Bits() && l.Contains(p.Addr()) {
			return p, nil
		}
	}
	if (p.Addr().Is4() && p.Bits() < 24) || (p.Addr().Is6() && p.Bits() < 48) {
		return p, fmt.Errorf("%s is too broad for owner infrastructure (need at least /24 for IPv4, /48 for IPv6)", p)
	}
	return p, nil
}

func (c *compiled) inCIDRs(a netip.Addr) bool {
	for _, p := range c.cidrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// suffixMatch returns the matching suffix, if any. Matching is label-aligned:
// ".test" matches "app.test" but neither "test" nor "apptest".
func (c *compiled) suffixMatch(name string) (string, bool) {
	for _, s := range c.suffixes {
		if strings.HasSuffix(name, s) && len(name) > len(s) {
			return s, true
		}
	}
	return "", false
}
