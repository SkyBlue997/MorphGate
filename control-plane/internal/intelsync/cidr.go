package intelsync

import (
	"fmt"
	"net/netip"
	"strings"
)

// cidrRules parameterises the per-entry checks shared by the Cloudflare IP
// artifact (docs/impl/phase1-spec.md §12.2) and the crawler registry (§12.3).
type cidrRules struct {
	minBitsV4, minBitsV6 int
	maxBitsV4, maxBitsV6 int
	// allowDocumentation permits the documentation ranges (only "test": true
	// crawler registries, §12.3).
	allowDocumentation bool
	// allowBareAddress accepts a single address without "/n" (§12.3: "no
	// non-canonical notation other than a single address").
	allowBareAddress bool
}

var (
	// cloudflareIPRules: §12.2, IPv4 /8–/32, IPv6 /16–/128.
	cloudflareIPRules = cidrRules{minBitsV4: 8, maxBitsV4: 32, minBitsV6: 16, maxBitsV6: 128}
	// crawlerRules: §12.3 (D-36), IPv4 at least /16, IPv6 at least /32.
	crawlerRules = cidrRules{minBitsV4: 16, maxBitsV4: 32, minBitsV6: 32, maxBitsV6: 128, allowBareAddress: true}
)

// specialRange is an address block that must never appear in (or overlap) an
// intelligence artifact entry.
type specialRange struct {
	prefix        netip.Prefix
	what          string
	documentation bool // allowed in test registries
}

// specialRanges lists the private, loopback, link-local, multicast,
// unspecified, CGNAT, reserved and documentation blocks of §12.2 / §12.3.
// Entries are rejected when they overlap any of these. The list is a superset
// of what the Rust reader (mg-intel, WP-R3) rejects, so everything mgctl
// writes also loads on the Edge.
var specialRanges = func() []specialRange {
	mk := func(s, what string, doc bool) specialRange {
		return specialRange{prefix: netip.MustParsePrefix(s), what: what, documentation: doc}
	}
	return []specialRange{
		mk("0.0.0.0/8", "unspecified (this network)", false),
		mk("10.0.0.0/8", "private (RFC 1918)", false),
		mk("100.64.0.0/10", "CGNAT (RFC 6598)", false),
		mk("127.0.0.0/8", "loopback", false),
		mk("169.254.0.0/16", "link-local", false),
		mk("172.16.0.0/12", "private (RFC 1918)", false),
		mk("192.0.0.0/24", "reserved (IETF protocol assignments)", false),
		mk("192.0.2.0/24", "documentation", true),
		mk("192.168.0.0/16", "private (RFC 1918)", false),
		mk("198.18.0.0/15", "reserved (benchmarking)", false),
		mk("198.51.100.0/24", "documentation", true),
		mk("203.0.113.0/24", "documentation", true),
		mk("224.0.0.0/4", "multicast", false),
		mk("240.0.0.0/4", "reserved", false),
		mk("::/128", "unspecified", false),
		mk("::1/128", "loopback", false),
		mk("::ffff:0:0/96", "IPv4-mapped", false),
		mk("fc00::/7", "private (unique local)", false),
		mk("fe80::/10", "link-local", false),
		mk("ff00::/8", "multicast", false),
		mk("2001::/23", "reserved (IETF protocol assignments)", false),
		mk("2001:db8::/32", "documentation", true),
		mk("3fff::/20", "documentation", true),
	}
}()

// globalUnicastV6 is the only IPv6 block intelligence entries may come from.
var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

// parseCIDR checks one artifact entry and returns it as a prefix. When
// strictText is set the text must already be canonical (what mgctl writes);
// otherwise differently written but equal networks (upper-case hex, a bare
// address) are accepted and the caller re-renders them with Prefix.String.
func parseCIDR(s string, r cidrRules, strictText bool) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, fmt.Errorf("empty entry")
	}
	if len(s) > 64 {
		return netip.Prefix{}, fmt.Errorf("entry of %d bytes is too long", len(s))
	}
	var p netip.Prefix
	if !strings.Contains(s, "/") {
		if !r.allowBareAddress {
			return netip.Prefix{}, fmt.Errorf("%q: not a CIDR (address/prefix-length)", s)
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q: invalid address", s)
		}
		if a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q: zoned addresses are not allowed", s)
		}
		if strictText && a.String() != s {
			return netip.Prefix{}, fmt.Errorf("%q: not in canonical form (want %s)", s, a)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	} else {
		var err error
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q: invalid CIDR", s)
		}
		if p.Masked() != p {
			return netip.Prefix{}, fmt.Errorf("%q: host bits set (network address is %s)", s, p.Masked())
		}
		if strictText && p.String() != s {
			return netip.Prefix{}, fmt.Errorf("%q: not in canonical form (want %s)", s, p)
		}
	}
	addr := p.Addr()
	if addr.Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q: IPv4-mapped IPv6 is not allowed, write the IPv4 network", s)
	}
	bits := p.Bits()
	if addr.Is4() {
		if bits < r.minBitsV4 || bits > r.maxBitsV4 {
			return netip.Prefix{}, fmt.Errorf("%q: IPv4 prefix length must be %d-%d", s, r.minBitsV4, r.maxBitsV4)
		}
	} else {
		if bits < r.minBitsV6 || bits > r.maxBitsV6 {
			return netip.Prefix{}, fmt.Errorf("%q: IPv6 prefix length must be %d-%d", s, r.minBitsV6, r.maxBitsV6)
		}
		// Every minimum length is longer than /3, so the prefix lies either
		// entirely inside or entirely outside global unicast.
		if !globalUnicastV6.Contains(addr) {
			return netip.Prefix{}, fmt.Errorf("%q: not IPv6 global unicast (2000::/3)", s)
		}
	}
	for _, sr := range specialRanges {
		if !sr.prefix.Overlaps(p) {
			continue
		}
		if sr.documentation && r.allowDocumentation {
			continue
		}
		if sr.documentation {
			return netip.Prefix{}, fmt.Errorf("%q: overlaps documentation range %s (allowed only in test registries)", s, sr.prefix)
		}
		return netip.Prefix{}, fmt.Errorf("%q: overlaps %s range %s", s, sr.what, sr.prefix)
	}
	return p, nil
}
