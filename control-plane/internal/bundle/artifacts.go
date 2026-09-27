package bundle

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oschwald/maxminddb-golang/v2"

	"morphgate/control-plane/internal/keys"
)

// ArtifactMaxSize is the size cap of each artifact kind (spec §12.1).
var ArtifactMaxSize = map[string]int64{
	"geoip-asn":        128 << 20,
	"geoip-country":    128 << 20,
	"cloudflare-ips":   1 << 20,
	"crawler-registry": 16 << 20,
	"datacenter-asns":  4 << 20,
	"tor-exits":        16 << 20,
}

// ValidateArtifact checks an artifact the way the Edge will parse it (spec
// §7.2, §12.2-§12.4) and returns its informational version: fetched_at /
// generated_at of JSON artifacts, the build_epoch (RFC 3339) of MaxMind DBs,
// "" for text lists.
func ValidateArtifact(name string, data []byte) (string, error) {
	limit, ok := ArtifactMaxSize[name]
	if !ok {
		return "", fmt.Errorf("unknown artifact %q", name)
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("%d bytes, the %s limit is %d", len(data), name, limit)
	}
	switch name {
	case "geoip-asn":
		return validateMMDB(data, "ASN")
	case "geoip-country":
		return validateMMDB(data, "Country", "City")
	case "cloudflare-ips":
		return validateCloudflareIPs(data)
	case "crawler-registry":
		return validateCrawlerRegistry(data)
	case "datacenter-asns":
		return "", validateASNList(data)
	default: // tor-exits
		return "", validateIPList(data)
	}
}

// validateMMDB opens and fully verifies a MaxMind DB whose database_type must
// contain one of want (spec §7.2).
func validateMMDB(data []byte, want ...string) (string, error) {
	r, err := maxminddb.OpenBytes(data)
	if err != nil {
		return "", fmt.Errorf("not a MaxMind DB: %w", err)
	}
	defer r.Close()
	if err := r.Verify(); err != nil {
		return "", fmt.Errorf("invalid MaxMind DB: %w", err)
	}
	dbType := r.Metadata.DatabaseType
	if !slices.ContainsFunc(want, func(w string) bool { return strings.Contains(dbType, w) }) {
		return "", fmt.Errorf("database_type %q does not contain %s", dbType, strings.Join(want, " or "))
	}
	return time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC().Format(time.RFC3339), nil
}

// strictJSON decodes one JSON object into v the way the Edge's serde reader
// does (keys.DecodeStrictJSON): every member required except optional, and
// unknown, case-variant, duplicate or null members rejected.
func strictJSON(data []byte, v any, optional ...string) error {
	return keys.DecodeStrictJSON(data, v, optional...)
}

// rfc3339 checks a timestamp in the form the Edge accepts (keys.ValidRFC3339).
func rfc3339(field, s string) error {
	if !keys.ValidRFC3339(s) {
		return fmt.Errorf("%s: %q is not an RFC 3339 timestamp", field, s)
	}
	return nil
}

// Special-purpose ranges no artifact CIDR may touch.
var (
	nonPublic = mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8",
	)
	// IETF protocol assignments (Teredo, ORCHID, ...): the IPv6 counterpart
	// of 192.0.0.0/24; mg-intel rejects it like the IPv4 block.
	ietfV6        = netip.MustParsePrefix("2001::/23")
	documentation = mustPrefixes("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")
	// globalUnicastV6 is the only IPv6 space mg-intel accepts in an artifact
	// (everything else is IETF-reserved, RFC 4291 §2.4).
	globalUnicastV6 = netip.MustParsePrefix("2000::/3")
)

// checkPublicPrefix applies the special-range rules shared by cloudflare-ips
// and the crawler registry, exactly as mg-intel does (a range the Edge
// rejects would make it reject the whole bundle): IPv6 only from global
// unicast, never the IETF block, no private / loopback / link-local /
// multicast / CGNAT / reserved overlap, documentation ranges only when allowed.
func checkPublicPrefix(p netip.Prefix, allowDocumentation bool) error {
	if !p.Addr().Is4() {
		// Every accepted IPv6 prefix is at least a /16, so it lies wholly
		// inside or wholly outside 2000::/3.
		if !globalUnicastV6.Contains(p.Addr()) || p.Bits() < globalUnicastV6.Bits() {
			return fmt.Errorf("%s is outside IPv6 global unicast %s", p, globalUnicastV6)
		}
		if p.Overlaps(ietfV6) {
			return fmt.Errorf("%s overlaps the reserved range %s", p, ietfV6)
		}
	}
	if q, bad := overlapsAny(p, nonPublic); bad {
		return fmt.Errorf("%s overlaps the special-purpose range %s", p, q)
	}
	if q, bad := overlapsAny(p, documentation); bad && !allowDocumentation {
		return fmt.Errorf("%s overlaps the documentation range %s", p, q)
	}
	return nil
}

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func overlapsAny(p netip.Prefix, set []netip.Prefix) (netip.Prefix, bool) {
	for _, q := range set {
		if p.Overlaps(q) {
			return q, true
		}
	}
	return netip.Prefix{}, false
}

// canonicalPrefix parses a CIDR that is written canonically (network
// address, zero host bits, the netip text form).
func canonicalPrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR", s)
	}
	if p.Masked() != p {
		return netip.Prefix{}, fmt.Errorf("%q has host bits set", s)
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q is an IPv4-mapped IPv6 prefix", s)
	}
	if p.String() != s {
		return netip.Prefix{}, fmt.Errorf("%q is not in canonical form (%s)", s, p)
	}
	return p, nil
}

type cloudflareIPs struct {
	V         int      `json:"v"`
	Kind      string   `json:"kind"`
	Source    string   `json:"source"`
	FetchedAt string   `json:"fetched_at"`
	ETag      string   `json:"etag"`
	IPv4CIDRs []string `json:"ipv4_cidrs"`
	IPv6CIDRs []string `json:"ipv6_cidrs"`
}

// validateCloudflareIPs applies spec §12.2.
func validateCloudflareIPs(data []byte) (string, error) {
	var f cloudflareIPs
	if err := strictJSON(data, &f); err != nil {
		return "", err
	}
	if f.V != 1 || f.Kind != "mg-cloudflare-ips" {
		return "", fmt.Errorf("v %d / kind %q, want 1 / mg-cloudflare-ips", f.V, f.Kind)
	}
	if err := rfc3339("fetched_at", f.FetchedAt); err != nil {
		return "", err
	}
	check := func(field string, list []string, min, max int, v4 bool, minBits int) error {
		if len(list) < min || len(list) > max {
			return fmt.Errorf("%s: %d entries, want %d-%d", field, len(list), min, max)
		}
		for _, s := range list {
			p, err := canonicalPrefix(s)
			if err != nil {
				return fmt.Errorf("%s: %v", field, err)
			}
			if p.Addr().Is4() != v4 {
				return fmt.Errorf("%s: %s is in the wrong address family", field, s)
			}
			if p.Bits() < minBits {
				return fmt.Errorf("%s: %s is shorter than /%d", field, s, minBits)
			}
			if err := checkPublicPrefix(p, false); err != nil {
				return fmt.Errorf("%s: %v", field, err)
			}
		}
		return nil
	}
	if err := check("ipv4_cidrs", f.IPv4CIDRs, 5, 64, true, 8); err != nil {
		return "", err
	}
	if err := check("ipv6_cidrs", f.IPv6CIDRs, 2, 32, false, 16); err != nil {
		return "", err
	}
	return f.FetchedAt, nil
}

type crawlerRegistry struct {
	V           int               `json:"v"`
	Kind        string            `json:"kind"`
	GeneratedAt string            `json:"generated_at"`
	Test        bool              `json:"test"`
	Operators   []crawlerOperator `json:"operators"`
}

type crawlerOperator struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Purpose  string   `json:"purpose"`
	UATokens []string `json:"ua_tokens"`
	Verify   struct {
		Mode         string   `json:"mode"`
		RDNSSuffixes []string `json:"rdns_suffixes"`
	} `json:"verify"`
	CIDRs   []string        `json:"cidrs"`
	Sources []crawlerSource `json:"sources"`
}

type crawlerSource struct {
	URL          string `json:"url"`
	Format       string `json:"format"`
	FetchedAt    string `json:"fetched_at"`
	CreationTime string `json:"creation_time"`
	SHA256       string `json:"sha256"`
	Stale        bool   `json:"stale"`
}

var (
	operatorIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	sha256HexPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	purposes          = []string{"search", "ai_training", "ai_search", "user_triggered", "archive", "other"}
	verifyModes       = []string{"ip_ranges", "rdns", "ip_ranges_or_rdns"}
	sourceFormats     = []string{"prefixes_json", "cidr_text"}
)

// maxOperatorCIDRs bounds one operator's ranges (spec §12.3).
const maxOperatorCIDRs = 20_000

// validateCrawlerRegistry applies every rule of spec §12.3 (D-36).
func validateCrawlerRegistry(data []byte) (string, error) {
	var f crawlerRegistry
	if err := strictJSON(data, &f, "test"); err != nil {
		return "", err
	}
	if f.V != 1 || f.Kind != "mg-crawler-registry" {
		return "", fmt.Errorf("v %d / kind %q, want 1 / mg-crawler-registry", f.V, f.Kind)
	}
	if err := rfc3339("generated_at", f.GeneratedAt); err != nil {
		return "", err
	}
	seen := map[string]bool{}
	for i, op := range f.Operators {
		where := fmt.Sprintf("operators[%d]", i)
		if !operatorIDPattern.MatchString(op.ID) {
			return "", fmt.Errorf("%s.id: %q does not match %s", where, op.ID, operatorIDPattern)
		}
		where = "operator " + op.ID
		if seen[op.ID] {
			return "", fmt.Errorf("%s: duplicate id", where)
		}
		seen[op.ID] = true
		if !slices.Contains(purposes, op.Purpose) {
			return "", fmt.Errorf("%s: purpose %q is not one of %s", where, op.Purpose, strings.Join(purposes, ", "))
		}
		if !slices.Contains(verifyModes, op.Verify.Mode) {
			return "", fmt.Errorf("%s: verify.mode %q is not one of %s", where, op.Verify.Mode, strings.Join(verifyModes, ", "))
		}
		if len(op.UATokens) < 1 || len(op.UATokens) > 8 {
			return "", fmt.Errorf("%s: %d ua_tokens, want 1-8", where, len(op.UATokens))
		}
		for _, tok := range op.UATokens {
			if n := utf8.RuneCountInString(tok); n < 3 || n > 64 {
				return "", fmt.Errorf("%s: ua_token %q must be 3-64 characters", where, tok)
			}
		}
		if op.Verify.Mode != "ip_ranges" && len(op.Verify.RDNSSuffixes) == 0 {
			return "", fmt.Errorf("%s: mode %s needs rdns_suffixes", where, op.Verify.Mode)
		}
		for _, sfx := range op.Verify.RDNSSuffixes {
			if sfx == "" || len(sfx) > 253 || sfx != strings.ToLower(sfx) {
				return "", fmt.Errorf("%s: rdns suffix %q must be lower-case and 1-253 bytes", where, sfx)
			}
		}
		if op.Verify.Mode == "ip_ranges" && len(op.CIDRs) == 0 {
			return "", fmt.Errorf("%s: mode ip_ranges needs cidrs", where)
		}
		if len(op.CIDRs) > maxOperatorCIDRs {
			return "", fmt.Errorf("%s: %d cidrs, at most %d", where, len(op.CIDRs), maxOperatorCIDRs)
		}
		for _, s := range op.CIDRs {
			if err := checkCrawlerCIDR(s, f.Test); err != nil {
				return "", fmt.Errorf("%s: %v", where, err)
			}
		}
		for _, src := range op.Sources {
			if !sha256HexPattern.MatchString(src.SHA256) {
				return "", fmt.Errorf("%s: source sha256 %q is not 64 lower-case hex digits", where, src.SHA256)
			}
			if err := rfc3339(where+" source fetched_at", src.FetchedAt); err != nil {
				return "", err
			}
			if !slices.Contains(sourceFormats, src.Format) {
				return "", fmt.Errorf("%s: source format %q is not one of %s", where, src.Format, strings.Join(sourceFormats, ", "))
			}
		}
	}
	return f.GeneratedAt, nil
}

// checkCrawlerCIDR: canonical network (a bare address counts as a host
// route), IPv4 >= /16, IPv6 >= /32, no special-purpose overlap, documentation
// ranges only in test registries.
func checkCrawlerCIDR(s string, test bool) error {
	var p netip.Prefix
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" || a.Is4In6() || a.String() != s {
			return fmt.Errorf("%q is not a canonical address or CIDR", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	} else {
		var err error
		if p, err = canonicalPrefix(s); err != nil {
			return err
		}
	}
	if min := map[bool]int{true: 16, false: 32}[p.Addr().Is4()]; p.Bits() < min {
		return fmt.Errorf("%s is broader than /%d", s, min)
	}
	if err := checkPublicPrefix(p, test); err != nil {
		if !test && slices.ContainsFunc(documentation, p.Overlaps) {
			return fmt.Errorf("%v (allowed only with \"test\": true)", err)
		}
		return err
	}
	return nil
}

// textLines yields the entries of a §12.4 text list: UTF-8, one entry per
// line, "#" starts a comment, blank lines ignored.
func textLines(data []byte, each func(line int, entry string) error) error {
	if !utf8.Valid(data) {
		return errors.New("not valid UTF-8")
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := each(n, line); err != nil {
			return fmt.Errorf("line %d: %v", n, err)
		}
	}
	return sc.Err()
}

// validateASNList: decimal ASNs 1-4294967295 of at most 10 digits (as
// mg-intel reads them), optional case-insensitive "AS".
func validateASNList(data []byte) error {
	return textLines(data, func(_ int, e string) error {
		s := e
		if len(s) > 2 && strings.EqualFold(s[:2], "as") {
			s = s[2:]
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 || len(s) > 10 {
			return fmt.Errorf("%q is not an ASN between 1 and 4294967295", e)
		}
		return nil
	})
}

// maxIPListEntries is mg-intel's IpSet limit (spec §7.1).
const maxIPListEntries = 1_000_000

// validateIPList: IP addresses or canonical CIDRs, at most 1,000,000.
func validateIPList(data []byte) error {
	entries := 0
	return textLines(data, func(_ int, e string) error {
		if entries++; entries > maxIPListEntries {
			return fmt.Errorf("more than %d entries", maxIPListEntries)
		}
		if strings.Contains(e, "/") {
			_, err := canonicalPrefix(e)
			return err
		}
		if a, err := netip.ParseAddr(e); err != nil || a.Zone() != "" {
			return fmt.Errorf("%q is not an IP address or CIDR", e)
		}
		return nil
	})
}
