package intelsync

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Crawler registry constants (docs/impl/phase1-spec.md §12.1, §12.3).
const (
	KindCrawlerRegistry          = "mg-crawler-registry"
	maxCrawlerRegistrySize       = 16 << 20 // §12.1
	maxCIDRsPerOperator          = 20000
	maxOperators                 = 256
	maxSourcesPerOperator        = 8
	minUATokens, maxUATokens     = 1, 8
	minUATokenLen, maxUATokenLen = 3, 64
	maxNameLen                   = 64
	maxSuffixLen                 = 253
	maxCreationTimeLen           = 64
)

// Verification modes and source formats (§12.3).
const (
	ModeIPRanges       = "ip_ranges"
	ModeRDNS           = "rdns"
	ModeIPRangesOrRDNS = "ip_ranges_or_rdns"
	FormatPrefixesJSON = "prefixes_json"
	FormatCIDRText     = "cidr_text"
)

var (
	operatorIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	suffixPattern     = regexp.MustCompile(`^[a-z0-9._-]+$`)
	sha256HexPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	purposes          = []string{"search", "ai_training", "ai_search", "user_triggered", "archive", "other"}
	modes             = []string{ModeIPRanges, ModeRDNS, ModeIPRangesOrRDNS}
	formats           = []string{FormatPrefixesJSON, FormatCIDRText}
)

// CrawlerRegistry is the `crawler-registry` artifact written by
// `mgctl crawler sync` (§12.3). Field order is the canonical key order.
type CrawlerRegistry struct {
	V           int               `json:"v"`
	Kind        string            `json:"kind"`
	GeneratedAt string            `json:"generated_at"`
	Test        bool              `json:"test,omitempty"`
	Operators   []CrawlerOperator `json:"operators"`
}

// CrawlerOperator is one crawler operator with its merged official ranges.
type CrawlerOperator struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Purpose  string          `json:"purpose"`
	UATokens []string        `json:"ua_tokens"`
	Verify   CrawlerVerify   `json:"verify"`
	CIDRs    []string        `json:"cidrs"`
	Sources  []CrawlerSource `json:"sources"`
}

// CrawlerVerify is the operator's verification method.
type CrawlerVerify struct {
	Mode         string   `json:"mode"`
	RDNSSuffixes []string `json:"rdns_suffixes"`
}

// CrawlerSource records where an operator's ranges came from.
type CrawlerSource struct {
	URL          string `json:"url"`
	Format       string `json:"format"`
	FetchedAt    string `json:"fetched_at"`
	CreationTime string `json:"creation_time"`
	SHA256       string `json:"sha256"`
	Stale        bool   `json:"stale"`
}

// ParseCrawlerRegistry decodes (rejecting unknown fields) and validates an
// artifact.
func ParseCrawlerRegistry(data []byte) (*CrawlerRegistry, error) {
	if len(data) > maxCrawlerRegistrySize {
		return nil, fmt.Errorf("crawler-registry: larger than %d bytes", maxCrawlerRegistrySize)
	}
	var r CrawlerRegistry
	if err := decodeStrict(data, &r); err != nil {
		return nil, fmt.Errorf("crawler-registry: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Encode renders the canonical JSON form. Absent lists are written as [].
func (r *CrawlerRegistry) Encode() ([]byte, error) {
	c := *r
	c.Operators = make([]CrawlerOperator, len(r.Operators))
	for i, op := range r.Operators {
		op.UATokens = nonNil(op.UATokens)
		op.Verify.RDNSSuffixes = nonNil(op.Verify.RDNSSuffixes)
		op.CIDRs = nonNil(op.CIDRs)
		if op.Sources == nil {
			op.Sources = []CrawlerSource{}
		}
		c.Operators[i] = op
	}
	if c.Operators == nil {
		c.Operators = []CrawlerOperator{}
	}
	return EncodeCanonical(&c)
}

// Validate applies every §12.3 rule (D-36). The writer (`crawler sync`) and
// the Edge reader (mg-intel) reject the same artifacts; this side is at
// least as strict.
func (r *CrawlerRegistry) Validate() error {
	if r.V != 1 {
		return fmt.Errorf("crawler-registry: v must be 1, got %d", r.V)
	}
	if r.Kind != KindCrawlerRegistry {
		return fmt.Errorf("crawler-registry: kind must be %q, got %q", KindCrawlerRegistry, r.Kind)
	}
	if !isRFC3339(r.GeneratedAt) {
		return fmt.Errorf("crawler-registry: generated_at %q is not RFC 3339", r.GeneratedAt)
	}
	if len(r.Operators) == 0 || len(r.Operators) > maxOperators {
		return fmt.Errorf("crawler-registry: %d operators, want 1-%d", len(r.Operators), maxOperators)
	}
	seen := make(map[string]bool, len(r.Operators))
	for i := range r.Operators {
		op := &r.Operators[i]
		if err := validateOperatorMeta(op.ID, op.Name, op.Purpose, op.UATokens, op.Verify.Mode, op.Verify.RDNSSuffixes); err != nil {
			return fmt.Errorf("crawler-registry: operator %d: %w", i, err)
		}
		if seen[op.ID] {
			return fmt.Errorf("crawler-registry: duplicate operator id %q", op.ID)
		}
		seen[op.ID] = true
		if err := validateOperatorRanges(op, r.Test); err != nil {
			return fmt.Errorf("crawler-registry: operator %q: %w", op.ID, err)
		}
	}
	return nil
}

// validateOperatorMeta checks the fields shared by the source YAML and the
// artifact.
func validateOperatorMeta(id, name, purpose string, uaTokens []string, mode string, suffixes []string) error {
	if !operatorIDPattern.MatchString(id) {
		return fmt.Errorf("id %q must match %s", id, operatorIDPattern)
	}
	if err := checkPrintable("name", name, maxNameLen); err != nil {
		return fmt.Errorf("%q: %w", id, err)
	}
	if !slices.Contains(purposes, purpose) {
		return fmt.Errorf("%q: purpose %q must be one of %v", id, purpose, purposes)
	}
	if len(uaTokens) < minUATokens || len(uaTokens) > maxUATokens {
		return fmt.Errorf("%q: %d ua_tokens, want %d-%d", id, len(uaTokens), minUATokens, maxUATokens)
	}
	for _, t := range uaTokens {
		if len(t) < minUATokenLen || len(t) > maxUATokenLen {
			return fmt.Errorf("%q: ua_token %q must be %d-%d characters", id, t, minUATokenLen, maxUATokenLen)
		}
		if err := checkPrintable("ua_token", t, maxUATokenLen); err != nil {
			return fmt.Errorf("%q: %w", id, err)
		}
	}
	if !slices.Contains(modes, mode) {
		return fmt.Errorf("%q: verify.mode %q must be one of %v", id, mode, modes)
	}
	if mode != ModeIPRanges && len(suffixes) == 0 {
		return fmt.Errorf("%q: verify.mode %s needs rdns_suffixes", id, mode)
	}
	for _, s := range suffixes {
		if len(s) < 1 || len(s) > maxSuffixLen {
			return fmt.Errorf("%q: rdns suffix %q must be 1-%d bytes", id, s, maxSuffixLen)
		}
		if !suffixPattern.MatchString(s) {
			return fmt.Errorf("%q: rdns suffix %q must be lower-case letters, digits, '.', '-' or '_'", id, s)
		}
		if !validRDNSSuffix(s) {
			return fmt.Errorf("%q: rdns suffix %q must start with '.' followed by at least two labels (e.g. .googlebot.com)", id, s)
		}
	}
	return nil
}

// validRDNSSuffix reports whether s has the rDNS suffix shape of ruling I-22:
// a leading '.' and at least two non-empty labels after it. The Edge
// (mg-intel) matches a suffix only on a label boundary, so ".googlebot.com"
// never matches "evilgooglebot.com"; a bare "googlebot.com" or a one-label
// ".com" would make forward-confirmed rDNS trivially satisfiable, and the
// reader rejects such an artifact, so the writer never produces one.
func validRDNSSuffix(s string) bool {
	rest, ok := strings.CutPrefix(s, ".")
	if !ok {
		return false
	}
	labels := strings.Split(rest, ".")
	return len(labels) >= 2 && !slices.Contains(labels, "")
}

func validateOperatorRanges(op *CrawlerOperator, test bool) error {
	if op.Verify.Mode == ModeIPRanges && len(op.CIDRs) == 0 {
		return fmt.Errorf("verify.mode ip_ranges needs at least one CIDR")
	}
	if len(op.CIDRs) > maxCIDRsPerOperator {
		return fmt.Errorf("%d CIDRs, at most %d", len(op.CIDRs), maxCIDRsPerOperator)
	}
	rules := crawlerRules
	rules.allowDocumentation = test
	for _, c := range op.CIDRs {
		if _, err := parseCIDR(c, rules, true); err != nil {
			return err
		}
	}
	if len(op.Sources) > maxSourcesPerOperator {
		return fmt.Errorf("%d sources, at most %d", len(op.Sources), maxSourcesPerOperator)
	}
	for _, s := range op.Sources {
		if _, err := checkHTTPSURL(s.URL); err != nil {
			return fmt.Errorf("source: %w", err)
		}
		if !slices.Contains(formats, s.Format) {
			return fmt.Errorf("source %s: format %q must be one of %v", s.URL, s.Format, formats)
		}
		if !isRFC3339(s.FetchedAt) {
			return fmt.Errorf("source %s: fetched_at %q is not RFC 3339", s.URL, s.FetchedAt)
		}
		if s.CreationTime != "" {
			if err := checkPrintable("creation_time", s.CreationTime, maxCreationTimeLen); err != nil {
				return fmt.Errorf("source %s: %w", s.URL, err)
			}
		}
		if !sha256HexPattern.MatchString(s.SHA256) {
			return fmt.Errorf("source %s: sha256 must be 64 lower-case hex digits", s.URL)
		}
	}
	return nil
}

// checkPrintable accepts 1..max bytes of printable ASCII (spaces allowed).
func checkPrintable(field, s string, max int) error {
	if s == "" || len(s) > max {
		return fmt.Errorf("%s must be 1-%d characters", field, max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return fmt.Errorf("%s must be printable ASCII", field)
		}
	}
	return nil
}

// find returns the operator with the given id, or nil.
func (r *CrawlerRegistry) find(id string) *CrawlerOperator {
	if r == nil {
		return nil
	}
	for i := range r.Operators {
		if r.Operators[i].ID == id {
			return &r.Operators[i]
		}
	}
	return nil
}

// sameContent reports whether two registries carry the same operators and
// ranges. Download metadata (generated_at, fetched_at, creation_time, body
// hashes) and the order of CIDRs are ignored, so a daily sync that finds no
// change keeps the artifact bytes, and the bundle's artifact hash, stable.
func sameContent(a, b *CrawlerRegistry) bool {
	if a.Test != b.Test || len(a.Operators) != len(b.Operators) {
		return false
	}
	for i := range a.Operators {
		x, y := &a.Operators[i], &b.Operators[i]
		if x.ID != y.ID || x.Name != y.Name || x.Purpose != y.Purpose || x.Verify.Mode != y.Verify.Mode ||
			!slices.Equal(x.UATokens, y.UATokens) ||
			!slices.Equal(nonNil(x.Verify.RDNSSuffixes), nonNil(y.Verify.RDNSSuffixes)) ||
			!slices.Equal(sortedCopy(x.CIDRs), sortedCopy(y.CIDRs)) ||
			len(x.Sources) != len(y.Sources) {
			return false
		}
		for j := range x.Sources {
			if x.Sources[j].URL != y.Sources[j].URL || x.Sources[j].Format != y.Sources[j].Format ||
				x.Sources[j].Stale != y.Sources[j].Stale {
				return false
			}
		}
	}
	return true
}
