// Package sitecfg parses and validates the owner's site YAML v1
// (docs/impl/phase1-spec.md §8.2): the input of `mgctl site check` and
// `mgctl bundle build`. It applies the documented defaults, so a parsed Site
// holds the effective values; §8.3 maps it onto a SiteBundle (package bundle).
//
// Parsing is purely syntactic and semantic on the YAML itself; files the site
// refers to (policies, list files, artifacts) are read by the bundle builder.
// Unknown keys, YAML anchors / aliases and multiple documents are errors.
// Relative paths are resolved against the directory of the YAML file.
package sitecfg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxFileSize bounds a site YAML file.
const MaxFileSize = 1 << 20

// Enumerations of the site YAML.
var (
	Profiles         = []string{"cloudflare", "direct_tls"}
	EnvironmentNames = []string{"production", "staging", "test", "dev"}
	Channels         = []string{"web", "api", "mobile"}
	Sensitivities    = []string{"low", "medium", "high", "critical"}
	LimiterKeys      = []string{"ip", "ip_prefix", "asn", "session", "route"}
	LimiterActions   = []string{"signal", "challenge", "rate_limit", "block"}
	LimiterModes     = []string{"enforce", "dry_run"}
	LimiterScopes    = []string{"global", "local"}
	CrawlerPurposes  = []string{"search", "ai_training", "ai_search", "user_triggered", "archive", "other"}
	CrawlerActions   = []string{"allow", "block"}
	OriginModes      = []string{"tunnel", "aop"}
	// SignalFamilies are the SignalFamily wire names (scoring.family_modes keys).
	SignalFamilies = []string{"network", "tls", "http", "client", "behavior", "reputation", "rate", "identity", "edge_tls", "external"}
	FamilyModes    = []string{"active", "shadow", "off"}
	// SignalIDs are the Phase 1 detector signal ids (scoring.weights keys, spec §5.7).
	SignalIDs = []string{
		"net.client_ip", "net.datacenter", "net.tor", "tls.proto_old", "edge_tls.proto_mismatch",
		"http.ua_missing", "http.ua_library", "http.accept_language_missing", "http.client_hints",
		"http.fetch_metadata_missing", "http.fetch_metadata_mismatch", "http.version_old",
		"rate.utilization", "rate.exceeded", "identity.clearance", "identity.bind_ipp_soft",
		"identity.crawler_failed", "external.cf_vbot",
	}
	// LimiterChallengeTypes are the challenge types a rate limiter may issue.
	LimiterChallengeTypes = []string{"invisible", "pow"}
)

// ArtifactKeys maps the artifacts.* keys to ArtifactRef names, in the order of
// the spec §12.1 table (also the order of SiteBundle.artifacts).
var ArtifactKeys = []struct{ Key, Name string }{
	{"geoip_asn", "geoip-asn"},
	{"geoip_country", "geoip-country"},
	{"cloudflare_ips", "cloudflare-ips"},
	{"crawler_registry", "crawler-registry"},
	{"datacenter_asns", "datacenter-asns"},
	{"tor_exits", "tor-exits"},
}

// Structural limits (spec §8.2, §4.1).
const (
	// MaxRoutesPerEnv bounds the declared routes of one environment; the
	// implicit "default" route comes on top (ruling I-24: at most 65 routes
	// in the bundle).
	MaxRoutesPerEnv   = 64
	MaxLimitersPerEnv = 64
	MaxPathsPerRoute  = 16
	MaxPatternLen     = 128
	MaxWildcards      = 4
	MaxListEntries    = 10_000
	MaxListEntryLen   = 256
	MaxTokenKeyIDs    = 3 // token.keys.json holds at most 3 keys
	MaxDVTMicros      = 7 * 86_400 * 1_000_000
	MaxSessionS       = 30 * 86_400
)

var (
	SitePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	ListenerPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	RouteNamePattern = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
	LimiterIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	KIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	ListNamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	methodPattern    = regexp.MustCompile(`^[A-Z][A-Z_-]{0,31}$`)
	labelPattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	ratePattern      = regexp.MustCompile(`^([0-9]+)/([0-9]*)(s|m|h)$`)
	rulesetPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
)

// Site is one parsed site YAML file with every default applied.
type Site struct {
	File string // the path it was loaded from ("" for Parse without a file)
	Dir  string // directory for relative paths
	Raw  []byte // the YAML bytes (source_digest)

	Version              int
	ID                   string // YAML key "site"
	Profile              string
	Hosts                []string
	AllowedListeners     []string
	MonitorOnly          bool
	NotBefore            *time.Time
	ShareIPVerdicts      bool
	CaseInsensitivePaths bool
	Cloudflare           *Cloudflare // set iff Profile == "cloudflare"
	Token                Token
	Clearance            Clearance
	Challenge            Challenge
	Scoring              Scoring
	Crawlers             Crawlers
	Events               Events
	OriginHeaders        OriginHeaders
	Lists                []NamedList // inline lists, declaration order
	ListFiles            []ListFile  // list_files, declaration order
	Artifacts            []Artifact  // ArtifactKeys order
	Environments         []Environment
}

// Cloudflare is the cloudflare: section (profile cloudflare only).
type Cloudflare struct {
	Zone                string
	LocationHeaders     bool
	Tier1               bool
	OwnerZones          []string
	PseudoIPv4Overwrite bool
	OriginMode          string // tunnel | aop | "" (mgctl cf audit only)
	AccountID, TunnelID string // mgctl cf audit only
}

// Token names the clearance token keys the bundle refers to.
type Token struct {
	ActiveKID  string
	VerifyKIDs []string
}

// KIDs is token_key_ids: [active_kid] + verify_kids.
func (t Token) KIDs() []string { return append([]string{t.ActiveKID}, t.VerifyKIDs...) }

// Clearance is the clearance: section.
type Clearance struct {
	TTLInvisibleS, TTLPowS, SessionMaxS uint32
	CTPShadow                           bool
}

// PowBits is the PoW difficulty per risk band.
type PowBits struct{ Low, Medium, High, VeryHigh uint32 }

// Rate is a GCRA rate: Rate requests per PeriodS seconds, Burst at once.
type Rate struct{ Rate, PeriodS, Burst uint32 }

// Issue is the clearance issuance quota (D-37).
type Issue struct{ PerIPP, PerASN, PeriodS uint32 }

// Challenge is the challenge: section.
type Challenge struct {
	TTLS           uint32
	PowBits        PowBits
	FallbackRet    string
	MaxFailures    uint32
	FailureWindowS uint32
	Submit         Rate
	Issue          Issue
}

// Scoring is the scoring: section (spec §5.7 initial values by default).
type Scoring struct {
	ThetaC         float64
	Kappa          float64 // 0 = profile default
	Z0             map[string]float64
	FamilyModes    map[string]string
	Weights        map[string]float64
	HMin           float64
	RulesetVersion string
}

// Crawlers is the crawlers: section (CrawlerPolicy).
type Crawlers struct {
	DefaultAction string
	Purposes      map[string]string
}

// Events is the events: section.
type Events struct {
	AllowSampleRate   float64
	AccessLog, Stream bool
}

// OriginHeaders is the origin_headers: section.
type OriginHeaders struct{ Scores, Reasons, Session bool }

// NamedList is one inline lists: entry.
type NamedList struct {
	Name    string
	Entries []string
}

// ListFile is one list_files: entry (text file, one entry per line).
type ListFile struct {
	Name, Path string // Path resolved against Site.Dir
	Line, Col  int
}

// Artifact is one configured artifacts: entry.
type Artifact struct {
	Key  string // YAML key, e.g. geoip_asn
	Name string // ArtifactRef.name, e.g. geoip-asn
	Path string // resolved against Site.Dir
	Line int
	Col  int
}

// Environment is one environments: entry.
type Environment struct {
	Name                    string
	Hosts                   []string
	Policies                []string // resolved against Site.Dir
	Routes                  []Route  // declaration order, then the implicit "default"
	RateLimits              []RateLimit
	AutomationAllowlistOnly bool
}

// Route is one route; Implicit marks the appended catch-all "default".
type Route struct {
	Name             string
	Paths            []string
	Hosts            []string
	Methods          []string
	Channel          string
	Sensitivity      string
	RequireClearance bool
	FailClosed       bool
	RedactPath       bool
	Implicit         bool
}

// RateLimit is one rate_limits: entry.
type RateLimit struct {
	ID       string
	Routes   []string // empty = every route of the environment
	Key      []string
	Rate     Rate
	Scope    string
	OnExceed OnExceed
	Mode     string
}

// OnExceed is what a limiter does when it is exceeded.
type OnExceed struct {
	Action      string  // signal | challenge | rate_limit | block
	Weight      float64 // signal
	Type        string  // challenge: invisible | pow
	RetryAfterS uint32  // rate_limit; 0 = computed from GCRA
}

// Defaults of the optional sections (spec §8.3).
func defaultChallenge() Challenge {
	return Challenge{
		TTLS: 120, PowBits: PowBits{14, 16, 18, 20}, FallbackRet: "/",
		MaxFailures: 5, FailureWindowS: 600,
		Submit: Rate{Rate: 30, PeriodS: 60, Burst: 10},
		Issue:  Issue{PerIPP: 60, PerASN: 600, PeriodS: 3600},
	}
}

func defaultClearance() Clearance {
	return Clearance{TTLInvisibleS: 1800, TTLPowS: 1800, SessionMaxS: 86400, CTPShadow: true}
}

// DefaultZ0 are the prior log-odds per route sensitivity (spec §5.7).
var DefaultZ0 = map[string]float64{"low": -2.197, "medium": -1.735, "high": -1.386, "critical": -1.099}

func defaultScoring() Scoring {
	z0 := map[string]float64{}
	for k, v := range DefaultZ0 {
		z0[k] = v
	}
	return Scoring{ThetaC: 0.4, Z0: z0, FamilyModes: map[string]string{"edge_tls": "shadow"},
		Weights: map[string]float64{}, HMin: -4.0, RulesetVersion: "v1"}
}

// Load reads and parses a site YAML file. The error is for I/O problems;
// validation problems are diagnostics.
func Load(path string) (*Site, []Diagnostic, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > MaxFileSize {
		return nil, nil, fmt.Errorf("%s: file is larger than %d bytes", path, MaxFileSize)
	}
	s, diags := Parse(path, data)
	if s != nil {
		s.File = path
		s.Dir = filepath.Dir(path)
	}
	return s, diags, nil
}

// Parse parses site YAML; file names the source in diagnostics and its
// directory resolves relative paths. It returns nil only when the document
// cannot be read at all; otherwise the Site is filled as far as possible and
// the caller must treat any error diagnostic as fatal.
func Parse(file string, data []byte) (*Site, []Diagnostic) {
	p := &parser{file: file}
	if len(data) > MaxFileSize {
		p.errorf(nil, "file is larger than %d bytes", MaxFileSize)
		return nil, p.diags
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			p.errorf(nil, "empty site file")
		} else {
			p.errorf(nil, "invalid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
		}
		return nil, p.diags
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		p.errorf(&extra, "multiple YAML documents are not supported")
		return nil, p.diags
	} else if !errors.Is(err, io.EOF) {
		p.errorf(nil, "invalid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
		return nil, p.diags
	}
	if a := findAlias(&doc); a != nil {
		p.errorf(a, "YAML anchors, aliases and merge keys are not supported in site files")
		return nil, p.diags
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	o := p.object(root, "")
	if o == nil {
		return nil, p.diags
	}
	s := &Site{
		File: file, Dir: filepath.Dir(file), Raw: bytes.Clone(data),
		MonitorOnly: true, Challenge: defaultChallenge(), Clearance: defaultClearance(),
		Scoring: defaultScoring(), Crawlers: Crawlers{DefaultAction: "allow", Purposes: map[string]string{}},
		Events:        Events{AllowSampleRate: 0.1, AccessLog: true, Stream: true},
		OriginHeaders: OriginHeaders{Scores: true, Reasons: false, Session: true},
	}
	p.parseSite(o, s)
	o.finish()
	return s, p.diags
}

func (p *parser) parseSite(o *object, s *Site) {
	if v := o.require("version"); v != nil {
		if n, ok := p.uint(v, "version", 0, 1<<31); ok && n != 1 {
			p.errorf(v, "version: must be 1, got %d", n)
		} else if ok {
			s.Version = 1
		}
	}
	if v := o.require("site"); v != nil {
		if id, ok := p.str(v, "site"); ok {
			if !SitePattern.MatchString(id) {
				p.errorf(v, "site: %q does not match %s", id, SitePattern)
			}
			s.ID = id
		}
	}
	profileNode := o.require("profile")
	if profileNode != nil {
		s.Profile, _ = p.enum(profileNode, "profile", Profiles)
	}
	hostsNode := o.require("hosts")
	if hostsNode != nil {
		s.Hosts = p.hostList(hostsNode, "hosts")
		if len(s.Hosts) == 0 && hostsNode.Kind == yaml.SequenceNode {
			p.errorf(hostsNode, "hosts: must list at least one host")
		}
	}
	if v := o.require("allowed_listeners"); v != nil {
		ls, ok := p.strList(v, "allowed_listeners", func(it *yaml.Node, path, s string) bool {
			if !ListenerPattern.MatchString(s) {
				p.errorf(it, "%s: %q does not match %s", path, s, ListenerPattern)
				return false
			}
			return true
		})
		if ok && len(ls) == 0 {
			p.errorf(v, "allowed_listeners: must list at least one listener")
		}
		if ok {
			p.uniqueStrings(v, "allowed_listeners", ls)
		}
		s.AllowedListeners = ls
	}
	if v := o.get("monitor_only"); v != nil {
		s.MonitorOnly, _ = p.boolean(v, "monitor_only")
	}
	if v := o.get("not_before"); v != nil {
		if v.Kind == yaml.ScalarNode && (v.Tag == "!!str" || v.Tag == "!!timestamp") {
			t, err := time.Parse(time.RFC3339, v.Value)
			switch {
			case err != nil:
				p.errorf(v, "not_before: must be an RFC 3339 timestamp such as 2026-10-01T00:00:00Z")
			case t.Before(time.Unix(0, 0)):
				// not_before_ms is signed; the Edge rejects a negative value.
				p.errorf(v, "not_before: must not be before 1970-01-01T00:00:00Z")
			default:
				s.NotBefore = &t
			}
		} else {
			p.errorf(v, "not_before: must be an RFC 3339 timestamp, not %s", kindName(v))
		}
	}
	if v := o.get("share_ip_verdicts"); v != nil {
		s.ShareIPVerdicts, _ = p.boolean(v, "share_ip_verdicts")
	}
	if v := o.get("case_insensitive_paths"); v != nil {
		s.CaseInsensitivePaths, _ = p.boolean(v, "case_insensitive_paths")
	}
	cf := o.get("cloudflare")
	switch {
	case cf != nil && s.Profile == "direct_tls":
		p.errorf(cf, "cloudflare: only allowed with profile cloudflare")
	case cf == nil && s.Profile == "cloudflare":
		p.errorf(o.node, "cloudflare: required with profile cloudflare")
	case cf != nil:
		s.Cloudflare = p.parseCloudflare(cf)
	}
	if v := o.require("token"); v != nil {
		s.Token = p.parseToken(v)
	}
	if v := o.get("clearance"); v != nil {
		p.parseClearance(v, &s.Clearance)
	}
	if v := o.get("challenge"); v != nil {
		p.parseChallenge(v, &s.Challenge)
	}
	if v := o.get("scoring"); v != nil {
		p.parseScoring(v, &s.Scoring)
	}
	if v := o.get("crawlers"); v != nil {
		p.parseCrawlers(v, &s.Crawlers)
	}
	if v := o.get("events"); v != nil {
		p.parseEvents(v, &s.Events)
	}
	if v := o.get("origin_headers"); v != nil {
		p.parseOriginHeaders(v, &s.OriginHeaders)
	}
	if v := o.get("lists"); v != nil {
		s.Lists = p.parseLists(v)
	}
	if v := o.get("list_files"); v != nil {
		s.ListFiles = p.parseListFiles(v, s.Dir)
	}
	for _, l := range s.ListFiles {
		if slices.ContainsFunc(s.Lists, func(n NamedList) bool { return n.Name == l.Name }) {
			p.add(SeverityError, nil, "list_files.%s: a list with this name is also defined in lists", l.Name)
			p.diags[len(p.diags)-1].Line, p.diags[len(p.diags)-1].Col = l.Line, l.Col
		}
	}
	if v := o.get("artifacts"); v != nil {
		s.Artifacts = p.parseArtifacts(v, s.Dir)
	}
	envNode := o.require("environments")
	if envNode != nil {
		s.Environments = p.parseEnvironments(envNode, s)
	}
	if hostsNode != nil && envNode != nil {
		p.checkHostPartition(envNode, s)
	}
}

// hostList reads a list of lower-case host names (no port, no trailing dot).
func (p *parser) hostList(n *yaml.Node, path string) []string {
	hs, ok := p.strList(n, path, func(it *yaml.Node, ip, h string) bool {
		if !isHostname(h) {
			p.errorf(it, "%s: %q is not a lower-case host name without port or trailing dot", ip, h)
			return false
		}
		return true
	})
	if ok {
		p.uniqueStrings(n, path, hs)
	}
	return hs
}

// isHostname accepts lower-case LDH host names of at most 253 bytes.
func isHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func (p *parser) parseCloudflare(n *yaml.Node) *Cloudflare {
	o := p.object(n, "cloudflare")
	if o == nil {
		return nil
	}
	defer o.finish()
	cf := &Cloudflare{}
	if v := o.require("zone"); v != nil {
		if z, ok := p.str(v, "cloudflare.zone"); ok {
			if !isHostname(z) {
				p.errorf(v, "cloudflare.zone: %q is not a lower-case zone name", z)
			}
			cf.Zone = z
		}
	}
	if v := o.get("location_headers"); v != nil {
		cf.LocationHeaders, _ = p.boolean(v, "cloudflare.location_headers")
	}
	if v := o.get("tier1"); v != nil {
		cf.Tier1, _ = p.boolean(v, "cloudflare.tier1")
	}
	if v := o.get("owner_zones"); v != nil {
		cf.OwnerZones = p.hostList(v, "cloudflare.owner_zones")
	}
	if v := o.get("pseudo_ipv4_overwrite"); v != nil {
		cf.PseudoIPv4Overwrite, _ = p.boolean(v, "cloudflare.pseudo_ipv4_overwrite")
	}
	if v := o.get("origin_mode"); v != nil {
		cf.OriginMode, _ = p.enum(v, "cloudflare.origin_mode", OriginModes)
	}
	if v := o.get("account_id"); v != nil {
		cf.AccountID, _ = p.str(v, "cloudflare.account_id")
	}
	if v := o.get("tunnel_id"); v != nil {
		cf.TunnelID, _ = p.str(v, "cloudflare.tunnel_id")
	}
	return cf
}

func (p *parser) parseToken(n *yaml.Node) Token {
	var t Token
	o := p.object(n, "token")
	if o == nil {
		return t
	}
	defer o.finish()
	kid := func(it *yaml.Node, path, s string) bool {
		if !KIDPattern.MatchString(s) {
			p.errorf(it, "%s: %q does not match %s", path, s, KIDPattern)
			return false
		}
		return true
	}
	if v := o.require("active_kid"); v != nil {
		if s, ok := p.str(v, "token.active_kid"); ok && kid(v, "token.active_kid", s) {
			t.ActiveKID = s
		}
	}
	if v := o.get("verify_kids"); v != nil {
		t.VerifyKIDs, _ = p.strList(v, "token.verify_kids", kid)
		all := t.KIDs()
		if p.uniqueStrings(v, "token.verify_kids (with active_kid)", all) && len(all) > MaxTokenKeyIDs {
			p.errorf(v, "token: %d key ids, but token.keys.json holds at most %d keys", len(all), MaxTokenKeyIDs)
		}
	}
	return t
}

func (p *parser) parseClearance(n *yaml.Node, c *Clearance) {
	o := p.object(n, "clearance")
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("ttl_invisible_s"); v != nil {
		c.TTLInvisibleS, _ = p.uint(v, "clearance.ttl_invisible_s", 60, 86400)
	}
	if v := o.get("ttl_pow_s"); v != nil {
		c.TTLPowS, _ = p.uint(v, "clearance.ttl_pow_s", 60, 86400)
	}
	if v := o.get("session_max_s"); v != nil {
		c.SessionMaxS, _ = p.uint(v, "clearance.session_max_s", 60, MaxSessionS)
	}
	if v := o.get("ctp_shadow"); v != nil {
		c.CTPShadow, _ = p.boolean(v, "clearance.ctp_shadow")
	}
	if c.SessionMaxS != 0 && (c.SessionMaxS < c.TTLInvisibleS || c.SessionMaxS < c.TTLPowS) {
		p.errorf(n, "clearance.session_max_s: %d is shorter than a clearance TTL (ttl_invisible_s %d, ttl_pow_s %d)", c.SessionMaxS, c.TTLInvisibleS, c.TTLPowS)
	}
}

func (p *parser) parseChallenge(n *yaml.Node, c *Challenge) {
	o := p.object(n, "challenge")
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("ttl_s"); v != nil {
		c.TTLS, _ = p.uint(v, "challenge.ttl_s", 10, 120)
	}
	if v := o.get("pow_bits"); v != nil {
		if po := p.object(v, "challenge.pow_bits"); po != nil {
			for _, f := range []struct {
				key string
				dst *uint32
			}{{"low", &c.PowBits.Low}, {"medium", &c.PowBits.Medium}, {"high", &c.PowBits.High}, {"very_high", &c.PowBits.VeryHigh}} {
				if fv := po.get(f.key); fv != nil {
					if b, ok := p.uint(fv, po.sub(f.key), 8, 24); ok {
						*f.dst = b
					}
				}
			}
			po.finish()
		}
	}
	if v := o.get("fallback_ret"); v != nil {
		if s, ok := p.str(v, "challenge.fallback_ret"); ok {
			if err := ValidateRet(s); err != nil {
				p.errorf(v, "challenge.fallback_ret: %q %v", s, err)
			} else {
				c.FallbackRet = s
			}
		}
	}
	if v := o.get("max_failures"); v != nil {
		c.MaxFailures, _ = p.uint(v, "challenge.max_failures", 1, 1000)
	}
	if v := o.get("failure_window_s"); v != nil {
		c.FailureWindowS, _ = p.uint(v, "challenge.failure_window_s", 60, 86400)
	}
	if v := o.get("submit"); v != nil {
		if so := p.object(v, "challenge.submit"); so != nil {
			p.rateFields(so, &c.Submit)
			so.finish()
			p.checkGCRA(v, "challenge.submit", c.Submit)
		}
	}
	if v := o.get("issue"); v != nil {
		if iso := p.object(v, "challenge.issue"); iso != nil {
			if fv := iso.get("per_ipp"); fv != nil {
				c.Issue.PerIPP, _ = p.uint(fv, "challenge.issue.per_ipp", 1, 100_000)
			}
			if fv := iso.get("per_asn"); fv != nil {
				c.Issue.PerASN, _ = p.uint(fv, "challenge.issue.per_asn", 1, 100_000)
			}
			if fv := iso.get("period_s"); fv != nil {
				c.Issue.PeriodS, _ = p.uint(fv, "challenge.issue.period_s", 1, 86400)
			}
			iso.finish()
			p.checkGCRA(v, "challenge.issue (per_ipp)", Rate{c.Issue.PerIPP, c.Issue.PeriodS, c.Issue.PerIPP})
			p.checkGCRA(v, "challenge.issue (per_asn)", Rate{c.Issue.PerASN, c.Issue.PeriodS, c.Issue.PerASN})
		}
	}
	// The failure limiters mg.c.fail / mg.c.fail.prefix derive from these (D-28).
	p.checkGCRA(n, "challenge failure quota", Rate{c.MaxFailures, c.FailureWindowS, c.MaxFailures})
	p.checkGCRA(n, "challenge failure quota per prefix", Rate{4 * c.MaxFailures, c.FailureWindowS, 4 * c.MaxFailures})
}

// rateFields reads rate / period_s / burst members (challenge.submit).
func (p *parser) rateFields(o *object, r *Rate) {
	if v := o.get("rate"); v != nil {
		r.Rate, _ = p.uint(v, o.sub("rate"), 1, 1<<32-1)
	}
	if v := o.get("period_s"); v != nil {
		r.PeriodS, _ = p.uint(v, o.sub("period_s"), 1, 86400)
	}
	if v := o.get("burst"); v != nil {
		r.Burst, _ = p.uint(v, o.sub("burst"), 1, 100_000)
	}
}

// GCRAValid mirrors mg_core::gcra::GcraParams::new: rate, period_s and burst
// non-zero, interval_us = period_s * 1e6 / rate (floor) non-zero, and
// interval_us * burst <= 7 days, so every Lua value stays below 2^53.
func GCRAValid(r Rate) bool {
	if r.Rate == 0 || r.PeriodS == 0 || r.Burst == 0 {
		return false
	}
	interval := uint64(r.PeriodS) * 1_000_000 / uint64(r.Rate)
	return interval > 0 && interval*uint64(r.Burst) <= MaxDVTMicros
}

func (p *parser) checkGCRA(n *yaml.Node, path string, r Rate) {
	if r.Rate == 0 || r.PeriodS == 0 || r.Burst == 0 {
		return // already reported
	}
	if !GCRAValid(r) {
		p.errorf(n, "%s: %d per %d s with burst %d is not a valid GCRA limiter (interval must be >= 1 us and interval x burst <= 7 days)", path, r.Rate, r.PeriodS, r.Burst)
	}
}

func (p *parser) parseScoring(n *yaml.Node, sc *Scoring) {
	o := p.object(n, "scoring")
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("theta_c"); v != nil {
		sc.ThetaC, _ = p.float(v, "scoring.theta_c", 0, 1)
	}
	if v := o.get("kappa"); v != nil {
		sc.Kappa, _ = p.float(v, "scoring.kappa", 0, 1)
	}
	if v := o.get("z0"); v != nil {
		if zo := p.object(v, "scoring.z0"); zo != nil {
			for _, k := range Sensitivities {
				if fv := zo.get(k); fv != nil {
					if f, ok := p.float(fv, zo.sub(k), -10, 10); ok {
						sc.Z0[k] = f
					}
				}
			}
			zo.finish()
		}
	}
	if v := o.get("family_modes"); v != nil {
		if fo := p.object(v, "scoring.family_modes"); fo != nil {
			for _, k := range SignalFamilies {
				if fv := fo.get(k); fv != nil {
					if m, ok := p.enum(fv, fo.sub(k), FamilyModes); ok {
						sc.FamilyModes[k] = m
					}
				}
			}
			fo.finish()
		}
	}
	if v := o.get("weights"); v != nil {
		if wo := p.object(v, "scoring.weights"); wo != nil {
			for _, k := range SignalIDs {
				if fv := wo.get(k); fv != nil {
					if w, ok := p.float(fv, "scoring.weights."+k, 0, 10); ok {
						sc.Weights[k] = w
					}
				}
			}
			for _, k := range wo.order {
				if !wo.used[k] {
					wo.used[k] = true
					p.errorf(wo.keys[k], "scoring.weights: %q is not a Phase 1 detector signal id (%s)", k, strings.Join(SignalIDs, ", "))
				}
			}
		}
	}
	if v := o.get("h_min"); v != nil {
		sc.HMin, _ = p.float(v, "scoring.h_min", -20, 0)
	}
	if v := o.get("ruleset_version"); v != nil {
		if s, ok := p.str(v, "scoring.ruleset_version"); ok {
			if !rulesetPattern.MatchString(s) {
				p.errorf(v, "scoring.ruleset_version: %q does not match %s", s, rulesetPattern)
			} else {
				sc.RulesetVersion = s
			}
		}
	}
}

func (p *parser) parseCrawlers(n *yaml.Node, c *Crawlers) {
	o := p.object(n, "crawlers")
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("default_action"); v != nil {
		if a, ok := p.enum(v, "crawlers.default_action", CrawlerActions); ok {
			c.DefaultAction = a
		}
	}
	if v := o.get("purposes"); v != nil {
		if po := p.object(v, "crawlers.purposes"); po != nil {
			for _, k := range CrawlerPurposes {
				if fv := po.get(k); fv != nil {
					if a, ok := p.enum(fv, po.sub(k), CrawlerActions); ok {
						c.Purposes[k] = a
					}
				}
			}
			po.finish()
		}
	}
}

func (p *parser) parseEvents(n *yaml.Node, e *Events) {
	o := p.object(n, "events")
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("allow_sample_rate"); v != nil {
		e.AllowSampleRate, _ = p.float(v, "events.allow_sample_rate", 0, 1)
	}
	if v := o.get("access_log"); v != nil {
		e.AccessLog, _ = p.boolean(v, "events.access_log")
	}
	if v := o.get("stream"); v != nil {
		e.Stream, _ = p.boolean(v, "events.stream")
	}
}

func (p *parser) parseOriginHeaders(n *yaml.Node, h *OriginHeaders) {
	o := p.object(n, "origin_headers")
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("scores"); v != nil {
		h.Scores, _ = p.boolean(v, "origin_headers.scores")
	}
	if v := o.get("reasons"); v != nil {
		h.Reasons, _ = p.boolean(v, "origin_headers.reasons")
	}
	if v := o.get("session"); v != nil {
		h.Session, _ = p.boolean(v, "origin_headers.session")
	}
}

func (p *parser) parseLists(n *yaml.Node) []NamedList {
	o := p.object(n, "lists")
	if o == nil {
		return nil
	}
	var out []NamedList
	for _, name := range o.order {
		o.used[name] = true
		path := "lists." + name
		if !ListNamePattern.MatchString(name) {
			p.errorf(o.keys[name], "%s: list name does not match %s", path, ListNamePattern)
			continue
		}
		items, ok := p.seq(o.vals[name], path)
		if !ok {
			continue
		}
		if len(items) > MaxListEntries {
			p.errorf(o.vals[name], "%s: %d entries, at most %d", path, len(items), MaxListEntries)
			continue
		}
		l := NamedList{Name: name, Entries: make([]string, 0, len(items))}
		for i, it := range items {
			ip := fmt.Sprintf("%s[%d]", path, i)
			s, ok := p.scalarText(it, ip)
			if !ok {
				continue
			}
			if len(s) > MaxListEntryLen {
				p.errorf(it, "%s: entry is %d bytes, at most %d", ip, len(s), MaxListEntryLen)
				continue
			}
			l.Entries = append(l.Entries, s)
		}
		out = append(out, l)
	}
	return out
}

func (p *parser) parseListFiles(n *yaml.Node, dir string) []ListFile {
	o := p.object(n, "list_files")
	if o == nil {
		return nil
	}
	var out []ListFile
	for _, name := range o.order {
		o.used[name] = true
		path := "list_files." + name
		if !ListNamePattern.MatchString(name) {
			p.errorf(o.keys[name], "%s: list name does not match %s", path, ListNamePattern)
			continue
		}
		if f, ok := p.str(o.vals[name], path); ok {
			if f == "" {
				p.errorf(o.vals[name], "%s: empty path", path)
				continue
			}
			out = append(out, ListFile{Name: name, Path: resolve(dir, f), Line: o.vals[name].Line, Col: o.vals[name].Column})
		}
	}
	return out
}

func (p *parser) parseArtifacts(n *yaml.Node, dir string) []Artifact {
	o := p.object(n, "artifacts")
	if o == nil {
		return nil
	}
	defer o.finish()
	var out []Artifact
	for _, ak := range ArtifactKeys {
		v := o.get(ak.Key)
		if v == nil {
			continue
		}
		if f, ok := p.str(v, "artifacts."+ak.Key); ok {
			if f == "" {
				p.errorf(v, "artifacts.%s: empty path", ak.Key)
				continue
			}
			out = append(out, Artifact{Key: ak.Key, Name: ak.Name, Path: resolve(dir, f), Line: v.Line, Col: v.Column})
		}
	}
	return out
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(dir, p)
}

// HasArtifact reports whether the site configures the named artifact.
func (s *Site) HasArtifact(name string) bool {
	return slices.ContainsFunc(s.Artifacts, func(a Artifact) bool { return a.Name == name })
}
