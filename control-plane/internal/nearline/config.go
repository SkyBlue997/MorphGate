package nearline

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Detector modes (spec §13.4).
const (
	ModeShadow  = "shadow"
	ModeEnforce = "enforce"
)

// Detector names: the <detector> of source "nearline/<detector>" and the
// detector label of the metrics.
const (
	DetScanner        = "scanner"
	DetSharedToken    = "shared_token"
	DetChallengeAbuse = "challenge_abuse"
	DetHighRate       = "high_rate"
)

// Detectors lists the detector names in a fixed order.
var Detectors = []string{DetScanner, DetSharedToken, DetChallengeAbuse, DetHighRate}

// CredentialsVar is the only variable expanded in configuration values.
const CredentialsVar = "CREDENTIALS_DIRECTORY"

// MaxConfigSize bounds the configuration file.
const MaxConfigSize = 64 << 10

// Duration is a YAML duration such as "15m" or "1h".
type Duration time.Duration

// UnmarshalYAML parses a Go duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return fmt.Errorf("line %d: expected a duration such as \"15m\"", n.Line)
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, n.Value)
	}
	*d = Duration(v)
	return nil
}

// Valkey is the valkey: section.
type Valkey struct {
	URL          string `yaml:"url"`
	User         string `yaml:"user"`
	PasswordFile string `yaml:"password_file"`
}

// Stream is the stream: section.
type Stream struct {
	Key           string `yaml:"key"`
	Group         string `yaml:"group"`
	Batch         int    `yaml:"batch"`
	BlockMs       int    `yaml:"block_ms"`
	ReclaimIdleMs int    `yaml:"reclaim_idle_ms"`
	ReclaimEveryS int    `yaml:"reclaim_every_s"`
}

// VerdictEvents is the verdict_events: section.
type VerdictEvents struct {
	VLMain string `yaml:"vl_main"`
}

// Windows is the windows: section.
type Windows struct {
	MaxKeys          int `yaml:"max_keys"`
	IPv6PrefixFactor int `yaml:"ipv6_prefix_factor"`
}

// ScannerParams configures the scanner detector.
type ScannerParams struct {
	Mode         string   `yaml:"mode"`
	BaitDistinct int      `yaml:"bait_distinct"`
	Distinct404  int      `yaml:"distinct_404"`
	Share404     float64  `yaml:"share_404"`
	Risk         int      `yaml:"risk"`
	TTL          Duration `yaml:"ttl"`
}

// SharedTokenParams configures the shared_token detector.
type SharedTokenParams struct {
	Mode           string   `yaml:"mode"`
	ProofMismatch  int      `yaml:"proof_mismatch"`
	DistinctPrefix int      `yaml:"distinct_prefix"`
	Risk           int      `yaml:"risk"`
	TTL            Duration `yaml:"ttl"`
}

// ChallengeAbuseParams configures the challenge_abuse detector.
type ChallengeAbuseParams struct {
	Mode         string   `yaml:"mode"`
	Fails        int      `yaml:"fails"`
	MaxPassRatio float64  `yaml:"max_pass_ratio"`
	Risk         int      `yaml:"risk"`
	TTL          Duration `yaml:"ttl"`
}

// HighRateParams configures the high_rate detector.
type HighRateParams struct {
	Mode         string   `yaml:"mode"`
	PerMinute    int      `yaml:"per_minute"`
	Minutes      int      `yaml:"minutes"`
	SharedEgress int      `yaml:"shared_egress"`
	Risk         int      `yaml:"risk"`
	TTL          Duration `yaml:"ttl"`
}

// DetectorsConfig is the detectors: section.
type DetectorsConfig struct {
	Scanner        ScannerParams        `yaml:"scanner"`
	SharedToken    SharedTokenParams    `yaml:"shared_token"`
	ChallengeAbuse ChallengeAbuseParams `yaml:"challenge_abuse"`
	HighRate       HighRateParams       `yaml:"high_rate"`
}

// Mode returns the mode of detector name.
func (d *DetectorsConfig) Mode(name string) string {
	switch name {
	case DetScanner:
		return d.Scanner.Mode
	case DetSharedToken:
		return d.SharedToken.Mode
	case DetChallengeAbuse:
		return d.ChallengeAbuse.Mode
	case DetHighRate:
		return d.HighRate.Mode
	}
	return ""
}

// Acceptance is the acceptance: section (spec §13.3 "验收比例").
type Acceptance struct {
	WindowDays     int `yaml:"window_days"`
	MinDenominator int `yaml:"min_denominator"`
	MaxKeysPerDay  int `yaml:"max_keys_per_day"`
}

// Config is the mg-nearline configuration file (spec §13.5).
type Config struct {
	Version       int             `yaml:"version"`
	Valkey        Valkey          `yaml:"valkey"`
	Stream        Stream          `yaml:"stream"`
	Sites         []string        `yaml:"sites"`
	VerdictEvents VerdictEvents   `yaml:"verdict_events"`
	MetricsListen string          `yaml:"metrics_listen"`
	Windows       Windows         `yaml:"windows"`
	Detectors     DetectorsConfig `yaml:"detectors"`
	Acceptance    Acceptance      `yaml:"acceptance"`
}

// DefaultConfig returns the defaults of spec §13.5; version, valkey.url and
// sites have none and must be set.
func DefaultConfig() Config {
	return Config{
		Stream:        Stream{Key: "mg:ev", Group: "nl", Batch: 512, BlockMs: 1000, ReclaimIdleMs: 60000, ReclaimEveryS: 60},
		MetricsListen: "127.0.0.1:9902",
		Windows:       Windows{MaxKeys: 200000, IPv6PrefixFactor: 4},
		Detectors: DetectorsConfig{
			Scanner:        ScannerParams{Mode: ModeShadow, BaitDistinct: 2, Distinct404: 30, Share404: 0.6, Risk: 80, TTL: Duration(15 * time.Minute)},
			SharedToken:    SharedTokenParams{Mode: ModeShadow, ProofMismatch: 3, DistinctPrefix: 2, Risk: 85, TTL: Duration(time.Hour)},
			ChallengeAbuse: ChallengeAbuseParams{Mode: ModeShadow, Fails: 30, MaxPassRatio: 0.1, Risk: 70, TTL: Duration(30 * time.Minute)},
			HighRate:       HighRateParams{Mode: ModeShadow, PerMinute: 600, Minutes: 5, SharedEgress: 3, Risk: 75, TTL: Duration(15 * time.Minute)},
		},
		Acceptance: Acceptance{WindowDays: 7, MinDenominator: 2000, MaxKeysPerDay: 200000},
	}
}

// LoadConfig reads and validates the configuration file at file. getenv
// supplies $CREDENTIALS_DIRECTORY (os.Getenv in production).
func LoadConfig(file string, getenv func(string) string) (*Config, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxConfigSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", file, MaxConfigSize)
	}
	cfg, err := ParseConfig(data, getenv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return cfg, nil
}

// ParseConfig parses and validates configuration YAML. Unknown keys are
// errors. In values, only ${CREDENTIALS_DIRECTORY} is expanded; any other
// ${...} is an error, and so is ${CREDENTIALS_DIRECTORY} when the variable
// is unset or empty.
func ParseConfig(data []byte, getenv func(string) string) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty configuration")
		}
		return nil, fmt.Errorf("invalid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("multiple YAML documents are not supported")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	if err := expandNode(&doc, getenv, false); err != nil {
		return nil, err
	}
	expanded, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("invalid YAML: %v", err)
	}
	cfg := DefaultConfig()
	strict := yaml.NewDecoder(bytes.NewReader(expanded))
	strict.KnownFields(true)
	if err := strict.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// expandNode applies the ${CREDENTIALS_DIRECTORY} rule to every scalar value
// and rejects anchors and aliases. Mapping keys are not expanded.
func expandNode(n *yaml.Node, getenv func(string) string, isKey bool) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("line %d: YAML anchors and aliases are not supported", n.Line)
	}
	if n.Kind == yaml.ScalarNode {
		if isKey || !strings.Contains(n.Value, "${") {
			return nil
		}
		const ref = "${" + CredentialsVar + "}"
		if strings.Contains(strings.ReplaceAll(n.Value, ref, ""), "${") {
			return fmt.Errorf("line %d: only %s is expanded in configuration values", n.Line, ref)
		}
		dir := getenv(CredentialsVar)
		if dir == "" {
			return fmt.Errorf("line %d: %s is used but $%s is not set", n.Line, ref, CredentialsVar)
		}
		n.Value = strings.ReplaceAll(n.Value, ref, dir)
		n.Style = yaml.DoubleQuotedStyle
		n.Tag = "!!str"
		return nil
	}
	for i, c := range n.Content {
		if err := expandNode(c, getenv, n.Kind == yaml.MappingNode && i%2 == 0); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks every rule that needs nothing but the parsed values.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if c.Version != 1 {
		add("version: must be 1")
	}
	if c.Valkey.URL == "" {
		add("valkey.url: required")
	} else if _, err := ParseValkeyURL(c.Valkey.URL); err != nil {
		add("valkey.url: %v", err)
	}
	if c.Valkey.User != "" && !aclUserPattern(c.Valkey.User) {
		add("valkey.user: must be 1-64 of [A-Za-z0-9_.-]")
	}
	if c.Valkey.PasswordFile != "" && !path.IsAbs(c.Valkey.PasswordFile) {
		add("valkey.password_file: must be an absolute path")
	}
	if c.Stream.Key == "" || strings.ContainsAny(c.Stream.Key, " \t\r\n") || len(c.Stream.Key) > 128 {
		add("stream.key: must be 1-128 bytes without whitespace")
	}
	if c.Stream.Group == "" || strings.ContainsAny(c.Stream.Group, " \t\r\n") || len(c.Stream.Group) > 64 {
		add("stream.group: must be 1-64 bytes without whitespace")
	}
	rangeCheck := func(name string, v, lo, hi int) {
		if v < lo || v > hi {
			add("%s: must be %d..%d, got %d", name, lo, hi, v)
		}
	}
	rangeCheck("stream.batch", c.Stream.Batch, 1, 10000)
	rangeCheck("stream.block_ms", c.Stream.BlockMs, 10, 10000)
	rangeCheck("stream.reclaim_idle_ms", c.Stream.ReclaimIdleMs, 1000, 3600000)
	rangeCheck("stream.reclaim_every_s", c.Stream.ReclaimEveryS, 1, 3600)
	if len(c.Sites) == 0 {
		add("sites: must list at least one site")
	}
	seen := map[string]bool{}
	for i, s := range c.Sites {
		switch {
		case !sitePattern.MatchString(s):
			add("sites[%d]: %q is not a site id ([a-z0-9][a-z0-9_-]{0,63})", i, s)
		case s == "all":
			add("sites[%d]: \"all\" is the cross-site verdict namespace, not a site", i)
		case seen[s]:
			add("sites[%d]: duplicate site %q", i, s)
		}
		seen[s] = true
	}
	if c.VerdictEvents.VLMain != "" {
		if _, err := VLInsertURL(c.VerdictEvents.VLMain); err != nil {
			add("verdict_events.vl_main: %v", err)
		}
	}
	if err := checkMetricsListen(c.MetricsListen); err != nil {
		add("metrics_listen: %v", err)
	}
	rangeCheck("windows.max_keys", c.Windows.MaxKeys, 1, 10_000_000)
	rangeCheck("windows.ipv6_prefix_factor", c.Windows.IPv6PrefixFactor, 1, 1000)

	d := &c.Detectors
	mode := func(name, m string) {
		if m != ModeShadow && m != ModeEnforce {
			add("detectors.%s.mode: must be shadow or enforce, got %q", name, m)
		}
	}
	risk := func(name string, r int) { rangeCheck("detectors."+name+".risk", r, 1, 100) }
	ttl := func(name string, t Duration) {
		v := time.Duration(t)
		if v < time.Second || v > 7*24*time.Hour || v%time.Millisecond != 0 {
			add("detectors.%s.ttl: must be 1s..168h in whole milliseconds", name)
		}
	}
	ratio := func(name string, v float64) {
		if !(v > 0 && v <= 1) {
			add("%s: must be in (0, 1]", name)
		}
	}
	mode(DetScanner, d.Scanner.Mode)
	rangeCheck("detectors.scanner.bait_distinct", d.Scanner.BaitDistinct, 1, 1000)
	rangeCheck("detectors.scanner.distinct_404", d.Scanner.Distinct404, 1, 1000)
	ratio("detectors.scanner.share_404", d.Scanner.Share404)
	risk(DetScanner, d.Scanner.Risk)
	ttl(DetScanner, d.Scanner.TTL)
	mode(DetSharedToken, d.SharedToken.Mode)
	rangeCheck("detectors.shared_token.proof_mismatch", d.SharedToken.ProofMismatch, 1, 100000)
	rangeCheck("detectors.shared_token.distinct_prefix", d.SharedToken.DistinctPrefix, 1, 1000)
	risk(DetSharedToken, d.SharedToken.Risk)
	ttl(DetSharedToken, d.SharedToken.TTL)
	mode(DetChallengeAbuse, d.ChallengeAbuse.Mode)
	rangeCheck("detectors.challenge_abuse.fails", d.ChallengeAbuse.Fails, 1, 100000)
	ratio("detectors.challenge_abuse.max_pass_ratio", d.ChallengeAbuse.MaxPassRatio)
	risk(DetChallengeAbuse, d.ChallengeAbuse.Risk)
	ttl(DetChallengeAbuse, d.ChallengeAbuse.TTL)
	mode(DetHighRate, d.HighRate.Mode)
	rangeCheck("detectors.high_rate.per_minute", d.HighRate.PerMinute, 1, 10_000_000)
	rangeCheck("detectors.high_rate.minutes", d.HighRate.Minutes, 1, 60)
	rangeCheck("detectors.high_rate.shared_egress", d.HighRate.SharedEgress, 1, 1000)
	risk(DetHighRate, d.HighRate.Risk)
	ttl(DetHighRate, d.HighRate.TTL)

	rangeCheck("acceptance.window_days", c.Acceptance.WindowDays, 1, 31)
	rangeCheck("acceptance.min_denominator", c.Acceptance.MinDenominator, 1, 100_000_000)
	rangeCheck("acceptance.max_keys_per_day", c.Acceptance.MaxKeysPerDay, 1, 10_000_000)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func aclUserPattern(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// ValkeyAddr is a parsed valkey.url.
type ValkeyAddr struct {
	Network string // "unix" or "tcp"
	Address string // socket path, or host:port
	DB      int
}

// ParseValkeyURL accepts unix:///absolute/path.sock or
// redis://<loopback IP literal>[:port][/db]. The worker's Valkey is on the
// same host (spec §13.5: loopback only); the URL never carries credentials
// (user and password_file do).
func ParseValkeyURL(raw string) (ValkeyAddr, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return ValkeyAddr{}, errors.New("not a URL")
	}
	if u.User != nil {
		return ValkeyAddr{}, errors.New("must not contain credentials (use user and password_file)")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return ValkeyAddr{}, errors.New("must not contain a query or fragment")
	}
	switch u.Scheme {
	case "unix":
		if u.Host != "" || !path.IsAbs(u.Path) || path.Clean(u.Path) != u.Path {
			return ValkeyAddr{}, errors.New("unix:// needs an absolute, clean socket path (unix:///run/valkey/valkey.sock)")
		}
		return ValkeyAddr{Network: "unix", Address: u.Path}, nil
	case "redis":
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Unmap().IsLoopback() {
			return ValkeyAddr{}, errors.New("redis:// needs a loopback IP literal such as 127.0.0.1 (loopback only)")
		}
		port := u.Port()
		if port == "" {
			port = "6379"
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return ValkeyAddr{}, errors.New("invalid port")
		}
		a := ValkeyAddr{Network: "tcp", Address: net.JoinHostPort(ip.String(), port)}
		if p := strings.TrimPrefix(u.Path, "/"); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 1<<16 || strconv.Itoa(n) != p {
				return ValkeyAddr{}, errors.New("path must be empty or a database number")
			}
			a.DB = n
		}
		return a, nil
	}
	return ValkeyAddr{}, fmt.Errorf("scheme must be unix or redis, got %q", u.Scheme)
}

// isInternalIP: loopback, RFC 1918, 100.64.0.0/10 or IPv6 unique local (the
// edge.toml rule for VictoriaLogs URLs and metrics_listen, Phase 1 I-11).
func isInternalIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		return ip.IsLoopback() || ip.IsPrivate() || (b[0] == 100 && b[1] >= 64 && b[1] < 128)
	}
	return ip.IsLoopback() || ip.IsPrivate()
}

func checkMetricsListen(s string) error {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return errors.New("must be <IP literal>:<port>")
	}
	if ap.Port() == 0 {
		return errors.New("port must not be 0")
	}
	if !isInternalIP(ap.Addr()) {
		return errors.New("must be a loopback, private (RFC 1918 / ULA) or 100.64.0.0/10 address; /metrics has no authentication")
	}
	return nil
}

// VictoriaLogs insert endpoint (same as the Edge, Phase 1 spec §13.1).
const (
	vlJSONLinePath    = "insert/jsonline"
	vlJSONLineQuery   = "_stream_fields=kind,site&_time_field=ts&_msg_field=msg"
	vlJSONContentType = "application/stream+json"
)

// VLInsertURL validates a VictoriaLogs base URL with the edge.toml rules
// (Phase 1 I-11) and returns its insert URL: http or https, a host, no
// credentials, query or fragment; http:// only to a loopback, RFC 1918, ULA
// or 100.64.0.0/10 IP literal, never a name.
func VLInsertURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", errors.New("invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", errors.New("URL has no host")
	}
	if u.Scheme == "http" {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !isInternalIP(ip) {
			return "", errors.New("http:// is only allowed to a loopback, private (RFC 1918 / ULA) or 100.64.0.0/10 address; use https://")
		}
	}
	if u.User != nil {
		return "", errors.New("URL must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", errors.New("URL must not contain a query or fragment")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + vlJSONLinePath
	u.RawPath = ""
	u.RawQuery = vlJSONLineQuery
	return u.String(), nil
}

// ReadPassword reads the one-line password file. The value is never logged.
func ReadPassword(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", fmt.Errorf("valkey.password_file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", fmt.Errorf("valkey.password_file: %w", err)
	}
	if len(data) > 4096 {
		return "", errors.New("valkey.password_file: larger than 4096 bytes")
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return "", errors.New("valkey.password_file: must hold exactly one non-empty line")
	}
	return s, nil
}

// SiteConfigured reports whether site is in the sites list.
func (c *Config) SiteConfigured(site string) bool { return slices.Contains(c.Sites, site) }
