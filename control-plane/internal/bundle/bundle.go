// Package bundle builds, signs, verifies and publishes MorphGate site bundles
// (docs/impl/phase1-spec.md §3.2, §8.3, §12.1, §14.2).
//
// Build maps a parsed site YAML (package sitecfg) onto a SiteBundle: it
// compiles every environment's policy files, keeps the enabled and unexpired
// rules in engine order (§5.4) with their policy IR, appends nothing the Edge
// could not load (a rule without IR fails the build), validates every
// artifact the way the Edge parses it and always writes the fully populated
// optional messages (§8.3: the Edge back-fills only missing messages). The
// output is deterministic: the same inputs and options give the same bytes.
//
// Sign / Verify implement the detached Ed25519 signature over
// "mg-bundle-v1" || 0x00 || bundle; Publish writes a verified bundle and its
// artifacts to a static directory tree (artifacts first, then the bundle).
package bundle

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/keys"
	"morphgate/control-plane/internal/policy"
	"morphgate/control-plane/internal/sitecfg"
)

// Limits shared with the Edge.
const (
	// MaxBundleSize bounds a serialized SiteBundle (spec §8.2) and the
	// SignedBundle around it.
	MaxBundleSize = 8 << 20
	// MaxSteps is the static evaluation step bound of one rule (spec §5.3).
	MaxSteps = 100_000
	// SchemaVersion of the Phase 1 SiteBundle.
	SchemaVersion = 1
	// IRVersion of the policy IR the Edge loads.
	IRVersion = 1
	// maxListFile bounds one list_files text file.
	maxListFile = 4 << 20
)

// BuildOptions control Build.
type BuildOptions struct {
	// Version of the bundle; 0 means the build time in Unix seconds.
	Version uint64
	// Now is the build time (created_at_ms, rule expiry); zero means time.Now.
	Now time.Time
	// MaxCost is the cel-go cost budget per rule; 0 means policy.DefaultMaxCost.
	MaxCost uint64
}

// BuildResult is a built bundle.
type BuildResult struct {
	Bundle    *morphgatev1.SiteBundle
	Bytes     []byte            // deterministic marshal
	Artifacts map[string]string // sha256 -> source path
	Warnings  []string
}

// BuildError lists every problem that prevented a build.
type BuildError struct{ Problems []string }

func (e *BuildError) Error() string {
	return fmt.Sprintf("%d problem(s):\n  %s", len(e.Problems), strings.Join(e.Problems, "\n  "))
}

// ruleProto converts a checked rule to its wire form; tests substitute a
// stand-in lowering to exercise the builder independently of the compiler.
var ruleProto = func(cr *policy.CheckedRule) *morphgatev1.CompiledRule { return cr.Proto() }

type builder struct {
	site     *sitecfg.Site
	opts     BuildOptions
	problems []string
	warnings []string
	lists    map[string][]string
	// Policy and list file bytes in order of appearance, for source_digest.
	policySources, listSources [][]byte
}

func (b *builder) problem(format string, args ...any) {
	b.problems = append(b.problems, fmt.Sprintf(format, args...))
}

func (b *builder) warn(format string, args ...any) {
	b.warnings = append(b.warnings, fmt.Sprintf(format, args...))
}

// Build maps a site onto a SiteBundle (spec §8.3). The site must have parsed
// without error diagnostics. Build fails when a rule has ir_version != 1 or
// empty expr_ir ("policy IR unavailable"), when an IR named_list is not a
// site list, or when an artifact fails its §12 validation.
func Build(site *sitecfg.Site, opts BuildOptions) (*BuildResult, error) {
	if site == nil {
		return nil, fmt.Errorf("no site")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	if opts.Version == 0 {
		opts.Version = uint64(opts.Now.Unix())
	}
	b := &builder{site: site, opts: opts}
	b.readLists()
	sb := &morphgatev1.SiteBundle{
		SchemaVersion:        SchemaVersion,
		SiteId:               site.ID,
		Version:              opts.Version,
		CreatedAtMs:          opts.Now.UnixMilli(),
		Upstream:             upstream(site.Profile),
		TokenKeyIds:          site.Token.KIDs(),
		MonitorOnly:          site.MonitorOnly,
		Hosts:                site.Hosts,
		AllowedListeners:     site.AllowedListeners,
		ShareIpVerdicts:      site.ShareIPVerdicts,
		CaseInsensitivePaths: site.CaseInsensitivePaths,
		Challenge:            challengeConfig(site.Challenge),
		Clearance:            clearanceConfig(site.Clearance),
		Scoring:              scoringConfig(site.Scoring),
		CrawlerPolicy:        &morphgatev1.CrawlerPolicy{Purposes: site.Crawlers.Purposes, DefaultAction: site.Crawlers.DefaultAction},
		Events:               &morphgatev1.EventConfig{AllowSampleRate: float32(site.Events.AllowSampleRate), AccessLog: site.Events.AccessLog, Stream: site.Events.Stream},
		OriginHeaders:        &morphgatev1.OriginHeaderConfig{Scores: site.OriginHeaders.Scores, Reasons: site.OriginHeaders.Reasons, Session: site.OriginHeaders.Session},
		Lists:                map[string]*morphgatev1.NamedList{},
	}
	if site.NotBefore != nil {
		sb.NotBeforeMs = site.NotBefore.UnixMilli()
	}
	if cf := site.Cloudflare; cf != nil && site.Profile == "cloudflare" {
		sb.Cloudflare = &morphgatev1.CloudflareSiteConfig{Zone: cf.Zone, LocationHeaders: cf.LocationHeaders, Tier1: cf.Tier1,
			OwnerZones: cf.OwnerZones, PseudoIpv4Overwrite: cf.PseudoIPv4Overwrite}
	}
	for name, entries := range b.lists {
		sb.Lists[name] = &morphgatev1.NamedList{Entries: entries}
	}
	for _, env := range site.Environments {
		sb.Environments = append(sb.Environments, b.environment(env))
	}
	artifacts := map[string]string{}
	sb.Artifacts = b.artifacts(artifacts)
	sb.SourceDigest = b.sourceDigest()

	if len(b.problems) > 0 {
		return nil, &BuildError{Problems: b.problems}
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(sb)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBundleSize {
		return nil, &BuildError{Problems: []string{fmt.Sprintf("the bundle is %d bytes, at most %d", len(data), MaxBundleSize)}}
	}
	return &BuildResult{Bundle: sb, Bytes: data, Artifacts: artifacts, Warnings: b.warnings}, nil
}

// readLists merges lists and list_files (sitecfg rejects duplicate names).
func (b *builder) readLists() {
	b.lists = map[string][]string{}
	for _, l := range b.site.Lists {
		b.lists[l.Name] = l.Entries
	}
	for _, lf := range b.site.ListFiles {
		data, err := keys.ReadFileLimit(lf.Path, maxListFile)
		if err != nil {
			b.problem("list_files.%s: %v", lf.Name, err)
			continue
		}
		b.listSources = append(b.listSources, data)
		entries := []string{}
		err = textLines(data, func(_ int, e string) error {
			if len(e) > sitecfg.MaxListEntryLen {
				return fmt.Errorf("entry is %d bytes, at most %d", len(e), sitecfg.MaxListEntryLen)
			}
			entries = append(entries, e)
			return nil
		})
		switch {
		case err != nil:
			b.problem("list_files.%s: %s: %v", lf.Name, lf.Path, err)
		case len(entries) > sitecfg.MaxListEntries:
			b.problem("list_files.%s: %d entries, at most %d", lf.Name, len(entries), sitecfg.MaxListEntries)
		default:
			b.lists[lf.Name] = entries
		}
	}
}

func upstream(profile string) *morphgatev1.UpstreamProfile {
	bits := func(fs ...morphgatev1.SignalFamily) uint32 {
		var m uint32
		for _, f := range fs {
			m |= 1 << uint32(f)
		}
		return m
	}
	if profile == "direct_tls" {
		return &morphgatev1.UpstreamProfile{Kind: morphgatev1.UpstreamProfileKind_UPSTREAM_PROFILE_KIND_DIRECT_TLS,
			ExpectedMask: bits(morphgatev1.SignalFamily_SIGNAL_FAMILY_NETWORK, morphgatev1.SignalFamily_SIGNAL_FAMILY_TLS,
				morphgatev1.SignalFamily_SIGNAL_FAMILY_HTTP, morphgatev1.SignalFamily_SIGNAL_FAMILY_IDENTITY, morphgatev1.SignalFamily_SIGNAL_FAMILY_RATE)}
	}
	return &morphgatev1.UpstreamProfile{Kind: morphgatev1.UpstreamProfileKind_UPSTREAM_PROFILE_KIND_CLOUDFLARE,
		ExpectedMask: bits(morphgatev1.SignalFamily_SIGNAL_FAMILY_NETWORK, morphgatev1.SignalFamily_SIGNAL_FAMILY_HTTP,
			morphgatev1.SignalFamily_SIGNAL_FAMILY_EDGE_TLS, morphgatev1.SignalFamily_SIGNAL_FAMILY_IDENTITY,
			morphgatev1.SignalFamily_SIGNAL_FAMILY_RATE, morphgatev1.SignalFamily_SIGNAL_FAMILY_EXTERNAL)}
}

func challengeConfig(c sitecfg.Challenge) *morphgatev1.ChallengeConfig {
	return &morphgatev1.ChallengeConfig{
		TtlS:           c.TTLS,
		PowBits:        &morphgatev1.ChallengeConfig_PowBits{Low: c.PowBits.Low, Medium: c.PowBits.Medium, High: c.PowBits.High, VeryHigh: c.PowBits.VeryHigh},
		FallbackRet:    c.FallbackRet,
		MaxFailures:    c.MaxFailures,
		FailureWindowS: c.FailureWindowS,
		SubmitRate:     c.Submit.Rate,
		SubmitPeriodS:  c.Submit.PeriodS,
		SubmitBurst:    c.Submit.Burst,
		IssuePerIpp:    c.Issue.PerIPP,
		IssuePerAsn:    c.Issue.PerASN,
		IssuePeriodS:   c.Issue.PeriodS,
	}
}

func clearanceConfig(c sitecfg.Clearance) *morphgatev1.ClearanceConfig {
	return &morphgatev1.ClearanceConfig{TtlInvisibleS: c.TTLInvisibleS, TtlPowS: c.TTLPowS, SessionMaxS: c.SessionMaxS, CtpShadow: c.CTPShadow}
}

func scoringConfig(s sitecfg.Scoring) *morphgatev1.ScoringConfig {
	f32 := func(m map[string]float64) map[string]float32 {
		out := make(map[string]float32, len(m))
		for k, v := range m {
			out[k] = float32(v)
		}
		return out
	}
	return &morphgatev1.ScoringConfig{ThetaC: float32(s.ThetaC), Kappa: float32(s.Kappa), Z0: f32(s.Z0),
		FamilyModes: s.FamilyModes, Weights: f32(s.Weights), HMin: float32(s.HMin), RulesetVersion: s.RulesetVersion}
}

func (b *builder) environment(env sitecfg.Environment) *morphgatev1.Environment {
	out := &morphgatev1.Environment{Name: env.Name, Hosts: env.Hosts, AutomationAllowlistOnly: env.AutomationAllowlistOnly}
	for _, r := range env.Routes {
		paths := r.Paths
		if b.site.CaseInsensitivePaths {
			paths = make([]string, len(r.Paths))
			for i, p := range r.Paths {
				paths[i] = strings.ToLower(p)
			}
		}
		out.Routes = append(out.Routes, &morphgatev1.Route{
			Id: r.Name, Name: r.Name, Hosts: r.Hosts, Paths: paths, Methods: r.Methods,
			Channel:          morphgatev1.Channel(morphgatev1.Channel_value["CHANNEL_"+strings.ToUpper(r.Channel)]),
			Sensitivity:      morphgatev1.RouteSensitivity(morphgatev1.RouteSensitivity_value["ROUTE_SENSITIVITY_"+strings.ToUpper(r.Sensitivity)]),
			FailClosed:       r.FailClosed,
			RequireClearance: r.RequireClearance,
			RedactPath:       r.RedactPath,
		})
	}
	for _, l := range env.RateLimits {
		rl := &morphgatev1.RateLimit{
			Id: l.ID, Key: l.Key, Algorithm: "gcra", Rate: l.Rate.Rate, PeriodS: l.Rate.PeriodS, Burst: l.Rate.Burst,
			OnExceed: l.OnExceed.Action, Mode: l.Mode, RouteIds: l.Routes, Scope: l.Scope,
		}
		switch l.OnExceed.Action {
		case "rate_limit":
			rl.RetryAfterS = l.OnExceed.RetryAfterS
		case "challenge":
			rl.ChallengeType = policy.ChallengeTypeEnum(l.OnExceed.Type)
		case "signal":
			rl.SignalWeight = float32(l.OnExceed.Weight)
		}
		out.RateLimits = append(out.RateLimits, rl)
	}
	out.Rules = b.rules(env)
	return out
}

// artifacts reads, validates and hashes every configured artifact.
func (b *builder) artifacts(paths map[string]string) []*morphgatev1.ArtifactRef {
	var refs []*morphgatev1.ArtifactRef
	for _, a := range b.site.Artifacts {
		data, err := keys.ReadFileLimit(a.Path, ArtifactMaxSize[a.Name])
		if err != nil {
			b.problem("artifacts.%s: %v", a.Key, err)
			continue
		}
		version, err := ValidateArtifact(a.Name, data)
		if err != nil {
			b.problem("artifacts.%s: %s: %v", a.Key, a.Path, err)
			continue
		}
		sum := sha256.Sum256(data)
		hexSum := hex.EncodeToString(sum[:])
		paths[hexSum] = a.Path
		refs = append(refs, &morphgatev1.ArtifactRef{Name: a.Name, Uri: "artifacts/" + hexSum, Sha256: hexSum,
			Version: version, Size: uint64(len(data))})
	}
	return refs
}

// sourceDigest is sha256 over the site YAML, every policy file and every
// list file, in order of appearance (spec §8.3).
func (b *builder) sourceDigest() string {
	h := sha256.New()
	h.Write(b.site.Raw)
	for _, s := range slices.Concat(b.policySources, b.listSources) {
		h.Write(s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// phaseIndex orders rule phases (spec §5.4).
func phaseIndex(p string) int {
	if i := slices.Index(policy.Phases, p); i >= 0 {
		return i
	}
	return len(policy.Phases)
}

// sortRules applies the engine order: phase, priority descending, id bytewise.
func sortRules(rules []*morphgatev1.CompiledRule) {
	slices.SortStableFunc(rules, func(a, b *morphgatev1.CompiledRule) int {
		return cmp.Or(
			cmp.Compare(phaseIndex(a.Phase), phaseIndex(b.Phase)),
			cmp.Compare(b.Priority, a.Priority),
			strings.Compare(a.Id, b.Id),
		)
	})
}

// readSource keeps a policy file's bytes for source_digest.
func (b *builder) readSource(path string) {
	if data, err := os.ReadFile(path); err == nil {
		b.policySources = append(b.policySources, data)
	}
}
