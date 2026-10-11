package bundle

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/policy"
	"morphgate/control-plane/internal/sitecfg"
)

// SchemaVersion2 marks a SiteBundle that uses Phase 2 fields or values
// (docs/impl/phase2-spec.md §3.2, D-66). A Phase 1 Edge rejects it and keeps
// its previous bundle instead of silently ignoring the new fields.
const SchemaVersion2 = 2

// phase2Configs writes the Phase 2 fields of a schema_version 2 bundle with
// every default explicit (§3.2: the Edge validates them and back-fills
// nothing).
func phase2Configs(sb *morphgatev1.SiteBundle, site *sitecfg.Site) {
	c, ix := site.Challenge, site.Challenge.Interactive
	sb.Challenge.DefaultLang = c.DefaultLang
	sb.Challenge.HelpPath = c.HelpPath
	sb.Challenge.PrivacyPath = c.PrivacyPath
	sb.Challenge.Interactive = &morphgatev1.InteractiveConfig{
		Enabled:          ix.Enabled,
		PowBits:          &morphgatev1.ChallengeConfig_PowBits{Low: ix.PowBits.Low, Medium: ix.PowBits.Medium, High: ix.PowBits.High, VeryHigh: ix.PowBits.VeryHigh},
		PowK:             ix.PowK,
		A11YBits:         ix.A11yBits,
		EscalateAfter:    ix.EscalateAfter,
		ScoringMode:      ix.ScoringMode,
		TPass:            float32(ix.TPass),
		TBlock:           float32(ix.TBlock),
		MinPowMs:         ix.MinPowMS,
		IssueRate:        ix.Issue.Rate,
		IssuePeriodS:     ix.Issue.PeriodS,
		IssueBurst:       ix.Issue.Burst,
		A11YIssuePerIp:   ix.A11yIssue.PerIP,
		A11YIssuePeriodS: ix.A11yIssue.PeriodS,
		A11YMinMs:        ix.A11yMinMS,
		RenewRate:        ix.Renew.Rate,
		RenewPeriodS:     ix.Renew.PeriodS,
		RenewBurst:       ix.Renew.Burst,
		A11YIssuePerIpp:  ix.A11yIssue.PerIPP,
	}
	cl := site.Clearance
	sb.Clearance.TtlInteractiveS = cl.TTLInteractiveS
	sb.Clearance.TtlInteractiveA11YS = cl.TTLInteractiveA11yS
	sb.Clearance.TtlInteractiveExtS = cl.TTLInteractiveExtS
	sb.Clearance.Refresh = cl.Refresh
	sb.Clearance.RefreshMaxInteractiveS = cl.RefreshMaxInteractiveS
	sb.Clearance.RefreshMaxExtS = cl.RefreshMaxExtS
	sb.Clearance.RefreshMaxPowS = cl.RefreshMaxPowS
	sb.Events.TelemetryBehavior = site.Events.TelemetryBehavior
	sb.Events.ScannerBaitsBuiltin = site.Events.ScannerBaitsBuiltin
	sb.Events.ScannerBaits = site.Events.ScannerBaitsExtra
	for _, p := range site.Providers {
		sb.Providers = append(sb.Providers, &morphgatev1.ProviderConfig{
			Id: p.ID, Enabled: p.Enabled, Sitekey: p.Sitekey, DeniedCountries: p.DenyCountries,
			RouteIds: p.Routes, TimeoutMs: p.TimeoutMS, Fallback: p.Fallback, Mode: p.Mode,
			Hostnames: p.Hostnames, Selection: p.Selection,
		})
	}
}

// schema decides schema_version (§3.2, §10.2): 2 when the YAML has a Phase 2
// key or value or a rule in the bundle reads a Phase 2 policy field, else 1
// with every Phase 2 field left unset, so a Phase 1 site builds byte for byte
// as before. Then it applies CheckSchema as a backstop.
func (b *builder) schema(sb *morphgatev1.SiteBundle) {
	sb.SchemaVersion = b.site.SchemaVersion()
	if sb.SchemaVersion == SchemaVersion && b.phase2Rule != "" {
		sb.SchemaVersion = SchemaVersion2
		b.warn("%s, a Phase 2 policy field: the bundle is schema_version 2, which a Phase 1 Edge rejects", b.phase2Rule)
	}
	if sb.SchemaVersion == SchemaVersion2 {
		phase2Configs(sb, b.site)
	} else {
		for _, where := range b.proofRules {
			b.warn("%s: identity.proof.* is always MISSING in a schema_version 1 bundle (D-66); add a Phase 2 key such as a route's proof: to enable MG-Proof", where)
		}
	}
	if err := CheckSchema(sb); err != nil {
		var se *SchemaError
		if errors.As(err, &se) {
			for _, p := range se.Problems {
				b.problem("bundle schema: %s", p)
			}
		} else {
			b.problem("bundle schema: %v", err)
		}
	}
}

// proofMode maps a route's proof key to the bundle enum.
func proofMode(p string) morphgatev1.ProofMode {
	if p == "required" {
		return morphgatev1.ProofMode_PROOF_MODE_REQUIRED
	}
	return morphgatev1.ProofMode_PROOF_MODE_OFF
}

// minLevel maps a route's min_level ("" = none) to the bundle enum.
func minLevel(l string) morphgatev1.ChallengeType {
	if l == "" {
		return morphgatev1.ChallengeType_CHALLENGE_TYPE_UNSPECIFIED
	}
	return policy.ChallengeTypeEnum(l)
}

// readsPhase2Field reports the first Phase 2 policy field a rule reads.
func readsPhase2Field(fields []string) string {
	for _, f := range fields {
		for _, p2 := range policy.Phase2Fields {
			if f == p2 || strings.HasPrefix(f, p2+".") || strings.HasPrefix(p2, f+".") {
				return p2
			}
		}
	}
	return ""
}

// readsProof reports whether a rule reads identity.proof.*.
func readsProof(fields []string) bool {
	return slices.ContainsFunc(fields, func(f string) bool {
		return f == policy.ProofField || strings.HasPrefix(f, policy.ProofField+".")
	})
}

// SchemaError lists every way a SiteBundle breaks the schema_version rules
// of §3.2 (D-66) or the Phase 2 ranges of §10.2 and §8.2.
type SchemaError struct{ Problems []string }

func (e *SchemaError) Error() string { return strings.Join(e.Problems, "; ") }

// CheckSchema applies the schema_version rules that the builder and the Edge
// share (§3.2): schema_version must be 1 or 2; under 1 every Phase 2 field is
// zero or empty and no limiter issues interactive challenges; under 2 the
// challenge, challenge.interactive, clearance and events messages are present
// and every Phase 2 field is within the §10.2 range, whether or not its
// feature is enabled, and providers follow §8.2. It is the builder's
// backstop and runs on every bundle mgctl signs, verifies or publishes.
func CheckSchema(sb *morphgatev1.SiteBundle) error {
	var c schemaCheck
	switch sb.GetSchemaVersion() {
	case SchemaVersion:
		c.phase1(sb)
	case SchemaVersion2:
		c.phase2(sb)
	default:
		c.fail("schema_version %d is neither 1 nor 2", sb.GetSchemaVersion())
	}
	if len(c.problems) > 0 {
		return &SchemaError{Problems: c.problems}
	}
	return nil
}

type schemaCheck struct{ problems []string }

func (c *schemaCheck) fail(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
}

func (c *schemaCheck) phase1(sb *morphgatev1.SiteBundle) {
	const why = "must be unset when schema_version is 1 (D-66)"
	ch := sb.GetChallenge()
	if ch.GetInteractive() != nil || ch.GetDefaultLang() != "" || ch.GetHelpPath() != "" || ch.GetPrivacyPath() != "" {
		c.fail("challenge.interactive, default_lang, help_path and privacy_path %s", why)
	}
	cl := sb.GetClearance()
	if cl.GetTtlInteractiveS() != 0 || cl.GetTtlInteractiveA11YS() != 0 || cl.GetTtlInteractiveExtS() != 0 || cl.GetRefresh() ||
		cl.GetRefreshMaxInteractiveS() != 0 || cl.GetRefreshMaxExtS() != 0 || cl.GetRefreshMaxPowS() != 0 {
		c.fail("the Phase 2 clearance fields (5-11) %s", why)
	}
	ev := sb.GetEvents()
	if ev.GetTelemetryBehavior() || ev.GetScannerBaitsBuiltin() || len(ev.GetScannerBaits()) > 0 {
		c.fail("events.telemetry_behavior, scanner_baits_builtin and scanner_baits %s", why)
	}
	if len(sb.GetProviders()) > 0 {
		c.fail("providers %s", why)
	}
	for _, env := range sb.GetEnvironments() {
		for _, r := range env.GetRoutes() {
			if r.GetProof() != morphgatev1.ProofMode_PROOF_MODE_OFF || r.GetMinLevel() != morphgatev1.ChallengeType_CHALLENGE_TYPE_UNSPECIFIED {
				c.fail("environment %s route %s: proof and min_level %s", env.GetName(), r.GetId(), why)
			}
		}
		for _, l := range env.GetRateLimits() {
			if l.GetChallengeType() == morphgatev1.ChallengeType_CHALLENGE_TYPE_INTERACTIVE {
				c.fail("environment %s limiter %s: challenge_type INTERACTIVE needs schema_version 2", env.GetName(), l.GetId())
			}
		}
	}
}

func (c *schemaCheck) rangeU(name string, v uint32, lo, hi uint32) {
	if v < lo || v > hi {
		c.fail("%s %d outside %d..%d", name, v, lo, hi)
	}
}

func (c *schemaCheck) gcra(name string, rate, period, burst uint32) {
	r := sitecfg.Rate{Rate: rate, PeriodS: period, Burst: burst}
	if !sitecfg.GCRAValid(r) {
		c.fail("%s: %d per %d s with burst %d is not a valid GCRA limiter", name, rate, period, burst)
	}
}

func (c *schemaCheck) phase2(sb *morphgatev1.SiteBundle) {
	ch, cl, ev := sb.GetChallenge(), sb.GetClearance(), sb.GetEvents()
	ix := ch.GetInteractive()
	if ch == nil || ix == nil || cl == nil || ev == nil {
		c.fail("schema_version 2 needs the challenge, challenge.interactive, clearance and events messages")
		return
	}
	if !slices.Contains(sitecfg.Languages, ch.GetDefaultLang()) {
		c.fail("challenge.default_lang %q is not one of %s", ch.GetDefaultLang(), strings.Join(sitecfg.Languages, ", "))
	}
	for name, p := range map[string]string{"challenge.help_path": ch.GetHelpPath(), "challenge.privacy_path": ch.GetPrivacyPath()} {
		if err := sitecfg.ValidateRet(p); err != nil {
			c.fail("%s %q %v", name, p, err)
		}
	}
	b := ix.GetPowBits()
	if b == nil {
		c.fail("challenge.interactive.pow_bits missing")
	} else {
		for name, v := range map[string]uint32{"low": b.GetLow(), "medium": b.GetMedium(), "high": b.GetHigh(), "very_high": b.GetVeryHigh()} {
			c.rangeU("challenge.interactive.pow_bits."+name, v, 8, 22)
		}
		if !(b.GetLow() <= b.GetMedium() && b.GetMedium() <= b.GetHigh() && b.GetHigh() <= b.GetVeryHigh()) {
			c.fail("challenge.interactive.pow_bits decrease with the risk band")
		}
	}
	c.rangeU("challenge.interactive.pow_k", ix.GetPowK(), 1, 8)
	c.rangeU("challenge.interactive.a11y_bits", ix.GetA11YBits(), 12, 24)
	c.rangeU("challenge.interactive.escalate_after", ix.GetEscalateAfter(), 1, 5)
	switch ix.GetScoringMode() {
	case "shadow":
		if ix.GetTPass() != 0 || ix.GetTBlock() != 0 {
			c.fail("challenge.interactive: t_pass and t_block are enforce only")
		}
	case "enforce":
		if !(ix.GetTPass() > 0 && ix.GetTPass() < ix.GetTBlock() && ix.GetTBlock() <= 1) {
			c.fail("challenge.interactive: enforce needs 0 < t_pass < t_block <= 1, got %g and %g", ix.GetTPass(), ix.GetTBlock())
		}
	default:
		c.fail("challenge.interactive.scoring_mode %q is not one of shadow, enforce", ix.GetScoringMode())
	}
	c.rangeU("challenge.interactive.min_pow_ms", ix.GetMinPowMs(), 0, 5000)
	c.rangeU("challenge.interactive.a11y_min_ms", ix.GetA11YMinMs(), 0, 10000)
	for _, l := range []struct {
		name                string
		rate, period, burst uint32
	}{
		{"challenge.interactive issue", ix.GetIssueRate(), ix.GetIssuePeriodS(), ix.GetIssueBurst()},
		{"challenge.interactive renew", ix.GetRenewRate(), ix.GetRenewPeriodS(), ix.GetRenewBurst()},
	} {
		c.rangeU(l.name+" period_s", l.period, 1, 86400)
		c.rangeU(l.name+" burst", l.burst, 1, 100_000)
		c.gcra(l.name, l.rate, l.period, l.burst)
		if uint64(l.rate)*4 > 1<<32-1 {
			c.fail("%s: the 4x ipp rate overflows", l.name)
		} else {
			c.gcra(l.name+" (ipp, 4x)", 4*l.rate, l.period, 4*l.burst)
		}
	}
	c.rangeU("challenge.interactive.a11y_issue_per_ip", ix.GetA11YIssuePerIp(), 1, 100_000)
	c.rangeU("challenge.interactive.a11y_issue_per_ipp", ix.GetA11YIssuePerIpp(), 1, 100_000)
	c.rangeU("challenge.interactive.a11y_issue_period_s", ix.GetA11YIssuePeriodS(), 1, 86400)
	if ix.GetA11YIssuePerIpp() < ix.GetA11YIssuePerIp() {
		c.fail("challenge.interactive: a11y_issue_per_ipp %d below a11y_issue_per_ip %d", ix.GetA11YIssuePerIpp(), ix.GetA11YIssuePerIp())
	}
	c.gcra("challenge.interactive a11y_issue (per_ip)", ix.GetA11YIssuePerIp(), ix.GetA11YIssuePeriodS(), ix.GetA11YIssuePerIp())
	c.gcra("challenge.interactive a11y_issue (per_ipp)", ix.GetA11YIssuePerIpp(), ix.GetA11YIssuePeriodS(), ix.GetA11YIssuePerIpp())

	c.rangeU("clearance.ttl_interactive_s", cl.GetTtlInteractiveS(), 300, 7200)
	c.rangeU("clearance.ttl_interactive_a11y_s", cl.GetTtlInteractiveA11YS(), 300, 3600)
	c.rangeU("clearance.ttl_interactive_ext_s", cl.GetTtlInteractiveExtS(), 300, 7200)
	c.rangeU("clearance.refresh_max_interactive_s", cl.GetRefreshMaxInteractiveS(), 900, 86400)
	c.rangeU("clearance.refresh_max_ext_s", cl.GetRefreshMaxExtS(), 900, 86400)
	c.rangeU("clearance.refresh_max_pow_s", cl.GetRefreshMaxPowS(), 0, 86400)

	if n := len(ev.GetScannerBaits()); n > sitecfg.MaxScannerBaits {
		c.fail("events.scanner_baits: %d patterns, at most %d", n, sitecfg.MaxScannerBaits)
	}
	for _, g := range ev.GetScannerBaits() {
		if err := checkPattern(g); err != nil {
			c.fail("events.scanner_baits %q: %v", g, err)
		}
	}

	routeIDs := map[string]bool{}
	for _, env := range sb.GetEnvironments() {
		for _, r := range env.GetRoutes() {
			routeIDs[r.GetId()] = true
			where := fmt.Sprintf("environment %s route %s", env.GetName(), r.GetId())
			switch r.GetProof() {
			case morphgatev1.ProofMode_PROOF_MODE_OFF, morphgatev1.ProofMode_PROOF_MODE_REQUIRED:
			default:
				c.fail("%s: unknown proof mode %d", where, r.GetProof())
			}
			switch r.GetMinLevel() {
			case morphgatev1.ChallengeType_CHALLENGE_TYPE_UNSPECIFIED, morphgatev1.ChallengeType_CHALLENGE_TYPE_INVISIBLE,
				morphgatev1.ChallengeType_CHALLENGE_TYPE_POW, morphgatev1.ChallengeType_CHALLENGE_TYPE_INTERACTIVE:
			default:
				c.fail("%s: min_level %s is not invisible, pow or interactive", where, r.GetMinLevel())
			}
			if r.GetNeverChallenge() && (r.GetProof() != morphgatev1.ProofMode_PROOF_MODE_OFF ||
				r.GetMinLevel() != morphgatev1.ChallengeType_CHALLENGE_TYPE_UNSPECIFIED) {
				c.fail("%s: proof and min_level contradict never_challenge", where)
			}
		}
	}
	c.providers(sb, routeIDs)
}

// providers applies §8.2 to SiteBundle.providers.
func (c *schemaCheck) providers(sb *morphgatev1.SiteBundle, routeIDs map[string]bool) {
	ps := sb.GetProviders()
	if len(ps) > sitecfg.MaxProviders {
		c.fail("providers: %d entries, at most %d", len(ps), sitecfg.MaxProviders)
	}
	for _, p := range ps {
		where := "provider " + p.GetId()
		if !slices.Contains(sitecfg.ProviderIDs, p.GetId()) {
			c.fail("provider id %q is not turnstile", p.GetId())
		}
		if !sitecfg.SitekeyPattern.MatchString(p.GetSitekey()) {
			c.fail("%s: sitekey %q does not match %s", where, p.GetSitekey(), sitecfg.SitekeyPattern)
		}
		if len(p.GetHostnames()) == 0 {
			c.fail("%s: hostnames empty", where)
		}
		for _, h := range p.GetHostnames() {
			if !slices.Contains(sb.GetHosts(), h) {
				c.fail("%s: hostname %q is not a site host", where, h)
			}
		}
		for _, id := range p.GetRouteIds() {
			if !routeIDs[id] {
				c.fail("%s: route %q does not exist", where, id)
			}
		}
		c.rangeU(where+" timeout_ms", p.GetTimeoutMs(), 1000, 5000)
		if p.GetFallback() != sitecfg.ProviderFallback {
			c.fail("%s: fallback %q is not self_hold (D-51)", where, p.GetFallback())
		}
		if !slices.Contains(sitecfg.ProviderModes, p.GetMode()) {
			c.fail("%s: mode %q is not shadow or enforce", where, p.GetMode())
		}
		if !slices.Contains(sitecfg.ProviderSelects, p.GetSelection()) {
			c.fail("%s: selection %q is not first or escalate_after_fail", where, p.GetSelection())
		}
		for _, cc := range p.GetDeniedCountries() {
			if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
				c.fail("%s: denied country %q is not an upper-case two-letter code", where, cc)
			}
		}
		if len(p.GetSecretRefs()) > 0 || len(p.GetAllowedCountries()) > 0 {
			c.fail("%s: secret_refs and allowed_countries must be empty (D-51)", where)
		}
	}
}

// checkPattern applies the route path pattern limits (spec §8.2 of Phase 1).
func checkPattern(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return errors.New("must start with /")
	case len(p) > sitecfg.MaxPatternLen:
		return fmt.Errorf("longer than %d bytes", sitecfg.MaxPatternLen)
	case strings.ContainsFunc(p, func(r rune) bool { return r <= 0x20 || r >= 0x7f }):
		return errors.New("must contain visible ASCII characters only")
	case sitecfg.WildcardCount(p) > sitecfg.MaxWildcards:
		return fmt.Errorf("more than %d wildcards", sitecfg.MaxWildcards)
	}
	return nil
}

// Phase2Summary is the Phase 2 part of a Summary (`mgctl bundle verify`,
// spec §16). It never holds secrets: the bundle has none (D-51).
type Phase2Summary struct {
	Interactive       InteractiveSummary `json:"interactive"`
	Providers         []ProviderSummary  `json:"providers"`
	ProofRequired     []string           `json:"proof_required"` // "<env>/<route>"
	MinLevels         map[string]string  `json:"min_levels"`     // "<env>/<route>" -> invisible | pow | interactive
	HelpPath          string             `json:"help_path"`
	PrivacyPath       string             `json:"privacy_path"`
	DefaultLang       string             `json:"default_lang"`
	Refresh           bool               `json:"refresh"`
	TelemetryBehavior bool               `json:"telemetry_behavior"`
}

// InteractiveSummary is challenge.interactive.
type InteractiveSummary struct {
	Enabled       bool      `json:"enabled"`
	PowBits       [4]uint32 `json:"pow_bits"` // low, medium, high, very_high
	PowK          uint32    `json:"pow_k"`
	A11yBits      uint32    `json:"a11y_bits"`
	EscalateAfter uint32    `json:"escalate_after"`
	ScoringMode   string    `json:"scoring_mode"`
	TPass         float32   `json:"t_pass,omitempty"`
	TBlock        float32   `json:"t_block,omitempty"`
	MinPowMS      uint32    `json:"min_pow_ms"`
	A11yMinMS     uint32    `json:"a11y_min_ms"`
}

// ProviderSummary is one external provider: public configuration only.
type ProviderSummary struct {
	ID              string   `json:"id"`
	Enabled         bool     `json:"enabled"`
	Sitekey         string   `json:"sitekey"`
	Hostnames       []string `json:"hostnames"`
	Routes          []string `json:"routes"` // empty: every route
	Selection       string   `json:"selection"`
	Mode            string   `json:"mode"`
	TimeoutMS       uint32   `json:"timeout_ms"`
	Fallback        string   `json:"fallback"`
	DeniedCountries []string `json:"denied_countries"`
}

// ScoringEnforceReminder is printed for scoring mode enforce (spec §7.8).
const ScoringEnforceReminder = "interactive scoring is enforce: t_pass must be above the highest ix.score of the samples completed with assistive technology (spec §7.8, §19 step 5)"

func summarizePhase2(sb *morphgatev1.SiteBundle) *Phase2Summary {
	ch, ix := sb.GetChallenge(), sb.GetChallenge().GetInteractive()
	b := ix.GetPowBits()
	s := &Phase2Summary{
		Interactive: InteractiveSummary{
			Enabled: ix.GetEnabled(), PowBits: [4]uint32{b.GetLow(), b.GetMedium(), b.GetHigh(), b.GetVeryHigh()},
			PowK: ix.GetPowK(), A11yBits: ix.GetA11YBits(), EscalateAfter: ix.GetEscalateAfter(),
			ScoringMode: ix.GetScoringMode(), TPass: ix.GetTPass(), TBlock: ix.GetTBlock(),
			MinPowMS: ix.GetMinPowMs(), A11yMinMS: ix.GetA11YMinMs(),
		},
		Providers: []ProviderSummary{}, ProofRequired: []string{}, MinLevels: map[string]string{},
		HelpPath: ch.GetHelpPath(), PrivacyPath: ch.GetPrivacyPath(), DefaultLang: ch.GetDefaultLang(),
		Refresh: sb.GetClearance().GetRefresh(), TelemetryBehavior: sb.GetEvents().GetTelemetryBehavior(),
	}
	for _, p := range sb.GetProviders() {
		s.Providers = append(s.Providers, ProviderSummary{
			ID: p.GetId(), Enabled: p.GetEnabled(), Sitekey: p.GetSitekey(), Hostnames: nonNil(p.GetHostnames()),
			Routes: nonNil(p.GetRouteIds()), Selection: p.GetSelection(), Mode: p.GetMode(), TimeoutMS: p.GetTimeoutMs(),
			Fallback: p.GetFallback(), DeniedCountries: nonNil(p.GetDeniedCountries()),
		})
	}
	for _, env := range sb.GetEnvironments() {
		for _, r := range env.GetRoutes() {
			key := env.GetName() + "/" + r.GetId()
			if r.GetProof() == morphgatev1.ProofMode_PROOF_MODE_REQUIRED {
				s.ProofRequired = append(s.ProofRequired, key)
			}
			if l := r.GetMinLevel(); l != morphgatev1.ChallengeType_CHALLENGE_TYPE_UNSPECIFIED {
				s.MinLevels[key] = strings.ToLower(strings.TrimPrefix(l.String(), "CHALLENGE_TYPE_"))
			}
		}
	}
	return s
}
