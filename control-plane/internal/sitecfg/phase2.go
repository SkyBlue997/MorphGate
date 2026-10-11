package sitecfg

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Phase 2 site YAML (docs/impl/phase2-spec.md §10.2, §3.2, §8.2).
//
// Every Phase 2 key that appears in the YAML is recorded in Site.Phase2Keys;
// a site with any of them (or a limiter with on_exceed type interactive) is
// built with schema_version 2, every other site with schema_version 1 and
// byte for byte the Phase 1 output (D-66).

// Enumerations of the Phase 2 keys.
var (
	ProofModes       = []string{"off", "required"}
	MinLevels        = []string{"invisible", "pow", "interactive"}
	Languages        = []string{"zh-CN", "en"}
	ScoringModes     = []string{"shadow", "enforce"}
	ProviderIDs      = []string{"turnstile"}
	ProviderModes    = []string{"shadow", "enforce"}
	ProviderSelects  = []string{"first", "escalate_after_fail"}
	ProviderFallback = "self_hold" // the only fallback in Phase 2 (D-51)
	// safeMethods never change state; the D-40 proof exemption covers GET
	// and HEAD navigations only, OPTIONS and TRACE carry no form data.
	safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
)

// Limits of the Phase 2 keys.
const (
	MaxProviders    = 1  // Phase 2: Turnstile only (§8.2)
	MaxScannerBaits = 64 // events.scanner_baits.extra
	MaxRefreshS     = 86400
)

var (
	// SitekeyPattern is a Turnstile widget sitekey (§8.2).
	SitekeyPattern = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)
	countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)
)

// Interactive is challenge.interactive (§10.2).
type Interactive struct {
	Enabled       bool
	PowBits       PowBits // self_hold, per sub-puzzle
	PowK          uint32
	A11yBits      uint32
	EscalateAfter uint32
	ScoringMode   string  // shadow | enforce
	TPass, TBlock float64 // enforce only
	MinPowMS      uint32
	A11yMinMS     uint32
	Issue         Rate // mg.ix.issue per ip entity; ipp 4x
	Renew         Rate // mg.c.renew per ip entity; ipp 4x
	A11yIssue     A11yIssue
}

// A11yIssue is the mg.a11y.issue quota (§7.9).
type A11yIssue struct{ PerIP, PerIPP, PeriodS uint32 }

// Provider is one providers: entry (§8.2; Turnstile only in Phase 2).
type Provider struct {
	ID            string
	Enabled       bool
	Sitekey       string
	Hostnames     []string
	Routes        []string // route names; empty = every route
	Selection     string   // first | escalate_after_fail
	Mode          string   // shadow | enforce
	TimeoutMS     uint32
	Fallback      string   // self_hold
	DenyCountries []string // bundle: denied_countries
}

func defaultInteractive() Interactive {
	return Interactive{
		PowBits: PowBits{14, 16, 18, 19}, PowK: 8, A11yBits: 17, EscalateAfter: 2,
		ScoringMode: "shadow", A11yMinMS: 2000,
		Issue:     Rate{Rate: 30, PeriodS: 600, Burst: 20},
		Renew:     Rate{Rate: 30, PeriodS: 600, Burst: 10},
		A11yIssue: A11yIssue{PerIP: 6, PerIPP: 120, PeriodS: 3600},
	}
}

// SchemaVersion is the SiteBundle schema_version the site builds to (§3.2,
// D-66): 2 when any Phase 2 key or value appears in the YAML, else 1. The
// bundle builder also writes 2 when a rule reads a Phase 2 policy field.
func (s *Site) SchemaVersion() uint32 {
	if len(s.Phase2Keys) > 0 {
		return 2
	}
	return 1
}

// phase2 reads an optional Phase 2 key like get and records its presence.
func (p *parser) phase2(o *object, key string) *yaml.Node {
	v := o.get(key)
	if v != nil {
		p.phase2Keys = append(p.phase2Keys, o.sub(key))
	}
	return v
}

// defaultRefreshMaxPowS is the refresh_max_pow_s default: 2 x ttl_pow_s,
// capped to the 86400 s range limit.
func defaultRefreshMaxPowS(ttlPowS uint32) uint32 {
	return uint32(min(2*uint64(ttlPowS), MaxRefreshS))
}

// parseClearancePhase2 reads the Phase 2 clearance keys (§10.2).
func (p *parser) parseClearancePhase2(o *object, c *Clearance) {
	for _, f := range []struct {
		key    string
		dst    *uint32
		lo, hi uint64
	}{
		{"ttl_interactive_s", &c.TTLInteractiveS, 300, 7200},
		{"ttl_interactive_a11y_s", &c.TTLInteractiveA11yS, 300, 3600},
		{"ttl_interactive_ext_s", &c.TTLInteractiveExtS, 300, 7200},
		{"refresh_max_interactive_s", &c.RefreshMaxInteractiveS, 900, MaxRefreshS},
		{"refresh_max_ext_s", &c.RefreshMaxExtS, 900, MaxRefreshS},
	} {
		if v := p.phase2(o, f.key); v != nil {
			if n, ok := p.uint(v, o.sub(f.key), f.lo, f.hi); ok {
				*f.dst = n
			}
		}
	}
	if v := p.phase2(o, "refresh"); v != nil {
		c.Refresh, _ = p.boolean(v, o.sub("refresh"))
	}
	if v := p.phase2(o, "refresh_max_pow_s"); v != nil {
		c.RefreshMaxPowS, _ = p.uint(v, o.sub("refresh_max_pow_s"), 0, MaxRefreshS)
	} else {
		c.RefreshMaxPowS = defaultRefreshMaxPowS(c.TTLPowS)
	}
}

// parseChallengePhase2 reads the Phase 2 challenge keys (§10.2).
func (p *parser) parseChallengePhase2(o *object, c *Challenge) {
	if v := p.phase2(o, "default_lang"); v != nil {
		if l, ok := p.enum(v, o.sub("default_lang"), Languages); ok {
			c.DefaultLang = l
		}
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"help_path", &c.HelpPath}, {"privacy_path", &c.PrivacyPath}} {
		v := p.phase2(o, f.key)
		if v == nil {
			continue
		}
		if s, ok := p.str(v, o.sub(f.key)); ok {
			if err := ValidateRet(s); err != nil {
				p.errorf(v, "%s: %q %v", o.sub(f.key), s, err)
			} else {
				*f.dst = s
			}
		}
	}
	if v := p.phase2(o, "interactive"); v != nil {
		p.parseInteractive(v, &c.Interactive)
	}
}

func (p *parser) parseInteractive(n *yaml.Node, ix *Interactive) {
	const path = "challenge.interactive"
	o := p.object(n, path)
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("enabled"); v != nil {
		ix.Enabled, _ = p.boolean(v, o.sub("enabled"))
	}
	if v := o.get("pow_bits"); v != nil {
		if po := p.object(v, o.sub("pow_bits")); po != nil {
			for _, f := range []struct {
				key string
				dst *uint32
			}{{"low", &ix.PowBits.Low}, {"medium", &ix.PowBits.Medium}, {"high", &ix.PowBits.High}, {"very_high", &ix.PowBits.VeryHigh}} {
				if fv := po.get(f.key); fv != nil {
					if b, ok := p.uint(fv, po.sub(f.key), 8, 22); ok {
						*f.dst = b
					}
				}
			}
			po.finish()
		}
	}
	b := ix.PowBits
	if !(b.Low <= b.Medium && b.Medium <= b.High && b.High <= b.VeryHigh) {
		p.errorf(n, "%s.pow_bits: must not decrease with the risk band (low %d, medium %d, high %d, very_high %d)", path, b.Low, b.Medium, b.High, b.VeryHigh)
	}
	if v := o.get("pow_k"); v != nil {
		ix.PowK, _ = p.uint(v, o.sub("pow_k"), 1, 8)
	}
	if v := o.get("a11y_bits"); v != nil {
		ix.A11yBits, _ = p.uint(v, o.sub("a11y_bits"), 12, 24)
	}
	if v := o.get("escalate_after"); v != nil {
		ix.EscalateAfter, _ = p.uint(v, o.sub("escalate_after"), 1, 5)
	}
	if v := o.get("scoring"); v != nil {
		p.parseScoringMode(v, o.sub("scoring"), ix)
	}
	if v := o.get("min_pow_ms"); v != nil {
		ix.MinPowMS, _ = p.uint(v, o.sub("min_pow_ms"), 0, 5000)
	}
	if v := o.get("a11y_min_ms"); v != nil {
		ix.A11yMinMS, _ = p.uint(v, o.sub("a11y_min_ms"), 0, 10000)
	}
	if v := o.get("issue"); v != nil {
		p.parseIxRate(v, o.sub("issue"), &ix.Issue)
	}
	if v := o.get("renew"); v != nil {
		p.parseIxRate(v, o.sub("renew"), &ix.Renew)
	}
	if v := o.get("a11y_issue"); v != nil {
		p.parseA11yIssue(v, o.sub("a11y_issue"), &ix.A11yIssue)
	}
}

// parseScoringMode reads {mode: shadow} or {mode: enforce, t_pass, t_block}
// (§7.8, D-49: enforce requires both thresholds).
func (p *parser) parseScoringMode(n *yaml.Node, path string, ix *Interactive) {
	o := p.object(n, path)
	if o == nil {
		return
	}
	defer o.finish()
	v := o.require("mode")
	if v == nil {
		return
	}
	mode, ok := p.enum(v, o.sub("mode"), ScoringModes)
	if !ok {
		return
	}
	ix.ScoringMode = mode
	tp, tb := o.get("t_pass"), o.get("t_block")
	if mode == "shadow" {
		for key, tv := range map[string]*yaml.Node{"t_pass": tp, "t_block": tb} {
			if tv != nil {
				p.errorf(tv, "%s: only with mode: enforce (shadow records the score and never uses thresholds)", o.sub(key))
			}
		}
		return
	}
	if tp == nil || tb == nil {
		p.errorf(n, "%s: mode enforce requires t_pass and t_block (0 < t_pass < t_block <= 1)", path)
		return
	}
	pass, ok1 := p.float(tp, o.sub("t_pass"), 0, 1)
	block, ok2 := p.float(tb, o.sub("t_block"), 0, 1)
	if !ok1 || !ok2 {
		return
	}
	// The bundle carries float32 values; check the order there.
	if !(float32(pass) > 0 && float32(pass) < float32(block) && float32(block) <= 1) {
		p.errorf(n, "%s: need 0 < t_pass < t_block <= 1, got t_pass %g and t_block %g", path, pass, block)
		return
	}
	ix.TPass, ix.TBlock = pass, block
	p.warnf(v, "%s: enforce: t_pass must be above the highest ix.score of the samples you completed with assistive technology (spec §7.8, §19 step 5)", o.sub("mode"))
}

// parseIxRate reads {rate: <n>/<duration>, burst: N}; the ipp tier is 4x
// rate and burst (D-67), so both tiers must be valid GCRA limiters.
func (p *parser) parseIxRate(n *yaml.Node, path string, r *Rate) {
	o := p.object(n, path)
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("rate"); v != nil {
		if spec, ok := p.str(v, o.sub("rate")); ok {
			if rate, period, err := ParseRate(spec); err != nil {
				p.errorf(v, "%s: %v", o.sub("rate"), err)
			} else {
				r.Rate, r.PeriodS = rate, period
			}
		}
	}
	if v := o.get("burst"); v != nil {
		r.Burst, _ = p.uint(v, o.sub("burst"), 1, 100_000)
	}
	p.checkGCRA(n, path, *r)
	p.checkGCRA(n, path+" (ipp, 4x)", scaled(*r, 4))
}

// scaled multiplies rate and burst (saturating; an overflow fails GCRAValid).
func scaled(r Rate, f uint64) Rate {
	mul := func(v uint32) uint32 { return uint32(min(uint64(v)*f, 1<<32-1)) }
	return Rate{Rate: mul(r.Rate), PeriodS: r.PeriodS, Burst: mul(r.Burst)}
}

func (p *parser) parseA11yIssue(n *yaml.Node, path string, a *A11yIssue) {
	o := p.object(n, path)
	if o == nil {
		return
	}
	defer o.finish()
	if v := o.get("per_ip"); v != nil {
		a.PerIP, _ = p.uint(v, o.sub("per_ip"), 1, 100_000)
	}
	if v := o.get("per_ipp"); v != nil {
		a.PerIPP, _ = p.uint(v, o.sub("per_ipp"), 1, 100_000)
	}
	if v := o.get("period_s"); v != nil {
		a.PeriodS, _ = p.uint(v, o.sub("period_s"), 1, 86400)
	}
	if a.PerIPP < a.PerIP {
		p.errorf(n, "%s: per_ipp %d must be at least per_ip %d", path, a.PerIPP, a.PerIP)
	}
	p.checkGCRA(n, path+" (per_ip)", Rate{a.PerIP, a.PeriodS, a.PerIP})
	p.checkGCRA(n, path+" (per_ipp)", Rate{a.PerIPP, a.PeriodS, a.PerIPP})
}

// parseEventsPhase2 reads events.telemetry_behavior and events.scanner_baits.
func (p *parser) parseEventsPhase2(o *object, e *Events) {
	if v := p.phase2(o, "telemetry_behavior"); v != nil {
		if b, ok := p.boolean(v, o.sub("telemetry_behavior")); ok {
			e.TelemetryBehavior = b
			if b {
				p.warnf(v, "%s: update the site's privacy notice before collecting behavior summaries (D-48, docs/07)", o.sub("telemetry_behavior"))
			}
		}
	}
	v := p.phase2(o, "scanner_baits")
	if v == nil {
		return
	}
	so := p.object(v, o.sub("scanner_baits"))
	if so == nil {
		return
	}
	defer so.finish()
	if bv := so.get("builtin"); bv != nil {
		e.ScannerBaitsBuiltin, _ = p.boolean(bv, so.sub("builtin"))
	}
	if xv := so.get("extra"); xv != nil {
		extra, ok := p.strList(xv, so.sub("extra"), p.checkRoutePattern)
		if ok {
			p.uniqueStrings(xv, so.sub("extra"), extra)
		}
		if xv.Kind == yaml.SequenceNode && len(xv.Content) > MaxScannerBaits {
			p.errorf(xv, "%s: %d patterns, at most %d", so.sub("extra"), len(xv.Content), MaxScannerBaits)
		}
		e.ScannerBaitsExtra = extra
	}
}

// parseRoutePhase2 reads proof and min_level of a route and applies the
// route-level rules of §10.2.
func (p *parser) parseRoutePhase2(o *object, r *Route, s *Site) {
	proofNode := p.phase2(o, "proof")
	if proofNode != nil {
		r.Proof, _ = p.enum(proofNode, o.sub("proof"), ProofModes)
	}
	levelNode := p.phase2(o, "min_level")
	if levelNode != nil {
		r.MinLevel, _ = p.enum(levelNode, o.sub("min_level"), MinLevels)
	}
	if r.NeverChallenge {
		// sendBeacon cannot carry MG-Proof and cannot take a challenge.
		if r.Proof == "required" {
			p.errorf(proofNode, "%s: proof required contradicts never_challenge (such endpoints can neither carry MG-Proof nor take a challenge)", o.sub("proof"))
		}
		if r.MinLevel != "" {
			p.errorf(levelNode, "%s: contradicts never_challenge (such endpoints cannot take a challenge)", o.sub("min_level"))
		}
	}
	if r.Proof == "required" && r.Channel == "web" && allowsUnsafeMethods(r.Methods) {
		p.warnf(proofNode, "%s: a web route that accepts non-safe methods: form posts must be sent with MorphGate.fetch, otherwise they carry no MG-Proof (D-40)", o.sub("proof"))
	}
	if r.MinLevel == "interactive" {
		if !s.Challenge.Interactive.Enabled {
			p.warnf(levelNode, "%s: interactive while challenge.interactive.enabled is false: the Edge requires pow instead (D-08, spec §5.2)", o.sub("min_level"))
		}
		if postOnly(r.Methods) {
			p.warnf(levelNode, "%s: interactive on a route with POST but not GET: visitors lose their form input when challenged; require it on the page route (GET)", o.sub("min_level"))
		}
	}
}

// allowsUnsafeMethods: no method restriction, or a method other than the
// safe ones.
func allowsUnsafeMethods(methods []string) bool {
	return len(methods) == 0 || slices.ContainsFunc(methods, func(m string) bool { return !slices.Contains(safeMethods, m) })
}

// postOnly: the route lists POST but not GET.
func postOnly(methods []string) bool {
	return slices.Contains(methods, "POST") && !slices.Contains(methods, "GET")
}

// checkInteractiveLimiter applies the §10.2 warnings to a limiter with
// on_exceed type interactive.
func (p *parser) checkInteractiveLimiter(n *yaml.Node, path string, l RateLimit, routes []Route, s *Site) {
	if !s.Challenge.Interactive.Enabled {
		p.warnf(n, "%s: on_exceed type interactive while challenge.interactive.enabled is false: the Edge issues pow instead (D-08, spec §5.2)", path)
	}
	if len(l.Routes) == 0 {
		return
	}
	for _, name := range l.Routes {
		i := slices.IndexFunc(routes, func(r Route) bool { return r.Name == name })
		if i < 0 || !postOnly(routes[i].Methods) {
			return
		}
	}
	p.warnf(n, "%s: interactive challenge on routes with POST but not GET only: visitors lose their form input when challenged; require it on the page route (GET)", path)
}

// parseProviders reads providers: (§8.2, D-51, D-70). It runs after the
// environments, whose routes the entries may name.
func (p *parser) parseProviders(n *yaml.Node, s *Site) []Provider {
	items, ok := p.seq(n, "providers")
	if !ok {
		return nil
	}
	if len(items) > MaxProviders {
		p.errorf(n, "providers: %d entries, at most %d in Phase 2 (turnstile)", len(items), MaxProviders)
	}
	var out []Provider
	for i, it := range items {
		pp := fmt.Sprintf("providers[%d]", i)
		o := p.object(it, pp)
		if o == nil {
			continue
		}
		pr := Provider{Enabled: true, Selection: "escalate_after_fail", Mode: "shadow", TimeoutMS: 4000, Fallback: ProviderFallback}
		if v := o.require("id"); v != nil {
			if id, ok := p.str(v, o.sub("id")); ok {
				switch {
				case id == "self_hold" || id == "pow_a11y":
					p.errorf(v, "%s: %q is built in and always offered; list only external providers here", o.sub("id"), id)
				case !slices.Contains(ProviderIDs, id):
					p.errorf(v, "%s: %q is not available in Phase 2 (only turnstile, D-70)", o.sub("id"), id)
				}
				pr.ID = id
			}
		}
		if v := o.get("enabled"); v != nil {
			pr.Enabled, _ = p.boolean(v, o.sub("enabled"))
		}
		if v := o.require("sitekey"); v != nil {
			if k, ok := p.str(v, o.sub("sitekey")); ok {
				if !SitekeyPattern.MatchString(k) {
					p.errorf(v, "%s: %q does not match %s", o.sub("sitekey"), k, SitekeyPattern)
				}
				pr.Sitekey = k
			}
		}
		if v := o.require("hostnames"); v != nil {
			pr.Hostnames = p.hostList(v, o.sub("hostnames"))
			if len(pr.Hostnames) == 0 && v.Kind == yaml.SequenceNode {
				p.errorf(v, "%s: must list at least one host name of the widget", o.sub("hostnames"))
			}
			for _, h := range pr.Hostnames {
				if !slices.Contains(s.Hosts, h) {
					p.errorf(v, "%s: %q is not one of the site's hosts", o.sub("hostnames"), h)
				}
			}
		}
		if v := o.get("routes"); v != nil {
			pr.Routes, _ = p.strList(v, o.sub("routes"), func(it *yaml.Node, ip, name string) bool {
				if !siteHasRoute(s, name) {
					p.errorf(it, "%s: no route %q in any environment", ip, name)
					return false
				}
				return true
			})
			p.uniqueStrings(v, o.sub("routes"), pr.Routes)
		}
		if v := o.get("selection"); v != nil {
			pr.Selection, _ = p.enum(v, o.sub("selection"), ProviderSelects)
		}
		if v := o.get("mode"); v != nil {
			pr.Mode, _ = p.enum(v, o.sub("mode"), ProviderModes)
		}
		if v := o.get("timeout_ms"); v != nil {
			pr.TimeoutMS, _ = p.uint(v, o.sub("timeout_ms"), 1000, 5000)
		}
		if v := o.get("fallback"); v != nil {
			if f, ok := p.str(v, o.sub("fallback")); ok && f != ProviderFallback {
				p.errorf(v, "%s: %q is not allowed; the only fallback is %s: the built-in providers are always offered, so fail_closed adds no protection and fail-open is never allowed (D-51)", o.sub("fallback"), f, ProviderFallback)
			}
		}
		if v := o.get("deny_countries"); v != nil {
			pr.DenyCountries, _ = p.strList(v, o.sub("deny_countries"), func(it *yaml.Node, ip, c string) bool {
				if !countryPattern.MatchString(c) {
					p.errorf(it, "%s: %q is not an upper-case ISO 3166-1 alpha-2 code", ip, c)
					return false
				}
				return true
			})
			p.uniqueStrings(v, o.sub("deny_countries"), pr.DenyCountries)
		}
		o.finish()
		if pr.Enabled && len(pr.DenyCountries) > 0 && !s.HasArtifact("geoip-country") &&
			(s.Cloudflare == nil || !s.Cloudflare.LocationHeaders) {
			p.warnf(it, "%s: deny_countries %s, but the site has neither artifacts.geoip_country nor cloudflare.location_headers: the country is always unknown, so Turnstile is never selected (spec §8.1)",
				pp, strings.Join(pr.DenyCountries, ","))
		}
		out = append(out, pr)
	}
	return out
}

func siteHasRoute(s *Site, name string) bool {
	return slices.ContainsFunc(s.Environments, func(e Environment) bool {
		return slices.ContainsFunc(e.Routes, func(r Route) bool { return r.Name == name })
	})
}
