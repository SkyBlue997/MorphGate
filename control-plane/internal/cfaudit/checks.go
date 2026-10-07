package cfaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"morphgate/control-plane/internal/cfapi"
	"morphgate/control-plane/internal/intelsync"
)

// Level is a check's severity (§14.3).
type Level string

// Check levels.
const (
	LevelError   Level = "error"
	LevelWarning Level = "warning"
	LevelInfo    Level = "info"
)

// Status is a check outcome (§14.3).
type Status string

// Check outcomes. warn is a failed warning- or info-level check (or the
// warning half of runtime_metrics).
const (
	StatusPass   Status = "pass"
	StatusFail   Status = "fail"
	StatusWarn   Status = "warn"
	StatusManual Status = "manual"
	StatusSkip   Status = "skip"
)

// CheckDef describes one audit check.
type CheckDef struct {
	N     int
	ID    string
	Level Level
	Title string
}

// Checks is the §14.3 table, in the order the audit runs and reports it.
var Checks = []CheckDef{
	{1, "origin_protection", LevelError, "Origin protection: healthy Tunnel, or zone-level / per-hostname AOP (never only global AOP)"},
	{2, "ssl_mode", LevelError, "SSL mode Full or Full (strict) (AOP)"},
	{3, "aop_cert_expiry", LevelWarning, "AOP client certificates valid for 30 more days (AOP)"},
	{4, "remove_visitor_ip_headers", LevelError, "Managed Transform \"Remove visitor IP headers\" off"},
	{5, "visitor_location_headers", LevelWarning, "Managed Transform \"Add visitor location headers\" on when the site uses them"},
	{6, "transform_rule_signals", LevelError, "Tier 0 Transform Rule mg_signals_v* complete, covering every site host"},
	{7, "pseudo_ipv4", LevelError, "Pseudo IPv4 off (or overwrite_header with pseudo_ipv4_overwrite)"},
	{8, "zero_rtt", LevelWarning, "0-RTT off"},
	{9, "bot_fight_mode", LevelError, "Bot Fight Mode off (Free)"},
	{10, "sbfm_skip", LevelError, "Super Bot Fight Mode allows automated traffic, or mg_skip_mg_paths skips it for /__mg/ (Pro+)"},
	{11, "skip_rule_order", LevelWarning, "mg_skip_mg_paths runs before block / challenge rules and keeps the /__mg/ flood rate limit"},
	{12, "cache_bypass_mg", LevelError, "mg_bypass_mg_paths is the last cache rule"},
	{13, "ttl_override_trap", LevelError, "No cacheable rule overrides the edge TTL of pages that may carry a challenge"},
	{14, "cf_challenge_overlap", LevelWarning, "No Cloudflare challenge rule covers /__mg/ or the site's routes"},
	{15, "rocket_loader", LevelWarning, "Rocket Loader off, or the SDK tag carries data-cfasync=\"false\""},
	{16, "ai_bot_policy", LevelWarning, "AI bot policies Allow (MorphGate is the single authority, mode A)"},
	{17, "precursor", LevelWarning, "Precursor off (no read API: manual)"},
	{18, "runtime_metrics", LevelError, "Edge runtime metrics over 24 h (--vm-url)"},
	{19, "ip_snapshot_age", LevelWarning, "Cloudflare IP snapshot synced within 48 h (--cf-ips)"},
	{20, "optional_rules", LevelInfo, "Optional /__mg/ flood rate limiting rule"},
	{21, "always_use_https", LevelError, "Always Use HTTPS on (HSTS reported)"},
}

// checkByID finds a check definition.
func checkByID(id string) (CheckDef, bool) {
	for _, c := range Checks {
		if c.ID == id {
			return c, true
		}
	}
	return CheckDef{}, false
}

// Result is one check outcome.
type Result struct {
	N      int    `json:"n"`
	ID     string `json:"id"`
	Level  Level  `json:"level"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
}

// Options configure an audit run.
type Options struct {
	Site   *Site
	CFIPs  string // --cf-ips artifact, "" to skip check 19
	VMURL  string // --vm-url, "" to skip check 18
	SDKDir string // --sdk-dir with challenge.html, for check 15
	// Acks marks manual checks as confirmed: check id -> note. Keys of the
	// form "ttl_override_trap:<rule ref>" accept one cache rule as a
	// reviewed exception of check 13.
	Acks   map[string]string
	Strict bool
	Now    time.Time
	// HTTP is used for VictoriaMetrics queries.
	HTTP *http.Client
}

// auditor runs the checks against one zone, caching API reads that several
// checks share.
type auditor struct {
	ctx   context.Context
	api   *cfapi.Client
	opts  Options
	site  *Site
	cf    *SiteCloudflare
	zone  *cfapi.Zone
	plan  string
	cache map[string]cached
}

type cached struct {
	v   any
	err error
}

func memo[T any](a *auditor, key string, load func() (T, error)) (T, error) {
	if c, ok := a.cache[key]; ok {
		v, _ := c.v.(T)
		return v, c.err
	}
	v, err := load()
	a.cache[key] = cached{v, err}
	return v, err
}

func (a *auditor) setting(name string) (string, error) {
	return memo(a, "setting/"+name, func() (string, error) {
		s, err := a.api.Setting(a.ctx, a.zone.ID, name)
		if err != nil {
			return "", err
		}
		return s.String()
	})
}

func (a *auditor) rawSetting(name string) (*cfapi.Setting, error) {
	return memo(a, "raw-setting/"+name, func() (*cfapi.Setting, error) {
		return a.api.Setting(a.ctx, a.zone.ID, name)
	})
}

func (a *auditor) managed() (*cfapi.ManagedHeaders, error) {
	return memo(a, "managed_headers", func() (*cfapi.ManagedHeaders, error) {
		return a.api.ManagedHeaders(a.ctx, a.zone.ID)
	})
}

func (a *auditor) ruleset(phase string) (*cfapi.Ruleset, error) {
	return memo(a, "ruleset/"+phase, func() (*cfapi.Ruleset, error) {
		return a.api.EntrypointRuleset(a.ctx, a.zone.ID, phase)
	})
}

func (a *auditor) bot() (*cfapi.BotManagement, error) {
	return memo(a, "bot_management", func() (*cfapi.BotManagement, error) {
		return a.api.BotManagement(a.ctx, a.zone.ID)
	})
}

func (a *auditor) aopSettings() (*cfapi.AOPSettings, error) {
	return memo(a, "aop_settings", func() (*cfapi.AOPSettings, error) {
		return a.api.AOPSettings(a.ctx, a.zone.ID)
	})
}

func (a *auditor) aopCerts() ([]cfapi.AOPCertificate, error) {
	return memo(a, "aop_certs", func() ([]cfapi.AOPCertificate, error) {
		return a.api.AOPCertificates(a.ctx, a.zone.ID)
	})
}

func (a *auditor) aopHost(host string) (*cfapi.AOPHostname, error) {
	return memo(a, "aop_host/"+host, func() (*cfapi.AOPHostname, error) {
		return a.api.AOPHostname(a.ctx, a.zone.ID, host)
	})
}

func (a *auditor) isTunnel() bool { return a.cf.OriginMode == "tunnel" }

// paidPlan reports whether the zone is on a plan with Super Bot Fight Mode.
func (a *auditor) paidPlan() bool {
	return a.plan == "pro" || a.plan == "business" || a.plan == "enterprise"
}

func res(st Status, format string, args ...any) Result {
	return Result{Status: st, Detail: fmt.Sprintf(format, args...)}
}

// failed is the status of a failed check at level l.
func failed(l Level) Status {
	if l == LevelError {
		return StatusFail
	}
	return StatusWarn
}

// permissionHints name the read permission an endpoint needs. Cloudflare's
// exact permission names still have to be confirmed per account (docs/08
// §2.10), so they are hints, not a contract.
var permissionHints = []struct{ fragment, hint string }{
	{"/rulesets/phases/" + cfapi.PhaseLateTransform, "Transform Rules Read"},
	{"/rulesets/phases/" + cfapi.PhaseCacheSettings, "Cache Rules Read"},
	{"/rulesets/phases/", "Zone WAF Read"},
	{"/managed_headers", "Transform Rules Read"},
	{"/bot_management", "Bot Management Read"},
	{"/origin_tls_client_auth", "SSL and Certificates Read"},
	{"/cfd_tunnel/", "Cloudflare Tunnel Read (account)"},
	{"/settings/", "Zone Settings Read"},
}

// apiProblem turns an API error into a result: permission errors (401 / 403)
// are manual (§14.3), anything else fails the check at its level.
func apiProblem(def CheckDef, err error) Result {
	var ae *cfapi.APIError
	if cfapi.IsForbidden(err) && errors.As(err, &ae) {
		hint := "zone read"
		for _, p := range permissionHints {
			if strings.Contains(ae.Path, p.fragment) {
				hint = p.hint
				break
			}
		}
		return res(StatusManual, "the API token may not read GET %s (needs %q or similar); confirm in the dashboard and --ack %s=<note>, or extend the read-only token", ae.Path, hint, def.ID)
	}
	return res(failed(def.Level), "Cloudflare API error: %v", err)
}

// enabledRules returns the enabled rules of a ruleset in order.
func enabledRules(rs *cfapi.Ruleset) []cfapi.Rule {
	var out []cfapi.Rule
	for _, r := range rs.Rules {
		if r.IsEnabled() {
			out = append(out, r)
		}
	}
	return out
}

func ruleNames(rules []cfapi.Rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Name())
	}
	return out
}

// skipParams is the action_parameters of a skip rule.
type skipParams struct {
	Phases   []string `json:"phases"`
	Products []string `json:"products"`
}

// coversMGPrefix reports whether an expression matches every /__mg/ request:
// the template expression itself or a top-level disjunct equal to it.
func coversMGPrefix(expr string) bool {
	want := normalizeExpr(SkipMGExpression)
	for _, term := range splitTopLevel(stripParens(normalizeExpr(expr)), " or ", "||") {
		if stripParens(term) == want {
			return true
		}
	}
	return false
}

// mgSkipRule returns the enabled mg_skip_mg_paths skip rule, its index among
// the enabled rules and its parameters.
func mgSkipRule(rs *cfapi.Ruleset) (idx int, rule *cfapi.Rule, p skipParams) {
	for i, r := range enabledRules(rs) {
		if r.Ref == RefSkipMG && r.Action == "skip" {
			_ = r.Params(&p)
			return i, &r, p
		}
	}
	return -1, nil, p
}

// floodRules are enabled rate limiting rules that match /__mg/ paths; a
// rule that only excludes /__mg/ (`and not starts_with(...)`) is not one.
func floodRules(rs *cfapi.Ruleset) []cfapi.Rule {
	var out []cfapi.Rule
	for _, r := range enabledRules(rs) {
		e := withoutExclusions(r.Expression)
		if strings.Contains(e, "/__mg/") || strings.Contains(e, "/__mg\"") {
			out = append(out, r)
		}
	}
	return out
}

// --- the checks ---------------------------------------------------------

type checkFunc func(a *auditor, def CheckDef) Result

var checkFuncs = map[string]checkFunc{
	"origin_protection":         checkOriginProtection,
	"ssl_mode":                  checkSSLMode,
	"aop_cert_expiry":           checkAOPCertExpiry,
	"remove_visitor_ip_headers": checkRemoveVisitorIPHeaders,
	"visitor_location_headers":  checkVisitorLocationHeaders,
	"transform_rule_signals":    checkTransformRuleSignals,
	"pseudo_ipv4":               checkPseudoIPv4,
	"zero_rtt":                  checkZeroRTT,
	"bot_fight_mode":            checkBotFightMode,
	"sbfm_skip":                 checkSBFMSkip,
	"skip_rule_order":           checkSkipRuleOrder,
	"cache_bypass_mg":           checkCacheBypassMG,
	"ttl_override_trap":         checkTTLOverrideTrap,
	"cf_challenge_overlap":      checkChallengeOverlap,
	"rocket_loader":             checkRocketLoader,
	"ai_bot_policy":             checkAIBotPolicy,
	"precursor":                 checkPrecursor,
	"runtime_metrics":           checkRuntimeMetrics,
	"ip_snapshot_age":           checkIPSnapshotAge,
	"optional_rules":            checkOptionalRules,
	"always_use_https":          checkAlwaysUseHTTPS,
}

// 1. The Edge must only be reachable through this zone: a healthy Tunnel, or
// AOP with the owner's own certificate (zone-level or per hostname). Global
// AOP only proves "came through Cloudflare", which any Cloudflare customer's
// Worker can do (ADR-0004, docs/08 §2.1).
func checkOriginProtection(a *auditor, def CheckDef) Result {
	if a.isTunnel() {
		if a.cf.AccountID == "" {
			return res(StatusManual, "origin_mode tunnel: set cloudflare.account_id and tunnel_id to read the tunnel status; confirm that the tunnel's ingress points only at the Edge on 127.0.0.1")
		}
		t, err := a.api.Tunnel(a.ctx, a.cf.AccountID, a.cf.TunnelID)
		if cfapi.IsNotFound(err) {
			return res(StatusFail, "tunnel %s not found in account %s", a.cf.TunnelID, a.cf.AccountID)
		}
		if err != nil {
			return apiProblem(def, err)
		}
		if t.Status != "healthy" {
			return res(StatusFail, "tunnel %s (%s) status %q, want healthy", t.Name, a.cf.TunnelID, t.Status)
		}
		return res(StatusPass, "tunnel %s healthy (%d connection(s))", t.Name, len(t.Connections))
	}
	settings, err := a.aopSettings()
	if err != nil {
		return apiProblem(def, err)
	}
	certs, err := a.aopCerts()
	if err != nil {
		return apiProblem(def, err)
	}
	active := 0
	for _, c := range certs {
		if c.Status == "active" {
			active++
		}
	}
	if settings.Enabled && active > 0 {
		return res(StatusPass, "zone-level AOP enabled with %d active certificate(s)", active)
	}
	var uncovered []string
	for _, h := range a.site.Hosts {
		ph, err := a.aopHost(h)
		if err != nil {
			return apiProblem(def, err)
		}
		if !perHostnameOn(ph) {
			uncovered = append(uncovered, h)
		}
	}
	if len(uncovered) == 0 {
		return res(StatusPass, "per-hostname AOP enabled for all %d host(s)", len(a.site.Hosts))
	}
	global, gerr := a.setting("tls_client_auth")
	switch {
	case gerr == nil && global == "on":
		return res(StatusFail, "only global AOP (Cloudflare's shared certificate) protects %s: it proves only that a request passed through Cloudflare, not through this zone; use zone-level or per-hostname AOP with the owner's certificate", strings.Join(uncovered, ", "))
	case settings.Enabled:
		return res(StatusFail, "zone-level AOP is enabled but no active zone certificate is uploaded, and %s have no per-hostname AOP", strings.Join(uncovered, ", "))
	}
	return res(StatusFail, "AOP is not enabled for %s (origin_mode aop)", strings.Join(uncovered, ", "))
}

func perHostnameOn(h *cfapi.AOPHostname) bool {
	return h != nil && h.Enabled != nil && *h.Enabled && h.CertID != "" && (h.Status == "" || h.Status == "active")
}

// 2. AOP needs SSL mode Full or Full (strict) (docs/08 §2.1).
func checkSSLMode(a *auditor, def CheckDef) Result {
	if a.isTunnel() {
		return res(StatusSkip, "origin_mode tunnel: the SSL mode does not apply to tunnel hostnames")
	}
	v, err := a.setting("ssl")
	if err != nil {
		return apiProblem(def, err)
	}
	if v == "full" || v == "strict" {
		return res(StatusPass, "ssl = %s", v)
	}
	return res(StatusFail, "ssl = %s; AOP needs full or strict (Full (strict) recommended)", v)
}

// 3. AOP certificates must not expire within 30 days.
func checkAOPCertExpiry(a *auditor, def CheckDef) Result {
	if a.isTunnel() {
		return res(StatusSkip, "origin_mode tunnel")
	}
	certs, err := a.aopCerts()
	if err != nil {
		return apiProblem(def, err)
	}
	type exp struct{ name, on string }
	var all []exp
	for _, c := range certs {
		if c.Status == "active" || c.Status == "" {
			all = append(all, exp{"zone certificate " + c.ID, c.ExpiresOn})
		}
	}
	for _, h := range a.site.Hosts {
		ph, err := a.aopHost(h)
		if err != nil {
			return apiProblem(def, err)
		}
		if perHostnameOn(ph) {
			all = append(all, exp{"per-hostname certificate of " + h, ph.ExpiresOn})
		}
	}
	if len(all) == 0 {
		return res(StatusSkip, "no active AOP certificates (see origin_protection)")
	}
	var problems []string
	earliest := time.Time{}
	for _, e := range all {
		t, err := time.Parse(time.RFC3339, e.on)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: unreadable expires_on %q", e.name, e.on))
			continue
		}
		left := t.Sub(a.opts.Now)
		if left < 30*24*time.Hour {
			problems = append(problems, fmt.Sprintf("%s expires %s (%d days left)", e.name, e.on, int(left.Hours()/24)))
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if len(problems) > 0 {
		return res(StatusWarn, "%s", strings.Join(problems, "; "))
	}
	return res(StatusPass, "%d certificate(s), earliest expiry %s (%d days)", len(all), earliest.Format(time.RFC3339), int(earliest.Sub(a.opts.Now).Hours()/24))
}

// 4. "Remove visitor IP headers" deletes CF-Connecting-IP (docs/08 §2.2).
func checkRemoveVisitorIPHeaders(a *auditor, def CheckDef) Result {
	m, err := a.managed()
	if err != nil {
		return apiProblem(def, err)
	}
	if h, ok := m.RequestHeader("remove_visitor_ip_headers"); ok && h.Enabled {
		return res(StatusFail, "remove_visitor_ip_headers is on: CF-Connecting-IP never reaches the Edge")
	}
	return res(StatusPass, "remove_visitor_ip_headers is off")
}

// 5. The Edge trusts the cf-ip* location headers only when the site says
// the Managed Transform is on.
func checkVisitorLocationHeaders(a *auditor, def CheckDef) Result {
	m, err := a.managed()
	if err != nil {
		return apiProblem(def, err)
	}
	h, available := m.RequestHeader("add_visitor_location_headers")
	state := "off"
	switch {
	case !available:
		state = "not available on this plan"
	case h.Enabled:
		state = "on"
	}
	if !a.cf.LocationHeaders {
		return res(StatusPass, "cloudflare.location_headers is false (add_visitor_location_headers %s)", state)
	}
	if state == "on" {
		return res(StatusPass, "add_visitor_location_headers is on")
	}
	return res(StatusWarn, "cloudflare.location_headers is true but add_visitor_location_headers is %s", state)
}

// headerOp is one entry of a rewrite rule's action_parameters.headers.
type headerOp struct {
	Operation  string `json:"operation"`
	Expression string `json:"expression"`
	Value      string `json:"value"`
}

func ruleHeaders(r *cfapi.Rule) (map[string]headerOp, error) {
	var p struct {
		Headers map[string]headerOp `json:"headers"`
	}
	if err := r.Params(&p); err != nil {
		return nil, err
	}
	out := make(map[string]headerOp, len(p.Headers))
	for k, v := range p.Headers {
		out[strings.ToLower(k)] = v
	}
	return out, nil
}

// 6. The Tier 0 rule must set every x-mg-cf-* signal from Cloudflare's own
// fields and remove the Tier 1 names, on every site host; otherwise a client
// can send its own values (docs/08 §2.3). Values of x-mg-upstream-key are
// secrets and never printed.
func checkTransformRuleSignals(a *auditor, def CheckDef) Result {
	rs, err := a.ruleset(cfapi.PhaseLateTransform)
	if err != nil {
		return apiProblem(def, err)
	}
	var signals, others []cfapi.Rule
	for _, r := range enabledRules(rs) {
		if signalsRefPattern.MatchString(r.Ref) {
			signals = append(signals, r)
		} else {
			others = append(others, r)
		}
	}
	if len(signals) == 0 {
		return res(StatusFail, "no enabled mg_signals_v* rule in %s (template adapters/cloudflare/transform-rule.request-headers.json)", cfapi.PhaseLateTransform)
	}
	var problems []string
	var keyRules []string
	checkKey := func(r *cfapi.Rule, op headerOp) {
		keyRules = append(keyRules, r.Name())
		switch {
		case op.Operation != "set" || op.Value == "":
			problems = append(problems, fmt.Sprintf("%s: %s must be set to a static value", r.Name(), UpstreamKeyHeader))
		case strings.HasPrefix(op.Value, UpstreamKeyPlaceholderPrefix):
			problems = append(problems, fmt.Sprintf("%s: %s still holds the template placeholder", r.Name(), UpstreamKeyHeader))
		}
		if missing, ok := missingHosts(r.Expression, a.site.Hosts); !ok {
			problems = append(problems, fmt.Sprintf("%s: cannot verify that the expression covers every site host (use true or http.host in {...})", r.Name()))
		} else if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("%s: expression does not cover %s (the Edge rejects requests without the key there)", r.Name(), strings.Join(missing, ", ")))
		}
	}
	for i := range signals {
		r := &signals[i]
		if r.Action != "rewrite" {
			problems = append(problems, fmt.Sprintf("%s: action %q, want rewrite", r.Name(), r.Action))
			continue
		}
		headers, err := ruleHeaders(r)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: unreadable action_parameters: %v", r.Name(), err))
			continue
		}
		names := make([]string, 0, len(Tier0Headers))
		for h := range Tier0Headers {
			names = append(names, h)
		}
		sort.Strings(names)
		for _, h := range names {
			op, ok := headers[h]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s: %s missing", r.Name(), h))
			case op.Operation != "set" || op.Value != "":
				problems = append(problems, fmt.Sprintf("%s: %s must be set from an expression", r.Name(), h))
			case !expressionMatches(h, op.Expression):
				problems = append(problems, fmt.Sprintf("%s: %s = %q, want %q", r.Name(), h, op.Expression, Tier0Headers[h]))
			}
		}
		for _, h := range Tier1Headers {
			if op, ok := headers[h]; !ok || op.Operation != "remove" {
				problems = append(problems, fmt.Sprintf("%s: %s must be removed", r.Name(), h))
			}
		}
		for h, op := range headers {
			switch {
			case h == UpstreamKeyHeader:
				checkKey(r, op)
			case strings.HasPrefix(h, "x-mg-") && Tier0Headers[h] == "" && !slices.Contains(Tier1Headers, h):
				problems = append(problems, fmt.Sprintf("%s: unexpected header %s", r.Name(), h))
			}
		}
		if missing, ok := missingHosts(r.Expression, a.site.Hosts); !ok {
			problems = append(problems, fmt.Sprintf("%s: cannot verify that expression %q covers every site host (use true or http.host in {...})", r.Name(), truncate(r.Expression, 120)))
		} else if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf("%s: expression does not cover %s, where clients could send their own x-mg-cf-* headers", r.Name(), strings.Join(missing, ", ")))
		}
	}
	for i := range others {
		r := &others[i]
		if r.Action != "rewrite" {
			continue
		}
		headers, err := ruleHeaders(r)
		if err != nil {
			continue
		}
		var touched []string
		for h, op := range headers {
			switch {
			case h == UpstreamKeyHeader:
				checkKey(r, op)
			case strings.HasPrefix(h, "x-mg-"):
				touched = append(touched, h)
			}
		}
		if len(touched) > 0 {
			sort.Strings(touched)
			problems = append(problems, fmt.Sprintf("rule %s also changes %s", r.Name(), strings.Join(touched, ", ")))
		}
	}
	sort.Strings(problems)
	key := "no x-mg-upstream-key rule (optional)"
	if len(keyRules) > 0 {
		key = fmt.Sprintf("x-mg-upstream-key set by %s (value not shown)", strings.Join(keyRules, ", "))
	}
	if len(problems) > 0 {
		return res(StatusFail, "%s; %s", strings.Join(problems, "; "), key)
	}
	return res(StatusPass, "%s complete; %s", strings.Join(ruleNames(signals), ", "), key)
}

func expressionMatches(header, got string) bool {
	g := normalizeExpr(got)
	if g == normalizeExpr(Tier0Headers[header]) {
		return true
	}
	for _, alt := range tier0Alternatives[header] {
		if g == normalizeExpr(alt) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// 7. With overwrite_header, CF-Connecting-IP is a pseudo IPv4 and the Edge
// must read CF-Connecting-IPv6 (docs/08 §2.2).
func checkPseudoIPv4(a *auditor, def CheckDef) Result {
	v, err := a.setting("pseudo_ipv4")
	if err != nil {
		return apiProblem(def, err)
	}
	switch {
	case v == "off":
		return res(StatusPass, "pseudo_ipv4 = off")
	case v == "overwrite_header" && a.cf.PseudoIPv4Overwrite:
		return res(StatusPass, "pseudo_ipv4 = overwrite_header and the site reads CF-Connecting-IPv6 (pseudo_ipv4_overwrite)")
	case v == "overwrite_header":
		return res(StatusFail, "pseudo_ipv4 = overwrite_header replaces CF-Connecting-IP with a pseudo IPv4, but cloudflare.pseudo_ipv4_overwrite is false")
	}
	return res(StatusFail, "pseudo_ipv4 = %s; want off (or overwrite_header with cloudflare.pseudo_ipv4_overwrite: true)", v)
}

// 8. 0-RTT lets early data be replayed (docs/08 §2.7).
func checkZeroRTT(a *auditor, def CheckDef) Result {
	v, err := a.setting("0rtt")
	if err != nil {
		return apiProblem(def, err)
	}
	if v == "off" {
		return res(StatusPass, "0rtt = off")
	}
	return res(StatusWarn, "0rtt = %s: early data can be replayed; the Edge answers Early-Data: 1 on /__mg/ state-changing requests with 425", v)
}

// 9. Bot Fight Mode cannot be skipped per path and challenges /__mg/*
// before MorphGate sees it (docs/08 §2.7).
func checkBotFightMode(a *auditor, def CheckDef) Result {
	bm, err := a.bot()
	if a.paidPlan() {
		if err == nil {
			if on, ok := bm.Bool("fight_mode"); ok && on {
				return res(StatusFail, "fight_mode is on")
			}
		}
		return res(StatusSkip, "plan %s has Super Bot Fight Mode instead (sbfm_skip)", a.plan)
	}
	if err != nil {
		if cfapi.IsForbidden(err) {
			return res(StatusManual, "cannot read bot_management (needs \"Bot Management Read\" or similar); confirm Bot Fight Mode is off under Security > Bots and --ack %s=<note>", def.ID)
		}
		return apiProblem(def, err)
	}
	on, ok := bm.Bool("fight_mode")
	if !ok {
		return res(StatusManual, "bot_management has no fight_mode field; confirm Bot Fight Mode is off under Security > Bots")
	}
	if on {
		return res(StatusFail, "Bot Fight Mode is on: it cannot be skipped for /__mg/* and challenges MorphGate's endpoints; turn it off")
	}
	return res(StatusPass, "fight_mode = false")
}

// 10. SBFM must let /__mg/ through: every automated group Allow, or the
// mg_skip_mg_paths rule skipping http_request_sbfm. With a Tunnel,
// "Definitely automated" must be Allow regardless (docs/08 §2.1).
func checkSBFMSkip(a *auditor, def CheckDef) Result {
	if a.plan == "free" {
		return res(StatusSkip, "Free plan: no Super Bot Fight Mode (see bot_fight_mode)")
	}
	skipCovers := false
	custom, cerr := a.ruleset(cfapi.PhaseFirewallCustom)
	if cerr == nil {
		if _, r, p := mgSkipRule(custom); r != nil && coversMGPrefix(r.Expression) && slices.Contains(p.Phases, "http_request_sbfm") {
			skipCovers = true
		}
	}
	bm, berr := a.bot()
	if berr != nil {
		if skipCovers && !a.isTunnel() {
			return res(StatusPass, "mg_skip_mg_paths skips http_request_sbfm for /__mg/ (SBFM settings unreadable: %v)", berr)
		}
		return apiProblem(def, berr)
	}
	da, daOK := bm.String("sbfm_definitely_automated")
	la, laOK := bm.String("sbfm_likely_automated")
	if !daOK && !laOK {
		if skipCovers && !a.isTunnel() {
			return res(StatusPass, "mg_skip_mg_paths skips http_request_sbfm for /__mg/")
		}
		if a.plan == "" || !a.paidPlan() {
			return res(StatusSkip, "no Super Bot Fight Mode settings on plan %q", a.plan)
		}
		return res(StatusManual, "bot_management has no SBFM fields; confirm the SBFM groups under Security > Bots")
	}
	groups := fmt.Sprintf("definitely_automated=%s", valueOr(da, daOK))
	if laOK {
		groups += fmt.Sprintf(", likely_automated=%s", la)
	}
	if a.isTunnel() && daOK && da != "allow" {
		return res(StatusFail, "%s: with a Tunnel, Definitely Automated must be Allow or cloudflared connections can fail (websocket: bad handshake)", groups)
	}
	if (!daOK || da == "allow") && (!laOK || la == "allow") {
		return res(StatusPass, "SBFM groups allow automated traffic (%s)", groups)
	}
	if skipCovers {
		return res(StatusPass, "%s; mg_skip_mg_paths skips http_request_sbfm for /__mg/", groups)
	}
	if cerr != nil {
		return apiProblem(def, cerr)
	}
	return res(StatusFail, "%s and no mg_skip_mg_paths rule skips http_request_sbfm for /__mg/ (template adapters/cloudflare/waf-skip.mg.json)", groups)
}

func valueOr(v string, ok bool) string {
	if !ok {
		return "(absent)"
	}
	return v
}

// 11. The skip rule must run before any block / challenge rule, must not
// disable the /__mg/ flood rate limit, and mg_skip_cleared must exclude
// /__mg/ (docs/08 §2.7, §2.9).
func checkSkipRuleOrder(a *auditor, def CheckDef) Result {
	custom, err := a.ruleset(cfapi.PhaseFirewallCustom)
	if err != nil {
		return apiProblem(def, err)
	}
	rl, err := a.ruleset(cfapi.PhaseRateLimit)
	if err != nil {
		return apiProblem(def, err)
	}
	idx, skip, p := mgSkipRule(custom)
	if skip == nil {
		return res(StatusWarn, "no enabled mg_skip_mg_paths skip rule in %s (template adapters/cloudflare/waf-skip.mg.json)", cfapi.PhaseFirewallCustom)
	}
	var problems []string
	if !coversMGPrefix(skip.Expression) {
		problems = append(problems, fmt.Sprintf("mg_skip_mg_paths expression %q does not match every /__mg/ request", truncate(skip.Expression, 120)))
	}
	var before []string
	for _, r := range enabledRules(custom)[:idx] {
		if slices.Contains(blockingActions, r.Action) {
			before = append(before, r.Name())
		}
	}
	if len(before) > 0 {
		problems = append(problems, fmt.Sprintf("rules %s run before mg_skip_mg_paths and may block or challenge /__mg/", strings.Join(before, ", ")))
	}
	if flood := floodRules(rl); len(flood) > 0 && slices.Contains(p.Phases, cfapi.PhaseRateLimit) {
		problems = append(problems, fmt.Sprintf("mg_skip_mg_paths skips http_ratelimit, disabling the /__mg/ flood rule(s) %s", strings.Join(ruleNames(flood), ", ")))
	}
	for _, r := range enabledRules(custom) {
		if r.Ref == RefSkipCleared && !excludesMG(r.Expression) {
			problems = append(problems, "mg_skip_cleared does not exclude /__mg/ (add: and not starts_with(http.request.uri.path, \"/__mg/\"))")
		}
	}
	if len(problems) > 0 {
		return res(StatusWarn, "%s", strings.Join(problems, "; "))
	}
	return res(StatusPass, "mg_skip_mg_paths is rule %d of %d and keeps rate limiting", idx+1, len(enabledRules(custom)))
}

// excludesMG reports whether an expression is a conjunction with the
// top-level term `not starts_with(http.request.uri.path, "/__mg/")`. Any
// top-level "or" / "xor" (in any spelling) disqualifies it, since "and"
// binds tighter than both.
func excludesMG(expr string) bool {
	e := stripParens(normalizeExpr(expr))
	toks, ok := tokenize(e)
	if !ok {
		return false
	}
	var conjuncts []string
	depth, from := 0, 0
	for _, t := range toks {
		if t.kind == tokPunct {
			switch t.text {
			case "(", "{", "[":
				depth++
			case ")", "}", "]":
				depth--
			}
		}
		if depth != 0 {
			continue
		}
		if isDisjunction(t) {
			return false
		}
		if isConjunction(t) {
			conjuncts = append(conjuncts, e[from:t.start])
			from = t.end
		}
	}
	conjuncts = append(conjuncts, e[from:])
	want := normalizeExpr(notMGPrefix)
	for _, c := range conjuncts {
		if stripParens(normalizeExpr(strings.TrimSpace(c))) == want {
			return true
		}
	}
	return false
}

// cacheParams is the action_parameters of a set_cache_settings rule.
type cacheParams struct {
	Cache   *bool `json:"cache"`
	EdgeTTL *struct {
		Mode          string            `json:"mode"`
		StatusCodeTTL []json.RawMessage `json:"status_code_ttl"`
	} `json:"edge_ttl"`
}

// 12. /__mg/ responses are per request: the bypass rule must be the last
// cache rule because the last matching rule wins (docs/08 §2.6).
func checkCacheBypassMG(a *auditor, def CheckDef) Result {
	rs, err := a.ruleset(cfapi.PhaseCacheSettings)
	if err != nil {
		return apiProblem(def, err)
	}
	rules := enabledRules(rs)
	if len(rules) == 0 {
		return res(StatusFail, "no cache rules; add adapters/cloudflare/cache-rule.bypass-mg.json as the last cache rule")
	}
	last := rules[len(rules)-1]
	if last.Ref != RefBypassMG {
		for i, r := range rules {
			if r.Ref == RefBypassMG {
				return res(StatusFail, "mg_bypass_mg_paths is rule %d of %d; rules after it (%s) win for /__mg/ requests they match", i+1, len(rules), strings.Join(ruleNames(rules[i+1:]), ", "))
			}
		}
		return res(StatusFail, "no enabled mg_bypass_mg_paths cache rule")
	}
	var p cacheParams
	if err := last.Params(&p); err != nil {
		return res(StatusFail, "mg_bypass_mg_paths: unreadable action_parameters: %v", err)
	}
	if last.Action != "set_cache_settings" || p.Cache == nil || *p.Cache {
		return res(StatusFail, "mg_bypass_mg_paths must be set_cache_settings with cache: false (bypass)")
	}
	if normalizeExpr(last.Expression) != normalizeExpr(BypassMGExpression) {
		return res(StatusFail, "mg_bypass_mg_paths expression %q, want %q", truncate(last.Expression, 160), BypassMGExpression)
	}
	return res(StatusPass, "mg_bypass_mg_paths is the last of %d cache rule(s)", len(rules))
}

// 13. "Eligible for cache" with an Edge TTL override strips Set-Cookie and
// caches the response, so a challenge or clearance response would be served
// to other visitors (docs/08 §2.6). The settings of all matching cache rules
// combine, so a TTL override in one rule and "Eligible for cache" in another
// make the same trap: an override rule that leaves `cache` unset (or sets it
// to false before a later eligible rule) is reported with every eligible
// rule outside static files, since expressions cannot be intersected.
func checkTTLOverrideTrap(a *auditor, def CheckDef) Result {
	rs, err := a.ruleset(cfapi.PhaseCacheSettings)
	if err != nil {
		return apiProblem(def, err)
	}
	type cacheRule struct {
		name          string
		cache         *bool
		override      bool
		laterEligible []string // eligible rules after this one
	}
	var rules []cacheRule
	var traps, acked []string
	for _, r := range enabledRules(rs) {
		if r.Action != "set_cache_settings" {
			continue
		}
		var p cacheParams
		if err := r.Params(&p); err != nil {
			traps = append(traps, r.Name()+" (unreadable action_parameters)")
			continue
		}
		if restrictedToStatic(r.Expression) {
			continue
		}
		override := p.EdgeTTL != nil && (p.EdgeTTL.Mode == "override_origin" || len(p.EdgeTTL.StatusCodeTTL) > 0)
		rules = append(rules, cacheRule{name: r.Name(), cache: p.Cache, override: override})
	}
	var eligible []string // non-static rules that set cache: true, in order
	for i := len(rules) - 1; i >= 0; i-- {
		rules[i].laterEligible = slices.Clone(eligible)
		if c := rules[i].cache; c != nil && *c {
			eligible = append([]string{rules[i].name}, eligible...)
		}
	}
	for _, r := range rules {
		if !r.override {
			continue
		}
		var why string
		switch {
		case r.cache != nil && *r.cache:
			why = r.name
		case r.cache == nil && len(eligible) > 0:
			why = fmt.Sprintf("%s (stacked with %s)", r.name, strings.Join(eligible, ", "))
		case r.cache != nil && len(r.laterEligible) > 0:
			why = fmt.Sprintf("%s (stacked with the later %s)", r.name, strings.Join(r.laterEligible, ", "))
		default:
			continue
		}
		if note, ok := a.opts.Acks["ttl_override_trap:"+r.name]; ok {
			acked = append(acked, fmt.Sprintf("%s (acknowledged: %s)", r.name, note))
			continue
		}
		traps = append(traps, why)
	}
	if len(traps) > 0 {
		return res(StatusFail, "cacheable rule(s) %s override the edge TTL on paths not limited to static files: Cloudflare then strips Set-Cookie and caches per-visitor challenge responses; limit them to static extensions or --ack ttl_override_trap:<ref>=<note>", strings.Join(traps, ", "))
	}
	if len(acked) > 0 {
		return res(StatusPass, "no unreviewed TTL overrides; %s", strings.Join(acked, "; "))
	}
	return res(StatusPass, "no cacheable rule overrides the edge TTL outside static files")
}

// 14. Cloudflare challenges on MorphGate's paths cause double challenges or
// loops (docs/08 §2.7).
func checkChallengeOverlap(a *auditor, def CheckDef) Result {
	custom, err := a.ruleset(cfapi.PhaseFirewallCustom)
	if err != nil {
		return apiProblem(def, err)
	}
	rl, err := a.ruleset(cfapi.PhaseRateLimit)
	if err != nil {
		return apiProblem(def, err)
	}
	prefixes := []string{"/__mg"}
	for _, p := range a.site.routePaths() {
		if lp := literalPrefix(p); lp != "" && !slices.Contains(prefixes, strings.ToLower(lp)) {
			prefixes = append(prefixes, strings.ToLower(lp))
		}
	}
	var overlaps []string
	for _, r := range append(enabledRules(custom), enabledRules(rl)...) {
		if !slices.Contains(challengeActions, r.Action) {
			continue
		}
		e := strings.ToLower(normalizeSpaces(stripParens(strings.TrimSpace(r.Expression))))
		if e == "true" {
			overlaps = append(overlaps, r.Name()+" (every request)")
			continue
		}
		// `and not starts_with(http.request.uri.path, "/__mg/")` is how a
		// rule stays off MorphGate's paths (docs/08 §2.7): excluded paths do
		// not count as covered.
		m := withoutExclusions(e)
		for _, p := range prefixes {
			if strings.Contains(m, p) {
				overlaps = append(overlaps, fmt.Sprintf("%s (%s)", r.Name(), p))
				break
			}
		}
	}
	if len(overlaps) > 0 {
		return res(StatusWarn, "Cloudflare challenge rules cover MorphGate paths: %s", strings.Join(overlaps, ", "))
	}
	return res(StatusPass, "no challenge rule covers /__mg/ or the site's %d route path prefix(es)", len(prefixes)-1)
}

var scriptTagPattern = regexp.MustCompile(`(?is)<script\b[^>]*>`)

// 15. Rocket Loader rewrites script loading unless the tag opts out
// (spec §11.2, docs/08 §2.7).
func checkRocketLoader(a *auditor, def CheckDef) Result {
	v, err := a.setting("rocket_loader")
	if err != nil {
		return apiProblem(def, err)
	}
	if v == "off" {
		return res(StatusPass, "rocket_loader = off")
	}
	if a.opts.SDKDir == "" {
		return res(StatusWarn, "rocket_loader = %s; pass --sdk-dir to confirm that challenge.html's SDK tag carries data-cfasync=\"false\"", v)
	}
	path := filepath.Join(a.opts.SDKDir, "challenge.html")
	f, err := os.Open(path)
	if err != nil {
		return res(StatusWarn, "rocket_loader = %s; cannot read %s: %v", v, path, err)
	}
	defer f.Close()
	tmpl, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return res(StatusWarn, "rocket_loader = %s; cannot read %s: %v", v, path, err)
	}
	tags := scriptTagPattern.FindAllString(string(tmpl), -1)
	if len(tags) == 0 {
		return res(StatusWarn, "rocket_loader = %s and %s has no <script> tag", v, path)
	}
	for _, tag := range tags {
		i := strings.Index(tag, `data-cfasync="false"`)
		src := strings.Index(tag, "src=")
		if i < 0 || (src >= 0 && src < i) {
			return res(StatusWarn, "rocket_loader = %s and a <script> tag in %s lacks data-cfasync=\"false\" before src", v, path)
		}
	}
	return res(StatusPass, "rocket_loader = %s, but every <script> tag in challenge.html carries data-cfasync=\"false\"", v)
}

// 16. Mode A: MorphGate is the single authority for crawlers, so Cloudflare's
// AI bot policies must allow (docs/05 §7.4).
func checkAIBotPolicy(a *auditor, def CheckDef) Result {
	bm, err := a.bot()
	if err != nil {
		return apiProblem(def, err)
	}
	var keys []string
	for k := range bm.Fields {
		if _, ok := bm.String(k); ok && strings.HasPrefix(k, "ai_") {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return res(StatusManual, "bot_management has no AI bot policy fields; confirm Search / Agent / Training are Allow under Security > Bots")
	}
	sort.Strings(keys)
	var all, blocking []string
	for _, k := range keys {
		v, _ := bm.String(k)
		all = append(all, k+"="+v)
		if v != "disabled" && v != "allow" && v != "off" {
			blocking = append(blocking, k+"="+v)
		}
	}
	if len(blocking) > 0 {
		return res(StatusWarn, "%s: Cloudflare blocks those crawlers before MorphGate can see or log them; mode A needs Allow", strings.Join(blocking, ", "))
	}
	return res(StatusPass, "%s", strings.Join(all, ", "))
}

// 17. Precursor has no documented read API.
func checkPrecursor(a *auditor, def CheckDef) Result {
	return res(StatusManual, "no read API; confirm Precursor is off in the dashboard (Maximize Security needs cf_clearance and breaks cookie-less fetches) and --ack precursor=<note>")
}

// 18. Runtime evidence from VictoriaMetrics over the last 24 h.
func checkRuntimeMetrics(a *auditor, def CheckDef) Result {
	if a.opts.VMURL == "" {
		return res(StatusSkip, "pass --vm-url to check the Edge's runtime metrics")
	}
	site := a.site.Site
	errQueries := []struct{ name, q string }{
		{"mg_cf_connecting_ip_missing_total", fmt.Sprintf(`sum(increase(mg_cf_connecting_ip_missing_total{site=%q}[24h]))`, site)},
		{`mg_upstream_auth_failures_total{reason="bad_secret_header"}`, `sum(increase(mg_upstream_auth_failures_total{reason="bad_secret_header"}[24h]))`},
		{"mg_cf_foreign_worker_total", fmt.Sprintf(`sum(increase(mg_cf_foreign_worker_total{site=%q}[24h]))`, site)},
	}
	var bad, detail []string
	for _, eq := range errQueries {
		v, err := a.vmScalar(eq.q)
		if err != nil {
			return res(StatusFail, "VictoriaMetrics query failed: %v", err)
		}
		detail = append(detail, fmt.Sprintf("%s +%s", eq.name, formatNum(v)))
		if v > 0 {
			bad = append(bad, eq.name)
		}
	}
	// hdr-names is excluded: any client can make it missing by sending one
	// header name longer than 64 bytes (§9.3), so its rate says nothing about
	// the zone's Transform Rules.
	missing, err := a.vmScalar(`max(sum by (signal) (increase(mg_upstream_signal_missing_total{profile="cloudflare",signal!="hdr-names"}[24h])))`)
	if err != nil {
		return res(StatusFail, "VictoriaMetrics query failed: %v", err)
	}
	requests, err := a.vmScalar(`sum(increase(mg_requests_total[24h]))`)
	if err != nil {
		return res(StatusFail, "VictoriaMetrics query failed: %v", err)
	}
	var warn string
	if requests > 0 {
		rate := missing / requests
		detail = append(detail, fmt.Sprintf("worst signal missing rate %.2f%%", rate*100))
		if rate >= 0.01 {
			warn = "Tier 0 signal missing rate >= 1%"
		}
	} else {
		// Without any request samples the zeros above prove nothing: the
		// URL may not be the VictoriaMetrics that scrapes this Edge.
		warn = "no mg_requests_total samples in 24 h: check that --vm-url is the VictoriaMetrics that scrapes this site's Edge"
	}
	switch {
	case len(bad) > 0:
		return res(StatusFail, "non-zero in 24 h: %s (%s)", strings.Join(bad, ", "), strings.Join(detail, "; "))
	case warn != "":
		return res(StatusWarn, "%s (%s)", warn, strings.Join(detail, "; "))
	}
	return res(StatusPass, "%s", strings.Join(detail, "; "))
}

func formatNum(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// vmScalar runs an instant query and returns the first sample's value; an
// empty result (the series never existed) is 0.
func (a *auditor) vmScalar(query string) (float64, error) {
	u := strings.TrimRight(a.opts.VMURL, "/") + "/api/v1/query?" + url.Values{"query": {query}}.Encode()
	req, err := http.NewRequestWithContext(a.ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", cfapi.UserAgent)
	var hc http.Client
	if a.opts.HTTP != nil {
		hc = *a.opts.HTTP
	}
	if hc.Timeout == 0 || hc.Timeout > 30*time.Second {
		hc.Timeout = 30 * time.Second
	}
	resp, err := hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseVMScalar(query, body)
}

// parseVMScalar reads the first sample of an instant query response; an
// empty result (the series never existed) is 0.
func parseVMScalar(query string, body []byte) (float64, error) {
	var r struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value [2]json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Status != "success" {
		return 0, fmt.Errorf("unexpected response to %s", query)
	}
	if len(r.Data.Result) == 0 {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(r.Data.Result[0].Value[1], &s); err != nil {
		return 0, fmt.Errorf("unexpected sample in response to %s", query)
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("unexpected sample %q", s)
	}
	// NaN compares false with 0 and would read as "no increase".
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("sample %q of %s is not a finite number", s, query)
	}
	return v, nil
}

// 19. The Cloudflare IP snapshot must have been synced recently.
func checkIPSnapshotAge(a *auditor, def CheckDef) Result {
	if a.opts.CFIPs == "" {
		return res(StatusSkip, "pass --cf-ips <artifact> to check the Cloudflare IP snapshot")
	}
	data, err := readAtMost(a.opts.CFIPs, maxCFIPsArtifactSize)
	if err != nil {
		return res(StatusWarn, "cannot read %s: %v", a.opts.CFIPs, err)
	}
	art, err := intelsync.ParseCloudflareIPs(data)
	if err != nil {
		return res(StatusWarn, "%s is not a valid artifact: %v", a.opts.CFIPs, err)
	}
	st, last, err := intelsync.ReadSyncState(intelsync.StatePath(a.opts.CFIPs))
	if err != nil {
		return res(StatusWarn, "no sync state (%v); run mgctl cf ips sync", err)
	}
	age := a.opts.Now.Sub(last)
	switch {
	case age > 48*time.Hour:
		return res(StatusWarn, "last successful sync %s ago (%s); the daily mgctl cf ips sync is failing", age.Truncate(time.Minute), st.LastSuccess)
	case age < -5*time.Minute:
		return res(StatusWarn, "last_success %s is in the future", st.LastSuccess)
	}
	return res(StatusPass, "last successful sync %s ago; %d IPv4 / %d IPv6 ranges, etag %s", age.Truncate(time.Minute), len(art.IPv4CIDRs), len(art.IPv6CIDRs), st.ETag)
}

// maxCFIPsArtifactSize is the §12.1 limit of the cloudflare-ips artifact.
const maxCFIPsArtifactSize = 1 << 20

// readAtMost reads up to limit+1 bytes of a file, so a wrong path (a device,
// a huge file) cannot exhaust memory; the artifact parser rejects anything
// over the limit.
func readAtMost(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

// 20. Report the optional /__mg/ flood rate limiting rule.
func checkOptionalRules(a *auditor, def CheckDef) Result {
	rl, err := a.ruleset(cfapi.PhaseRateLimit)
	if err != nil {
		return apiProblem(def, err)
	}
	flood := floodRules(rl)
	if len(flood) == 0 {
		return res(StatusPass, "no /__mg/ flood rate limiting rule (optional, docs/08 §2.7)")
	}
	if custom, err := a.ruleset(cfapi.PhaseFirewallCustom); err == nil {
		if _, r, p := mgSkipRule(custom); r != nil && slices.Contains(p.Phases, cfapi.PhaseRateLimit) {
			return res(StatusWarn, "flood rule(s) %s exist but mg_skip_mg_paths skips http_ratelimit for /__mg/", strings.Join(ruleNames(flood), ", "))
		}
	}
	return res(StatusPass, "/__mg/ flood rate limiting rule(s) %s active", strings.Join(ruleNames(flood), ", "))
}

// 21. The __Host- clearance cookie needs https (D-32).
func checkAlwaysUseHTTPS(a *auditor, def CheckDef) Result {
	v, err := a.setting("always_use_https")
	if err != nil {
		return apiProblem(def, err)
	}
	hsts := "HSTS unknown"
	if s, err := a.rawSetting("security_header"); err == nil {
		var sh struct {
			STS *struct {
				Enabled bool  `json:"enabled"`
				MaxAge  int64 `json:"max_age"`
			} `json:"strict_transport_security"`
		}
		if json.Unmarshal(s.Value, &sh) == nil && sh.STS != nil {
			if sh.STS.Enabled {
				hsts = fmt.Sprintf("HSTS on (max-age %d)", sh.STS.MaxAge)
			} else {
				hsts = "HSTS off (recommended on)"
			}
		}
	}
	if v == "on" {
		return res(StatusPass, "always_use_https = on; %s", hsts)
	}
	return res(StatusFail, "always_use_https = %s: http visitors never keep the __Host- clearance cookie and require_clearance routes challenge them forever (D-32); %s", v, hsts)
}
