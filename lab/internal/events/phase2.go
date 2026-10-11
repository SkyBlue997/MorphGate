package events

// Phase 2 checks (docs/impl/phase2-spec.md §17 WP-L2, §20):
//
//   - Providers: on a route that offers Turnstile, every interactive
//     challenge decided for a visitor whose country is not on the scenario's
//     allowed list (a country in deny_countries, an unknown or malformed
//     one) names a first provider other than Turnstile, and every one for an
//     allowed country names Turnstile (selection: first), so the negative
//     half cannot pass vacuously.
//   - Near-line: mg-nearline's scanner reports a shadow verdict without
//     writing it and writes an enforce verdict; each within the latency
//     bound after the request that triggered it; afterwards the request of
//     the address with the enforce verdict carries that verdict, scores
//     higher than the controls and is challenged, never blocked, while the
//     controls (the shadow address, a fresh one) are forwarded. Verdict
//     lines carry pseudonymous keys only and never the scanner label.

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// ProvidersOptions selects the decisions of the provider scenario.
type ProvidersOptions struct {
	Site string
	// Route is the route id whose interactive challenges are checked.
	Route string
	// Offer lists the countries (as the decision event records them) that
	// must be offered the provider; every other country, and none, must not.
	Offer []string
	// Provider is the external provider id (default "turnstile").
	Provider string
	// WantOffered and WantWithheld are the exact numbers of challenges with
	// and without the provider first (0: at least one).
	WantOffered, WantWithheld int
}

// ProvidersReport is the outcome of CheckProviders.
type ProvidersReport struct {
	Provider          string
	Offered, Withheld int
	// Countries maps each recorded country ("unknown" when none) to the
	// number of challenges seen for it.
	Countries map[string]int
	Problems  []string
}

// OK reports whether the check passed.
func (r ProvidersReport) OK() bool { return len(r.Problems) == 0 }

func (r ProvidersReport) String() string {
	var cs []string
	for _, c := range sortedKeys(r.Countries) {
		cs = append(cs, fmt.Sprintf("%s %d", c, r.Countries[c]))
	}
	return fmt.Sprintf("providers: %s first in %d interactive challenge(s) for allowed countries, withheld from %d (countries: %s)",
		r.Provider, r.Offered, r.Withheld, strings.Join(cs, ", "))
}

// country returns the Cloudflare country of the decision, else the GeoLite2
// one (phase2-spec §8.1), else "".
func (r *Record) country() string {
	if r.Ctx == nil {
		return ""
	}
	if c := r.Ctx.Net.UpstreamCountry; c != "" {
		return c
	}
	return r.Ctx.Net.Country
}

// CheckProviders checks who was offered the external provider on o.Route.
func CheckProviders(recs []Record, o ProvidersOptions) ProvidersReport {
	rep := ProvidersReport{Provider: o.Provider, Countries: map[string]int{}}
	if rep.Provider == "" {
		rep.Provider = "turnstile"
	}
	problem := func(format string, args ...any) { rep.Problems = append(rep.Problems, fmt.Sprintf(format, args...)) }
	if o.Route == "" {
		problem("no route given")
		return rep
	}
	for i := range recs {
		r := &recs[i]
		if r.Kind != "decision" || r.Ctx == nil || r.Decision == nil || (o.Site != "" && r.Site != o.Site) || r.Ctx.RouteID != o.Route {
			continue
		}
		if r.Decision.Action != "challenge" {
			continue
		}
		if r.Decision.ChallengeType != "interactive" {
			problem("%s: %s challenge on route %s, want interactive", r.describe(), r.Decision.ChallengeType, o.Route)
			continue
		}
		c := r.country()
		label := c
		if label == "" {
			label = "unknown"
		}
		rep.Countries[label]++
		first := r.Decision.ProviderID
		switch {
		case c != "" && slices.Contains(o.Offer, c):
			rep.Offered++
			if first != rep.Provider {
				problem("%s: country %s was not offered %s (first provider %q)", r.describe(), c, rep.Provider, first)
			}
		default:
			rep.Withheld++
			if first == rep.Provider {
				problem("%s: country %s got a C that offers %s first", r.describe(), label, rep.Provider)
			}
			if first == "" {
				problem("%s: interactive challenge without a provider", r.describe())
			}
		}
	}
	switch {
	case o.WantOffered > 0 && rep.Offered != o.WantOffered:
		problem("%d challenge(s) for allowed countries, want %d", rep.Offered, o.WantOffered)
	case rep.Offered == 0:
		problem("no interactive challenge for an allowed country on route %s: the check would pass vacuously", o.Route)
	}
	switch {
	case o.WantWithheld > 0 && rep.Withheld != o.WantWithheld:
		problem("%d challenge(s) for denied or unknown countries, want %d", rep.Withheld, o.WantWithheld)
	case rep.Withheld == 0:
		problem("no interactive challenge for a denied or unknown country on route %s", o.Route)
	}
	return rep
}

// NearlineOptions selects the records of the near-line scenario.
type NearlineOptions struct {
	Site string
	// Detector is the near-line detector (default "scanner"); its verdicts
	// have source "nearline/<detector>".
	Detector string
	// After is the path prefix of the requests sent once the verdicts exist.
	After string
	// ShadowIP and EnforceIP sent the bait requests while the detector was
	// in shadow and in enforce mode; FreshIP (optional) sent none.
	ShadowIP, EnforceIP, FreshIP string
	// MaxLatencyMS bounds the time from the triggering request's decision
	// event to the verdict (0: not checked).
	MaxLatencyMS int64
}

// NearlineReport is the outcome of CheckNearline.
type NearlineReport struct {
	Detector string
	// Verdict lines of the detector, by mode.
	Shadow, Enforce int
	// MaxLatencyMS is the longest time from a triggering decision to its
	// verdict.
	MaxLatencyMS int64
	// The after-requests: the enforce address's (challenged) and the
	// controls' (forwarded), with the lowest and highest scores.
	Challenged, Controls       int
	EnforceScore, ControlScore float64
	Problems                   []string
}

// OK reports whether the check passed.
func (r NearlineReport) OK() bool { return len(r.Problems) == 0 }

func (r NearlineReport) String() string {
	return fmt.Sprintf("nearline/%s: %d shadow and %d enforce verdict(s), at most %d ms after the triggering request; %d request(s) with the enforce verdict challenged (score >= %.0f), %d control request(s) forwarded (score <= %.0f)",
		r.Detector, r.Shadow, r.Enforce, r.MaxLatencyMS, r.Challenged, r.EnforceScore, r.Controls, r.ControlScore)
}

// pseudoKey is the shape of a kh() key (Phase 1 spec §9.6): 32 lower-case
// hex characters, never an address.
var pseudoKey = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (r *Record) decisionIP() string {
	if r.Ctx == nil {
		return ""
	}
	return r.Ctx.Net.IP
}

func (r *Record) nearlineVerdicts() []CtxVerdict {
	if r.Ctx == nil {
		return nil
	}
	var out []CtxVerdict
	for _, v := range r.Ctx.Verdicts {
		if strings.HasPrefix(v.Source, "nearline/") {
			out = append(out, v)
		}
	}
	return out
}

// CheckNearline checks the near-line run: recs holds the Edge's events and
// mg-nearline's kind=verdict lines.
func CheckNearline(recs []Record, o NearlineOptions) NearlineReport {
	rep := NearlineReport{Detector: o.Detector}
	if rep.Detector == "" {
		rep.Detector = "scanner"
	}
	problem := func(format string, args ...any) { rep.Problems = append(rep.Problems, fmt.Sprintf(format, args...)) }
	if o.After == "" || o.ShadowIP == "" || o.EnforceIP == "" {
		problem("the after prefix and the shadow and enforce addresses are required")
		return rep
	}
	source := "nearline/" + rep.Detector
	site := func(r *Record) bool { return o.Site == "" || r.Site == o.Site }

	// Verdict lines (phase2-spec §13.4, §15.3).
	enforceKeys := map[string]bool{}
	for i := range recs {
		r := &recs[i]
		if r.Kind != "verdict" || !site(r) {
			continue
		}
		if _, err := netip.ParseAddr(r.Key); err == nil || !pseudoKey.MatchString(r.Key) {
			problem("%s: the key is not a pseudonymous key", r.describe())
		}
		if slices.Contains(r.Labels, "scanner") {
			problem("%s: a near-line verdict carries the scanner label (D-53)", r.describe())
		}
		if r.Source != source || r.Detector != rep.Detector {
			continue
		}
		var ip string
		switch r.Mode {
		case "shadow":
			rep.Shadow++
			ip = o.ShadowIP
			if r.Written {
				problem("%s: a shadow verdict was written", r.describe())
			}
		case "enforce":
			rep.Enforce++
			ip = o.EnforceIP
			if !r.Written {
				problem("%s: the enforce verdict was not written", r.describe())
			}
			enforceKeys[r.Key] = true
		default:
			problem("%s: unknown mode %q", r.describe(), r.Mode)
			continue
		}
		if r.Risk == nil || r.Risk.Value <= 0 || r.Risk.Value > 100 {
			problem("%s: risk outside 1-100", r.describe())
		}
		// The trigger is the address's last decision before the verdict.
		var trigger *Record
		for j := range recs {
			d := &recs[j]
			if d.Kind == "decision" && site(d) && d.decisionIP() == ip && d.TS <= r.TS && (trigger == nil || d.TS > trigger.TS) {
				trigger = d
			}
		}
		if trigger == nil {
			problem("%s: no decision event from %s before the verdict", r.describe(), ip)
			continue
		}
		lat := r.TS - trigger.TS
		rep.MaxLatencyMS = max(rep.MaxLatencyMS, lat)
		if o.MaxLatencyMS > 0 && lat > o.MaxLatencyMS {
			problem("%s: %d ms after the triggering request, want <= %d ms", r.describe(), lat, o.MaxLatencyMS)
		}
	}
	if rep.Shadow == 0 {
		problem("no shadow %s verdict line", source)
	}
	if rep.Enforce == 0 {
		problem("no enforce %s verdict line", source)
	}

	// Decisions: a near-line verdict never blocks (D-53), and the
	// after-requests.
	first := true
	for i := range recs {
		r := &recs[i]
		if r.Kind != "decision" || !site(r) {
			continue
		}
		nl := r.nearlineVerdicts()
		action, dry := r.action()
		if len(nl) > 0 && (action == "block" || r.botClass() == "scanner") {
			problem("%s: decided %q (class %q) with a near-line verdict", r.describe(), action, r.botClass())
		}
		if !strings.HasPrefix(r.decisionPath(), o.After) {
			continue
		}
		score := 0.0
		if r.Risk != nil {
			score = r.Risk.Score
		}
		switch ip := r.decisionIP(); ip {
		case o.EnforceIP:
			rep.Challenged++
			if first || score < rep.EnforceScore {
				rep.EnforceScore = score
			}
			first = false
			if !slices.ContainsFunc(nl, func(v CtxVerdict) bool { return v.Source == source && enforceKeys[v.Key] }) {
				problem("%s: the request does not carry the enforce %s verdict", r.describe(), source)
			}
			if action != "challenge" || dry {
				problem("%s: decided %q (dry_run %v), want an enforced challenge", r.describe(), action, dry)
			}
		case o.ShadowIP, o.FreshIP:
			if ip == "" {
				continue
			}
			rep.Controls++
			rep.ControlScore = max(rep.ControlScore, score)
			if len(nl) > 0 {
				problem("%s: a control request carries a near-line verdict (%s)", r.describe(), nl[0].Source)
			}
			if action != "allow" && action != "log" && action != "tag" {
				problem("%s: control request decided %q, want it forwarded", r.describe(), action)
			}
		}
	}
	switch {
	case rep.Challenged == 0:
		problem("no request from %s under %q", o.EnforceIP, o.After)
	case rep.Controls == 0:
		problem("no control request under %q", o.After)
	case rep.EnforceScore <= rep.ControlScore:
		problem("the enforce verdict did not raise the risk: score %.0f, controls up to %.0f", rep.EnforceScore, rep.ControlScore)
	}
	return rep
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
