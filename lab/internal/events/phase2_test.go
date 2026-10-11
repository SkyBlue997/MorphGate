package events

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// testdata/phase2-run.jsonl holds the decision, access and feedback events
// of site labp2 from a passing scripts/lab-e2e.sh run (run id replaced by
// "sample", "signals" and "hits" dropped); testdata/phase2-verdicts.jsonl
// holds mg-nearline's kind=verdict lines of the same run. They pin the
// event fields the Phase 2 checks read.
const (
	p2Run      = "testdata/phase2-run.jsonl"
	p2Verdicts = "testdata/phase2-verdicts.jsonl"
	// Addresses of phase2-nearline-baits / -after in that run.
	shadowIP  = "203.0.113.120"
	enforceIP = "203.0.113.121"
	freshIP   = "203.0.113.122"
)

func recordedPhase2(t *testing.T) []Record {
	t.Helper()
	recs, err := ReadFiles(p2Run, p2Verdicts)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func providersOpts() ProvidersOptions {
	return ProvidersOptions{Site: "labp2", Route: "login", Offer: []string{"US", "DE"}, WantOffered: 3, WantWithheld: 7}
}

func nearlineOpts() NearlineOptions {
	return NearlineOptions{Site: "labp2", After: "/nl/sample/", ShadowIP: shadowIP, EnforceIP: enforceIP,
		FreshIP: freshIP, MaxLatencyMS: 10000}
}

func problems(ps []string) string { return strings.Join(ps, "\n") }

func TestRecordedPhase2Run(t *testing.T) {
	recs := recordedPhase2(t)
	if recs[len(recs)-1].File != p2Verdicts || recs[0].File != p2Run {
		t.Errorf("ReadFiles does not name the files: %q, %q", recs[0].File, recs[len(recs)-1].File)
	}
	prv := CheckProviders(recs, providersOpts())
	if !prv.OK() || prv.Countries["CN"] != 3 || prv.Countries["unknown"] != 3 || prv.Countries["T1"] != 1 {
		t.Errorf("providers on the recorded run: %+v", prv)
	}
	if want := "turnstile first in 3 interactive challenge(s) for allowed countries, withheld from 7 (countries: CN 3, DE 2, T1 1, US 1, unknown 3)"; !strings.Contains(prv.String(), want) {
		t.Errorf("String() = %q", prv.String())
	}
	nl := CheckNearline(recs, nearlineOpts())
	if !nl.OK() || nl.Shadow != 1 || nl.Enforce != 1 || nl.Challenged != 1 || nl.Controls != 2 ||
		nl.EnforceScore != 73 || nl.ControlScore != 45 || nl.MaxLatencyMS <= 0 || nl.MaxLatencyMS > 10000 {
		t.Errorf("nearline on the recorded run: %+v", nl)
	}
	if !strings.Contains(nl.String(), "1 shadow and 1 enforce verdict(s)") {
		t.Errorf("String() = %q", nl.String())
	}
	clr := CheckClearance(recs, ClearanceOptions{Site: "labp2", Protected: "/p2/", WantFeedback: 8})
	if !clr.OK() || clr.Renewals != 2 || clr.Submissions != 12 || clr.Protected != 13 {
		t.Errorf("clearance on the recorded run: %+v", clr)
	}
	if !strings.Contains(clr.String(), "8 feedback event(s) (and 2 of renewals)") {
		t.Errorf("String() = %q", clr.String())
	}
}

func TestRiskAcceptsObjectAndNumber(t *testing.T) {
	var r Record
	if err := json.Unmarshal([]byte(`{"kind":"verdict","risk":85}`), &r); err != nil || r.Risk == nil || r.Risk.Value != 85 {
		t.Errorf("verdict risk: %+v, %v", r.Risk, err)
	}
	r = Record{}
	if err := json.Unmarshal([]byte(`{"kind":"decision","risk":{"bot_class":"human_likely","score":20,"top_reasons":["x"]}}`), &r); err != nil ||
		r.Risk.Score != 20 || r.Risk.BotClass != "human_likely" || r.Risk.TopReasons[0] != "x" {
		t.Errorf("decision risk: %+v, %v", r.Risk, err)
	}
	for _, bad := range []string{`{"kind":"x","risk":"high"}`, `{"kind":"x","risk":{"score":"x"}}`, `{"kind":"x","risk":[1]}`} {
		if err := json.Unmarshal([]byte(bad), &Record{}); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

// find returns the first record that matches.
func find(t *testing.T, recs []Record, match func(*Record) bool) *Record {
	t.Helper()
	for i := range recs {
		if match(&recs[i]) {
			return &recs[i]
		}
	}
	t.Fatal("no matching record")
	return nil
}

func loginDecision(country string) func(*Record) bool {
	return func(r *Record) bool {
		return r.Kind == "decision" && r.Ctx != nil && r.Ctx.RouteID == "login" && r.Ctx.Net.UpstreamCountry == country
	}
}

func TestCheckProvidersFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, recs []Record)
		opts   func(*ProvidersOptions)
		want   string
	}{
		{"denied country offered", func(t *testing.T, recs []Record) {
			find(t, recs, loginDecision("CN")).Decision.ProviderID = "turnstile"
		}, nil, "country CN got a C that offers turnstile first"},
		{"unknown country offered", func(t *testing.T, recs []Record) {
			find(t, recs, loginDecision("")).Decision.ProviderID = "turnstile"
		}, nil, "country unknown got a C that offers turnstile first"},
		{"allowed country not offered", func(t *testing.T, recs []Record) {
			find(t, recs, loginDecision("DE")).Decision.ProviderID = "self_hold"
		}, nil, `country DE was not offered turnstile (first provider "self_hold")`},
		{"no provider", func(t *testing.T, recs []Record) {
			find(t, recs, loginDecision("T1")).Decision.ProviderID = ""
		}, nil, "interactive challenge without a provider"},
		{"not interactive", func(t *testing.T, recs []Record) {
			find(t, recs, loginDecision("CN")).Decision.ChallengeType = "pow"
		}, nil, "pow challenge on route login, want interactive"},
		{"geo country counts", func(t *testing.T, recs []Record) {
			r := find(t, recs, loginDecision(""))
			r.Ctx.Net.Country = "US"
		}, nil, "country US was not offered turnstile"},
		{"offered count", nil, func(o *ProvidersOptions) { o.WantOffered = 4 }, "3 challenge(s) for allowed countries, want 4"},
		{"withheld count", nil, func(o *ProvidersOptions) { o.WantWithheld = 6 }, "7 challenge(s) for denied or unknown countries, want 6"},
		{"vacuous", nil, func(o *ProvidersOptions) { o.Offer, o.WantOffered, o.WantWithheld = []string{"FR"}, 0, 0 }, "would pass vacuously"},
		// Route "account" never offers Turnstile and saw only US visitors.
		{"nothing withheld", nil, func(o *ProvidersOptions) {
			o.Route, o.Offer, o.WantOffered, o.WantWithheld = "account", []string{"US"}, 0, 0
		}, "no interactive challenge for a denied or unknown country on route account"},
		{"other route", nil, func(o *ProvidersOptions) { o.Route, o.Offer, o.WantOffered, o.WantWithheld = "account", nil, 0, 0 }, "would pass vacuously"},
		{"no route", nil, func(o *ProvidersOptions) { o.Route = "" }, "no route given"},
	}
	for _, tc := range cases {
		recs := recordedPhase2(t)
		if tc.mutate != nil {
			tc.mutate(t, recs)
		}
		o := providersOpts()
		if tc.opts != nil {
			tc.opts(&o)
		}
		rep := CheckProviders(recs, o)
		if rep.OK() || !strings.Contains(problems(rep.Problems), tc.want) {
			t.Errorf("%s: problems = %q, want %q", tc.name, rep.Problems, tc.want)
		}
	}
}

func verdictLine(mode string) func(*Record) bool {
	return func(r *Record) bool { return r.Kind == "verdict" && r.Mode == mode }
}

func afterDecision(ip string) func(*Record) bool {
	return func(r *Record) bool {
		return r.Kind == "decision" && r.decisionIP() == ip && strings.HasPrefix(r.decisionPath(), "/nl/sample/")
	}
}

func TestCheckNearlineFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, recs []Record)
		opts   func(*NearlineOptions)
		want   string
	}{
		{"shadow written", func(t *testing.T, recs []Record) {
			find(t, recs, verdictLine("shadow")).Written = true
		}, nil, "a shadow verdict was written"},
		{"enforce not written", func(t *testing.T, recs []Record) {
			find(t, recs, verdictLine("enforce")).Written = false
		}, nil, "the enforce verdict was not written"},
		{"address as key", func(t *testing.T, recs []Record) {
			find(t, recs, verdictLine("shadow")).Key = shadowIP
		}, nil, "not a pseudonymous key"},
		{"scanner label", func(t *testing.T, recs []Record) {
			v := find(t, recs, verdictLine("enforce"))
			v.Labels = append(v.Labels, "scanner")
		}, nil, "carries the scanner label (D-53)"},
		{"risk out of range", func(t *testing.T, recs []Record) {
			find(t, recs, verdictLine("enforce")).Risk.Value = 0
		}, nil, "risk outside 1-100"},
		{"unknown mode", func(t *testing.T, recs []Record) {
			find(t, recs, verdictLine("shadow")).Mode = "dry"
		}, nil, `unknown mode "dry"`},
		{"no shadow verdict", func(t *testing.T, recs []Record) {
			find(t, recs, verdictLine("shadow")).Source = "nearline/high_rate"
		}, nil, "no shadow nearline/scanner verdict line"},
		{"slow", func(t *testing.T, recs []Record) {
			find(t, recs, verdictLine("enforce")).TS += 20000
		}, nil, "after the triggering request, want <= 10000 ms"},
		{"no trigger", nil, func(o *NearlineOptions) { o.ShadowIP = "198.51.100.1" }, "no decision event from 198.51.100.1 before the verdict"},
		{"enforce address forwarded", func(t *testing.T, recs []Record) {
			find(t, recs, afterDecision(enforceIP)).Decision.Action = "tag"
		}, nil, `decided "tag" (dry_run false), want an enforced challenge`},
		{"challenge only recorded", func(t *testing.T, recs []Record) {
			find(t, recs, afterDecision(enforceIP)).Decision.DryRun = true
		}, nil, "want an enforced challenge"},
		{"verdict blocks", func(t *testing.T, recs []Record) {
			find(t, recs, afterDecision(enforceIP)).Decision.Action = "block"
		}, nil, `decided "block" (class "automation_likely") with a near-line verdict`},
		{"scanner class", func(t *testing.T, recs []Record) {
			find(t, recs, afterDecision(enforceIP)).Risk.BotClass = "scanner"
		}, nil, `(class "scanner") with a near-line verdict`},
		{"verdict missing", func(t *testing.T, recs []Record) {
			find(t, recs, afterDecision(enforceIP)).Ctx.Verdicts = nil
		}, nil, "does not carry the enforce nearline/scanner verdict"},
		{"another key", func(t *testing.T, recs []Record) {
			find(t, recs, afterDecision(enforceIP)).Ctx.Verdicts[0].Key = strings.Repeat("0", 32)
		}, nil, "does not carry the enforce nearline/scanner verdict"},
		{"control with verdict", func(t *testing.T, recs []Record) {
			d := find(t, recs, afterDecision(freshIP))
			d.Ctx.Verdicts = []CtxVerdict{{Type: "ip", Key: strings.Repeat("a", 32), Risk: 80, Source: "nearline/scanner"}}
		}, nil, "a control request carries a near-line verdict"},
		{"control challenged", func(t *testing.T, recs []Record) {
			find(t, recs, afterDecision(shadowIP)).Decision.Action = "challenge"
		}, nil, `control request decided "challenge", want it forwarded`},
		{"not raised", func(t *testing.T, recs []Record) {
			find(t, recs, afterDecision(freshIP)).Risk.Score = 73
		}, nil, "did not raise the risk: score 73, controls up to 73"},
		{"no after-requests", nil, func(o *NearlineOptions) { o.After = "/elsewhere/" }, "no request from 203.0.113.121"},
		{"no controls", nil, func(o *NearlineOptions) { o.ShadowIP, o.FreshIP = "198.51.100.1", "" }, "no control request"},
		{"missing options", nil, func(o *NearlineOptions) { o.EnforceIP = "" }, "are required"},
	}
	for _, tc := range cases {
		recs := recordedPhase2(t)
		if tc.mutate != nil {
			tc.mutate(t, recs)
		}
		o := nearlineOpts()
		if tc.opts != nil {
			tc.opts(&o)
		}
		rep := CheckNearline(recs, o)
		if rep.OK() || !strings.Contains(problems(rep.Problems), tc.want) {
			t.Errorf("%s: problems = %q, want %q", tc.name, rep.Problems, tc.want)
		}
	}
	// Without the verdict file there are no verdict lines at all.
	recs, err := ReadFiles(p2Run)
	if err != nil {
		t.Fatal(err)
	}
	if rep := CheckNearline(recs, nearlineOpts()); rep.OK() || !strings.Contains(problems(rep.Problems), "no enforce nearline/scanner verdict line") {
		t.Errorf("events only: %q", rep.Problems)
	}
}

func TestClearanceRenewals(t *testing.T) {
	recs := recordedPhase2(t)
	// A renewal answered with a new C (200), or a renewal feedback that is
	// not a failure, is a problem.
	find(t, recs, func(r *Record) bool { return r.Kind == "access" && r.Path == "/__mg/c/renew" }).Status = 200
	find(t, recs, func(r *Record) bool { return r.Kind == "feedback" && r.Renew }).Outcome = "renew_rebind"
	rep := CheckClearance(recs, ClearanceOptions{Site: "labp2", Protected: "/p2/", WantFeedback: 8})
	got := problems(rep.Problems)
	if !strings.Contains(got, "challenge submission answered 200") || !strings.Contains(got, `unexpected feedback outcome "renew_rebind"`) {
		t.Errorf("problems = %q", rep.Problems)
	}
}

func TestReadFilesErrors(t *testing.T) {
	if _, err := ReadFiles("testdata/missing.jsonl"); err == nil {
		t.Error("missing file: no error")
	}
	bad := t.TempDir() + "/bad.jsonl"
	if err := os.WriteFile(bad, []byte("{\"kind\":\"access\"}\nnot json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFiles(p2Verdicts, bad); err == nil || !strings.Contains(err.Error(), "bad.jsonl: line 2") {
		t.Errorf("malformed second file: %v", err)
	}
}
