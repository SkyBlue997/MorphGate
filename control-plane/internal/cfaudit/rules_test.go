package cfaudit

import (
	"encoding/json"
	"math"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"morphgate/control-plane/internal/cfapi"
)

const adaptersDir = "../../../adapters/cloudflare/"

type templateRule struct {
	Ref              string `json:"ref"`
	Expression       string `json:"expression"`
	Action           string `json:"action"`
	ActionParameters struct {
		Headers map[string]struct {
			Operation  string `json:"operation"`
			Expression string `json:"expression"`
			Value      string `json:"value"`
		} `json:"headers"`
		Cache  *bool    `json:"cache"`
		Phases []string `json:"phases"`
	} `json:"action_parameters"`
}

func loadTemplate(t *testing.T, name string) templateRule {
	t.Helper()
	var rs struct {
		Rules []templateRule `json:"rules"`
	}
	if err := json.Unmarshal(mustRead(t, adaptersDir+name), &rs); err != nil || len(rs.Rules) != 1 {
		t.Fatalf("%s: %v", name, err)
	}
	return rs.Rules[0]
}

// §14.3 check 6: the expectations written in Go match the adapters
// templates (adapters/ is outside the Go module and cannot be embedded).
func TestExpectationsMatchAdapterTemplates(t *testing.T) {
	signals := loadTemplate(t, "transform-rule.request-headers.json")
	if !signalsRefPattern.MatchString(signals.Ref) || signals.Action != "rewrite" || signals.Expression != "true" {
		t.Errorf("signals rule %+v", signals)
	}
	sets := map[string]string{}
	var removes []string
	for h, op := range signals.ActionParameters.Headers {
		switch op.Operation {
		case "set":
			sets[h] = op.Expression
		case "remove":
			removes = append(removes, h)
		default:
			t.Errorf("%s: operation %q", h, op.Operation)
		}
	}
	if len(sets) != len(Tier0Headers) {
		t.Errorf("template sets %d headers, Go expects %d", len(sets), len(Tier0Headers))
	}
	for h, want := range Tier0Headers {
		if sets[h] != want {
			t.Errorf("%s: template %q, Go %q", h, sets[h], want)
		}
	}
	sort.Strings(removes)
	tier1 := append([]string(nil), Tier1Headers...)
	sort.Strings(tier1)
	if !slices.Equal(removes, tier1) {
		t.Errorf("template removes %v, Go %v", removes, tier1)
	}

	bypass := loadTemplate(t, "cache-rule.bypass-mg.json")
	if bypass.Ref != RefBypassMG || bypass.Expression != BypassMGExpression || bypass.Action != "set_cache_settings" ||
		bypass.ActionParameters.Cache == nil || *bypass.ActionParameters.Cache {
		t.Errorf("bypass template %+v", bypass)
	}
	for _, f := range []string{"waf-skip.mg.json", "waf-skip.mg.no-flood-limit.json"} {
		skip := loadTemplate(t, f)
		if skip.Ref != RefSkipMG || skip.Expression != SkipMGExpression || skip.Action != "skip" ||
			!slices.Contains(skip.ActionParameters.Phases, "http_request_sbfm") || !coversMGPrefix(skip.Expression) {
			t.Errorf("%s: %+v", f, skip)
		}
	}

	key := loadTemplate(t, "transform-rule.upstream-key.json")
	op, ok := key.ActionParameters.Headers[UpstreamKeyHeader]
	if !ok || op.Operation != "set" || !strings.HasPrefix(op.Value, UpstreamKeyPlaceholderPrefix) || key.Expression != "true" {
		t.Errorf("upstream key template %+v", key)
	}
	if regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(op.Value) {
		t.Error("the placeholder must never look like a real key")
	}
}

func TestNormalizeExpr(t *testing.T) {
	same := [][2]string{
		{BypassMGExpression, "starts_with( http.request.uri.path ,\"/__mg/\" )  and\n not starts_with(http.request.uri.path, \"/__mg/s/\")"},
		{`http.host in {"a" "b"}`, `http.host in { "a"  "b" }`},
	}
	for _, p := range same {
		if normalizeExpr(p[0]) != normalizeExpr(p[1]) {
			t.Errorf("%q != %q", normalizeExpr(p[0]), normalizeExpr(p[1]))
		}
	}
	different := [][2]string{
		{`a eq "x y"`, `a eq "x  y"`}, // whitespace inside strings is significant
		{BypassMGExpression, SkipMGExpression},
		{"a and b", "a or b"},
	}
	for _, p := range different {
		if normalizeExpr(p[0]) == normalizeExpr(p[1]) {
			t.Errorf("%q == %q", p[0], p[1])
		}
	}
}

func TestHostCoverage(t *testing.T) {
	hosts := []string{"example.com", "www.example.com"}
	cases := []struct {
		expr       string
		missing    []string
		recognised bool
	}{
		{"true", nil, true},
		{"(true)", nil, true},
		{`http.host in {"example.com" "www.example.com" "other.example.com"}`, nil, true},
		{`http.host in {"example.com"}`, []string{"www.example.com"}, true},
		{`(http.host eq "example.com") or (http.host == "www.example.com")`, nil, true},
		// String comparisons are case-sensitive and Cloudflare compares
		// http.host with the lower-case host name, so an upper-case literal
		// never matches it: it must not count as covering the host.
		{`http.host eq "EXAMPLE.com" or http.host eq "www.example.com"`, []string{"example.com"}, true},
		{`http.host in {"Example.com" "www.example.com"}`, []string{"example.com"}, true},
		{`http.host eq "example.com"`, []string{"www.example.com"}, true},
		{`http.host in {"example.com" "www.example.com"} and not ip.src in {1.2.3.4}`, nil, false},
		{`http.host contains "example"`, nil, false},
		{`starts_with(http.request.uri.path, "/")`, nil, false},
		{`true or http.host eq "x"`, nil, false},
	}
	for _, tc := range cases {
		missing, ok := missingHosts(tc.expr, hosts)
		if ok != tc.recognised || !slices.Equal(missing, tc.missing) {
			t.Errorf("%s: missing %v ok %v, want %v %v", tc.expr, missing, ok, tc.missing, tc.recognised)
		}
	}
}

func TestRestrictedToStatic(t *testing.T) {
	yes := []string{
		`http.request.uri.path.extension in {"js" "css" "png" "woff2"}`,
		`(http.host eq "example.com" and http.request.uri.path.extension in {"js" "css"})`,
		`http.request.uri.path.extension eq "webp"`,
		`ends_with(http.request.uri.path, ".js") and http.host eq "example.com"`,
		`starts_with(http.request.uri.path, "/__mg/s/")`,
		// Other terms of a conjunction only narrow it, negated or not.
		`http.request.uri.path.extension in {"css"} and not http.host eq "static.example.com"`,
		`http.request.uri.path.extension in {"css"} && !(http.host in {"a.example.com" "b.example.com"})`,
		`http.request.uri.path.extension in {"css"} and http.request.uri.path != "/x.css"`,
		// Keywords inside string literals are data.
		`http.request.uri.path.extension in {"css"} and http.host eq "or"`,
		`http.request.uri.path.extension in {"css"} and not starts_with(http.request.uri.path, "/a || not b")`,
	}
	no := []string{
		`true`,
		`http.host eq "example.com"`,
		`http.request.uri.path.extension in {"js" "html"}`,
		`http.request.uri.path.extension in {"js"} or http.host eq "example.com"`,
		`not http.request.uri.path.extension in {"js"}`,
		`http.request.uri.path.extension in {""}`,
		`starts_with(http.request.uri.path, "/static/")`,
		`starts_with(http.request.uri.path, "/__mg/")`,
		// A disjunction or exclusive or at any depth, in any spelling, can
		// match pages whatever the extension test says.
		`http.host eq "example.com" and (http.request.uri.path.extension in {"css" "js"} or starts_with(http.request.uri.path, "/blog/"))`,
		`http.request.uri.path.extension in {"css"}||true`,
		`(http.request.uri.path.extension in {"css"})or(true)`,
		`http.request.uri.path.extension in {"css"} xor true`,
		`http.request.uri.path.extension in {"css"} ^^ true`,
		`http.request.uri.path.extension in {"css"} OR true`,
		// A negation that covers the extension test inverts it.
		`not (http.host eq "example.com" and http.request.uri.path.extension in {"css"})`,
		`!(http.request.uri.path.extension in {"css"}) and http.host eq "example.com"`,
		`http.host eq "example.com" and not ends_with(http.request.uri.path, ".css")`,
		// Unreadable expressions are never static.
		`http.request.uri.path.extension in {"css} and true`,
		`http.request.uri.path.extension in {"css"} and (true`,
	}
	for _, e := range yes {
		if !restrictedToStatic(e) {
			t.Errorf("%s: want static", e)
		}
	}
	for _, e := range no {
		if restrictedToStatic(e) {
			t.Errorf("%s: want not static", e)
		}
	}
}

// §14.3 check 14: simple negated terms only exclude what they mention; a
// negated compound term, nested negations and unreadable expressions keep
// the literal text.
func TestWithoutExclusions(t *testing.T) {
	mg := `/__mg`
	cases := []struct {
		expr    string
		mention bool // the result still mentions /__mg
	}{
		{`http.request.uri.path contains "/wp-" and not starts_with(http.request.uri.path, "/__mg/")`, false},
		{`!(starts_with(http.request.uri.path, "/__mg/")) && ip.src.country in {"T1"}`, false},
		{`not http.request.uri.path eq "/__mg/c" and http.host eq "example.com"`, false},
		{`starts_with(http.request.uri.path, "/__mg/")`, true},
		{`http.request.uri.path ne "/__mg/c"`, true}, // not a negation keyword: literal reading
		{`not (http.host eq "example.com" and starts_with(http.request.uri.path, "/__mg/"))`, true},
		{`not (not starts_with(http.request.uri.path, "/__mg/"))`, true},
		{`not (a and not starts_with(http.request.uri.path, "/__mg/"))`, true},
		{`not starts_with(http.request.uri.path, "/__mg/`, true}, // unterminated string
	}
	for _, tc := range cases {
		if got := strings.Contains(withoutExclusions(tc.expr), mg); got != tc.mention {
			t.Errorf("%s: mentions /__mg after exclusions = %v, want %v (%q)", tc.expr, got, tc.mention, withoutExclusions(tc.expr))
		}
	}
}

func TestTokenize(t *testing.T) {
	toks, ok := tokenize(`a||b and r#"x "or" y"# ne "q\"or" && !(c != 1)`)
	if !ok {
		t.Fatal("not ok")
	}
	var kinds []string
	for _, tk := range toks {
		switch {
		case isDisjunction(tk):
			kinds = append(kinds, "OR")
		case isConjunction(tk):
			kinds = append(kinds, "AND")
		case isNegation(tk):
			kinds = append(kinds, "NOT")
		}
	}
	if strings.Join(kinds, " ") != "OR AND AND NOT" {
		t.Errorf("connectives %v", kinds)
	}
	for _, bad := range []string{`"open`, `(a`, `a)`, `{a)`, `r#"x"`, `"\`} {
		if _, ok := tokenize(bad); ok {
			t.Errorf("%q tokenized", bad)
		}
	}
}

func TestSkipExpressions(t *testing.T) {
	if !coversMGPrefix(`(starts_with(http.request.uri.path, "/__mg/")) or http.request.uri.path eq "/x"`) {
		t.Error("disjunction with the /__mg/ prefix must cover /__mg/")
	}
	if coversMGPrefix(`starts_with(http.request.uri.path, "/__mg/") and http.request.method eq "POST"`) {
		t.Error("a conjunction covers only part of /__mg/")
	}
	if !excludesMG(`is_timed_hmac_valid_v0("k", http.request.cookies["__Host-mg_cfp"][0], 1800, http.request.timestamp.sec, 0, "s") and not starts_with(http.request.uri.path, "/__mg/")`) {
		t.Error("mg_skip_cleared template must exclude /__mg/")
	}
	if excludesMG(`is_timed_hmac_valid_v0("k", x, 1800, y, 0, "s")`) || excludesMG(`a or not starts_with(http.request.uri.path, "/__mg/")`) {
		t.Error("exclusion not required at the top level")
	}
	// "and" binds tighter than "xor" and "or" in any spelling: these match
	// /__mg/ whenever a is true.
	for _, e := range []string{
		`a xor b and not starts_with(http.request.uri.path, "/__mg/")`,
		`(a)or(b) and not starts_with(http.request.uri.path, "/__mg/")`,
		`a^^b && not starts_with(http.request.uri.path, "/__mg/")`,
	} {
		if excludesMG(e) {
			t.Errorf("%s: a disjunction keeps /__mg/ in", e)
		}
	}
	if !excludesMG(`(a or b) && (not starts_with(http.request.uri.path, "/__mg/"))`) {
		t.Error("a bracketed disjunction inside a conjunction still excludes /__mg/")
	}
	// A rate limiting rule that only excludes /__mg/ is not a /__mg/ flood rule.
	rl := &cfapi.Ruleset{Rules: []cfapi.Rule{
		{Ref: "login-limit", Expression: `http.request.uri.path eq "/login" and not starts_with(http.request.uri.path, "/__mg/")`},
		{Ref: "mg_flood", Expression: `starts_with(http.request.uri.path, "/__mg/") and http.request.method eq "POST"`},
	}}
	if got := ruleNames(floodRules(rl)); !slices.Equal(got, []string{"mg_flood"}) {
		t.Errorf("flood rules %v", got)
	}
	if got := literalPrefix("/account/reset/**"); got != "/account/reset" {
		t.Errorf("literalPrefix = %q", got)
	}
	if literalPrefix("/**") != "" || literalPrefix("/") != "" {
		t.Error("the root prefix must be ignored")
	}
}

// §2.4 item 3: the expression helpers and the site reader never panic.
func TestHelpersRandomInputs(t *testing.T) {
	seeds := []string{BypassMGExpression, `http.host in {"a" "b"} or (http.host eq "c")`, `"\"(`,
		`http.request.uri.path.extension in {"js" "css"}`, string(mustRead(t, scenarioRoot+"/green/site.yaml"))}
	x := uint64(0x853c49e6748fea9b)
	next := func() uint64 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x }
	alphabet := []byte(`"(){}[] \,.:-_aon&|!/*` + "\n\t")
	for i := 0; i < 12000; i++ {
		b := []byte(seeds[next()%uint64(len(seeds))])
		for n := 1 + next()%5; n > 0 && len(b) > 0; n-- {
			j := next() % uint64(len(b))
			if next()%2 == 0 {
				b[j] = alphabet[next()%uint64(len(alphabet))]
			} else {
				b = b[:j]
			}
		}
		s := string(b)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", s, r)
				}
			}()
			_ = normalizeExpr(s)
			_, _ = missingHosts(s, []string{"a"})
			_ = restrictedToStatic(s)
			_ = coversMGPrefix(s)
			_ = excludesMG(s)
			_ = literalPrefix(s)
			_, _ = tokenize(s)
			_ = withoutExclusions(s)
			_, _ = ParseSite("fuzz.yaml", b)
		}()
	}
}

func TestChecksTable(t *testing.T) {
	if len(Checks) != 21 {
		t.Fatalf("%d checks, want 21 (§14.3)", len(Checks))
	}
	seen := map[string]bool{}
	for i, c := range Checks {
		if c.N != i+1 || seen[c.ID] || checkFuncs[c.ID] == nil || c.Title == "" {
			t.Errorf("check %d: %+v", i+1, c)
		}
		seen[c.ID] = true
	}
	if len(checkFuncs) != len(Checks) {
		t.Errorf("%d implementations for %d checks", len(checkFuncs), len(Checks))
	}
	_ = os.Getenv
}

// §2.4 item 3: the VictoriaMetrics response parser never panics, and only
// finite numbers are samples.
func TestParseVMScalar(t *testing.T) {
	seed := []byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1790589600,"12.5"]}]}}`)
	if v, err := parseVMScalar("q", seed); err != nil || v != 12.5 {
		t.Fatalf("%v %v", v, err)
	}
	for _, bad := range []string{
		`{"status":"success","data":{"result":[{"value":[1,"NaN"]}]}}`,
		`{"status":"success","data":{"result":[{"value":[1,"+Inf"]}]}}`,
		`{"status":"success","data":{"result":[{"value":[1]}]}}`,
		`{"status":"error","data":{"result":[]}}`,
		`{"status":"success","data":{"result":[{"value":[1,12]}]}}`,
	} {
		if _, err := parseVMScalar("q", []byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	x := uint64(0x6a09e667f3bcc909)
	next := func() uint64 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; return x }
	for i := 0; i < 12000; i++ {
		b := append([]byte(nil), seed...)
		for n := 1 + next()%4; n > 0; n-- {
			b[next()%uint64(len(b))] = byte(next())
		}
		if next()%3 == 0 {
			b = b[:next()%uint64(len(b))]
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", b, r)
				}
			}()
			if v, err := parseVMScalar("q", b); err == nil && (math.IsNaN(v) || math.IsInf(v, 0)) {
				t.Fatalf("non-finite sample accepted from %q", b)
			}
		}()
	}
}
