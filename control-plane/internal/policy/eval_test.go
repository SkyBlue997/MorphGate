package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestResultString(t *testing.T) {
	for r, want := range map[Result]string{ResultFalse: "false", ResultTrue: "true", ResultUnknown: "unknown", ResultError: "error", Result(9): "Result(9)"} {
		if r.String() != want {
			t.Errorf("%d.String() = %q, want %q", int(r), r.String(), want)
		}
	}
}

// TestEvalWithMissingSemantics exercises spec §4.3 / §5.3 through the
// reference evaluator on one Input with different MISSING sets.
func TestEvalWithMissingSemantics(t *testing.T) {
	ev, err := NewEvaluator(map[string][]string{"owners": {"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	in := &Input{
		Req:      Request{Method: "GET", Path: "/login", Headers: map[string]string{"accept": "text/html"}},
		Net:      Net{IP: "10.1.2.3"},
		EdgeTLS:  EdgeTLS{Version: "TLSv1.3"},
		Identity: Identity{Crawler: Crawler{CFVBot: true, CFVBotCat: "Search Engine Crawler"}},
	}
	cases := []struct {
		expr    string
		missing []string
		want    Result
		paths   []string // unknown paths reported by cel-go
	}{
		{`edge_tls.version == "TLSv1.3"`, nil, ResultTrue, nil},
		{`edge_tls.version == "TLSv1.3"`, []string{"edge_tls"}, ResultUnknown, []string{"edge_tls"}},
		{`edge_tls.version == "TLSv1.3"`, []string{"edge_tls.version"}, ResultUnknown, []string{"edge_tls.version"}},
		{`edge_tls.version == "TLSv1.3"`, []string{"edge_tls.cipher"}, ResultTrue, nil},
		{`has(edge_tls.version)`, []string{"edge_tls"}, ResultFalse, nil},
		{`has(edge_tls.cipher)`, nil, ResultTrue, nil}, // ABSENT: zero value, but available
		{`has(identity.crawler.cf_vbot_cat)`, []string{"identity.crawler.cf_vbot"}, ResultTrue, nil},
		{`identity.crawler.cf_vbot`, []string{"identity.crawler.cf_vbot"}, ResultUnknown, []string{"identity.crawler.cf_vbot"}},
		{`!has(net.ip) || !ip_in(net.ip, list("owners"))`, []string{"net.ip"}, ResultTrue, nil},
		{`!has(net.ip) || !ip_in(net.ip, list("owners"))`, nil, ResultFalse, nil},
		{`ip_in(net.ip, list("owners")) && edge_tls.version == "x"`, []string{"net", "edge_tls"}, ResultUnknown, []string{"edge_tls", "net"}},
		{`req.headers["cookie"] == "x"`, nil, ResultError, nil},
		{`req.headers["cookie"] == "x" || edge_tls.version == ""`, []string{"edge_tls"}, ResultUnknown, []string{"edge_tls"}},
		{`req.headers["cookie"] == edge_tls.version`, []string{"edge_tls"}, ResultError, nil},
		// index_map is strict (spec §5.3): the first ERROR among map and key
		// wins over UNKNOWN. Only map fields can be indexed (ruling I-20), so
		// a conditional index is written inside the branches, and an UNKNOWN
		// condition makes it UNKNOWN without evaluating either index.
		{`req.headers[req.headers["cookie"]] == edge_tls.version`, []string{"edge_tls"}, ResultError, nil},
		{`rate[req.headers["cookie"]] > 0.5`, []string{"net"}, ResultError, nil},
		{`(net.tor ? req.headers[req.headers["cookie"]] : req.headers[req.headers["cookie"]]) == "x"`, []string{"net"}, ResultUnknown, []string{"net"}},
		{`(net.tor ? req.headers["accept"] : req.headers["accept"]) == "text/html"`, []string{"net"}, ResultUnknown, []string{"net"}},
		{`(net.tor ? req.headers.accept : req.headers.accept) == "text/html"`, nil, ResultTrue, nil},
		{`(net.tor ? req.headers[req.headers["cookie"]] : req.headers["accept"]) == "x"`, nil, ResultFalse, nil},
	}
	for _, tc := range cases {
		cr := compileExpr(t, tc.expr)
		res, raw, err := ev.evaluate(cr, in, tc.missing, 0)
		if err != nil || res != tc.want {
			t.Errorf("%s with MISSING %v = %v, %v; want %v", tc.expr, tc.missing, res, err, tc.want)
			continue
		}
		if got := unknownPaths(raw); !slices.Equal(got, tc.paths) {
			t.Errorf("%s with MISSING %v: unknown paths %v, want %v", tc.expr, tc.missing, got, tc.paths)
		}
		// The has() substitution works on a copy: the rule is unchanged.
		if again, err := ev.EvalWithMissing(cr, in, nil); err != nil || (tc.missing == nil && again != res) {
			t.Errorf("%s: re-evaluation without MISSING = %v, %v", tc.expr, again, err)
		}
	}
}

func TestEvalWithMissingRejectsBadArguments(t *testing.T) {
	ev, err := NewEvaluator(nil)
	if err != nil {
		t.Fatal(err)
	}
	cr := compileExpr(t, "net.tor")
	for _, missing := range [][]string{{"tls.ja5"}, {""}, {"req.headers.accept"}, {"net."}, {"Net"}} {
		if _, err := ev.EvalWithMissing(cr, &Input{}, missing); err == nil || !strings.Contains(err.Error(), "is not a policy field") {
			t.Errorf("MISSING %q accepted: %v", missing, err)
		}
	}
	if _, err := ev.EvalWithMissing(nil, &Input{}, nil); err == nil {
		t.Error("nil rule accepted")
	}
	if _, err := ev.Eval(nil, &Input{}); err == nil {
		t.Error("Eval(nil) accepted")
	}
	// A nil Input reads as all zero values.
	if res, err := ev.EvalWithMissing(cr, nil, nil); err != nil || res != ResultFalse {
		t.Errorf("nil input = %v, %v", res, err)
	}
}

// TestEvalMatchesEvalWithMissing: Eval is EvalWithMissing without MISSING
// paths, with errors returned as errors, plus the cel-go cost limit.
func TestEvalMatchesEvalWithMissing(t *testing.T) {
	ev, err := NewEvaluator(map[string][]string{"hosts": {"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	in := &Input{Req: Request{Host: "example.com", Path: "/a", Headers: map[string]string{"accept": "*/*"}}}
	for _, expr := range []string{
		`req.host in list("hosts")`, `has(tls.ja4) && tls.ja4.value == ""`, `req.headers.accept == "*/*"`,
		`req.headers["nope"] == ""`, `glob(req.path, "/*")`,
	} {
		cr := compileExpr(t, expr)
		res, err := ev.EvalWithMissing(cr, in, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ev.Eval(cr, in)
		switch res {
		case ResultError:
			if err == nil {
				t.Errorf("%s: Eval returned %v without the error", expr, got)
			}
		default:
			if err != nil || got != (res == ResultTrue) {
				t.Errorf("%s: Eval = %v, %v; EvalWithMissing = %v", expr, got, err, res)
			}
		}
	}
	// Inputs beyond the §4.1 size caps exceed the rule's cost budget.
	cr := compileExpr(t, `req.query.endsWith(req.path)`)
	big := &Input{Req: Request{Path: "/" + strings.Repeat("a", 20*8192)}}
	if _, err := ev.Eval(cr, big); err == nil || !strings.Contains(err.Error(), "cost") {
		t.Errorf("oversized path: err = %v, want a cost limit error", err)
	}
	cr = compileExpr(t, `req.headers.referer.contains(req.headers.origin)`)
	big = &Input{Req: Request{Headers: map[string]string{"referer": strings.Repeat("r", 20*8192), "origin": "o"}}}
	if _, err := ev.Eval(cr, big); err == nil || !strings.Contains(err.Error(), "cost") {
		t.Errorf("oversized header value: err = %v, want a cost limit error", err)
	}
}

// TestEvalAtSizeCaps: inputs at the §4.1 size caps are within every rule's
// cost budget, whichever syntax reads them (req.headers.x and
// req.headers["x"] read the same 8 KiB value), and a rule the static step
// bound accepts is not rejected by the supplementary cel-go cost check.
func TestEvalAtSizeCaps(t *testing.T) {
	ev, err := NewEvaluator(nil)
	if err != nil {
		t.Fatal(err)
	}
	value := strings.Repeat("v", 8192)
	in := &Input{Req: Request{
		Method: strings.Repeat("M", 32), Host: strings.Repeat("h", 253),
		Path: "/" + strings.Repeat("p", 8191), Query: strings.Repeat("q", 8192),
		Headers: map[string]string{"referer": value, "origin": value + "", "x-a": value},
	}}
	for _, expr := range []string{
		`req.headers.referer.contains(req.host)`,
		`req.headers.referer == req.headers.origin`,
		`req.headers.referer.startsWith(req.headers.origin)`,
		`req.headers.referer.endsWith(req.headers["x-a"])`,
		`req.headers.referer.contains(req.headers.origin)`,
		`req.headers["referer"].contains(req.headers["origin"])`,
		`req.path.contains(req.query)`,
		`req.query.contains(req.method)`,
		`glob(req.headers.referer, "v*v")`,
	} {
		cr := compileExpr(t, expr)
		if _, err := ev.Eval(cr, in); err != nil {
			t.Errorf("%s at the size caps (cel-go cost estimate %d): %v", expr, cr.Cost.Max, err)
		}
	}
	for _, pair := range [][2]string{
		{`req.headers.referer.contains(req.host)`, `req.headers["referer"].contains(req.host)`},
		{`size(req.headers.referer) > 1`, `size(req.headers["referer"]) > 1`},
		{`req.headers.referer == "x"`, `req.headers["referer"] == "x"`},
	} {
		a, b := compileExpr(t, pair[0]), compileExpr(t, pair[1])
		if a.Cost != b.Cost {
			t.Errorf("cel-go cost of %s = %+v, of %s = %+v; want equal", pair[0], a.Cost, pair[1], b.Cost)
		}
	}
}
