package policy

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

// Deterministic randomized tests (docs/impl/phase1-spec.md §2.4 item 3): a
// fixed-seed xorshift generator, at least 10,000 inputs per parser, and the
// assertion that bad input yields errors, never a panic.

type xorshift uint64

func (x *xorshift) next() uint64 {
	v := uint64(*x)
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	*x = xorshift(v)
	return v
}

func (x *xorshift) intn(n int) int { return int(x.next() % uint64(n)) }

func pick[T any](x *xorshift, items []T) T { return items[x.intn(len(items))] }

const randomInputs = 10_000

// TestParseAndCheckRandomInput feeds random bytes, random token soup and
// mutated valid policy files through Parse and Compiler.Check.
func TestParseAndCheckRandomInput(t *testing.T) {
	rng := xorshift(0x9e3779b97f4a7c15)
	c := newTestCompiler(t, Options{})
	valid := `policies:
  - id: r
    phase: identity
    expr: route.env in ["staging"] && (!has(net.ip) || !ip_in(net.ip, list("owner_cidrs"))) && glob(req.path, "/a/**")
    action: block
    params: {type: pow}
`
	tokens := []string{
		"policies:", "\n  - ", "id: r", "phase: bot", "expr: ", "action: log", "{", "}", "[", "]", "'", `"`,
		"req.path", "net.ip", "tls.ja4", "has(", ")", "&&", "||", "!", "?", ":", "==", "<", "in", "size(",
		"list(\"x\")", "ip_in(", "glob(", ",", "1", "1.5", "-", "+", "u", "b\"\"", "null", ".all(x, x)",
		"\\u00e9", "\xff", "\x00", "#", "&a", "*a", "<<:", "\t", "\n",
	}
	for i := range randomInputs {
		var data []byte
		switch i % 3 {
		case 0:
			data = make([]byte, rng.intn(200))
			for j := range data {
				data[j] = byte(rng.next())
			}
		case 1:
			var b strings.Builder
			for range rng.intn(40) {
				b.WriteString(pick(&rng, tokens))
			}
			data = []byte(b.String())
		default:
			data = []byte(valid)
			for range 1 + rng.intn(4) {
				data[rng.intn(len(data))] = byte(rng.next())
			}
		}
		rules, _ := Parse("random.yaml", data)
		checked, _ := c.Check(rules)
		for _, cr := range checked {
			if cr.IR == nil || cr.IR.GetMaxSteps() > MaxIRSteps || len(cr.ExprIR) == 0 {
				t.Fatalf("input %d compiled without valid IR: %q", i, data)
			}
		}
	}
}

// TestIRBytesRandomInput decodes random and bit-flipped IR bytes and runs
// the static analysis (MaxSteps, irShape, irFields) on whatever decodes: it
// must not panic on trees the compiler did not produce (spec §2.4). It does
// not check the bound itself; malformed shapes are the Rust loader's job.
func TestIRBytesRandomInput(t *testing.T) {
	rng := xorshift(0x2545f4914f6cdd1d)
	seed := compileExpr(t, `has(tls.ja4) ? tls.ja4.value in list("bad_ja4") : edge_tls.ciphers_sha1 in list("bad") || glob(req.path, "/a/*") && req.headers.accept.startsWith("t")`).ExprIR
	for i := range randomInputs {
		var data []byte
		if i%2 == 0 {
			data = make([]byte, rng.intn(64))
			for j := range data {
				data[j] = byte(rng.next())
			}
		} else {
			data = slices.Clone(seed)
			for range 1 + rng.intn(3) {
				data[rng.intn(len(data))] ^= byte(1 << rng.intn(8))
			}
		}
		var pe morphgatev1.PolicyExpr
		if err := proto.Unmarshal(data, &pe); err != nil {
			continue
		}
		_ = MaxSteps(pe.GetRoot())
		if pe.GetRoot() != nil {
			irShape(pe.GetRoot(), 1)
			irFields(pe.GetRoot())
		}
	}
}

// exprGen generates random, mostly well-typed policy expressions over the
// schema.
type exprGen struct {
	rng *xorshift
}

var (
	genBoolFields   = []string{"net.tor", "upstream.authenticated", "tls.ja4.authenticated", "identity.proof.valid", "identity.crawler.claimed", "identity.crawler.verified", "identity.crawler.cf_vbot"}
	genIntFields    = []string{"net.asn", "edge_tls.hello_len", "identity.token.age", "risk.score"}
	genStringFields = []string{"req.method", "req.host", "req.path", "req.query", "net.ip", "net.country", "tls.version", "tls.ja4.value", "http.version", "edge_tls.version", "identity.token.level", "identity.crawler.cf_vbot_cat", "risk.class", "route.name"}
	genListFields   = []string{"labels", "risk.reasons", "http.header_order"}
	genHasPaths     = []string{"tls", "tls.ja4", "tls.ja4.value", "http.header_order", "http.version", "edge_tls.hello_len", "net.ip", "identity.proof", "identity.crawler.cf_vbot", "identity.crawler.cf_vbot_cat", "req.headers"}
	genStrings      = []string{`""`, `"a"`, `"GET"`, `"/a/b"`, `"10.1.2.3"`, `"2001:db8::1"`, `"été"`, `"\U0001F600"`, `"x-a"`, `"TLSv1.3"`, `"10.0.0.0/8"`}
	genHeaderKeys   = []string{"a", "x-a", "accept", "nope"}
	genGlobs        = []string{"*", "**", "/a/*", "/**", "?", "/a?b", "*a*", "é*"}
	genListNames    = []string{"l1", "l2", "ips", "empty"}
)

func (g *exprGen) boolExpr(depth int) string {
	if depth <= 0 {
		switch g.rng.intn(3) {
		case 0:
			return pick(g.rng, []string{"true", "false"})
		case 1:
			return "has(" + pick(g.rng, genHasPaths) + ")"
		}
		return pick(g.rng, genBoolFields)
	}
	d := depth - 1
	switch g.rng.intn(14) {
	case 0:
		return "!(" + g.boolExpr(d) + ")"
	case 1:
		return "(" + g.boolExpr(d) + " && " + g.boolExpr(d) + ")"
	case 2:
		return "(" + g.boolExpr(d) + " || " + g.boolExpr(d) + ")"
	case 3:
		return "(" + g.boolExpr(d) + " ? " + g.boolExpr(d) + " : " + g.boolExpr(d) + ")"
	case 4:
		return g.intExpr(d) + pick(g.rng, []string{" == ", " != ", " < ", " <= ", " > ", " >= "}) + g.intExpr(d)
	case 5:
		return g.stringExpr(d) + pick(g.rng, []string{" == ", " != ", " < ", " >= "}) + g.stringExpr(d)
	case 6:
		return g.boolExpr(d) + pick(g.rng, []string{" == ", " != "}) + g.boolExpr(d)
	case 7:
		return g.stringExpr(d) + " in " + g.listExpr(d)
	case 8:
		return g.stringExpr(d) + " in " + pick(g.rng, []string{"req.headers", "rate"})
	case 9:
		return g.stringExpr(d) + "." + pick(g.rng, []string{"startsWith", "endsWith", "contains"}) + "(" + g.stringExpr(d) + ")"
	case 10:
		return "ip_in(" + g.stringExpr(d) + ", " + g.listExpr(d) + ")"
	case 11:
		return fmt.Sprintf("glob(%s, %q)", g.stringExpr(d), pick(g.rng, genGlobs))
	case 12:
		return g.doubleExpr(d) + pick(g.rng, []string{" < ", " == ", " >= "}) + g.doubleExpr(d)
	}
	return g.intExpr(d) + " in [1, 64500, " + g.intExpr(d) + "]"
}

func (g *exprGen) intExpr(depth int) string {
	if depth <= 0 || g.rng.intn(3) == 0 {
		if g.rng.intn(2) == 0 {
			return pick(g.rng, []string{"0", "1", "-1", "64500", "200"})
		}
		return pick(g.rng, genIntFields)
	}
	d := depth - 1
	switch g.rng.intn(3) {
	case 0:
		return "size(" + g.stringExpr(d) + ")"
	case 1:
		return "size(" + pick(g.rng, []string{g.listExpr(d), "req.headers", "rate"}) + ")"
	}
	return "(" + g.boolExpr(d) + " ? " + g.intExpr(d) + " : " + g.intExpr(d) + ")"
}

func (g *exprGen) doubleExpr(depth int) string {
	switch g.rng.intn(3) {
	case 0:
		return pick(g.rng, []string{"0.5", "0.0", "1.0"})
	case 1:
		return "risk.confidence"
	}
	if depth > 0 && g.rng.intn(2) == 0 {
		return g.indexExpr("rate", depth-1)
	}
	return fmt.Sprintf("rate[%q]", pick(g.rng, []string{"a", "b", "nope"}))
}

// indexExpr indexes the map field m with a computed key, or indexes a
// computed map (a conditional of m) with a literal or computed key: the
// strictness of index_map (an ERROR key beats an UNKNOWN map, spec §5.3).
func (g *exprGen) indexExpr(m string, depth int) string {
	key := fmt.Sprintf("%q", pick(g.rng, genHeaderKeys))
	if g.rng.intn(2) == 0 {
		key = g.stringExpr(depth)
	}
	if g.rng.intn(2) == 0 {
		return m + "[" + key + "]"
	}
	return "(" + g.boolExpr(depth) + " ? " + m + " : " + m + ")[" + key + "]"
}

func (g *exprGen) stringExpr(depth int) string {
	if depth <= 0 || g.rng.intn(2) == 0 {
		if g.rng.intn(2) == 0 {
			return pick(g.rng, genStrings)
		}
		return pick(g.rng, genStringFields)
	}
	d := depth - 1
	switch g.rng.intn(4) {
	case 0, 1:
		return fmt.Sprintf("req.headers[%q]", pick(g.rng, genHeaderKeys))
	case 2:
		return g.indexExpr("req.headers", d)
	}
	return "(" + g.boolExpr(d) + " ? " + g.stringExpr(d) + " : " + g.stringExpr(d) + ")"
}

func (g *exprGen) listExpr(depth int) string {
	switch g.rng.intn(4) {
	case 0:
		n := g.rng.intn(4)
		els := make([]string, n)
		for i := range els {
			els[i] = g.stringExpr(depth - 1)
		}
		return "[" + strings.Join(els, ", ") + "]"
	case 1:
		return fmt.Sprintf("list(%q)", pick(g.rng, genListNames))
	case 2:
		if depth > 0 {
			return "(" + g.boolExpr(depth-1) + " ? " + g.listExpr(depth-1) + " : " + g.listExpr(depth-1) + ")"
		}
	}
	return pick(g.rng, genListFields)
}

func randomInput(rng *xorshift) *Input {
	s := func() string {
		return pick(rng, []string{"", "a", "GET", "/a/b", "10.1.2.3", "2001:db8::1", "::ffff:10.0.0.1", "été", "\U0001F600", "x-a", "TLSv1.3", "zz"})
	}
	in := &Input{
		Req: Request{Method: s(), Host: s(), Path: s(), Query: s(), Channel: s(),
			Headers: map[string]string{}},
		Net:      Net{IP: s(), ASN: int64(rng.intn(3)) * 64500, Country: s(), ConnType: s(), Tor: rng.intn(2) == 0},
		Upstream: Upstream{Profile: s(), Authenticated: rng.intn(2) == 0, AuthMethod: s()},
		TLS:      TLS{JA4: JA4{Value: s(), Source: s(), Authenticated: rng.intn(2) == 0}, Version: s()},
		HTTP:     HTTP{Version: s(), HeaderOrder: []string{s(), s()}},
		EdgeTLS:  EdgeTLS{Version: s(), HelloLen: int64(rng.intn(400))},
		Identity: Identity{
			Token:   Token{Level: s(), Age: int64(rng.intn(4000))},
			Proof:   Proof{Valid: rng.intn(2) == 0},
			Crawler: Crawler{Claimed: rng.intn(2) == 0, Verified: rng.intn(2) == 0, CFVBot: rng.intn(2) == 0, CFVBotCat: s()},
		},
		Risk:   Risk{Score: int64(rng.intn(101)), Confidence: float64(rng.intn(3)) / 2, Class: s(), Reasons: []string{s()}},
		Route:  Route{Name: s()},
		Rate:   map[string]float64{},
		Labels: []string{s(), s()},
	}
	for _, k := range genHeaderKeys[:3] {
		if rng.intn(2) == 0 {
			in.Req.Headers[k] = s()
		}
	}
	for _, k := range []string{"a", "b"} {
		if rng.intn(2) == 0 {
			in.Rate[k] = float64(rng.intn(3)) / 2
		}
	}
	return in
}

// TestRandomExpressionsDifferential compiles random expressions and checks,
// on random inputs and random MISSING sets, that the cel-go reference and the
// independent §5.3 IR interpreter agree, that evaluation never exceeds
// max_steps and that lowering is deterministic.
func TestRandomExpressionsDifferential(t *testing.T) {
	rng := xorshift(0xd1b54a32d192ed03)
	gen := &exprGen{rng: &rng}
	lists := map[string][]string{
		"l1": {"a", "GET", "10.0.0.0/8"}, "l2": {"TLSv1.3", "été"},
		"ips": {"10.0.0.0/8", "2001:db8::/32", "::ffff:10.0.0.0/104"}, "empty": {},
	}
	ev, err := NewEvaluator(lists)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestCompiler(t, Options{MaxCost: 1 << 62})
	missingPool := []string{"tls", "tls.ja4", "http.header_order", "http.version", "edge_tls", "edge_tls.hello_len", "net.ip", "net", "identity.proof", "identity.crawler.cf_vbot", "req.headers", "risk"}
	const exprs = 2500
	compiled := 0
	outcomes := map[string]int{}
	for i := range exprs {
		expr := gen.boolExpr(1 + rng.intn(4))
		rule := &Rule{ID: "r", Phase: "bot", Expr: expr, Action: "log", Mode: DefaultMode, Rollout: DefaultRollout}
		checked, diags := c.Check([]*Rule{rule})
		if len(checked) == 0 {
			// Type errors (e.g. the ternary of mismatched kinds) and the
			// step bound are expected; lowering must not fail on anything
			// the generator emits otherwise.
			for _, d := range diags.Errors() {
				if strings.Contains(d.Message, unsupportedPrefix) {
					t.Errorf("expr %d %s: %s", i, expr, d.Message)
				}
			}
			continue
		}
		compiled++
		cr := checked[0]
		if again, err := Lower(cr); err != nil || !proto.Equal(again, cr.IR) {
			t.Fatalf("%s: Lower is not deterministic: %v", expr, err)
		}
		for range 3 {
			in := randomInput(&rng)
			var missing []string
			for _, p := range missingPool {
				if rng.intn(4) == 0 {
					missing = append(missing, p)
				}
			}
			res, raw, err := ev.evaluate(cr, in, missing, 0)
			if err != nil {
				t.Fatalf("%s: %v", expr, err)
			}
			it := &irInterp{in: in, missing: missing, lists: lists}
			got, paths := it.evalRule(cr.IR)
			if got != res.String() {
				t.Fatalf("differential mismatch\n  expr:    %s\n  missing: %v\n  input:   %+v\n  cel-go:  %s (%v)\n  IR:      %s", expr, missing, in, res, raw, got)
			}
			if got == "unknown" {
				requireUnderMissing(t, expr, paths, missing)
			}
			if it.steps > cr.IR.GetMaxSteps() {
				t.Fatalf("%s: %d steps > max_steps %d", expr, it.steps, cr.IR.GetMaxSteps())
			}
			outcomes[got]++
		}
	}
	t.Logf("%d of %d random expressions compiled; outcomes %v", compiled, exprs, outcomes)
	// The generator must keep producing meaningful programs and outcomes.
	if compiled < exprs/2 {
		t.Errorf("only %d of %d random expressions compiled", compiled, exprs)
	}
	for _, o := range []string{"true", "false", "unknown", "error"} {
		if outcomes[o] < 50 {
			t.Errorf("only %d random evaluations were %s: %v", outcomes[o], o, outcomes)
		}
	}
}
