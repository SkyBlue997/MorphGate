package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

// compileExpr compiles one expression as a rule and fails on any error.
func compileExpr(t *testing.T, expr string) *CheckedRule {
	t.Helper()
	cr, diags := compileCase(t, conformanceCase{Name: "test", Expr: expr})
	if cr == nil || diags.HasErrors() {
		t.Fatalf("%s: %v", expr, diagStrings(diags))
	}
	return cr
}

// irText renders an IR expression compactly for comparisons.
func irText(e *morphgatev1.Expr) string {
	return strings.Join(strings.Fields(prototext.MarshalOptions{}.Format(e)), " ")
}

// TestLowerShapes pins the §5.1 mapping on small expressions by comparing
// their IR with the IR of hand-built trees.
func TestLowerShapes(t *testing.T) {
	f := irField
	s := irString
	i := func(v int64) *morphgatev1.Expr {
		return irLiteral(&morphgatev1.Literal{Value: &morphgatev1.Literal_IntValue{IntValue: v}})
	}
	d := func(v float64) *morphgatev1.Expr {
		return irLiteral(&morphgatev1.Literal{Value: &morphgatev1.Literal_DoubleValue{DoubleValue: v}})
	}
	b := func(v bool) *morphgatev1.Expr {
		return irLiteral(&morphgatev1.Literal{Value: &morphgatev1.Literal_BoolValue{BoolValue: v}})
	}
	and := func(args ...*morphgatev1.Expr) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_And{And: &morphgatev1.Nary{Args: args}}}
	}
	or := func(args ...*morphgatev1.Expr) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Or{Or: &morphgatev1.Nary{Args: args}}}
	}
	not := func(x *morphgatev1.Expr) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Not{Not: &morphgatev1.Unary{Arg: x}}}
	}
	cmp := func(op morphgatev1.CompareOp, l, r *morphgatev1.Expr) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Compare{Compare: &morphgatev1.Compare{Op: op, Lhs: l, Rhs: r}}}
	}
	bin := func(kind string, l, r *morphgatev1.Expr) *morphgatev1.Expr {
		x := &morphgatev1.Binary{Lhs: l, Rhs: r}
		switch kind {
		case "in_list":
			return &morphgatev1.Expr{Kind: &morphgatev1.Expr_InList{InList: x}}
		case "in_map":
			return &morphgatev1.Expr{Kind: &morphgatev1.Expr_InMap{InMap: x}}
		case "index_map":
			return &morphgatev1.Expr{Kind: &morphgatev1.Expr_IndexMap{IndexMap: x}}
		}
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_IpIn{IpIn: x}}
	}
	list := func(els ...*morphgatev1.Expr) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_List{List: &morphgatev1.ListLiteral{Elements: els}}}
	}
	size := func(x *morphgatev1.Expr) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Size{Size: &morphgatev1.Unary{Arg: x}}}
	}
	str := func(fn morphgatev1.StringFunction, target, arg *morphgatev1.Expr) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_StringCall{StringCall: &morphgatev1.StringCall{Function: fn, Target: target, Arg: arg}}}
	}
	has := func(p string) *morphgatev1.Expr { return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Has{Has: p}} }
	named := func(n string) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_NamedList{NamedList: n}}
	}
	cond := func(c, x, y *morphgatev1.Expr) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Cond{Cond: &morphgatev1.Cond{Cond: c, ThenExpr: x, ElseExpr: y}}}
	}
	globOf := func(subject *morphgatev1.Expr, p string) *morphgatev1.Expr {
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Glob{Glob: &morphgatev1.Glob{Subject: subject, Pattern: p}}}
	}
	const (
		eq = morphgatev1.CompareOp_COMPARE_OP_EQ
		ne = morphgatev1.CompareOp_COMPARE_OP_NE
		lt = morphgatev1.CompareOp_COMPARE_OP_LT
		le = morphgatev1.CompareOp_COMPARE_OP_LE
		gt = morphgatev1.CompareOp_COMPARE_OP_GT
		ge = morphgatev1.CompareOp_COMPARE_OP_GE
	)
	cases := []struct {
		expr string
		want *morphgatev1.Expr
	}{
		{"true", b(true)},
		{"risk.score >= -1", cmp(ge, f("risk.score"), i(-1))},
		{"risk.confidence < 0.5", cmp(lt, f("risk.confidence"), d(0.5))},
		{`req.method != "GET"`, cmp(ne, f("req.method"), s("GET"))},
		{`req.host <= "m"`, cmp(le, f("req.host"), s("m"))},
		{"net.asn > 0", cmp(gt, f("net.asn"), i(0))},
		{"net.tor == false", cmp(eq, f("net.tor"), b(false))},
		// && / || chains flatten into one n-ary node, left to right, however
		// the parser balanced them; a different operator nests.
		{"net.tor && upstream.authenticated && identity.proof.valid && identity.crawler.verified",
			and(f("net.tor"), f("upstream.authenticated"), f("identity.proof.valid"), f("identity.crawler.verified"))},
		{"net.tor && (upstream.authenticated && identity.proof.valid)",
			and(f("net.tor"), f("upstream.authenticated"), f("identity.proof.valid"))},
		{"(net.tor || upstream.authenticated) && (identity.proof.valid || identity.crawler.verified)",
			and(or(f("net.tor"), f("upstream.authenticated")), or(f("identity.proof.valid"), f("identity.crawler.verified")))},
		{"net.tor || upstream.authenticated && identity.proof.valid",
			or(f("net.tor"), and(f("upstream.authenticated"), f("identity.proof.valid")))},
		{"!(net.tor && upstream.authenticated)", not(and(f("net.tor"), f("upstream.authenticated")))},
		// cel-go's parser drops pairs of "!".
		{"!!net.tor", f("net.tor")},
		{"!!!net.tor", not(f("net.tor"))},
		{`net.tor ? "a" == req.method : false`, cond(f("net.tor"), cmp(eq, s("a"), f("req.method")), b(false))},
		// Map-typed fields: select and index are the same node.
		{`req.headers.accept == "x"`, cmp(eq, bin("index_map", f("req.headers"), s("accept")), s("x"))},
		{`req.headers["accept"] == "x"`, cmp(eq, bin("index_map", f("req.headers"), s("accept")), s("x"))},
		{`rate["a"] > 0.5`, cmp(gt, bin("index_map", f("rate"), s("a")), d(0.5))},
		{`"a" in rate`, bin("in_map", s("a"), f("rate"))},
		{`"scanner" in labels`, bin("in_list", s("scanner"), f("labels"))},
		{`req.host in list("hosts")`, bin("in_list", f("req.host"), named("hosts"))},
		{`net.asn in [1, 2]`, bin("in_list", f("net.asn"), list(i(1), i(2)))},
		{`ip_in(net.ip, ["10.0.0.0/8"])`, bin("ip_in", f("net.ip"), list(s("10.0.0.0/8")))},
		{"size(labels) == 0", cmp(eq, size(f("labels")), i(0))},
		{"labels.size() == 0", cmp(eq, size(f("labels")), i(0))},
		{`req.path.startsWith("/a")`, str(morphgatev1.StringFunction_STRING_FUNCTION_STARTS_WITH, f("req.path"), s("/a"))},
		{`req.path.endsWith("/a")`, str(morphgatev1.StringFunction_STRING_FUNCTION_ENDS_WITH, f("req.path"), s("/a"))},
		{`req.path.contains("/a")`, str(morphgatev1.StringFunction_STRING_FUNCTION_CONTAINS, f("req.path"), s("/a"))},
		{`glob(req.path, "/a/**")`, globOf(f("req.path"), "/a/**")},
		{"has(tls.ja4) && has(identity.crawler.cf_vbot)", and(has("tls.ja4"), has("identity.crawler.cf_vbot"))},
		{`"\u00e9" == req.query`, cmp(eq, s("\u00e9"), f("req.query"))},
	}
	for _, tc := range cases {
		cr := compileExpr(t, tc.expr)
		if !proto.Equal(cr.IR.GetRoot(), tc.want) {
			t.Errorf("%s:\n  got  %s\n  want %s", tc.expr, irText(cr.IR.GetRoot()), irText(tc.want))
		}
		if cr.IR.GetIrVersion() != IRVersion {
			t.Errorf("%s: ir_version %d", tc.expr, cr.IR.GetIrVersion())
		}
	}
}

// TestLowerFieldsAndLists: PolicyExpr.fields lists every field and has()
// path (sorted, unique, prefixes kept); CheckedRule.Lists every list() name.
func TestLowerFieldsAndLists(t *testing.T) {
	cr := compileExpr(t, `has(tls.ja4) ? tls.ja4.value in list("bad_ja4") : edge_tls.ciphers_sha1 in list("bad_cf") || req.headers.accept == "" || tls.ja4.value in list("bad_ja4")`)
	if want := []string{"edge_tls.ciphers_sha1", "req.headers", "tls.ja4", "tls.ja4.value"}; !slices.Equal(cr.IR.GetFields(), want) {
		t.Errorf("fields = %v, want %v", cr.IR.GetFields(), want)
	}
	if want := []string{"bad_cf", "bad_ja4"}; !slices.Equal(cr.Lists, want) {
		t.Errorf("lists = %v, want %v", cr.Lists, want)
	}
}

// TestLowerDeterministic: the IR is a pure function of the checked
// expression. Independent compilers, formatting and comments give the same
// bytes, which also equal Lower() and the proto marshalled again.
func TestLowerDeterministic(t *testing.T) {
	variants := []string{
		`route.env in ["staging", "test"] && !ip_in(net.ip, list("owner_cidrs")) && req.headers.accept.startsWith("text/")`,
		"route.env in [\"staging\",\"test\"]&&!ip_in(net.ip,list(\"owner_cidrs\"))\n  && req.headers[\"accept\"].startsWith(\"text/\") // trailing comment",
	}
	var first []byte
	for i, expr := range variants {
		for range 2 {
			cr := compileExpr(t, expr)
			if first == nil {
				first = cr.ExprIR
			}
			if !bytes.Equal(cr.ExprIR, first) {
				t.Errorf("variant %d: IR bytes differ:\n  %x\n  %x", i, cr.ExprIR, first)
			}
			pe, err := Lower(cr)
			if err != nil {
				t.Fatal(err)
			}
			again, err := proto.MarshalOptions{Deterministic: true}.Marshal(pe)
			if err != nil || !bytes.Equal(again, cr.ExprIR) {
				t.Errorf("Lower() re-marshals to different bytes: %v", err)
			}
		}
	}
}

// TestLowerValidPolicyFiles: every rule of the valid policy files lowers to
// IR, and Proto() / JSON() carry it (the WP-G1 done-definition for `mgctl
// policy compile`).
func TestLowerValidPolicyFiles(t *testing.T) {
	files, err := filepath.Glob("../../testdata/policies/valid/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no valid testdata: %v", err)
	}
	for _, file := range files {
		checked, diags := checkFiles(t, file)
		if diags.HasErrors() {
			t.Fatalf("%s: %v", file, diagStrings(diags))
		}
		rules, _ := ParseFile(file)
		if len(checked) != len(rules) {
			t.Errorf("%s: %d of %d rules compiled", file, len(checked), len(rules))
		}
		for _, cr := range checked {
			if cr.IR == nil || len(cr.ExprIR) == 0 || cr.IR.GetMaxSteps() == 0 || cr.IR.GetMaxSteps() > MaxIRSteps {
				t.Errorf("%s: missing or bad IR: %v", cr.ID, cr.IR)
				continue
			}
			pe, err := Lower(cr)
			if err != nil || !proto.Equal(pe, cr.IR) {
				t.Errorf("%s: Lower() = %v, %v; want the IR computed by Check", cr.ID, pe, err)
			}
			pb := cr.Proto()
			if pb.GetIrVersion() != IRVersion || !bytes.Equal(pb.GetExprIr(), cr.ExprIR) {
				t.Errorf("%s: Proto() ir_version %d, %d IR bytes", cr.ID, pb.GetIrVersion(), len(pb.GetExprIr()))
			}
			var js map[string]any
			raw, _ := json.Marshal(cr.JSON())
			if err := json.Unmarshal(raw, &js); err != nil {
				t.Fatal(err)
			}
			if js["expr_ir"] != base64.StdEncoding.EncodeToString(cr.ExprIR) || js["max_steps"] != float64(cr.IR.GetMaxSteps()) || js["ir_version"] != float64(IRVersion) {
				t.Errorf("%s: JSON ir fields = %v %v %v", cr.ID, js["ir_version"], js["expr_ir"], js["max_steps"])
			}
		}
	}
}

// TestProtoWithoutIR: a CheckedRule that did not come from Check carries no
// IR and reports ir_version 0, so the bundle builder refuses it ("policy IR
// unavailable") instead of shipping a rule the Edge cannot load.
func TestProtoWithoutIR(t *testing.T) {
	cr := &CheckedRule{Rule: &Rule{ID: "x", Phase: "bot", Expr: "true", Action: "log", Mode: "enforce", Rollout: 100}}
	if pb := cr.Proto(); pb.GetIrVersion() != 0 || len(pb.GetExprIr()) != 0 {
		t.Errorf("Proto() = %v", pb)
	}
	if js := cr.JSON(); js.IRVersion != 0 || js.ExprIR != "" || js.MaxSteps != 0 {
		t.Errorf("JSON() = %+v", js)
	}
	if _, err := Lower(cr); err == nil {
		t.Error("Lower() of a rule without a checked AST succeeded")
	}
	if _, err := Lower(nil); err == nil {
		t.Error("Lower(nil) succeeded")
	}
	// Proto() hands out a copy: mutating it does not change the rule.
	full := compileExpr(t, "net.tor")
	full.Proto().ExprIr[0] ^= 0xff
	if !bytes.Equal(full.Proto().GetExprIr(), full.ExprIR) || full.ExprIR[0] != 0x08 {
		t.Error("Proto() aliases the rule's IR bytes")
	}
}

// TestLowerRejects covers every construct of spec §5.2 with its diagnostic
// and the position of the offending sub-expression.
func TestLowerRejects(t *testing.T) {
	cases := []struct {
		expr string
		want string // substring of the diagnostic, including its column
	}{
		{`risk.score > 1 && req.path + "x" == "y"`, `:4:39: error: rule "r": expr: unsupported in policy IR: string concatenation`},
		{`risk.score + 1 > 2`, `:4:23: error: rule "r": expr: unsupported in policy IR: arithmetic (+)`},
		{`net.tor && -risk.score < 0`, `:4:23: error: rule "r": expr: unsupported in policy IR: unary minus on a non-literal value`},
		{`size(labels + ["a"]) > 0`, `:4:24: error: rule "r": expr: unsupported in policy IR: list concatenation`},
		{`req.path.matches("^/a")`, `:4:28: error: rule "r": expr: unsupported in policy IR: matches() (regular expressions)`},
		{`labels.exists(l, l == "x") || net.tor`, `:4:25: error: rule "r": expr: unsupported in policy IR: macro exists() (macros and comprehensions)`},
		{`labels.all(l, l == "x")`, `unsupported in policy IR: macro all()`},
		{`labels.exists_one(l, l == "x")`, `unsupported in policy IR: macro exists_one()`},
		{`size(labels.map(l, l)) > 0`, `unsupported in policy IR: macro map()`},
		{`size(labels.filter(l, l == "x")) > 0`, `unsupported in policy IR: macro filter()`},
		{`net.tor && int(risk.confidence) > 0`, `:4:26: error: rule "r": expr: unsupported in policy IR: type conversion int()`},
		{`uint(risk.score) == uint(1)`, `unsupported in policy IR: type conversion uint()`},
		{`double(risk.score) > 0.5`, `unsupported in policy IR: type conversion double()`},
		{`string(risk.score) == "1"`, `unsupported in policy IR: type conversion string()`},
		{`size(bytes(req.path)) > 0`, `unsupported in policy IR: type conversion bytes()`},
		{`dyn(risk.score) == 1`, `unsupported in policy IR: type conversion dyn()`},
		{`type(risk.score) == int`, `unsupported in policy IR: type conversion type()`},
		{`bool("true")`, `unsupported in policy IR: type conversion bool()`},
		{`timestamp("2026-01-01T00:00:00Z") < timestamp("2027-01-01T00:00:00Z")`, `unsupported in policy IR: timestamps and durations (timestamp())`},
		{`duration("1s") > duration("0s")`, `unsupported in policy IR: timestamps and durations (duration())`},
		{`1u == 1u`, `unsupported in policy IR: uint literal`},
		{`b"a" == b"a"`, `unsupported in policy IR: bytes literal`},
		{`null == null`, `unsupported in policy IR: null literal`},
		{`"a" in {"a": 1}`, `unsupported in policy IR: map literal`},
		{`policy.Request{method: "GET"}.method == "GET"`, `unsupported in policy IR: message literal`},
		{`net.tor && labels[0] == "x"`, `:4:29: error: rule "r": expr: unsupported in policy IR: list index l[i]`},
		{`net.tor < true`, `unsupported in policy IR: ordering of bool values (<)`},
		{`labels == ["a"]`, `unsupported in policy IR: == on list(string) values`},
		{`req.headers != req.headers`, `unsupported in policy IR: != on map(string, string) values`},
		{`[[1]] == [[1]]`, `unsupported in policy IR: list literal with list(int) elements`},
		{`labels in [labels]`, `unsupported in policy IR: list literal with list(string) elements`},
		{`net.tor && tls.ja4 == tls.ja4`, `:4:26: error: rule "r": expr: unsupported in policy IR: tls.ja4 used as a value; read one of its fields`},
		{`req == req`, `unsupported in policy IR: req used as a value`},
		{`(net.tor ? tls.ja4 : tls.ja4).value == ""`, `unsupported in policy IR: tls.ja4 used as a value`},
		// Ruling I-20: only a map field can be indexed or selected, never a
		// map computed by ?: (whichever branch types or keys).
		{`net.tor && (net.tor ? req.headers : req.headers)["accept"] == "x"`, `:4:60: error: rule "r": expr: unsupported in policy IR: computed map; index or select a map field directly`},
		{`(net.tor ? req.headers : req.headers).accept == "x"`, `unsupported in policy IR: computed map`},
		{`(net.tor ? rate : rate)["login"] > 0.5`, `unsupported in policy IR: computed map`},
		{`(net.tor ? req.headers : req.headers)[req.headers["k"]] == "x"`, `unsupported in policy IR: computed map`},
		{`(net.tor ? req.headers : (risk.score > 50 ? req.headers : req.headers)).accept == "x"`, `unsupported in policy IR: computed map`},
		{`net.tor && has(req.headers.accept)`, `:4:26: error: rule "r": expr: unsupported in policy IR: has() on a map key; use "accept" in <map> instead`},
		{`has(rate.login)`, `unsupported in policy IR: has() on a map key`},
		// Optional syntax is a parse error in this environment; it still
		// carries the §5.2 message prefix.
		{`req.?path == "x"`, `:4:15: error: rule "r": expr: unsupported in policy IR: optional syntax ('.?')`},
		{`req.headers[?"accept"] == "x"`, `unsupported in policy IR: optional syntax ('[?')`},
		{`req.method in [?req.method]`, `unsupported in policy IR: optional syntax ('?')`},
		{`req.host in list(req.host)`, `list() takes a string literal name so lists can be resolved when the bundle is built`},
		{`req.host in list("Bad Name")`, `list name "Bad Name" must match`},
		{`glob(req.path, req.query)`, `glob() pattern must be a string literal`},
		{`glob(req.path, "")`, `glob() pattern must not be empty`},
		{`ip_in(net.ip, ["10.0.0.0/33"])`, `ip_in: invalid CIDR "10.0.0.0/33"`},
		{`ip_in("10.0.0.0/8", ["10.0.0.0/8"])`, `ip_in: "10.0.0.0/8" is not an IP address`},
		// glob on req.path costs 2 + 8192 * len(pattern) / 16 steps: 196 bytes is over the bound.
		{`glob(req.path, "` + strings.Repeat("a", 196) + `")`, `rule exceeds the evaluation step bound: 100354 > 100000`},
	}
	for _, tc := range cases {
		src := "policies:\n  - id: r\n    phase: bot\n    expr: '" + tc.expr + "'\n    action: log\n"
		checked, diags := checkSource(t, Options{MaxCost: 1 << 62}, src)
		if len(checked) != 0 || !diags.HasErrors() {
			t.Errorf("%s: compiled without errors", tc.expr)
			continue
		}
		requireDiag(t, diags, tc.want)
	}
}

// TestLowerStructureLimits: the compiler rejects IR the Edge would refuse
// (spec §5.3 structure limits).
func TestLowerStructureLimits(t *testing.T) {
	long := `req.path == "` + strings.Repeat("a", MaxIRStringBytes+1) + `"`
	many := "req.method in [" + strings.Repeat(`"a", `, MaxIRListElements) + `"a"]`
	nest := func(n int) string { // n nested conditionals around a field: depth n + 1
		return strings.Repeat("net.tor ? (", n) + "net.tor" + strings.Repeat(") : false", n)
	}
	deep := nest(MaxIRDepth)
	wide := strings.Repeat("net.tor || ", MaxIRNodes) + "net.tor"
	cases := []struct{ expr, want string }{
		{long, "unsupported in policy IR: string literal of 4097 bytes (limit 4096)"},
		{`glob(req.path, "` + strings.Repeat("a", MaxIRStringBytes+1) + `")`, "unsupported in policy IR: glob() pattern of 4097 bytes (limit 4096)"},
		// req.headers.<name> lowers to index_map with a string literal key.
		{`req.headers.` + strings.Repeat("a", MaxIRStringBytes+1) + ` == "x"`, "unsupported in policy IR: map key of 4097 bytes (limit 4096)"},
		{many, "unsupported in policy IR: list literal with 1001 elements (limit 1000)"},
		{deep, "unsupported in policy IR: expression nests 51 levels deep (limit 50)"},
		{wide, "unsupported in policy IR: expression has 4098 IR nodes (limit 4096)"},
	}
	for _, tc := range cases {
		_, diags := compileCase(t, conformanceCase{Name: "limits", Expr: tc.expr})
		requireDiag(t, diags, tc.want)
	}
	// Right at the limits is fine.
	for _, expr := range []string{
		`glob(req.path, "` + strings.Repeat("a", 195) + `")`, // 99842 steps
		`req.path == "` + strings.Repeat("a", MaxIRStringBytes) + `"`,
		`req.headers.` + strings.Repeat("a", MaxIRStringBytes) + ` == "x"`,
		"req.method in [" + strings.Repeat(`"a", `, MaxIRListElements-1) + `"a"]`,
		nest(MaxIRDepth - 1),
	} {
		cr := compileExpr(t, expr)
		if n, depth := irShape(cr.IR.GetRoot(), 1); n > MaxIRNodes || depth > MaxIRDepth {
			t.Errorf("shape %d nodes, depth %d", n, depth)
		}
	}
}

// TestLowerErrorFromAPI: Lower reports the same problems as Check for a
// checked AST that the compiler would reject.
func TestLowerErrorFromAPI(t *testing.T) {
	c := newTestCompiler(t, Options{})
	ast, iss := c.env.Compile(`risk.score * 2 > 1 && labels.all(l, l != "")`)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	_, err := Lower(&CheckedRule{Rule: &Rule{ID: "direct"}, AST: ast})
	if err == nil || !strings.Contains(err.Error(), `rule "direct": unsupported in policy IR: arithmetic (*); unsupported in policy IR: macro all()`) {
		t.Errorf("Lower() error = %v", err)
	}
	// A CheckedRule assembled by hand, without its Rule, is an error, not a
	// panic, both for Lower and for the evaluator.
	if _, err := Lower(&CheckedRule{AST: ast}); err == nil || !strings.Contains(err.Error(), "unsupported in policy IR") {
		t.Errorf("Lower() without Rule: error = %v", err)
	}
	if _, err := Lower(&CheckedRule{}); err == nil {
		t.Error("Lower() without AST succeeded")
	}
	ok, iss := c.env.Compile(`req.headers["nope"] == ""`)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	ev, err := NewEvaluator(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Eval(&CheckedRule{AST: ok}, &Input{}); err == nil {
		t.Error("Eval() without Rule succeeded")
	}
	if res, err := ev.EvalWithMissing(&CheckedRule{AST: ok}, &Input{}, nil); err != nil || res != ResultError {
		t.Errorf("EvalWithMissing() without Rule = %v, %v", res, err)
	}
}

// TestUnsupportedIRFile checks the invalid fixture end to end: one error per
// rule, located at the sub-expression.
func TestUnsupportedIRFile(t *testing.T) {
	_, diags := checkFiles(t, "../../testdata/policies/invalid/unsupported-ir.yaml")
	want := []string{
		`unsupported-ir.yaml:7:40: error: rule "arithmetic": expr: unsupported in policy IR: arithmetic (*)`,
		`unsupported-ir.yaml:12:24: error: rule "macro": expr: unsupported in policy IR: macro exists() (macros and comprehensions)`,
		`unsupported-ir.yaml:17:27: error: rule "regex": expr: unsupported in policy IR: matches() (regular expressions)`,
		`unsupported-ir.yaml:22:14: error: rule "has-on-header": expr: unsupported in policy IR: has() on a map key; use "cookie" in <map> instead`,
		`unsupported-ir.yaml:28: error: rule "step-bound": expr: rule exceeds the evaluation step bound: 114703 > 100000 (at expr 1:`,
		`unsupported-ir.yaml:36:54: error: rule "computed-map": expr: unsupported in policy IR: computed map`,
	}
	for _, w := range want {
		requireDiag(t, diags, w)
	}
	if n := len(diags.Errors()); n != len(want) {
		t.Errorf("%d errors, want %d:\n  %s", n, len(want), strings.Join(diagStrings(diags), "\n  "))
	}
}
