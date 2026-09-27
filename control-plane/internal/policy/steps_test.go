package policy

import (
	"math"
	"testing"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

// TestMaxStepsByHand checks the static step bound of spec §5.3 on
// expressions computed by hand. S(x): strings in bytes (req.path 8192,
// req.method 32, req.host 253, other strings 256, headers values 8192), lists
// and maps in entries (labels 64, req.headers 128, http.header_order 128,
// named lists 10,000); bool and numeric results 0.
func TestMaxStepsByHand(t *testing.T) {
	cases := []struct {
		expr string
		want uint64
		why  string
	}{
		{"true", 1, "literal"},
		{"net.tor", 1, "field"},
		{"has(tls.ja4)", 1, "has"},
		{"!net.tor", 2, "not 1 + field 1"},
		{"net.tor && net.tor && net.tor", 4, "and 1 + 3 fields"},
		{"net.tor || net.tor", 3, "or 1 + 2 fields"},
		{"risk.score > 1", 3, "compare on ints costs 1, + 2 children"},
		{"net.tor == true", 3, "compare on bools costs 1"},
		{"risk.confidence < 0.5", 3, "compare on doubles costs 1"},
		{`req.method == "GET"`, 4, "1 + ceil((32 + 3) / 64) = 2, + 2"},
		{`req.path == "/"`, 132, "1 + ceil((8192 + 1) / 64) = 130, + 2"},
		{`req.path == ""`, 131, "1 + ceil(8192 / 64) = 129, + 2"},
		{`req.path == req.query`, 259, "1 + ceil(16384 / 64) = 257, + 2"},
		{`req.host == "a"`, 7, "1 + ceil((253 + 1) / 64) = 5, + 2"},
		{`net.country == ""`, 7, "other strings: 1 + ceil(256 / 64) = 5, + 2"},
		{`req.headers["user-agent"] == ""`, 134, "compare 1 + ceil(8192 / 64) = 129; index_map 2 + 2; literal 1"},
		{`rate["x"] > 0.5`, 6, "compare 1 (a rate value is a double, S = 0); index_map 2 + 2; literal 1"},
		{`"a" in req.headers`, 4, "in_map 2 + 2 children"},
		{`"a" in labels`, 67, "in_list 1 + 64, + 2"},
		{`"a" in risk.reasons`, 35, "in_list 1 + 32, + 2"},
		{`"a" in http.header_order`, 131, "in_list 1 + 128, + 2"},
		{`req.method in ["GET", "HEAD"]`, 7, "in_list 1 + 2; field 1; list 1 + 2"},
		{`req.host in list("hosts")`, 10003, "in_list 1 + 10000; field 1; named_list 1"},
		{`ip_in(net.ip, list("owner"))`, 10003, "ip_in 1 + 10000, + 2"},
		{`ip_in(net.ip, ["10.0.0.0/8", "::1"])`, 7, "ip_in 1 + 2; field 1; list 1 + 2"},
		{"size(req.path) > 0", 132, "size 1 + ceil(8192 / 64) = 129 + field 1; compare 1 + literal 1"},
		{"size(labels) > 0", 4, "size of a list costs 1"},
		{"size(req.headers) > 0", 4, "size of a map costs 1"},
		{`req.path.startsWith("/a")`, 132, "string_call 1 + ceil(8194 / 64) = 130, + 2"},
		{`req.query.endsWith(req.path)`, 259, "string_call 1 + ceil(16384 / 64) = 257, + 2"},
		{`glob(req.path, "/a/*")`, 2050, "glob 1 + floor(8192 * 4 / 16) = 2049, + field 1"},
		{`glob(req.method, "P*")`, 6, "glob 1 + floor(32 * 2 / 16) = 5, + field 1"},
		{`glob(req.host, "*.example.test")`, 223, "glob 1 + floor(253 * 14 / 16) = 222, + field 1"},
		{`net.tor ? req.path == "" : true`, 133, "cond 1 + condition 1 + max(131, 1)"},
		{`(net.tor ? req.path : req.method) == ""`, 133, "compare 1 + ceil(max(8192, 32) / 64) = 129; cond 1 + 1 + max(1, 1) = 3; literal 1"},
		{`(net.tor ? req.headers : req.headers)["a"] == ""`, 136, "compare 129; index_map 2 + cond 3 + literal 1 = 6; literal 1"},
		{`req.method in (net.tor ? ["a"] : ["b", "c", "d"])`, 11, "in_list 1 + max(1, 3) = 4; field 1; cond 1 + 1 + max(2, 4) = 6"},
	}
	for _, tc := range cases {
		cr := compileExpr(t, tc.expr)
		if got := MaxSteps(cr.IR.GetRoot()); got != tc.want || cr.IR.GetMaxSteps() != tc.want {
			t.Errorf("MaxSteps(%s) = %d (PolicyExpr.max_steps %d), want %d (%s)", tc.expr, got, cr.IR.GetMaxSteps(), tc.want, tc.why)
		}
	}
}

// TestMaxStepsNoShortCircuitDiscount: and / or count every argument; cond
// counts only the larger branch.
func TestMaxStepsNoShortCircuitDiscount(t *testing.T) {
	a := MaxSteps(compileExpr(t, `false && req.path == ""`).IR.GetRoot())
	b := MaxSteps(compileExpr(t, `true || req.path == ""`).IR.GetRoot())
	if a != 1+1+131 || b != 1+1+131 {
		t.Errorf("and = %d, or = %d, want 133 both", a, b)
	}
	c := MaxSteps(compileExpr(t, `net.tor ? req.path == "" : req.query == "" || req.path == ""`).IR.GetRoot())
	if want := uint64(1 + 1 + (1 + 131 + 131)); c != want {
		t.Errorf("cond = %d, want %d", c, want)
	}
}

// TestMaxStepsSaturatesAndRejectsMalformed: MaxSteps never overflows and
// never under-estimates a malformed tree.
func TestMaxStepsSaturatesAndRejectsMalformed(t *testing.T) {
	path := &morphgatev1.Expr{Kind: &morphgatev1.Expr_Field{Field: "req.path"}}
	huge := &morphgatev1.Expr{Kind: &morphgatev1.Expr_Glob{Glob: &morphgatev1.Glob{Subject: path, Pattern: string(make([]byte, 1<<20))}}}
	if got, want := MaxSteps(huge), uint64(1+8192*(1<<20)/16+1); got != want {
		t.Errorf("glob with a 1 MiB pattern = %d, want %d", got, want)
	}
	// Valid trees cannot reach 2^64 in practice (every size is capped), so
	// the saturating helpers are tested directly.
	if satMul(math.MaxUint64, 2) != math.MaxUint64 || satMul(1<<32, 1<<32) != math.MaxUint64 ||
		satAdd(math.MaxUint64, 1) != math.MaxUint64 || satMul(0, math.MaxUint64) != 0 || satMul(3, 5) != 15 {
		t.Error("saturating arithmetic")
	}
	if ceilDiv(0, 64) != 0 || ceilDiv(1, 64) != 1 || ceilDiv(64, 64) != 1 || ceilDiv(65, 64) != 2 || ceilDiv(math.MaxUint64, 64) != math.MaxUint64/64+1 {
		t.Error("ceilDiv")
	}

	malformed := []*morphgatev1.Expr{
		nil,
		{},
		{Kind: &morphgatev1.Expr_Literal{Literal: &morphgatev1.Literal{}}},
		{Kind: &morphgatev1.Expr_Field{Field: "req.nope"}},
		{Kind: &morphgatev1.Expr_Field{Field: "tls"}}, // a struct is not a value
		{Kind: &morphgatev1.Expr_Has{Has: "nope"}},
		{Kind: &morphgatev1.Expr_Not{Not: &morphgatev1.Unary{}}},
		{Kind: &morphgatev1.Expr_Compare{Compare: &morphgatev1.Compare{Lhs: path}}},
		{Kind: &morphgatev1.Expr_And{And: &morphgatev1.Nary{Args: []*morphgatev1.Expr{path, nil}}}},
		{Kind: &morphgatev1.Expr_Cond{Cond: &morphgatev1.Cond{Cond: path, ThenExpr: path}}},
		{Kind: &morphgatev1.Expr_Glob{Glob: &morphgatev1.Glob{Pattern: "*"}}},
	}
	for _, e := range malformed {
		if got := MaxSteps(e); got != math.MaxUint64 {
			t.Errorf("MaxSteps(%v) = %d, want saturation for a malformed tree", e, got)
		}
	}
}

// TestMaxStepsFieldCaps: the step bound and the cel-go cost estimator use
// the same §4.1 size caps.
func TestMaxStepsFieldCaps(t *testing.T) {
	for p, want := range map[string]uint64{
		"req.path": 8192, "req.query": 8192, "req.method": 32, "req.host": 253, "req.headers": 128,
		"http.header_order": 128, "labels": 64, "risk.reasons": 32, "rate": 64, "tls.ja4.value": 36,
		"edge_tls.ciphers_sha1": 40, "edge_tls.ext_sha1": 40,
		"net.ip": 256, "route.name": 256, "identity.crawler.cf_vbot_cat": 256,
		"net.asn": 0, "risk.confidence": 0, "net.tor": 0, "tls": 0, "nope": 0,
	} {
		if got := fieldSizeCap(p); got != want {
			t.Errorf("fieldSizeCap(%s) = %d, want %d", p, got, want)
		}
	}
	if mapValueSizeCap("req.headers") != 8192 || mapValueSizeCap("rate") != 0 || mapValueSizeCap("labels") != 0 {
		t.Error("map value caps")
	}
	for p := range sizeHints {
		base := p
		for _, suffix := range []string{".@keys", ".@values", ".@items"} {
			if len(p) > len(suffix) && p[len(p)-len(suffix):] == suffix {
				base = p[:len(p)-len(suffix)]
			}
		}
		if !isSchemaPath(base) {
			t.Errorf("sizeHints key %q is not a schema path", p)
		}
	}
}

// TestMaxStepsMatchesSerializedIR: max_steps survives serialization and is
// recomputed identically from the decoded tree (what the Edge does).
func TestMaxStepsMatchesSerializedIR(t *testing.T) {
	cr := compileExpr(t, `glob(req.path, "/admin/**") && !ip_in(net.ip, ["127.0.0.1", "10.0.0.0/8", "fc00::/7"])`)
	var pe morphgatev1.PolicyExpr
	if err := proto.Unmarshal(cr.ExprIR, &pe); err != nil {
		t.Fatal(err)
	}
	// and 1 + glob (1 + 8192 * 9 / 16 = 4609, + 1) + not (1 + ip_in (1 + 3 + 1 + 4))
	if want := uint64(1 + 4610 + 10); pe.GetMaxSteps() != want || MaxSteps(pe.GetRoot()) != want {
		t.Errorf("max_steps = %d, recomputed %d, want %d", pe.GetMaxSteps(), MaxSteps(pe.GetRoot()), want)
	}
}
