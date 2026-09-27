package bundle

import (
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/policy"
	"morphgate/control-plane/internal/sitecfg"
)

// Phase 1 rule parameters (spec §3.2): which keys each action takes.
var paramsFor = map[string][]string{
	"challenge":  {"type"},
	"tag":        {"label"},
	"rate_limit": {"limiter", "retry_after_s"},
}

var (
	phase1Params         = []string{"type", "label", "limiter", "retry_after_s"}
	phase1ChallengeTypes = []string{"invisible", "pow", "interactive"}
	tagLabelPattern      = regexp.MustCompile(`^[a-z0-9_.-]{1,32}$`)
)

// rules compiles an environment's policy files and returns the rules that go
// into the bundle, in engine order.
func (b *builder) rules(env sitecfg.Environment) []*morphgatev1.CompiledRule {
	compiler, err := policy.NewCompiler(policy.Options{
		MaxCost: b.opts.MaxCost,
		Profile: b.site.Profile,
		Now:     func() time.Time { return b.opts.Now },
	})
	if err != nil {
		b.problem("environment %s: %v", env.Name, err)
		return nil
	}
	var parsed []*policy.Rule
	var diags policy.Diagnostics
	for _, f := range env.Policies {
		b.readSource(f)
		rs, ds := policy.ParseFile(f)
		parsed = append(parsed, rs...)
		diags = append(diags, ds...)
	}
	checked, ds := compiler.Check(parsed)
	diags = append(diags, ds...)
	for _, d := range diags {
		if d.Severity == policy.SeverityError {
			b.problem("environment %s: %s", env.Name, d)
		} else {
			b.warn("environment %s: %s", env.Name, d)
		}
	}
	if diags.HasErrors() {
		return nil
	}
	var out []*morphgatev1.CompiledRule
	for _, cr := range checked {
		// Disabled and expired rules never enter the bundle (D-19).
		if cr.Mode == "disabled" || (cr.ExpiresAt != nil && !b.opts.Now.Before(*cr.ExpiresAt)) {
			continue
		}
		where := fmt.Sprintf("environment %s: %s:%d: rule %q", env.Name, cr.File, cr.Pos.Line, cr.ID)
		ok := b.checkRule(where, cr, env, diags)
		pb := ruleProto(cr)
		if pb.IrVersion != IRVersion || len(pb.ExprIr) == 0 {
			b.problem("%s: policy IR unavailable (ir_version %d, %d IR bytes): the Edge cannot load this rule", where, pb.IrVersion, len(pb.ExprIr))
			continue
		}
		if b.checkIR(where, pb.ExprIr) && ok {
			out = append(out, pb)
		}
	}
	sortRules(out)
	return out
}

// checkRule applies the Phase 1 rule restrictions of spec §3.2 and §8.2.
func (b *builder) checkRule(where string, cr *policy.CheckedRule, env sitecfg.Environment, diags policy.Diagnostics) bool {
	ok := true
	fail := func(format string, args ...any) {
		b.problem("%s: %s", where, fmt.Sprintf(format, args...))
		ok = false
	}
	if cr.Action == "tarpit" {
		fail("action tarpit is not available in Phase 1 (D-09)")
	}
	for _, k := range slices.Sorted(maps.Keys(cr.Params)) {
		switch {
		case !slices.Contains(phase1Params, k):
			fail("params.%s is not a Phase 1 parameter (%s)", k, strings.Join(phase1Params, ", "))
		case !slices.Contains(paramsFor[cr.Action], k):
			fail("params.%s does not apply to action %s", k, cr.Action)
		}
	}
	switch cr.Action {
	case "challenge":
		t, set := cr.Params["type"]
		switch {
		case set && !slices.Contains(phase1ChallengeTypes, t):
			fail("params.type %q is not available in Phase 1 (%s)", t, strings.Join(phase1ChallengeTypes, ", "))
		case t == "interactive" && !slices.ContainsFunc(diags, func(d policy.Diagnostic) bool {
			return d.RuleID == cr.ID && d.Severity == policy.SeverityWarning && strings.Contains(d.Message, "interactive")
		}):
			b.warn("%s: params.type interactive runs as pow in Phase 1 (D-08)", where)
		}
	case "tag":
		if l, set := cr.Params["label"]; !set || !tagLabelPattern.MatchString(l) {
			fail("a tag rule needs params.label matching %s", tagLabelPattern)
		}
	case "rate_limit":
		if s, set := cr.Params["retry_after_s"]; set {
			if n, err := strconv.ParseUint(s, 10, 32); err != nil || n < 1 || n > 86400 {
				fail("params.retry_after_s %q must be a whole number of seconds between 1 and 86400", s)
			}
		}
		if id, set := cr.Params["limiter"]; set {
			if !sitecfg.LimiterIDPattern.MatchString(id) {
				fail("params.limiter %q does not match %s", id, sitecfg.LimiterIDPattern)
			} else if !slices.ContainsFunc(env.RateLimits, func(l sitecfg.RateLimit) bool { return l.ID == id }) {
				b.warn("%s: params.limiter %q is not a rate limiter of environment %s", where, id, env.Name)
			}
		}
	}
	for _, name := range cr.Lists {
		if _, found := b.lists[name]; !found {
			fail("list(%q) is not defined in lists or list_files", name)
		}
	}
	return ok
}

// checkIR decodes the rule's PolicyExpr as a backstop: version, step bound,
// named lists defined, and lists used by ip_in made of addresses and CIDRs.
func (b *builder) checkIR(where string, ir []byte) bool {
	var pe morphgatev1.PolicyExpr
	if err := proto.Unmarshal(ir, &pe); err != nil {
		b.problem("%s: policy IR does not decode: %v", where, err)
		return false
	}
	ok := true
	if pe.IrVersion != IRVersion || pe.Root == nil {
		b.problem("%s: policy IR has ir_version %d and root %v, want %d and an expression", where, pe.IrVersion, pe.Root != nil, IRVersion)
		ok = false
	}
	if pe.MaxSteps > MaxSteps {
		b.problem("%s: rule exceeds the evaluation step bound: %d > %d", where, pe.MaxSteps, MaxSteps)
		ok = false
	}
	named, ipLists := irLists(pe.Root)
	for _, name := range named {
		if _, found := b.lists[name]; !found {
			b.problem("%s: policy IR uses list %q, which is not defined in lists or list_files", where, name)
			ok = false
		}
	}
	for _, name := range ipLists {
		for _, e := range b.lists[name] {
			if !ipOrCIDR(e) {
				b.problem("%s: list %q is used with ip_in() but entry %q is not an IP address or CIDR (every evaluation would fail)", where, name, e)
				ok = false
				break
			}
		}
	}
	return ok
}

// irLists returns the named lists an expression uses and, separately, those
// used directly as the list argument of ip_in(), each sorted and unique.
func irLists(root *morphgatev1.Expr) (named, ipIn []string) {
	seen, seenIP := map[string]bool{}, map[string]bool{}
	stack := []*morphgatev1.Expr{root}
	push := func(es ...*morphgatev1.Expr) {
		for _, e := range es {
			if e != nil {
				stack = append(stack, e)
			}
		}
	}
	for len(stack) > 0 {
		e := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if e == nil {
			continue
		}
		switch k := e.Kind.(type) {
		case *morphgatev1.Expr_NamedList:
			seen[k.NamedList] = true
		case *morphgatev1.Expr_List:
			push(k.List.GetElements()...)
		case *morphgatev1.Expr_Not:
			push(k.Not.GetArg())
		case *morphgatev1.Expr_And:
			push(k.And.GetArgs()...)
		case *morphgatev1.Expr_Or:
			push(k.Or.GetArgs()...)
		case *morphgatev1.Expr_Cond:
			push(k.Cond.GetCond(), k.Cond.GetThenExpr(), k.Cond.GetElseExpr())
		case *morphgatev1.Expr_Compare:
			push(k.Compare.GetLhs(), k.Compare.GetRhs())
		case *morphgatev1.Expr_InList:
			push(k.InList.GetLhs(), k.InList.GetRhs())
		case *morphgatev1.Expr_InMap:
			push(k.InMap.GetLhs(), k.InMap.GetRhs())
		case *morphgatev1.Expr_IndexMap:
			push(k.IndexMap.GetLhs(), k.IndexMap.GetRhs())
		case *morphgatev1.Expr_Size:
			push(k.Size.GetArg())
		case *morphgatev1.Expr_StringCall:
			push(k.StringCall.GetTarget(), k.StringCall.GetArg())
		case *morphgatev1.Expr_IpIn:
			if name := k.IpIn.GetRhs().GetNamedList(); name != "" {
				seenIP[name] = true
			}
			push(k.IpIn.GetLhs(), k.IpIn.GetRhs())
		case *morphgatev1.Expr_Glob:
			push(k.Glob.GetSubject())
		}
	}
	return slices.Sorted(maps.Keys(seen)), slices.Sorted(maps.Keys(seenIP))
}

// ipOrCIDR accepts what ip_in() accepts as a list entry (spec §5.3).
func ipOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}
