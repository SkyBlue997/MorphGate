package policy

import (
	"slices"
	"strings"

	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

// UpstreamProfiles are the profile names a policy file may declare with the
// top-level `profile:` key: the lower-case morphgate.v1.UpstreamProfileKind
// values in enum order (docs/08 §1.1).
var UpstreamProfiles = func() []string {
	var out []string
	for n := int32(1); ; n++ {
		name, ok := morphgatev1.UpstreamProfileKind_name[n]
		if !ok {
			return out
		}
		out = append(out, strings.ToLower(strings.TrimPrefix(name, "UPSTREAM_PROFILE_KIND_")))
	}
}()

// CheckedProfiles are the profiles whose always-MISSING fields the compiler
// knows (the Phase 1 profiles). Other declared profiles skip the check.
var CheckedProfiles = []string{"cloudflare", "direct_tls"}

// alwaysMissing lists, per UpstreamProfile, the field prefixes that are
// MISSING on every request of that profile in Phase 1, with a hint (spec §4.4;
// docs/03 §3.1 per-signal table, docs/08 §2.5, D-07).
var alwaysMissing = map[string][]struct{ prefix, hint string }{
	"cloudflare": {
		{"tls", "Cloudflare terminates the visitor's TLS; edge_tls.* is the weak, shadow-first substitute"},
		{"http.header_order", "Cloudflare does not preserve header order"},
		{"identity.proof", "proof of possession arrives in Phase 2"},
		{"identity.agent", "agent identities arrive in Phase 3"},
	},
	"direct_tls": {
		{"edge_tls", "edge_tls.* is only forwarded by Cloudflare"},
		{"identity.crawler.cf_vbot", "the verified-bot flag is only forwarded by Cloudflare"},
		{"identity.crawler.cf_vbot_cat", "the verified-bot category is only forwarded by Cloudflare"},
		{"tls.ja4", "JA4 is a Phase 1 spike only"},
		{"identity.proof", "proof of possession arrives in Phase 2"},
		{"identity.agent", "agent identities arrive in Phase 3"},
	},
}

// Cloudflare's verified-bot fields: corroboration only (docs/05 §3.4, docs/06 §2).
var cloudflareVerifiedBotFields = []string{"identity.crawler.cf_vbot", "identity.crawler.cf_vbot_cat"}

// effectiveProfile is the profile a rule is checked against: the one its file
// declares, else Options.Profile, else "" (no check).
func (c *Compiler) effectiveProfile(r *Rule) string {
	if r.Profile != "" {
		return r.Profile
	}
	return c.opts.Profile
}

// checkAvailability warns about reads of fields that are always MISSING under
// the rule's profile and are not guarded by has() (docs/06 §2). It is a
// warning, not an error: a policy file may serve several sites, and the rule
// is still well defined (it simply never matches through that field).
//
// Guard approximation: a read of f counts as guarded when the expression also
// contains has(g) for g on the same path as f (g == f, or one is a prefix of
// the other) and inside the MISSING region, e.g. has(tls.ja4) guards
// tls.ja4.value. Positions are not compared: CEL's && and || are commutative
// for unknown values, so `x.v == 1 && has(x)` behaves like `has(x) && x.v == 1`.
//
// Evaluation-time MISSING semantics (unknown, missing_input) are spec §5.3;
// Evaluator.EvalWithMissing is the reference implementation.
func (c *Compiler) checkAvailability(r *Rule, refs exprRefs, diags *Diagnostics) {
	profile := c.effectiveProfile(r)
	for _, f := range refs.reads {
		for _, m := range alwaysMissing[profile] {
			if !underPath(f, m.prefix) {
				continue
			}
			guarded := slices.ContainsFunc(refs.tests, func(g string) bool {
				return underPath(g, m.prefix) && (underPath(f, g) || underPath(g, f))
			})
			if !guarded {
				diags.warnf(r.File, r.exprPos, r.ID, "expr",
					"%s is always MISSING under the %s profile (%s); comparisons on it evaluate to unknown, guard them with has(%s)",
					f, profile, m.hint, guardPath(f, m.prefix))
			}
		}
	}
}

// checkCorroboration warns about allow / block rules that rely on Cloudflare's
// verified-bot fields without MorphGate's own verification: the Cloudflare
// flag may never decide an allow or a block on its own (docs/05 §3.4, docs/06
// §2). The rule is accepted when a top-level && condition (not negated, not
// inside ||) is MorphGate's own evidence: identity.crawler.verified, or a
// comparison of risk.class with a class name.
func checkCorroboration(r *Rule, expr celast.Expr, refs exprRefs, diags *Diagnostics) {
	if r.Action != "allow" && r.Action != "block" {
		return
	}
	var used []string
	for _, f := range cloudflareVerifiedBotFields {
		if slices.Contains(refs.reads, f) || slices.Contains(refs.tests, f) {
			used = append(used, f)
		}
	}
	if len(used) == 0 || slices.ContainsFunc(conjuncts(expr), isOwnVerification) {
		return
	}
	diags.warnf(r.File, r.exprPos, r.ID, "expr",
		"%s decision depends on %s, which is Cloudflare corroboration only; add identity.crawler.verified or a risk.class == \"...\" check as a top-level && condition",
		r.Action, strings.Join(used, " and "))
}

// guardPath suggests the has() argument for a read of f in the MISSING region
// prefix: the region itself when it is a field (has() needs a selection), else
// the field directly below the namespace, e.g. tls.ja4 for tls.ja4.value.
func guardPath(f, prefix string) string {
	parts := strings.Split(f, ".")
	n := max(strings.Count(prefix, ".")+1, 2)
	if n >= len(parts) {
		return f
	}
	return strings.Join(parts[:n], ".")
}

// conjuncts flattens a top-level chain of && into its operands.
func conjuncts(e celast.Expr) []celast.Expr {
	if e.Kind() == celast.CallKind && e.AsCall().FunctionName() == operators.LogicalAnd {
		var out []celast.Expr
		for _, a := range e.AsCall().Args() {
			out = append(out, conjuncts(a)...)
		}
		return out
	}
	return []celast.Expr{e}
}

// isOwnVerification matches `identity.crawler.verified`,
// `identity.crawler.verified == true` and `risk.class == "<name>"` (either
// operand order).
func isOwnVerification(e celast.Expr) bool {
	if selectPath(e) == "identity.crawler.verified" {
		return true
	}
	if e.Kind() != celast.CallKind || e.AsCall().FunctionName() != operators.Equals {
		return false
	}
	args := e.AsCall().Args()
	for _, pair := range [][2]celast.Expr{{args[0], args[1]}, {args[1], args[0]}} {
		field, lit := selectPath(pair[0]), pair[1]
		switch field {
		case "identity.crawler.verified":
			if lit.Kind() == celast.LiteralKind && lit.AsLiteral() == types.True {
				return true
			}
		case "risk.class":
			if _, ok := stringLiteral(lit); ok {
				return true
			}
		}
	}
	return false
}
