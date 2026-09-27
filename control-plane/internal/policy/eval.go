package policy

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"
)

// Result is the outcome of evaluating a rule expression under the
// three-valued MISSING semantics of docs/impl/phase1-spec.md §5.3.
type Result int

const (
	// ResultFalse: the rule does not match.
	ResultFalse Result = iota
	// ResultTrue: the rule matches.
	ResultTrue
	// ResultUnknown: the result depends on a MISSING field; the rule does not
	// match and the Edge records missing_input.
	ResultUnknown
	// ResultError: evaluation failed (no such key, invalid ip_in entry,
	// unknown named list, ...); the rule does not match and the Edge records
	// eval_error.
	ResultError
)

// String returns the conformance-fixture name of r: "false", "true",
// "unknown" or "error" (the `expect` values of testdata/policy-ir/cases.json).
func (r Result) String() string {
	switch r {
	case ResultFalse:
		return "false"
	case ResultTrue:
		return "true"
	case ResultUnknown:
		return "unknown"
	case ResultError:
		return "error"
	}
	return fmt.Sprintf("Result(%d)", int(r))
}

// Evaluator runs checked rules against an Input with cel-go. It is the
// reference semantics that the Rust IR evaluator is tested against
// (testdata/policy-ir); the data plane never runs cel-go.
type Evaluator struct {
	env *cel.Env
}

// NewEvaluator returns an evaluator whose list(name) resolves from lists.
func NewEvaluator(lists map[string][]string) (*Evaluator, error) {
	env, err := newEnv(func(name string) ([]string, bool) {
		l, ok := lists[name]
		return l, ok
	})
	if err != nil {
		return nil, err
	}
	// The strict map index that strictIndex rewrites computed-map indexes
	// to. Its name starts with '@', so policy source can never call it; it
	// exists only in the evaluator's environment, not in the compiler's.
	v := cel.TypeParamType("V")
	env, err = env.Extend(cel.Function(strictIndexFunction,
		cel.Overload("mg_strict_index_map_string",
			[]*cel.Type{cel.MapType(cel.StringType, v), cel.StringType}, v,
			cel.BinaryBinding(func(m, k ref.Val) ref.Val {
				idx, ok := m.(traits.Indexer)
				if !ok {
					return types.MaybeNoSuchOverloadErr(m)
				}
				return idx.Get(k)
			}))))
	if err != nil {
		return nil, err
	}
	return &Evaluator{env: env}, nil
}

// EvalWithMissing evaluates the rule with the given MISSING paths (spec §4.3:
// each a schema path such as "tls", "http.header_order" or
// "edge_tls.hello_len"; a path is MISSING when it equals or lies below one of
// them). The semantics are spec §5.3 without step counting: has(p) is false
// exactly for MISSING paths, reading a MISSING field is unknown, && / ||
// absorb unknown with false / true and prefer unknown over error, strict
// operations return their first error before any unknown, and a conditional
// with an unknown condition is unknown.
//
// Implementation (spec §5.3 "Go reference semantics"): every has(p) is first
// replaced by the literal !missing(p); then cel-go partial evaluation runs
// with one unknown attribute pattern per MISSING path. The error return is
// for invalid arguments (a nil rule, a path that is not in the schema), not
// for expression errors, which are ResultError.
func (e *Evaluator) EvalWithMissing(cr *CheckedRule, in *Input, missing []string) (Result, error) {
	res, _, err := e.evaluate(cr, in, missing, 0)
	return res, err
}

// Eval reports whether the rule's expression matches in, with no MISSING
// paths (has(x) is true for every field): EvalWithMissing(cr, in, nil) with
// ResultError returned as an error. The rule's estimated worst-case cel-go
// cost doubles as a runtime cost limit, so inputs larger than the size caps
// of spec §4.1 (e.g. a path over 8 KiB) fail with a cost error, as the Edge
// would reject them.
func (e *Evaluator) Eval(cr *CheckedRule, in *Input) (bool, error) {
	var costLimit uint64 = 1
	if cr != nil {
		costLimit = max(cr.Cost.Max, 1)
	}
	res, out, err := e.evaluate(cr, in, nil, costLimit)
	switch {
	case err != nil:
		return false, err
	case res == ResultError:
		return false, fmt.Errorf("rule %q: %v", cr.ruleID(), out)
	case res == ResultUnknown:
		return false, fmt.Errorf("rule %q: unknown result without MISSING paths", cr.ruleID())
	}
	return res == ResultTrue, nil
}

// evaluate runs the rule and returns the result together with the raw cel-go
// value (a *types.Unknown carries the attribute trails of the unknown reads).
// costLimit 0 means no limit.
func (e *Evaluator) evaluate(cr *CheckedRule, in *Input, missing []string, costLimit uint64) (Result, ref.Val, error) {
	if cr == nil || cr.AST == nil {
		return ResultError, nil, errNoIR
	}
	if in == nil {
		in = &Input{}
	}
	patterns := make([]*cel.AttributePatternType, 0, len(missing))
	for _, p := range missing {
		if !isSchemaPath(p) {
			return ResultError, nil, fmt.Errorf("policy: MISSING path %q is not a policy field", p)
		}
		parts := strings.Split(p, ".")
		pat := cel.AttributePattern(parts[0])
		for _, q := range parts[1:] {
			pat = pat.QualString(q)
		}
		patterns = append(patterns, pat)
	}

	opt, err := cel.NewStaticOptimizer(hasSubstitution{missing: missing}, strictIndex{})
	if err != nil {
		return ResultError, nil, err
	}
	ast, iss := opt.Optimize(e.env, cr.AST)
	if iss != nil && iss.Err() != nil {
		return ResultError, nil, fmt.Errorf("rule %q: %w", cr.ruleID(), iss.Err())
	}
	progOpts := []cel.ProgramOption{cel.EvalOptions(cel.OptPartialEval)}
	if costLimit > 0 {
		progOpts = append(progOpts, cel.CostLimit(costLimit),
			cel.CostTrackerOptions(interpreter.OverloadCostTracker(overloads.ContainsString, containsActualCost)))
	}
	prg, err := e.env.Program(ast, progOpts...)
	if err != nil {
		return ResultError, nil, fmt.Errorf("rule %q: %w", cr.ruleID(), err)
	}
	vars, err := cel.PartialVars(in.activation(), patterns...)
	if err != nil {
		return ResultError, nil, err
	}
	out, _, err := prg.Eval(vars)
	switch v := out.(type) {
	case types.Bool:
		if err == nil {
			if v {
				return ResultTrue, out, nil
			}
			return ResultFalse, out, nil
		}
	case *types.Unknown:
		return ResultUnknown, out, nil
	}
	if out == nil && err != nil {
		out = types.WrapErr(err)
	}
	return ResultError, out, nil
}

// unknownPaths returns the dotted attribute paths recorded in a cel-go
// unknown value, sorted and unique ("tls", "edge_tls.hello_len").
func unknownPaths(v ref.Val) []string {
	unk, ok := v.(*types.Unknown)
	if !ok {
		return nil
	}
	var out []string
	for _, id := range unk.IDs() {
		trails, _ := unk.GetAttributeTrails(id)
		for _, t := range trails {
			parts := []string{t.Variable()}
			for _, q := range t.QualifierPath() {
				parts = append(parts, fmt.Sprint(q))
			}
			if p := strings.Join(parts, "."); !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// hasSubstitution is a cel-go AST optimizer that replaces every has(p) by the
// literal !missing(p), so that has() follows spec §5.3 (false iff MISSING;
// true for ABSENT zero values) instead of cel-go's native-type presence test.
type hasSubstitution struct {
	missing []string
}

var errHasOnComputedValue = errors.New("has() on a computed value")

// Optimize implements cel.ASTOptimizer.
func (h hasSubstitution) Optimize(ctx *cel.OptimizerContext, a *celast.AST) *celast.AST {
	var tests []celast.Expr
	celast.PostOrderVisit(a.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() == celast.SelectKind && e.AsSelect().IsTestOnly() {
			tests = append(tests, e)
		}
	}))
	for _, e := range tests {
		p := selectPath(e)
		if p == "" {
			// The compiler rejects has() on anything but a schema field.
			ctx.ReportErrorAtID(e.ID(), "%v", errHasOnComputedValue)
			continue
		}
		e.SetKindCase(ctx.NewLiteral(types.Bool(!isMissing(p, h.missing))))
	}
	return a
}

// strictIndexFunction is the evaluator-only strict map index (see strictIndex).
const strictIndexFunction = "@mg_strict_index"

// strictIndex is a cel-go AST optimizer that rewrites m[k] into the strict
// function @mg_strict_index(m, k) when m is computed (a conditional) rather
// than a field. cel-go resolves an index on a computed operand as a relative
// attribute: it evaluates the operand and returns it when it is unknown,
// without evaluating the key, so `(c ? m1 : m2)[k]` with an UNKNOWN c and an
// ERROR k would be unknown. index_map is a strict node in spec §5.3 (the
// first ERROR of its children wins over UNKNOWN), and a strict cel-go
// function has exactly those semantics. Indexes on fields (req.headers[k],
// rate[k]) are absolute attributes, which cel-go already evaluates strictly;
// they are left alone.
type strictIndex struct{}

// Optimize implements cel.ASTOptimizer.
func (strictIndex) Optimize(ctx *cel.OptimizerContext, a *celast.AST) *celast.AST {
	var indexes []celast.Expr
	celast.PostOrderVisit(a.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() != celast.CallKind || e.AsCall().FunctionName() != operators.Index {
			return
		}
		if args := e.AsCall().Args(); len(args) == 2 && selectPath(args[0]) == "" {
			indexes = append(indexes, e)
		}
	}))
	for _, e := range indexes {
		args := e.AsCall().Args()
		e.SetKindCase(ctx.NewCall(strictIndexFunction, args[0], args[1]))
	}
	return a
}

// isMissing reports whether path is MISSING under the MISSING set (spec §4.3).
func isMissing(path string, missing []string) bool {
	return slices.ContainsFunc(missing, func(m string) bool { return underPath(path, m) })
}
