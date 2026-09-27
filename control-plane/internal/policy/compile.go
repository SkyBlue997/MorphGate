package policy

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

// IRVersion is the version of the restricted IR emitted in CompiledRule.
// 0 means "no IR": IR generation is implemented in Phase 1.
const IRVersion = 0

// DefaultMaxCost is the default worst-case CEL cost budget per rule. The
// examples in docs/06 stay well below 20k; a named-list lookup costs ~10k.
const DefaultMaxCost = 100_000

var listNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

// Options configure a Compiler.
type Options struct {
	// MaxCost rejects rules whose estimated worst-case cost exceeds it.
	// Zero means DefaultMaxCost.
	MaxCost uint64
	// Profile is the UpstreamProfile assumed for files that do not declare
	// one with `profile:` (mgctl -profile). A file that declares a different
	// profile is an error. Empty: only declared profiles are checked.
	// Must be one of CheckedProfiles.
	Profile string
	// Now is used for expiry warnings; nil means time.Now.
	Now func() time.Time
}

// Compiler type-checks rules against the policy environment.
type Compiler struct {
	env  *cel.Env
	opts Options
}

// CheckedRule is a rule whose expression compiled to a boolean CEL program.
type CheckedRule struct {
	*Rule
	AST  *cel.Ast
	Cost checker.CostEstimate
	// Fields lists the context fields the expression reads, e.g. "risk.score".
	Fields []string
	// Lists names the named lists the expression uses via list("name"),
	// sorted and unique (docs/impl/phase1-spec.md §8.2: every referenced
	// list must be defined by the site).
	Lists []string
}

// NewCompiler builds the CEL environment. It fails only on programming errors.
func NewCompiler(opts Options) (*Compiler, error) {
	if opts.MaxCost == 0 {
		opts.MaxCost = DefaultMaxCost
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Profile != "" && !slices.Contains(CheckedProfiles, opts.Profile) {
		if slices.Contains(UpstreamProfiles, opts.Profile) {
			return nil, fmt.Errorf("upstream profile %q has no field-availability table yet (checked profiles: %s)", opts.Profile, strings.Join(CheckedProfiles, ", "))
		}
		return nil, fmt.Errorf("unknown upstream profile %q (checked profiles: %s)", opts.Profile, strings.Join(CheckedProfiles, ", "))
	}
	env, err := newEnv(nil)
	if err != nil {
		return nil, err
	}
	return &Compiler{env: env, opts: opts}, nil
}

// Check validates rules (from one or more files) and compiles their
// expressions. It returns the rules that compiled without errors; the caller
// must still treat any error diagnostic as fatal for the whole set.
func (c *Compiler) Check(rules []*Rule) ([]*CheckedRule, Diagnostics) {
	var diags Diagnostics
	firstByID := make(map[string]*Rule, len(rules))
	profileChecked := make(map[string]bool)
	var out []*CheckedRule
	for _, r := range rules {
		if r.Profile != "" && c.opts.Profile != "" && r.Profile != c.opts.Profile && !profileChecked[r.File] {
			profileChecked[r.File] = true
			diags.errorf(r.File, r.profilePos, "", "profile", "file declares profile %q but the check was requested for %q", r.Profile, c.opts.Profile)
		}
		if r.ID != "" {
			if prev, dup := firstByID[r.ID]; dup {
				diags.errorf(r.File, r.posOf("id"), r.ID, "id", "duplicate rule id (first defined at %s:%d)", prev.File, prev.Pos.Line)
			} else {
				firstByID[r.ID] = r
			}
		}
		c.checkSemantics(r, &diags)
		if r.Expr == "" {
			continue
		}
		if cr := c.compileExpr(r, &diags); cr != nil {
			out = append(out, cr)
		}
	}
	return out, diags
}

func (c *Compiler) checkSemantics(r *Rule, diags *Diagnostics) {
	if r.Action == "challenge" {
		if t, ok := r.Params["type"]; ok && !slices.Contains(ChallengeTypes, t) {
			diags.errorf(r.File, r.posOf("params"), r.ID, "params.type", "%q is not one of %s", t, strings.Join(ChallengeTypes, ", "))
		}
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(c.opts.Now()) {
		diags.warnf(r.File, r.posOf("expires_at"), r.ID, "expires_at", "rule expired at %s and will not be applied", r.ExpiresAt.Format(time.RFC3339))
	}
	if r.Rollout == 0 && r.Mode != "disabled" {
		diags.warnf(r.File, r.posOf("rollout"), r.ID, "rollout", "rollout 0 means the rule never applies; use mode: disabled instead")
	}
}

func (c *Compiler) compileExpr(r *Rule, diags *Diagnostics) *CheckedRule {
	ast, iss := c.env.Compile(r.Expr)
	if iss != nil && iss.Err() != nil {
		for _, e := range iss.Errors() {
			pos, where := r.exprDiagPos(e.Location.Line(), e.Location.Column())
			diags.errorf(r.File, pos, r.ID, "expr", "%s%s", e.Message, where)
		}
		return nil
	}
	if !ast.OutputType().IsExactType(types.BoolType) {
		diags.errorf(r.File, r.exprPos, r.ID, "expr", "expression must evaluate to bool, got %s", ast.OutputType())
		return nil
	}

	nerr := len(diags.Errors())
	refs := c.walk(r, ast, diags)
	if len(diags.Errors()) > nerr {
		return nil
	}

	cost, err := c.env.EstimateCost(ast, costEstimator{})
	if err != nil {
		diags.errorf(r.File, r.exprPos, r.ID, "expr", "cost estimation failed: %v", err)
		return nil
	}
	if cost.Max > c.opts.MaxCost {
		diags.errorf(r.File, r.exprPos, r.ID, "expr", "estimated worst-case cost %d exceeds the limit %d", cost.Max, c.opts.MaxCost)
		return nil
	}
	c.checkAvailability(r, refs, diags)
	checkCorroboration(r, ast.NativeRep().Expr(), refs, diags)
	fields := longestPaths(append(slices.Clone(refs.reads), refs.tests...))
	return &CheckedRule{Rule: r, AST: ast, Cost: cost, Fields: fields, Lists: refs.lists}
}

// exprRefs are the context fields an expression refers to.
type exprRefs struct {
	// reads are the field paths the expression reads a value from, longest
	// paths only ("tls.ja4.value" implies "tls.ja4" and "tls").
	reads []string
	// tests are the paths tested for availability with has(), e.g. "tls.ja4".
	tests []string
	// lists are the names passed to list("..."), sorted and unique.
	lists []string
}

// walk performs the static checks that cel-go's type checker cannot express
// and collects the context fields the expression refers to.
func (c *Compiler) walk(r *Rule, ast *cel.Ast, diags *Diagnostics) exprRefs {
	native := ast.NativeRep()
	info := native.SourceInfo()
	report := func(e celast.Expr, format string, args ...any) {
		loc := info.GetStartLocation(e.ID())
		pos, where := r.exprDiagPos(loc.Line(), loc.Column())
		diags.errorf(r.File, pos, r.ID, "expr", "%s%s", fmt.Sprintf(format, args...), where)
	}

	// has(a.b.c) is a test-only selection; its operand chain (a.b, a) is part
	// of the presence test, not a read.
	testSet := map[string]struct{}{}
	inTest := map[int64]bool{}
	celast.PostOrderVisit(native.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() != celast.SelectKind || !e.AsSelect().IsTestOnly() {
			return
		}
		if p := selectPath(e); p != "" {
			testSet[p] = struct{}{}
		}
		for op := e.AsSelect().Operand(); ; op = op.AsSelect().Operand() {
			inTest[op.ID()] = true
			if op.Kind() != celast.SelectKind {
				break
			}
		}
	}))

	readSet := map[string]struct{}{}
	listSet := map[string]struct{}{}
	celast.PostOrderVisit(native.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		switch e.Kind() {
		case celast.SelectKind, celast.IdentKind:
			if inTest[e.ID()] || (e.Kind() == celast.SelectKind && e.AsSelect().IsTestOnly()) {
				return
			}
			if p := selectPath(e); p != "" {
				readSet[p] = struct{}{}
			}
		case celast.CallKind:
			call := e.AsCall()
			args := call.Args()
			switch call.FunctionName() {
			case "list":
				name, ok := stringLiteral(args[0])
				switch {
				case !ok:
					report(args[0], "list() takes a string literal name so lists can be resolved when the bundle is built")
				case !listNamePattern.MatchString(name):
					report(args[0], "list name %q must match %s", name, listNamePattern)
				default:
					listSet[name] = struct{}{}
				}
			case "ip_in":
				if ip, ok := stringLiteral(args[0]); ok {
					if _, err := parseIPOrPrefix(ip); err != nil || strings.Contains(ip, "/") {
						report(args[0], "ip_in: %q is not an IP address", ip)
					}
				}
				if args[1].Kind() == celast.ListKind {
					for _, el := range args[1].AsList().Elements() {
						if s, ok := stringLiteral(el); ok {
							if _, err := parseIPOrPrefix(s); err != nil {
								report(el, "%v", err)
							}
						}
					}
				}
			case "glob":
				p, ok := stringLiteral(args[1])
				switch {
				case !ok:
					report(args[1], "glob() pattern must be a string literal")
				case p == "":
					report(args[1], "glob() pattern must not be empty")
				}
			}
		}
	}))
	return exprRefs{
		reads: longestPaths(slices.Collect(maps.Keys(readSet))),
		tests: longestPaths(slices.Collect(maps.Keys(testSet))),
		lists: slices.Sorted(maps.Keys(listSet)),
	}
}

// longestPaths drops every path that is a prefix of another one ("tls.ja4"
// when "tls.ja4.value" is present) and duplicates, and sorts the rest.
func longestPaths(paths []string) []string {
	var out []string
	for _, f := range paths {
		covered := slices.ContainsFunc(paths, func(g string) bool {
			return g != f && strings.HasPrefix(g, f+".")
		})
		if !covered && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}

// selectPath returns "a.b.c" for a chain of field selections rooted at a
// policy variable, or "" for anything else (e.g. selections on call results).
func selectPath(e celast.Expr) string {
	var parts []string
	for {
		switch e.Kind() {
		case celast.SelectKind:
			sel := e.AsSelect()
			parts = append(parts, sel.FieldName())
			e = sel.Operand()
			continue
		case celast.IdentKind:
			name := e.AsIdent()
			if !slices.Contains(Namespaces(), name) {
				return ""
			}
			parts = append(parts, name)
			slices.Reverse(parts)
			return strings.Join(parts, ".")
		}
		return ""
	}
}

func stringLiteral(e celast.Expr) (string, bool) {
	if e.Kind() != celast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().(types.String)
	return string(s), ok
}

// exprDiagPos maps a CEL location (1-based line, 0-based column) onto the
// policy file. For expressions that are not a single verbatim line it returns
// the expression start plus a CEL-relative suffix.
func (r *Rule) exprDiagPos(line, col int) (Position, string) {
	if r.exprInline && line == 1 && r.exprPos.Col > 0 {
		return Position{Line: r.exprPos.Line, Col: r.exprPos.Col + col}, ""
	}
	pos := r.exprPos
	if pos.Line == 0 {
		pos = r.posOf("expr")
	}
	return pos, fmt.Sprintf(" (at expr %d:%d)", line, col+1)
}

// CompiledRuleJSON is the `mgctl policy compile` output for one rule. Field
// names follow morphgate.v1.CompiledRule; cost and source are extra metadata.
// expr_ir is intentionally absent until IR generation lands in Phase 1.
type CompiledRuleJSON struct {
	ID             string            `json:"id"`
	Phase          string            `json:"phase"`
	Priority       int32             `json:"priority"`
	ExprSource     string            `json:"expr_source"`
	IRVersion      uint32            `json:"ir_version"`
	Action         string            `json:"action"`
	Params         map[string]string `json:"params,omitempty"`
	Mode           string            `json:"mode"`
	RolloutPercent uint32            `json:"rollout_percent"`
	Temporary      bool              `json:"temporary,omitempty"`
	ExpiresAtMs    int64             `json:"expires_at_ms,omitempty"`
	Locked         bool              `json:"locked"`
	Owner          string            `json:"owner,omitempty"`
	Description    string            `json:"description,omitempty"`
	Fields         []string          `json:"fields"`
	Cost           CostJSON          `json:"cost"`
	Source         SourceJSON        `json:"source"`
}

// CostJSON is cel-go's worst-case cost estimate.
type CostJSON struct {
	Min uint64 `json:"min"`
	Max uint64 `json:"max"`
}

// SourceJSON points back at the rule in its policy file.
type SourceJSON struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// JSON returns the compile output for the rule.
func (cr *CheckedRule) JSON() CompiledRuleJSON {
	out := CompiledRuleJSON{
		ID:             cr.ID,
		Phase:          cr.Phase,
		Priority:       cr.Priority,
		ExprSource:     cr.Expr,
		IRVersion:      IRVersion,
		Action:         cr.Action,
		Params:         cr.Params,
		Mode:           cr.Mode,
		RolloutPercent: uint32(cr.Rollout),
		Temporary:      cr.Temporary,
		Locked:         cr.Locked,
		Owner:          cr.Owner,
		Description:    cr.Description,
		Fields:         cr.Fields,
		Cost:           CostJSON{Min: cr.Cost.Min, Max: cr.Cost.Max},
		Source:         SourceJSON{File: cr.File, Line: cr.Pos.Line},
	}
	if out.Fields == nil {
		out.Fields = []string{}
	}
	if cr.ExpiresAt != nil {
		out.ExpiresAtMs = cr.ExpiresAt.UnixMilli()
	}
	return out
}

// Proto converts the rule to the shared contract message. ExprIr stays empty
// and IrVersion 0 until Phase 1.
func (cr *CheckedRule) Proto() *morphgatev1.CompiledRule {
	pb := &morphgatev1.CompiledRule{
		Id:             cr.ID,
		Phase:          cr.Phase,
		Priority:       cr.Priority,
		ExprSource:     cr.Expr,
		IrVersion:      IRVersion,
		Action:         ActionEnum(cr.Action),
		Params:         cr.Params,
		Mode:           cr.Mode,
		RolloutPercent: uint32(cr.Rollout),
		Locked:         cr.Locked,
	}
	if cr.ExpiresAt != nil {
		pb.ExpiresAtMs = cr.ExpiresAt.UnixMilli()
	}
	return pb
}

// ActionEnum maps a policy action name to morphgate.v1.Action
// (ACTION_UNSPECIFIED for unknown names).
func ActionEnum(action string) morphgatev1.Action {
	return morphgatev1.Action(morphgatev1.Action_value["ACTION_"+strings.ToUpper(action)])
}

// ChallengeTypeEnum maps params.type of a challenge rule to morphgate.v1.ChallengeType.
func ChallengeTypeEnum(t string) morphgatev1.ChallengeType {
	return morphgatev1.ChallengeType(morphgatev1.ChallengeType_value["CHALLENGE_TYPE_"+strings.ToUpper(t)])
}
