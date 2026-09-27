package policy

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

// Limits of the policy IR (docs/impl/phase1-spec.md §5.3). The Edge rejects a
// rule beyond any of them when it loads the bundle, and with it the whole
// bundle; the compiler rejects the rule first so that it never emits IR the
// Edge refuses.
const (
	// MaxIRSteps bounds the static worst-case evaluation steps of a rule
	// (MaxSteps; ADR-0006 decision 8, D-26).
	MaxIRSteps = 100_000
	// MaxIRNodes bounds the number of Expr nodes of a rule's IR.
	MaxIRNodes = 4096
	// MaxIRDepth bounds the nesting depth of a rule's IR (the root is depth 1).
	// It is 50, not more, because the Edge decodes the IR with prost, whose
	// fixed recursion limit of 100 nested messages admits no deeper tree (an
	// IR node below the root is two messages: Expr and its body).
	MaxIRDepth = 50
	// MaxIRStringBytes bounds a string literal and a glob() pattern.
	MaxIRStringBytes = 4096
	// MaxIRListElements bounds a list literal.
	MaxIRListElements = 1000
)

// unsupportedPrefix starts every diagnostic for a CEL construct the IR cannot
// express (spec §5.2).
const unsupportedPrefix = "unsupported in policy IR: "

// errNoIR is returned by Lower for a rule that was not type-checked.
var errNoIR = errors.New("policy: rule has no checked expression")

// Lower converts a checked rule's expression to the policy IR (spec §5.1),
// with the static step bound in PolicyExpr.MaxSteps (spec §5.3). The result
// is a pure function of the checked expression: it holds no expression ids,
// source positions or types. Lower fails for the constructs of spec §5.2, for
// IR beyond the §5.3 structure limits and for a step bound above MaxIRSteps;
// Compiler.Check reports the same problems as diagnostics located at the
// offending sub-expression.
func Lower(cr *CheckedRule) (*morphgatev1.PolicyExpr, error) {
	if cr == nil || cr.AST == nil {
		return nil, errNoIR
	}
	var problems []string
	pe, _ := lowerAST(cr.AST.NativeRep(), func(_ celast.Expr, format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	})
	if len(problems) > 0 {
		return nil, fmt.Errorf("rule %q: %s", cr.ruleID(), strings.Join(problems, "; "))
	}
	return pe, nil
}

// reportFunc records a problem at a sub-expression of the checked AST.
type reportFunc func(e celast.Expr, format string, args ...any)

// lowerAST lowers a checked AST and returns the IR together with the names of
// the named lists it references (sorted, unique). It returns a nil IR when it
// reported any problem.
func lowerAST(a *celast.AST, report reportFunc) (*morphgatev1.PolicyExpr, []string) {
	l := &lowerer{ast: a, lists: map[string]struct{}{}}
	l.report = func(e celast.Expr, format string, args ...any) {
		l.failed = true
		report(e, format, args...)
	}
	root := l.lower(a.Expr())
	if root == nil || l.failed {
		return nil, nil
	}
	if n, depth := irShape(root, 1); n > MaxIRNodes {
		l.report(a.Expr(), unsupportedPrefix+"expression has %d IR nodes (limit %d)", n, MaxIRNodes)
	} else if depth > MaxIRDepth {
		l.report(a.Expr(), unsupportedPrefix+"expression nests %d levels deep (limit %d)", depth, MaxIRDepth)
	}
	steps := MaxSteps(root)
	if steps > MaxIRSteps {
		l.report(a.Expr(), "rule exceeds the evaluation step bound: %d > %d", steps, MaxIRSteps)
	}
	if l.failed {
		return nil, nil
	}
	return &morphgatev1.PolicyExpr{
		IrVersion: IRVersion,
		Root:      root,
		Fields:    irFields(root),
		MaxSteps:  steps,
	}, slices.Sorted(maps.Keys(l.lists))
}

type lowerer struct {
	ast    *celast.AST
	report reportFunc
	failed bool
	lists  map[string]struct{}
}

// unsupported reports a construct of spec §5.2 and returns nil so that the
// caller propagates the failure without reporting its own node again.
func (l *lowerer) unsupported(e celast.Expr, format string, args ...any) *morphgatev1.Expr {
	l.report(e, unsupportedPrefix+format, args...)
	return nil
}

// kindOf is the checked type of a sub-expression.
func (l *lowerer) kindOf(e celast.Expr) valueKind {
	t := l.ast.GetType(e.ID())
	if t == nil {
		return kindUnknown
	}
	switch t.Kind() {
	case types.BoolKind:
		return kindBool
	case types.IntKind:
		return kindInt
	case types.DoubleKind:
		return kindDouble
	case types.StringKind:
		return kindString
	case types.ListKind:
		return kindList
	case types.MapKind:
		return kindMap
	case types.StructKind:
		return kindStruct
	}
	return kindUnknown
}

// typeName renders the checked type of a sub-expression for diagnostics.
func (l *lowerer) typeName(e celast.Expr) string {
	if t := l.ast.GetType(e.ID()); t != nil {
		return t.String()
	}
	return "unknown"
}

func (l *lowerer) overloadIs(e celast.Expr, ids ...string) bool {
	return slices.ContainsFunc(l.ast.GetOverloadIDs(e.ID()), func(id string) bool {
		return slices.Contains(ids, id)
	})
}

func (l *lowerer) lower(e celast.Expr) *morphgatev1.Expr {
	switch e.Kind() {
	case celast.LiteralKind:
		return l.literal(e)
	case celast.IdentKind:
		return l.ident(e)
	case celast.SelectKind:
		return l.selection(e)
	case celast.ListKind:
		return l.list(e)
	case celast.CallKind:
		return l.call(e)
	case celast.MapKind:
		return l.unsupported(e, "map literal")
	case celast.StructKind:
		return l.unsupported(e, "message literal")
	case celast.ComprehensionKind:
		if m, ok := l.ast.SourceInfo().GetMacroCall(e.ID()); ok && m.Kind() == celast.CallKind {
			return l.unsupported(e, "macro %s() (macros and comprehensions)", m.AsCall().FunctionName())
		}
		return l.unsupported(e, "comprehension")
	}
	return l.unsupported(e, "expression of kind %v", e.Kind())
}

func (l *lowerer) literal(e celast.Expr) *morphgatev1.Expr {
	switch v := e.AsLiteral().(type) {
	case types.Bool:
		return irLiteral(&morphgatev1.Literal{Value: &morphgatev1.Literal_BoolValue{BoolValue: bool(v)}})
	case types.Int:
		return irLiteral(&morphgatev1.Literal{Value: &morphgatev1.Literal_IntValue{IntValue: int64(v)}})
	case types.Double:
		return irLiteral(&morphgatev1.Literal{Value: &morphgatev1.Literal_DoubleValue{DoubleValue: float64(v)}})
	case types.String:
		if len(v) > MaxIRStringBytes {
			return l.unsupported(e, "string literal of %d bytes (limit %d)", len(v), MaxIRStringBytes)
		}
		return irString(string(v))
	case types.Uint:
		return l.unsupported(e, "uint literal")
	case types.Bytes:
		return l.unsupported(e, "bytes literal")
	case types.Null:
		return l.unsupported(e, "null literal")
	}
	return l.unsupported(e, "%s literal", e.AsLiteral().Type().TypeName())
}

func (l *lowerer) ident(e celast.Expr) *morphgatev1.Expr {
	name := e.AsIdent()
	if !isSchemaPath(name) {
		return l.unsupported(e, "identifier %s", name)
	}
	if l.kindOf(e) == kindStruct {
		return l.unsupported(e, "%s used as a value; read one of its fields", name)
	}
	return irField(name)
}

func (l *lowerer) selection(e celast.Expr) *morphgatev1.Expr {
	sel := e.AsSelect()
	operandIsMap := l.kindOf(sel.Operand()) == kindMap
	if sel.IsTestOnly() {
		if operandIsMap {
			return l.unsupported(e, "has() on a map key; use %q in <map> instead", sel.FieldName())
		}
		p := selectPath(e)
		if p == "" || !isSchemaPath(p) {
			return l.unsupported(e, "has() on a computed value")
		}
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Has{Has: p}}
	}
	if operandIsMap {
		// req.headers.accept is req.headers["accept"]; the key becomes a
		// string literal and is bound by the same §5.3 limit.
		m := l.lower(sel.Operand())
		if m == nil {
			return nil
		}
		if n := len(sel.FieldName()); n > MaxIRStringBytes {
			return l.unsupported(e, "map key of %d bytes (limit %d)", n, MaxIRStringBytes)
		}
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_IndexMap{IndexMap: &morphgatev1.Binary{Lhs: m, Rhs: irString(sel.FieldName())}}}
	}
	p := selectPath(e)
	if p == "" || !isSchemaPath(p) {
		// Report an unsupported operand (a message literal, a struct-valued
		// conditional, ...) as itself.
		if l.lower(sel.Operand()) == nil {
			return nil
		}
		return l.unsupported(e, "field selection on a computed value")
	}
	if l.kindOf(e) == kindStruct {
		return l.unsupported(e, "%s used as a value; read one of its fields", p)
	}
	return irField(p)
}

func (l *lowerer) list(e celast.Expr) *morphgatev1.Expr {
	lst := e.AsList()
	if len(lst.OptionalIndices()) > 0 {
		return l.unsupported(e, "optional list elements")
	}
	elems := lst.Elements()
	if len(elems) > MaxIRListElements {
		return l.unsupported(e, "list literal with %d elements (limit %d)", len(elems), MaxIRListElements)
	}
	for _, el := range elems {
		if !l.kindOf(el).scalar() {
			return l.unsupported(e, "list literal with %s elements; elements must be bool, int, double or string", l.typeName(el))
		}
		if l.kindOf(el) != l.kindOf(elems[0]) {
			return l.unsupported(e, "list literal mixing %s and %s elements", l.typeName(elems[0]), l.typeName(el))
		}
	}
	out, ok := l.lowerAll(elems)
	if !ok {
		return nil
	}
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_List{List: &morphgatev1.ListLiteral{Elements: out}}}
}

// lowerAll lowers every expression (so that all problems are reported) and
// reports whether all of them succeeded.
func (l *lowerer) lowerAll(es []celast.Expr) ([]*morphgatev1.Expr, bool) {
	out := make([]*morphgatev1.Expr, len(es))
	ok := true
	for i, e := range es {
		out[i] = l.lower(e)
		ok = ok && out[i] != nil
	}
	return out, ok
}

var compareOps = map[string]morphgatev1.CompareOp{
	operators.Equals:        morphgatev1.CompareOp_COMPARE_OP_EQ,
	operators.NotEquals:     morphgatev1.CompareOp_COMPARE_OP_NE,
	operators.Less:          morphgatev1.CompareOp_COMPARE_OP_LT,
	operators.LessEquals:    morphgatev1.CompareOp_COMPARE_OP_LE,
	operators.Greater:       morphgatev1.CompareOp_COMPARE_OP_GT,
	operators.GreaterEquals: morphgatev1.CompareOp_COMPARE_OP_GE,
}

// orderingOverloads are the <, <=, >, >= overloads the IR supports: int,
// double and string operands of the same type.
var orderingOverloads = []string{
	overloads.LessInt64, overloads.LessDouble, overloads.LessString,
	overloads.LessEqualsInt64, overloads.LessEqualsDouble, overloads.LessEqualsString,
	overloads.GreaterInt64, overloads.GreaterDouble, overloads.GreaterString,
	overloads.GreaterEqualsInt64, overloads.GreaterEqualsDouble, overloads.GreaterEqualsString,
}

var stringFunctions = map[string]struct {
	overload string
	fn       morphgatev1.StringFunction
}{
	overloads.StartsWith: {overloads.StartsWithString, morphgatev1.StringFunction_STRING_FUNCTION_STARTS_WITH},
	overloads.EndsWith:   {overloads.EndsWithString, morphgatev1.StringFunction_STRING_FUNCTION_ENDS_WITH},
	overloads.Contains:   {overloads.ContainsString, morphgatev1.StringFunction_STRING_FUNCTION_CONTAINS},
}

var arithmeticOps = map[string]string{
	operators.Add:      "+",
	operators.Subtract: "-",
	operators.Multiply: "*",
	operators.Divide:   "/",
	operators.Modulo:   "%",
}

func (l *lowerer) call(e celast.Expr) *morphgatev1.Expr {
	call := e.AsCall()
	fn := call.FunctionName()
	args := call.Args()
	if call.IsMemberFunction() {
		args = append([]celast.Expr{call.Target()}, args...)
	}
	switch fn {
	case operators.LogicalAnd, operators.LogicalOr:
		// Directly nested && (or ||) become one n-ary node, left to right.
		var terms []celast.Expr
		flattenLogical(e, fn, &terms)
		out, ok := l.lowerAll(terms)
		if !ok {
			return nil
		}
		if fn == operators.LogicalAnd {
			return &morphgatev1.Expr{Kind: &morphgatev1.Expr_And{And: &morphgatev1.Nary{Args: out}}}
		}
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Or{Or: &morphgatev1.Nary{Args: out}}}

	case operators.LogicalNot:
		x := l.lower(args[0])
		if x == nil {
			return nil
		}
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Not{Not: &morphgatev1.Unary{Arg: x}}}

	case operators.Conditional:
		out, ok := l.lowerAll(args)
		if !ok {
			return nil
		}
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Cond{Cond: &morphgatev1.Cond{Cond: out[0], ThenExpr: out[1], ElseExpr: out[2]}}}

	case operators.Equals, operators.NotEquals, operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals:
		return l.compare(e, fn, args)

	case operators.In:
		return l.in(e, args)

	case operators.Index:
		out, ok := l.lowerAll(args)
		switch {
		case !ok:
			return nil
		case l.overloadIs(e, overloads.IndexMap):
			return &morphgatev1.Expr{Kind: &morphgatev1.Expr_IndexMap{IndexMap: &morphgatev1.Binary{Lhs: out[0], Rhs: out[1]}}}
		case l.overloadIs(e, overloads.IndexList):
			return l.unsupported(e, "list index l[i]")
		}
		return l.unsupported(e, "index on %s", l.typeName(args[0]))

	case overloads.Size:
		x := l.lower(args[0])
		switch {
		case x == nil:
			return nil
		case !l.overloadIs(e, overloads.SizeString, overloads.SizeList, overloads.SizeMap,
			overloads.SizeStringInst, overloads.SizeListInst, overloads.SizeMapInst):
			return l.unsupported(e, "size() of %s", l.typeName(args[0]))
		}
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Size{Size: &morphgatev1.Unary{Arg: x}}}

	case overloads.StartsWith, overloads.EndsWith, overloads.Contains:
		out, ok := l.lowerAll(args)
		sf := stringFunctions[fn]
		switch {
		case !ok:
			return nil
		case !l.overloadIs(e, sf.overload):
			return l.unsupported(e, "%s() on %s", fn, l.typeName(args[0]))
		}
		return &morphgatev1.Expr{Kind: &morphgatev1.Expr_StringCall{StringCall: &morphgatev1.StringCall{Function: sf.fn, Target: out[0], Arg: out[1]}}}

	case overloads.Matches:
		return l.unsupported(e, "matches() (regular expressions)")

	case "ip_in":
		return l.ipIn(e, args)
	case "list":
		return l.namedList(e, args)
	case "glob":
		return l.glob(e, args)

	case operators.Negate:
		return l.unsupported(e, "unary minus on a non-literal value")
	case operators.OptSelect, operators.OptIndex:
		return l.unsupported(e, "optional syntax")
	case overloads.TypeConvertTimestamp, overloads.TypeConvertDuration:
		return l.unsupported(e, "timestamps and durations (%s())", fn)
	case overloads.TypeConvertInt, overloads.TypeConvertUint, overloads.TypeConvertDouble, overloads.TypeConvertBool,
		overloads.TypeConvertString, overloads.TypeConvertBytes, overloads.TypeConvertDyn, overloads.TypeConvertType:
		return l.unsupported(e, "type conversion %s()", fn)
	}
	if op, ok := arithmeticOps[fn]; ok {
		switch {
		case l.overloadIs(e, overloads.AddString):
			return l.unsupported(e, "string concatenation")
		case l.overloadIs(e, overloads.AddList):
			return l.unsupported(e, "list concatenation")
		case l.overloadIs(e, overloads.AddBytes):
			return l.unsupported(e, "bytes concatenation")
		}
		return l.unsupported(e, "arithmetic (%s)", op)
	}
	return l.unsupported(e, "function %s()", fn)
}

func flattenLogical(e celast.Expr, fn string, out *[]celast.Expr) {
	if e.Kind() == celast.CallKind && e.AsCall().FunctionName() == fn {
		for _, a := range e.AsCall().Args() {
			flattenLogical(a, fn, out)
		}
		return
	}
	*out = append(*out, e)
}

// compare lowers ==, !=, <, <=, >, >=. The operands are lowered first so that
// an unsupported operand (a conversion, a struct value, ...) is reported as
// itself rather than as an unsupported comparison.
func (l *lowerer) compare(e celast.Expr, fn string, args []celast.Expr) *morphgatev1.Expr {
	out, ok := l.lowerAll(args)
	if !ok {
		return nil
	}
	op := compareOps[fn]
	lk, rk := l.kindOf(args[0]), l.kindOf(args[1])
	opName := strings.Trim(fn, "_")
	switch {
	case !lk.scalar() || lk != rk:
		return l.unsupported(e, "%s on %s values; only bool, int, double and string values of the same type can be compared", opName, l.typeName(args[0]))
	case op != morphgatev1.CompareOp_COMPARE_OP_EQ && op != morphgatev1.CompareOp_COMPARE_OP_NE && lk == kindBool:
		return l.unsupported(e, "ordering of bool values (%s)", opName)
	case op != morphgatev1.CompareOp_COMPARE_OP_EQ && op != morphgatev1.CompareOp_COMPARE_OP_NE && !l.overloadIs(e, orderingOverloads...):
		return l.unsupported(e, "%s on %s values", opName, l.typeName(args[0]))
	}
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Compare{Compare: &morphgatev1.Compare{Op: op, Lhs: out[0], Rhs: out[1]}}}
}

func (l *lowerer) in(e celast.Expr, args []celast.Expr) *morphgatev1.Expr {
	out, ok := l.lowerAll(args)
	if !ok {
		return nil
	}
	lk := l.kindOf(args[0])
	var wrap func(b *morphgatev1.Binary) *morphgatev1.Expr
	switch {
	case l.overloadIs(e, overloads.InList):
		if !lk.scalar() {
			return l.unsupported(e, "in with a %s left operand; the left side must be a bool, int, double or string", l.typeName(args[0]))
		}
		wrap = func(b *morphgatev1.Binary) *morphgatev1.Expr {
			return &morphgatev1.Expr{Kind: &morphgatev1.Expr_InList{InList: b}}
		}
	case l.overloadIs(e, overloads.InMap):
		if lk != kindString {
			return l.unsupported(e, "in with a %s key; map keys are strings", l.typeName(args[0]))
		}
		wrap = func(b *morphgatev1.Binary) *morphgatev1.Expr {
			return &morphgatev1.Expr{Kind: &morphgatev1.Expr_InMap{InMap: b}}
		}
	default:
		return l.unsupported(e, "in on %s", l.typeName(args[1]))
	}
	return wrap(&morphgatev1.Binary{Lhs: out[0], Rhs: out[1]})
}

// ipIn lowers ip_in(ip, list). String literals are validated here so that a
// typo in an owner network fails at compile time instead of at the Edge.
func (l *lowerer) ipIn(e celast.Expr, args []celast.Expr) *morphgatev1.Expr {
	if !l.overloadIs(e, "ip_in_string_list_string") {
		return l.unsupported(e, "ip_in() on %s", l.typeName(args[0]))
	}
	ok := true
	if ip, isLit := stringLiteral(args[0]); isLit {
		if _, err := parseIPOrPrefix(ip); err != nil || strings.Contains(ip, "/") {
			l.report(args[0], "ip_in: %q is not an IP address", ip)
			ok = false
		}
	}
	if args[1].Kind() == celast.ListKind {
		for _, el := range args[1].AsList().Elements() {
			if s, isLit := stringLiteral(el); isLit {
				if _, err := parseIPOrPrefix(s); err != nil {
					l.report(el, "%v", err)
					ok = false
				}
			}
		}
	}
	out, lowered := l.lowerAll(args)
	if !ok || !lowered {
		return nil
	}
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_IpIn{IpIn: &morphgatev1.Binary{Lhs: out[0], Rhs: out[1]}}}
}

// namedList lowers list("name"). The name must be a literal so the bundle
// builder can resolve and check the list (spec §8.2).
func (l *lowerer) namedList(e celast.Expr, args []celast.Expr) *morphgatev1.Expr {
	if !l.overloadIs(e, "list_string") {
		return l.unsupported(e, "list() on %s", l.typeName(args[0]))
	}
	name, ok := stringLiteral(args[0])
	switch {
	case !ok:
		l.report(args[0], "list() takes a string literal name so lists can be resolved when the bundle is built")
		return nil
	case !listNamePattern.MatchString(name):
		l.report(args[0], "list name %q must match %s", name, listNamePattern)
		return nil
	}
	l.lists[name] = struct{}{}
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_NamedList{NamedList: name}}
}

// glob lowers glob(subject, "pattern"); the pattern must be a non-empty
// literal (its length enters the static step bound).
func (l *lowerer) glob(e celast.Expr, args []celast.Expr) *morphgatev1.Expr {
	if !l.overloadIs(e, "glob_string_string") {
		return l.unsupported(e, "glob() on %s", l.typeName(args[0]))
	}
	p, ok := stringLiteral(args[1])
	switch {
	case !ok:
		l.report(args[1], "glob() pattern must be a string literal")
		return nil
	case p == "":
		l.report(args[1], "glob() pattern must not be empty")
		return nil
	case len(p) > MaxIRStringBytes:
		return l.unsupported(args[1], "glob() pattern of %d bytes (limit %d)", len(p), MaxIRStringBytes)
	}
	subject := l.lower(args[0])
	if subject == nil {
		return nil
	}
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Glob{Glob: &morphgatev1.Glob{Subject: subject, Pattern: p}}}
}

func irLiteral(lit *morphgatev1.Literal) *morphgatev1.Expr {
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Literal{Literal: lit}}
}

func irString(s string) *morphgatev1.Expr {
	return irLiteral(&morphgatev1.Literal{Value: &morphgatev1.Literal_StringValue{StringValue: s}})
}

func irField(p string) *morphgatev1.Expr {
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Field{Field: p}}
}

// irChildren returns the direct sub-expressions of an IR node in evaluation
// order.
func irChildren(e *morphgatev1.Expr) []*morphgatev1.Expr {
	switch k := e.GetKind().(type) {
	case *morphgatev1.Expr_List:
		return k.List.GetElements()
	case *morphgatev1.Expr_Not:
		return []*morphgatev1.Expr{k.Not.GetArg()}
	case *morphgatev1.Expr_And:
		return k.And.GetArgs()
	case *morphgatev1.Expr_Or:
		return k.Or.GetArgs()
	case *morphgatev1.Expr_Cond:
		return []*morphgatev1.Expr{k.Cond.GetCond(), k.Cond.GetThenExpr(), k.Cond.GetElseExpr()}
	case *morphgatev1.Expr_Compare:
		return []*morphgatev1.Expr{k.Compare.GetLhs(), k.Compare.GetRhs()}
	case *morphgatev1.Expr_InList:
		return []*morphgatev1.Expr{k.InList.GetLhs(), k.InList.GetRhs()}
	case *morphgatev1.Expr_InMap:
		return []*morphgatev1.Expr{k.InMap.GetLhs(), k.InMap.GetRhs()}
	case *morphgatev1.Expr_IndexMap:
		return []*morphgatev1.Expr{k.IndexMap.GetLhs(), k.IndexMap.GetRhs()}
	case *morphgatev1.Expr_Size:
		return []*morphgatev1.Expr{k.Size.GetArg()}
	case *morphgatev1.Expr_StringCall:
		return []*morphgatev1.Expr{k.StringCall.GetTarget(), k.StringCall.GetArg()}
	case *morphgatev1.Expr_IpIn:
		return []*morphgatev1.Expr{k.IpIn.GetLhs(), k.IpIn.GetRhs()}
	case *morphgatev1.Expr_Glob:
		return []*morphgatev1.Expr{k.Glob.GetSubject()}
	}
	return nil
}

// irShape returns the node count and the nesting depth of an IR tree whose
// root is at the given depth.
func irShape(e *morphgatev1.Expr, depth int) (nodes, maxDepth int) {
	nodes, maxDepth = 1, depth
	for _, c := range irChildren(e) {
		n, d := irShape(c, depth+1)
		nodes += n
		maxDepth = max(maxDepth, d)
	}
	return nodes, maxDepth
}

// irFields returns the sorted unique paths of every field and has node:
// PolicyExpr.fields, the schema paths the expression reads or has()-tests.
func irFields(root *morphgatev1.Expr) []string {
	set := map[string]struct{}{}
	var visit func(e *morphgatev1.Expr)
	visit = func(e *morphgatev1.Expr) {
		switch k := e.GetKind().(type) {
		case *morphgatev1.Expr_Field:
			set[k.Field] = struct{}{}
		case *morphgatev1.Expr_Has:
			set[k.Has] = struct{}{}
		}
		for _, c := range irChildren(e) {
			visit(c)
		}
	}
	visit(root)
	return slices.Sorted(maps.Keys(set))
}
