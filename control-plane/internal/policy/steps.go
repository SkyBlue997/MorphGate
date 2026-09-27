package policy

import (
	"math"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

// MaxSteps returns the static worst-case evaluation step count of an IR
// expression (docs/impl/phase1-spec.md §5.3 "step bound"). Evaluating a node
// costs cost(node) steps plus the steps of the children it evaluates; the
// bound assumes every child is evaluated (no short-circuit discount for and /
// or; cond takes 1 + steps(cond) + the larger branch) and replaces every
// input size |x| by its upper bound S(x):
//
//   - literal: its actual size (UTF-8 bytes of a string);
//   - field: the §4.1 size cap of the path (strings in bytes, lists and maps
//     in entries; 0 for bool and numeric fields);
//   - index_map: the cap of one value of the map (8192 for req.headers, 0 for
//     rate);
//   - named_list: 10,000 (MaxNamedListEntries);
//   - list literal: its element count;
//   - cond: the larger of its branches;
//   - every bool or numeric result: 0.
//
// Node costs: literal, field, has, named_list, list, not, and, or, cond: 1;
// compare: 1 + ceil((S(lhs) + S(rhs)) / 64) on strings, 1 otherwise; in_list
// and ip_in: 1 + S(rhs); in_map, index_map: 2; size: 1 + ceil(S(x) / 64) on a
// string, 1 otherwise; string_call: 1 + ceil((S(target) + S(arg)) / 64); glob:
// 1 + floor(S(subject) * len(pattern) / 16).
//
// Arithmetic saturates at math.MaxUint64. A malformed tree (a missing node or
// operand, an unknown field path) also yields math.MaxUint64, so that it can
// never pass the MaxIRSteps check. The Rust loader (mg_core::policy::max_steps)
// recomputes the same value and rejects the rule when it differs from
// PolicyExpr.max_steps.
func MaxSteps(e *morphgatev1.Expr) uint64 {
	return irBound(e).steps
}

// bound is the static analysis of one IR node.
type bound struct {
	steps    uint64    // worst-case steps of the node including its children
	size     uint64    // S(x)
	kind     valueKind // result kind
	mapValue uint64    // maps: S of one value
	mapKind  valueKind // maps: kind of the values
}

var malformed = bound{steps: math.MaxUint64}

func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return math.MaxUint64
}

func satMul(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxUint64/b {
		return math.MaxUint64
	}
	return a * b
}

func ceilDiv(a, d uint64) uint64 {
	q := a / d
	if a%d != 0 {
		q++
	}
	return q
}

// costPlus returns cost plus the steps of every child.
func costPlus(cost uint64, children ...bound) uint64 {
	s := cost
	for _, c := range children {
		s = satAdd(s, c.steps)
	}
	return s
}

func boolResult(steps uint64) bound {
	return bound{steps: steps, kind: kindBool}
}

func irBound(e *morphgatev1.Expr) bound {
	switch k := e.GetKind().(type) {
	case *morphgatev1.Expr_Literal:
		switch v := k.Literal.GetValue().(type) {
		case *morphgatev1.Literal_BoolValue:
			return bound{steps: 1, kind: kindBool}
		case *morphgatev1.Literal_IntValue:
			return bound{steps: 1, kind: kindInt}
		case *morphgatev1.Literal_DoubleValue:
			return bound{steps: 1, kind: kindDouble}
		case *morphgatev1.Literal_StringValue:
			return bound{steps: 1, size: uint64(len(v.StringValue)), kind: kindString}
		}
		return malformed

	case *morphgatev1.Expr_Field:
		sf, ok := schema[k.Field]
		if !ok || sf.kind == kindStruct {
			return malformed
		}
		return bound{steps: 1, size: fieldSizeCap(k.Field), kind: sf.kind,
			mapValue: mapValueSizeCap(k.Field), mapKind: sf.mapValue}

	case *morphgatev1.Expr_Has:
		if !isSchemaPath(k.Has) {
			return malformed
		}
		return boolResult(1)

	case *morphgatev1.Expr_NamedList:
		return bound{steps: 1, size: MaxNamedListEntries, kind: kindList}

	case *morphgatev1.Expr_List:
		elems := k.List.GetElements()
		steps := uint64(1)
		for _, el := range elems {
			steps = satAdd(steps, irBound(el).steps)
		}
		return bound{steps: steps, size: uint64(len(elems)), kind: kindList}

	case *morphgatev1.Expr_Not:
		return boolResult(costPlus(1, irBound(k.Not.GetArg())))

	case *morphgatev1.Expr_And:
		return boolResult(naryBound(k.And.GetArgs()))

	case *morphgatev1.Expr_Or:
		return boolResult(naryBound(k.Or.GetArgs()))

	case *morphgatev1.Expr_Cond:
		c := irBound(k.Cond.GetCond())
		t := irBound(k.Cond.GetThenExpr())
		f := irBound(k.Cond.GetElseExpr())
		return bound{
			steps:    satAdd(satAdd(1, c.steps), max(t.steps, f.steps)),
			size:     max(t.size, f.size),
			kind:     t.kind,
			mapValue: max(t.mapValue, f.mapValue),
			mapKind:  t.mapKind,
		}

	case *morphgatev1.Expr_Compare:
		l, r := irBound(k.Compare.GetLhs()), irBound(k.Compare.GetRhs())
		cost := uint64(1)
		if l.kind == kindString || r.kind == kindString {
			cost = satAdd(1, ceilDiv(satAdd(l.size, r.size), 64))
		}
		return boolResult(costPlus(cost, l, r))

	case *morphgatev1.Expr_InList:
		l, r := irBound(k.InList.GetLhs()), irBound(k.InList.GetRhs())
		return boolResult(costPlus(satAdd(1, r.size), l, r))

	case *morphgatev1.Expr_InMap:
		l, r := irBound(k.InMap.GetLhs()), irBound(k.InMap.GetRhs())
		return boolResult(costPlus(2, l, r))

	case *morphgatev1.Expr_IndexMap:
		l, r := irBound(k.IndexMap.GetLhs()), irBound(k.IndexMap.GetRhs())
		return bound{steps: costPlus(2, l, r), size: l.mapValue, kind: l.mapKind}

	case *morphgatev1.Expr_Size:
		x := irBound(k.Size.GetArg())
		cost := uint64(1)
		if x.kind == kindString {
			cost = satAdd(1, ceilDiv(x.size, 64))
		}
		return bound{steps: costPlus(cost, x), kind: kindInt}

	case *morphgatev1.Expr_StringCall:
		t, a := irBound(k.StringCall.GetTarget()), irBound(k.StringCall.GetArg())
		return boolResult(costPlus(satAdd(1, ceilDiv(satAdd(t.size, a.size), 64)), t, a))

	case *morphgatev1.Expr_IpIn:
		l, r := irBound(k.IpIn.GetLhs()), irBound(k.IpIn.GetRhs())
		return boolResult(costPlus(satAdd(1, r.size), l, r))

	case *morphgatev1.Expr_Glob:
		s := irBound(k.Glob.GetSubject())
		cost := satAdd(1, satMul(s.size, uint64(len(k.Glob.GetPattern())))/16)
		return boolResult(costPlus(cost, s))
	}
	return malformed
}

func naryBound(args []*morphgatev1.Expr) uint64 {
	steps := uint64(1)
	for _, a := range args {
		steps = satAdd(steps, irBound(a).steps)
	}
	return steps
}
