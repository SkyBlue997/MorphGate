package policy

import (
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
)

// irInterp is a test-only, independent implementation of the IR evaluation
// semantics of docs/impl/phase1-spec.md §5.3 (values, UNKNOWN, ERROR and step
// counting). The conformance test runs it next to the cel-go reference
// Evaluator so that a lowering bug shows up in this package instead of only
// in the Rust suite. It is deliberately written from the spec table, not from
// the lowering code.
type irInterp struct {
	in      *Input
	missing []string
	lists   map[string][]string
	steps   uint64
	// outcomes records, per IR node kind, the outcomes seen while
	// evaluating ("true", "false", "value", "unknown", "error").
	outcomes map[string]map[string]bool
}

type irValue struct {
	kind valueKind
	b    bool
	i    int64
	d    float64
	s    string
	list []irValue
	m    map[string]irValue
}

// irResult is a value, an UNKNOWN (non-nil unknown) or an ERROR (err != "").
type irResult struct {
	v       irValue
	unknown []string
	err     string
}

func (r irResult) isUnknown() bool { return r.unknown != nil }
func (r irResult) isError() bool   { return r.err != "" }

func (r irResult) outcome() string {
	switch {
	case r.isError():
		return "error"
	case r.isUnknown():
		return "unknown"
	case r.v.kind == kindBool && r.v.b:
		return "true"
	case r.v.kind == kindBool:
		return "false"
	}
	return "value"
}

func errResult(kind string) irResult { return irResult{err: kind} }
func boolRes(b bool) irResult        { return irResult{v: irValue{kind: kindBool, b: b}} }

// size is |x| of spec §5.3: UTF-8 bytes of a string, entries of a list or map.
func (v irValue) size() uint64 {
	switch v.kind {
	case kindString:
		return uint64(len(v.s))
	case kindList:
		return uint64(len(v.list))
	case kindMap:
		return uint64(len(v.m))
	}
	return 0
}

// evalRule evaluates a rule's root with the §5.3 rule result mapping and the
// runtime step limit.
func (it *irInterp) evalRule(pe *morphgatev1.PolicyExpr) (string, []string) {
	it.steps = 0
	r := it.eval(pe.GetRoot())
	switch {
	case it.steps > MaxIRSteps:
		return "error", nil // step_limit terminates the whole rule
	case r.isError():
		return "error", nil
	case r.isUnknown():
		return "unknown", r.unknown
	case r.v.kind != kindBool:
		return "error", nil // no_such_overload
	case r.v.b:
		return "true", nil
	}
	return "false", nil
}

func (it *irInterp) record(kind string, r irResult) irResult {
	if it.outcomes != nil {
		if it.outcomes[kind] == nil {
			it.outcomes[kind] = map[string]bool{}
		}
		it.outcomes[kind][r.outcome()] = true
	}
	return r
}

func (it *irInterp) charge(n uint64) { it.steps = satAdd(it.steps, n) }

func (it *irInterp) isMissing(p string) bool { return isMissing(p, it.missing) }

// strict evaluates the children left to right: the first ERROR wins, then
// the union of UNKNOWNs.
func (it *irInterp) strict(children ...*morphgatev1.Expr) ([]irValue, *irResult) {
	vals := make([]irValue, len(children))
	var firstErr *irResult
	var unknown []string
	for i, c := range children {
		r := it.eval(c)
		switch {
		case r.isError():
			if firstErr == nil {
				firstErr = &r
			}
		case r.isUnknown():
			unknown = union(unknown, r.unknown)
		default:
			vals[i] = r.v
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if unknown != nil {
		return nil, &irResult{unknown: unknown}
	}
	return vals, nil
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, p := range b {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	if out == nil {
		out = []string{}
	}
	return out
}

func (it *irInterp) eval(e *morphgatev1.Expr) irResult {
	switch k := e.GetKind().(type) {
	case *morphgatev1.Expr_Literal:
		it.charge(1)
		switch v := k.Literal.GetValue().(type) {
		case *morphgatev1.Literal_BoolValue:
			return it.record("literal", boolRes(v.BoolValue))
		case *morphgatev1.Literal_IntValue:
			return it.record("literal", irResult{v: irValue{kind: kindInt, i: v.IntValue}})
		case *morphgatev1.Literal_DoubleValue:
			return it.record("literal", irResult{v: irValue{kind: kindDouble, d: v.DoubleValue}})
		case *morphgatev1.Literal_StringValue:
			return it.record("literal", irResult{v: irValue{kind: kindString, s: v.StringValue}})
		}
		panic("malformed literal")

	case *morphgatev1.Expr_Field:
		it.charge(1)
		if it.isMissing(k.Field) {
			return it.record("field", irResult{unknown: []string{k.Field}})
		}
		return it.record("field", irResult{v: inputValue(it.in, k.Field)})

	case *morphgatev1.Expr_Has:
		it.charge(1)
		return it.record("has", boolRes(!it.isMissing(k.Has)))

	case *morphgatev1.Expr_NamedList:
		it.charge(1)
		entries, ok := it.lists[k.NamedList]
		if !ok {
			return it.record("named_list", errResult("unknown_list"))
		}
		return it.record("named_list", irResult{v: stringList(entries)})

	case *morphgatev1.Expr_List:
		it.charge(1)
		vals, bad := it.strict(k.List.GetElements()...)
		if bad != nil {
			return it.record("list", *bad)
		}
		return it.record("list", irResult{v: irValue{kind: kindList, list: vals}})

	case *morphgatev1.Expr_Not:
		it.charge(1)
		vals, bad := it.strict(k.Not.GetArg())
		if bad != nil {
			return it.record("not", *bad)
		}
		if vals[0].kind != kindBool {
			return it.record("not", errResult("no_such_overload"))
		}
		return it.record("not", boolRes(!vals[0].b))

	case *morphgatev1.Expr_And:
		it.charge(1)
		return it.record("and", it.logical(k.And.GetArgs(), false))

	case *morphgatev1.Expr_Or:
		it.charge(1)
		return it.record("or", it.logical(k.Or.GetArgs(), true))

	case *morphgatev1.Expr_Cond:
		it.charge(1)
		c := it.eval(k.Cond.GetCond())
		switch {
		case c.isError():
			return it.record("cond", c)
		case c.isUnknown():
			return it.record("cond", c)
		case c.v.kind != kindBool:
			return it.record("cond", errResult("no_such_overload"))
		case c.v.b:
			return it.record("cond", it.eval(k.Cond.GetThenExpr()))
		}
		return it.record("cond", it.eval(k.Cond.GetElseExpr()))

	case *morphgatev1.Expr_Compare:
		vals, bad := it.strict(k.Compare.GetLhs(), k.Compare.GetRhs())
		if bad != nil {
			it.charge(1)
			return it.record("compare", *bad)
		}
		l, r := vals[0], vals[1]
		if l.kind == kindString && r.kind == kindString {
			it.charge(1 + ceilDiv(l.size()+r.size(), 64))
		} else {
			it.charge(1)
		}
		return it.record("compare", compareValues(k.Compare.GetOp(), l, r))

	case *morphgatev1.Expr_InList:
		vals, bad := it.strict(k.InList.GetLhs(), k.InList.GetRhs())
		if bad != nil {
			it.charge(1)
			return it.record("in_list", *bad)
		}
		x, l := vals[0], vals[1]
		if l.kind != kindList {
			it.charge(1)
			return it.record("in_list", errResult("no_such_overload"))
		}
		it.charge(1 + l.size())
		for _, el := range l.list {
			if el.kind == x.kind && compareValues(morphgatev1.CompareOp_COMPARE_OP_EQ, el, x).v.b {
				return it.record("in_list", boolRes(true))
			}
		}
		return it.record("in_list", boolRes(false))

	case *morphgatev1.Expr_InMap:
		it.charge(2)
		vals, bad := it.strict(k.InMap.GetLhs(), k.InMap.GetRhs())
		if bad != nil {
			return it.record("in_map", *bad)
		}
		if vals[0].kind != kindString || vals[1].kind != kindMap {
			return it.record("in_map", errResult("no_such_overload"))
		}
		_, ok := vals[1].m[vals[0].s]
		return it.record("in_map", boolRes(ok))

	case *morphgatev1.Expr_IndexMap:
		it.charge(2)
		vals, bad := it.strict(k.IndexMap.GetLhs(), k.IndexMap.GetRhs())
		if bad != nil {
			return it.record("index_map", *bad)
		}
		if vals[0].kind != kindMap || vals[1].kind != kindString {
			return it.record("index_map", errResult("no_such_overload"))
		}
		v, ok := vals[0].m[vals[1].s]
		if !ok {
			return it.record("index_map", errResult("no_such_key"))
		}
		return it.record("index_map", irResult{v: v})

	case *morphgatev1.Expr_Size:
		vals, bad := it.strict(k.Size.GetArg())
		if bad != nil {
			it.charge(1)
			return it.record("size", *bad)
		}
		x := vals[0]
		switch x.kind {
		case kindString:
			it.charge(1 + ceilDiv(x.size(), 64))
			return it.record("size", irResult{v: irValue{kind: kindInt, i: int64(utf8.RuneCountInString(x.s))}})
		case kindList, kindMap:
			it.charge(1)
			return it.record("size", irResult{v: irValue{kind: kindInt, i: int64(x.size())}})
		}
		it.charge(1)
		return it.record("size", errResult("no_such_overload"))

	case *morphgatev1.Expr_StringCall:
		vals, bad := it.strict(k.StringCall.GetTarget(), k.StringCall.GetArg())
		if bad != nil {
			it.charge(1)
			return it.record("string_call", *bad)
		}
		t, a := vals[0], vals[1]
		if t.kind != kindString || a.kind != kindString {
			it.charge(1)
			return it.record("string_call", errResult("no_such_overload"))
		}
		it.charge(1 + ceilDiv(t.size()+a.size(), 64))
		tr, ar := []rune(t.s), []rune(a.s)
		var ok bool
		switch k.StringCall.GetFunction() {
		case morphgatev1.StringFunction_STRING_FUNCTION_STARTS_WITH:
			ok = len(ar) <= len(tr) && slices.Equal(tr[:len(ar)], ar)
		case morphgatev1.StringFunction_STRING_FUNCTION_ENDS_WITH:
			ok = len(ar) <= len(tr) && slices.Equal(tr[len(tr)-len(ar):], ar)
		case morphgatev1.StringFunction_STRING_FUNCTION_CONTAINS:
			for i := 0; i+len(ar) <= len(tr) && !ok; i++ {
				ok = slices.Equal(tr[i:i+len(ar)], ar)
			}
		default:
			return it.record("string_call", errResult("no_such_overload"))
		}
		return it.record("string_call", boolRes(ok))

	case *morphgatev1.Expr_IpIn:
		vals, bad := it.strict(k.IpIn.GetLhs(), k.IpIn.GetRhs())
		if bad != nil {
			it.charge(1)
			return it.record("ip_in", *bad)
		}
		ip, l := vals[0], vals[1]
		if ip.kind != kindString || l.kind != kindList {
			it.charge(1)
			return it.record("ip_in", errResult("no_such_overload"))
		}
		it.charge(1 + l.size())
		entries := make([]string, len(l.list))
		for i, el := range l.list {
			if el.kind != kindString {
				return it.record("ip_in", errResult("no_such_overload"))
			}
			entries[i] = el.s
		}
		ok, err := ipIn(ip.s, entries)
		if err != nil {
			return it.record("ip_in", errResult("invalid_argument"))
		}
		return it.record("ip_in", boolRes(ok))

	case *morphgatev1.Expr_Glob:
		vals, bad := it.strict(k.Glob.GetSubject())
		if bad != nil {
			it.charge(1)
			return it.record("glob", *bad)
		}
		s := vals[0]
		if s.kind != kindString {
			it.charge(1)
			return it.record("glob", errResult("no_such_overload"))
		}
		it.charge(1 + satMul(s.size(), uint64(len(k.Glob.GetPattern())))/16)
		ok, err := glob(s.s, k.Glob.GetPattern())
		if err != nil {
			return it.record("glob", errResult("invalid_argument"))
		}
		return it.record("glob", boolRes(ok))
	}
	panic(fmt.Sprintf("malformed IR node %v", e))
}

// logical implements and (short = false) and or (short = true) of §5.3:
// every argument is evaluated; a short-circuit value wins, then UNKNOWN (the
// union of paths), then the first ERROR or non-bool argument.
func (it *irInterp) logical(args []*morphgatev1.Expr, short bool) irResult {
	var unknown []string
	var firstErr *irResult
	decided := false
	for _, a := range args {
		r := it.eval(a)
		switch {
		case r.isUnknown():
			unknown = union(unknown, r.unknown)
		case r.isError():
			if firstErr == nil {
				firstErr = &r
			}
		case r.v.kind != kindBool:
			if firstErr == nil {
				e := errResult("no_such_overload")
				firstErr = &e
			}
		case r.v.b == short:
			decided = true
		}
	}
	switch {
	case decided:
		return boolRes(short)
	case unknown != nil:
		return irResult{unknown: unknown}
	case firstErr != nil:
		return *firstErr
	}
	return boolRes(!short)
}

func compareValues(op morphgatev1.CompareOp, l, r irValue) irResult {
	if l.kind != r.kind || !l.kind.scalar() {
		return errResult("no_such_overload")
	}
	var c int
	switch l.kind {
	case kindBool:
		if op != morphgatev1.CompareOp_COMPARE_OP_EQ && op != morphgatev1.CompareOp_COMPARE_OP_NE {
			return errResult("no_such_overload")
		}
		if l.b != r.b {
			c = 1
		}
	case kindInt:
		c = cmpOrdered(l.i, r.i)
	case kindString:
		c = strings.Compare(l.s, r.s) // UTF-8 byte order = Unicode scalar order
	case kindDouble:
		if math.IsNaN(l.d) || math.IsNaN(r.d) {
			return boolRes(op == morphgatev1.CompareOp_COMPARE_OP_NE)
		}
		c = cmpOrdered(l.d, r.d)
	}
	switch op {
	case morphgatev1.CompareOp_COMPARE_OP_EQ:
		return boolRes(c == 0)
	case morphgatev1.CompareOp_COMPARE_OP_NE:
		return boolRes(c != 0)
	case morphgatev1.CompareOp_COMPARE_OP_LT:
		return boolRes(c < 0)
	case morphgatev1.CompareOp_COMPARE_OP_LE:
		return boolRes(c <= 0)
	case morphgatev1.CompareOp_COMPARE_OP_GT:
		return boolRes(c > 0)
	case morphgatev1.CompareOp_COMPARE_OP_GE:
		return boolRes(c >= 0)
	}
	return errResult("no_such_overload")
}

func cmpOrdered[T int64 | float64](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func stringList(entries []string) irValue {
	out := irValue{kind: kindList, list: make([]irValue, len(entries))}
	for i, s := range entries {
		out.list[i] = irValue{kind: kindString, s: s}
	}
	return out
}

// inputValue reads a schema field from Input through the `cel` tags.
func inputValue(in *Input, path string) irValue {
	v := reflect.ValueOf(in).Elem()
	for part := range strings.SplitSeq(path, ".") {
		t := v.Type()
		found := false
		for i := range t.NumField() {
			if t.Field(i).Tag.Get("cel") == part {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			panic("no field " + path)
		}
	}
	return goValue(v)
}

func goValue(v reflect.Value) irValue {
	switch v.Kind() {
	case reflect.Bool:
		return irValue{kind: kindBool, b: v.Bool()}
	case reflect.Int64:
		return irValue{kind: kindInt, i: v.Int()}
	case reflect.Float64:
		return irValue{kind: kindDouble, d: v.Float()}
	case reflect.String:
		return irValue{kind: kindString, s: v.String()}
	case reflect.Slice:
		out := irValue{kind: kindList, list: []irValue{}}
		for i := range v.Len() {
			out.list = append(out.list, goValue(v.Index(i)))
		}
		return out
	case reflect.Map:
		out := irValue{kind: kindMap, m: map[string]irValue{}}
		for _, k := range v.MapKeys() {
			out.m[k.String()] = goValue(v.MapIndex(k))
		}
		return out
	}
	panic("unsupported Go value " + v.Kind().String())
}
