package policy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

// MaxNamedListEntries bounds a named list (spec §4.1, checked when the site
// bundle is built): list("x") has at most this many entries, each at most
// defaultStringCap bytes.
const MaxNamedListEntries = 10_000

// sizeHints are the size caps of spec §4.1 for the paths that do not use the
// defaults (defaultStringCap bytes for strings, defaultListCap entries for
// lists and maps). Paths use cel-go's cost-estimator naming: "@keys" /
// "@values" for map keys and values, "@items" for list elements. The Edge
// guarantees every cap (§9.3.1 rejects oversized requests), so both the
// cel-go cost estimate and the static step bound of the IR (MaxSteps) rely
// on them.
var sizeHints = map[string]uint64{
	"req.path":                 8192,
	"req.query":                8192,
	"req.method":               32,
	"req.host":                 253,
	"req.headers":              128,
	"req.headers.@keys":        256,
	"req.headers.@values":      8192,
	"http.header_order":        128,
	"http.header_order.@items": 256,
	"labels":                   64,
	"risk.reasons":             32,
	"rate":                     64,
	"tls.ja4.value":            36,
	"edge_tls.ciphers_sha1":    40,
	"edge_tls.ext_sha1":        40,
}

// ListResolver returns the entries of a named list such as "owner_cidrs".
type ListResolver func(name string) ([]string, bool)

// Namespaces returns the policy variable names in declaration order.
func Namespaces() []string {
	t := reflect.TypeFor[Input]()
	out := make([]string, 0, t.NumField())
	for i := range t.NumField() {
		out = append(out, t.Field(i).Tag.Get("cel"))
	}
	return out
}

// newEnv builds the CEL environment. Variables are derived from the fields of
// Input so the Go types are the single source of truth for the language surface.
// lists resolves list(name) at evaluation time; nil means evaluation of list()
// fails, which is fine for type-checking only.
func newEnv(lists ListResolver) (*cel.Env, error) {
	opts := []cel.EnvOption{
		ext.NativeTypes(ext.ParseStructTags(true), reflect.TypeFor[Input]()),
	}
	t := reflect.TypeFor[Input]()
	for i := range t.NumField() {
		f := t.Field(i)
		ct, err := celTypeOf(f.Type)
		if err != nil {
			return nil, fmt.Errorf("policy: field %s: %w", f.Name, err)
		}
		opts = append(opts, cel.Variable(f.Tag.Get("cel"), ct))
	}
	opts = append(opts, extensionFunctions(lists)...)
	// Mixed-type list literals ([1.0, "a"], [1, 2.0]) are type errors: cel-go
	// would otherwise type them list(dyn) and compare elements numerically
	// across types, which the IR's same-type in_list cannot express (spec §5.1).
	// CrossTypeNumericComparisons stays at its default (off) for the same reason.
	opts = append(opts, cel.HomogeneousAggregateLiterals())
	// Keep the original macro calls in the source info so that a rejected
	// comprehension can be reported by its macro name (all, exists, ...).
	opts = append(opts, cel.EnableMacroCallTracking())
	return cel.NewEnv(opts...)
}

// celTypeOf maps the Go field types used in Input onto CEL types.
func celTypeOf(t reflect.Type) (*cel.Type, error) {
	switch t.Kind() {
	case reflect.Struct:
		return cel.ObjectType("policy." + t.Name()), nil
	case reflect.Map:
		if t.Key().Kind() == reflect.String && t.Elem().Kind() == reflect.Float64 {
			return cel.MapType(cel.StringType, cel.DoubleType), nil
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.String {
			return cel.ListType(cel.StringType), nil
		}
	}
	return nil, fmt.Errorf("unsupported type %s", t)
}

func extensionFunctions(lists ListResolver) []cel.EnvOption {
	stringList := reflect.TypeFor[[]string]()
	return []cel.EnvOption{
		cel.Function("ip_in",
			cel.Overload("ip_in_string_list_string",
				[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)}, cel.BoolType,
				cel.BinaryBinding(func(ip, list ref.Val) ref.Val {
					entries, err := list.ConvertToNative(stringList)
					if err != nil {
						return types.WrapErr(err)
					}
					ok, err := ipIn(string(ip.(types.String)), entries.([]string))
					if err != nil {
						return types.WrapErr(err)
					}
					return types.Bool(ok)
				}))),
		cel.Function("list",
			cel.Overload("list_string",
				[]*cel.Type{cel.StringType}, cel.ListType(cel.StringType),
				cel.UnaryBinding(func(name ref.Val) ref.Val {
					n := string(name.(types.String))
					if lists == nil {
						return types.NewErr("list(%q): named lists are resolved by the Edge at evaluation time", n)
					}
					entries, ok := lists(n)
					if !ok {
						return types.NewErr("list(%q): unknown named list", n)
					}
					return types.NewStringList(types.DefaultTypeAdapter, entries)
				}))),
		cel.Function("glob",
			cel.Overload("glob_string_string",
				[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(s, pattern ref.Val) ref.Val {
					ok, err := glob(string(s.(types.String)), string(pattern.(types.String)))
					if err != nil {
						return types.WrapErr(err)
					}
					return types.Bool(ok)
				}))),
	}
}

// costEstimator supplies size bounds for context values and costs for the
// extension functions so that cel-go can compute a finite worst-case cost.
type costEstimator struct{}

func (costEstimator) EstimateSize(n checker.AstNode) *checker.SizeEstimate {
	path := n.Path()
	if len(path) == 0 {
		return nil
	}
	p := strings.Join(path, ".")
	if last := len(path) - 1; last > 0 && !strings.HasPrefix(path[last], "@") {
		// A selection on a map field (req.headers.referer) reads one value of
		// the map, like req.headers["referer"] (path req.headers.@values).
		if m := strings.Join(path[:last], "."); schema[m].kind == kindMap {
			p = m + ".@values"
		}
	}
	if s, ok := sizeHints[p]; ok {
		return &checker.SizeEstimate{Min: 0, Max: s}
	}
	switch n.Type().Kind() {
	case types.StringKind, types.BytesKind:
		return &checker.SizeEstimate{Min: 0, Max: defaultStringCap}
	case types.ListKind, types.MapKind:
		return &checker.SizeEstimate{Min: 0, Max: defaultListCap}
	}
	return nil
}

func (costEstimator) EstimateCallCost(function, _ string, target *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
	maxSize := func(n checker.AstNode, fallback uint64) uint64 {
		if s := n.ComputedSize(); s != nil {
			return s.Max
		}
		return fallback
	}
	switch function {
	case "list":
		return &checker.CallEstimate{
			CostEstimate: checker.CostEstimate{Min: 1, Max: 1},
			ResultSize:   &checker.SizeEstimate{Min: 0, Max: MaxNamedListEntries},
		}
	case "ip_in":
		// One address parse plus one prefix comparison per entry.
		n := maxSize(args[1], MaxNamedListEntries)
		return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: 1, Max: 1 + n}}
	case "glob":
		// Dynamic-programming matcher, costed like the IR step bound (spec
		// §5.3): 1 + len(s) * len(pattern) / 16.
		s := maxSize(args[0], defaultStringCap)
		p := maxSize(args[1], defaultStringCap)
		return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: 1, Max: 1 + satMul(s, p)/16}}
	case overloads.Contains:
		// cel-go costs s.contains(t) as quadratic, so its default estimate
		// rejects rules such as req.path.contains(req.query) that are far
		// inside the normative step bound (spec §5.2: the cel-go check is
		// supplementary, the step bound decides). Cost it like string_call
		// in §5.3 instead; containsActualCost is the matching runtime cost.
		if target != nil && len(args) == 1 {
			return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: 1,
				Max: stringCallCost(maxSize(*target, defaultStringCap), maxSize(args[0], defaultStringCap))}}
		}
	}
	return nil
}

// stringCallCost is the §5.3 cost of string_call: 1 + ceil((|s| + |t|) / 64).
func stringCallCost(s, t uint64) uint64 {
	return satAdd(1, ceilDiv(satAdd(s, t), 64))
}

// containsActualCost is the runtime counterpart of the contains() estimate
// (cel.CostTrackerOptions), so that Evaluator.Eval's cost limit admits every
// input within the §4.1 size caps.
func containsActualCost(args []ref.Val, _ ref.Val) *uint64 {
	if len(args) != 2 {
		return nil
	}
	s, ok1 := args[0].(types.String)
	t, ok2 := args[1].(types.String)
	if !ok1 || !ok2 {
		return nil
	}
	c := stringCallCost(uint64(len(s)), uint64(len(t)))
	return &c
}
