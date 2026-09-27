package policy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

// Size assumptions used by the cost estimator. They bound what the Edge will
// hand to an expression; Phase 1 enforces the same limits when building the
// evaluation context.
const (
	MaxNamedListEntries = 10_000
	defaultStringSize   = 256
	defaultListSize     = 64
)

var sizeHints = map[string]uint64{
	"req.path":              8192,
	"req.query":             8192,
	"req.host":              253,
	"req.headers":           128,
	"req.headers.@keys":     256,
	"req.headers.@values":   8192,
	"http.header_order":     128,
	"labels":                64,
	"risk.reasons":          32,
	"rate":                  64,
	"tls.ja4.value":         36,
	"edge_tls.ciphers_sha1": 40,
	"edge_tls.ext_sha1":     40,
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
	if s, ok := sizeHints[strings.Join(path, ".")]; ok {
		return &checker.SizeEstimate{Min: 0, Max: s}
	}
	switch n.Type().Kind() {
	case types.StringKind, types.BytesKind:
		return &checker.SizeEstimate{Min: 0, Max: defaultStringSize}
	case types.ListKind, types.MapKind:
		return &checker.SizeEstimate{Min: 0, Max: defaultListSize}
	}
	return nil
}

func (costEstimator) EstimateCallCost(function, _ string, _ *checker.AstNode, args []checker.AstNode) *checker.CallEstimate {
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
		// Dynamic-programming matcher: len(s) * len(pattern) steps, weighted
		// like cel-go's own string operations (0.1 per character step).
		s := maxSize(args[0], defaultStringSize)
		p := maxSize(args[1], defaultStringSize)
		return &checker.CallEstimate{CostEstimate: checker.CostEstimate{Min: 1, Max: 1 + (s*p+9)/10}}
	}
	return nil
}
