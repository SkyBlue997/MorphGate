package policy

import (
	"reflect"
	"strings"
)

// valueKind is the kind of value a schema path or IR node produces.
type valueKind int

const (
	kindUnknown valueKind = iota
	kindStruct
	kindBool
	kindInt
	kindDouble
	kindString
	kindList // list(string) for every list field of the schema
	kindMap  // map(string, V); see schemaField.mapValue
)

func (k valueKind) String() string {
	switch k {
	case kindStruct:
		return "struct"
	case kindBool:
		return "bool"
	case kindInt:
		return "int"
	case kindDouble:
		return "double"
	case kindString:
		return "string"
	case kindList:
		return "list"
	case kindMap:
		return "map"
	}
	return "unknown"
}

func (k valueKind) scalar() bool {
	return k == kindBool || k == kindInt || k == kindDouble || k == kindString
}

// schemaField describes one path of Input: a namespace, a struct field or a
// leaf ("req", "identity.crawler", "net.ip", "req.headers").
type schemaField struct {
	kind     valueKind
	mapValue valueKind // value kind of a map field
}

// schema maps every Input path to its kind. It is derived from the `cel`
// tags, so Input stays the single source of truth for the policy language
// surface (spec §4.1).
var schema = func() map[string]schemaField {
	out := map[string]schemaField{}
	var walk func(prefix string, t reflect.Type)
	walk = func(prefix string, t reflect.Type) {
		for i := range t.NumField() {
			f := t.Field(i)
			path := f.Tag.Get("cel")
			if prefix != "" {
				path = prefix + "." + path
			}
			sf := schemaField{kind: kindOfGo(f.Type)}
			if sf.kind == kindMap {
				sf.mapValue = kindOfGo(f.Type.Elem())
			}
			out[path] = sf
			if sf.kind == kindStruct {
				walk(path, f.Type)
			}
		}
	}
	walk("", reflect.TypeFor[Input]())
	return out
}()

func kindOfGo(t reflect.Type) valueKind {
	switch t.Kind() {
	case reflect.Struct:
		return kindStruct
	case reflect.Bool:
		return kindBool
	case reflect.Int64:
		return kindInt
	case reflect.Float64:
		return kindDouble
	case reflect.String:
		return kindString
	case reflect.Slice:
		return kindList
	case reflect.Map:
		return kindMap
	}
	return kindUnknown
}

// isSchemaPath reports whether p names a namespace, struct field or leaf of
// the policy schema. MISSING paths (spec §4.3) must be schema paths.
func isSchemaPath(p string) bool {
	_, ok := schema[p]
	return ok
}

// underPath reports whether path is prefix or lies below it.
func underPath(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+".")
}

// Size caps of spec §4.1: strings are bounded in UTF-8 bytes, lists and maps
// in entries. The Edge guarantees them (protocol limits, parse checks,
// truncation, bundle validation); the cost estimator (sizeHints) and the
// static step bound (MaxSteps) both assume them.
const (
	defaultStringCap = 256
	defaultListCap   = 64
)

// fieldSizeCap is S(field p) of spec §5.3: the §4.1 size cap of a string,
// list or map field, 0 for bool and numeric fields.
func fieldSizeCap(p string) uint64 {
	sf, ok := schema[p]
	if !ok {
		return 0
	}
	switch sf.kind {
	case kindString:
		if s, ok := sizeHints[p]; ok {
			return s
		}
		return defaultStringCap
	case kindList, kindMap:
		if s, ok := sizeHints[p]; ok {
			return s
		}
		return defaultListCap
	}
	return 0
}

// mapValueSizeCap is the size cap of one value of the map field p:
// 8192 for req.headers, 0 for rate (double values).
func mapValueSizeCap(p string) uint64 {
	sf, ok := schema[p]
	if !ok || sf.kind != kindMap || sf.mapValue != kindString {
		return 0
	}
	if s, ok := sizeHints[p+".@values"]; ok {
		return s
	}
	return defaultStringCap
}
