package sitecfg

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Severity values of a Diagnostic.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Diagnostic is one problem found in a site YAML file.
type Diagnostic struct {
	File      string
	Line, Col int // 1-based; 0 when unknown
	Severity  string
	Message   string
}

// String renders "file:line:col: severity: message".
func (d Diagnostic) String() string {
	var b strings.Builder
	b.WriteString(d.File)
	if d.Line > 0 {
		fmt.Fprintf(&b, ":%d", d.Line)
		if d.Col > 0 {
			fmt.Fprintf(&b, ":%d", d.Col)
		}
	}
	fmt.Fprintf(&b, ": %s: %s", d.Severity, d.Message)
	return b.String()
}

// HasErrors reports whether any diagnostic is an error.
func HasErrors(ds []Diagnostic) bool {
	return slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Severity == SeverityError })
}

// parser collects diagnostics while walking the YAML tree.
type parser struct {
	file  string
	diags []Diagnostic
}

func (p *parser) add(sev string, n *yaml.Node, format string, args ...any) {
	d := Diagnostic{File: p.file, Severity: sev, Message: fmt.Sprintf(format, args...)}
	if n != nil {
		d.Line, d.Col = n.Line, n.Column
	}
	p.diags = append(p.diags, d)
}

func (p *parser) errorf(n *yaml.Node, format string, args ...any) {
	p.add(SeverityError, n, format, args...)
}

func (p *parser) warnf(n *yaml.Node, format string, args ...any) {
	p.add(SeverityWarning, n, format, args...)
}

// object is a YAML mapping whose keys are consumed one by one; finish()
// reports the keys nobody asked for.
type object struct {
	p     *parser
	node  *yaml.Node
	path  string
	keys  map[string]*yaml.Node // key node
	vals  map[string]*yaml.Node
	order []string
	used  map[string]bool
}

// object returns n as an object, or nil (with an error) when it is not a mapping.
func (p *parser) object(n *yaml.Node, path string) *object {
	if n.Kind != yaml.MappingNode {
		p.errorf(n, "%s: must be a mapping, not %s", path, kindName(n))
		return nil
	}
	o := &object{p: p, node: n, path: path, keys: map[string]*yaml.Node{}, vals: map[string]*yaml.Node{}, used: map[string]bool{}}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" {
			p.errorf(k, "%s: keys must be plain strings", path)
			continue
		}
		if _, dup := o.keys[k.Value]; dup {
			p.errorf(k, "%s: duplicate key %q", path, k.Value)
			continue
		}
		o.keys[k.Value], o.vals[k.Value] = k, v
		o.order = append(o.order, k.Value)
	}
	return o
}

// sub is the dotted path of a member.
func (o *object) sub(key string) string {
	if o.path == "" {
		return key
	}
	return o.path + "." + key
}

// get returns the value of key (nil when absent) and marks it as known.
func (o *object) get(key string) *yaml.Node {
	o.used[key] = true
	v := o.vals[key]
	if v != nil && v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
		return nil
	}
	return v
}

// finish reports unknown keys.
func (o *object) finish() {
	for _, k := range o.order {
		if !o.used[k] {
			o.p.errorf(o.keys[k], "%s: unknown key %q", o.path0(), k)
		}
	}
}

func (o *object) path0() string {
	if o.path == "" {
		return "site"
	}
	return o.path
}

// require reports a missing key.
func (o *object) require(key string) *yaml.Node {
	v := o.get(key)
	if v == nil {
		o.p.errorf(o.node, "%s: required", o.sub(key))
	}
	return v
}

// str reads a string scalar.
func (p *parser) str(n *yaml.Node, path string) (string, bool) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		p.errorf(n, "%s: must be a string, not %s", path, kindName(n))
		return "", false
	}
	return n.Value, true
}

// scalarText reads any non-null scalar as text (list entries: numbers allowed).
func (p *parser) scalarText(n *yaml.Node, path string) (string, bool) {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" || n.Tag == "!!binary" {
		p.errorf(n, "%s: must be a scalar value, not %s", path, kindName(n))
		return "", false
	}
	return n.Value, true
}

func (p *parser) enum(n *yaml.Node, path string, allowed []string) (string, bool) {
	s, ok := p.str(n, path)
	if !ok {
		return "", false
	}
	if !slices.Contains(allowed, s) {
		p.errorf(n, "%s: %q is not one of %s", path, s, strings.Join(allowed, ", "))
		return "", false
	}
	return s, true
}

func (p *parser) boolean(n *yaml.Node, path string) (bool, bool) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!bool" {
		p.errorf(n, "%s: must be true or false, not %s", path, kindName(n))
		return false, false
	}
	var b bool
	if err := n.Decode(&b); err != nil {
		p.errorf(n, "%s: must be true or false", path)
		return false, false
	}
	return b, true
}

// uint reads a decimal integer in [lo, hi].
func (p *parser) uint(n *yaml.Node, path string, lo, hi uint64) (uint32, bool) {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!int" {
		p.errorf(n, "%s: must be an integer, not %s", path, kindName(n))
		return 0, false
	}
	v, err := strconv.ParseUint(n.Value, 10, 64)
	if err != nil {
		p.errorf(n, "%s: must be a decimal integer between %d and %d, got %s", path, lo, hi, n.Value)
		return 0, false
	}
	if v < lo || v > hi {
		p.errorf(n, "%s: must be between %d and %d, got %d", path, lo, hi, v)
		return 0, false
	}
	return uint32(v), true
}

// float reads a finite number in [lo, hi].
func (p *parser) float(n *yaml.Node, path string, lo, hi float64) (float64, bool) {
	if n.Kind != yaml.ScalarNode || (n.Tag != "!!float" && n.Tag != "!!int") {
		p.errorf(n, "%s: must be a number, not %s", path, kindName(n))
		return 0, false
	}
	v, err := strconv.ParseFloat(n.Value, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		p.errorf(n, "%s: must be a finite decimal number, got %s", path, n.Value)
		return 0, false
	}
	if v < lo || v > hi {
		p.errorf(n, "%s: must be between %g and %g, got %g", path, lo, hi, v)
		return 0, false
	}
	return v, true
}

// seq returns the items of a sequence node, or nil (with an error).
func (p *parser) seq(n *yaml.Node, path string) ([]*yaml.Node, bool) {
	if n.Kind != yaml.SequenceNode {
		p.errorf(n, "%s: must be a list, not %s", path, kindName(n))
		return nil, false
	}
	return n.Content, true
}

// strList reads a list of strings; each is checked by check (nil: any).
func (p *parser) strList(n *yaml.Node, path string, check func(item *yaml.Node, path, s string) bool) ([]string, bool) {
	items, ok := p.seq(n, path)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	good := true
	for i, it := range items {
		ip := fmt.Sprintf("%s[%d]", path, i)
		s, ok := p.str(it, ip)
		if ok && check != nil {
			ok = check(it, ip, s)
		}
		if !ok {
			good = false
			continue
		}
		out = append(out, s)
	}
	return out, good
}

// uniqueStrings reports duplicates in a list read by strList.
func (p *parser) uniqueStrings(n *yaml.Node, path string, items []string) bool {
	seen := map[string]bool{}
	for _, s := range items {
		if seen[s] {
			p.errorf(n, "%s: duplicate entry %q", path, s)
			return false
		}
		seen[s] = true
	}
	return true
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.AliasNode:
		return "an alias"
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!null":
			return "null"
		case "!!str":
			return fmt.Sprintf("the string %q", n.Value)
		case "!!int", "!!float":
			return "the number " + n.Value
		case "!!bool":
			return "the boolean " + n.Value
		}
		return fmt.Sprintf("the %s value %q", strings.TrimPrefix(n.Tag, "!!"), n.Value)
	}
	return "an unexpected node"
}

// findAlias returns the first anchor, alias or merge key in the tree.
func findAlias(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || (n.Kind == yaml.ScalarNode && n.Tag == "!!merge") {
		return n
	}
	for _, c := range n.Content {
		if a := findAlias(c); a != nil {
			return a
		}
	}
	return nil
}
