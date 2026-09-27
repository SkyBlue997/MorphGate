package policy

import (
	"bytes"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxFileSize bounds a single policy file; policy files are small and hand-written.
const MaxFileSize = 1 << 20

var (
	ruleIDPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
	paramKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	yamlLinePattern = regexp.MustCompile(`line (\d+)`)
)

// fieldParsers maps every accepted rule key to its parser. Keys not listed here
// are rejected, so typos such as `mdoe:` never silently fall back to defaults.
var fieldParsers = map[string]func(p *ruleParser, v *yaml.Node){
	"id": func(p *ruleParser, v *yaml.Node) {
		if s, ok := p.str("id", v); ok {
			if !ruleIDPattern.MatchString(s) {
				p.errf("id", v, "must match %s", ruleIDPattern)
			}
			p.r.ID = s
		}
	},
	"phase": func(p *ruleParser, v *yaml.Node) {
		if s, ok := p.enum("phase", v, Phases); ok {
			p.r.Phase = s
		}
	},
	"priority": func(p *ruleParser, v *yaml.Node) {
		if n, ok := p.integer("priority", v, -1_000_000, 1_000_000); ok {
			p.r.Priority = int32(n)
		}
	},
	"expr": func(p *ruleParser, v *yaml.Node) {
		if s, ok := p.str("expr", v); ok {
			p.r.Expr = strings.TrimSpace(s)
			p.r.exprPos, p.r.exprInline = exprLocation(p.lines, v)
		}
	},
	"action": func(p *ruleParser, v *yaml.Node) {
		if s, ok := p.enum("action", v, Actions); ok {
			p.r.Action = s
		}
	},
	"params": (*ruleParser).params,
	"mode": func(p *ruleParser, v *yaml.Node) {
		if s, ok := p.enum("mode", v, Modes); ok {
			p.r.Mode = s
		}
	},
	"rollout": func(p *ruleParser, v *yaml.Node) {
		if n, ok := p.integer("rollout", v, 0, 100); ok {
			p.r.Rollout = int(n)
		}
	},
	"temporary": func(p *ruleParser, v *yaml.Node) {
		if b, ok := p.boolean("temporary", v); ok {
			p.r.Temporary = b
		}
	},
	"expires_at": func(p *ruleParser, v *yaml.Node) {
		if s, ok := p.str("expires_at", v); ok {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				p.errf("expires_at", v, "must be an RFC 3339 timestamp such as 2026-12-31T23:59:59Z")
				return
			}
			p.r.ExpiresAt = &t
		}
	},
	"locked": func(p *ruleParser, v *yaml.Node) {
		if b, ok := p.boolean("locked", v); ok {
			p.r.Locked = b
		}
	},
	"owner": func(p *ruleParser, v *yaml.Node) {
		if s, ok := p.str("owner", v); ok {
			p.r.Owner = s
		}
	},
	"description": func(p *ruleParser, v *yaml.Node) {
		if s, ok := p.str("description", v); ok {
			p.r.Description = s
		}
	},
}

// knownFields is the sorted list of accepted rule keys, for error messages.
var knownFields = func() []string {
	keys := make([]string, 0, len(fieldParsers))
	for k := range fieldParsers {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}()

// ParseFile reads and parses one policy file.
func ParseFile(path string) ([]*Rule, Diagnostics) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Diagnostics{{File: path, Severity: SeverityError, Message: err.Error()}}
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, Diagnostics{{File: path, Severity: SeverityError, Message: err.Error()}}
	}
	if len(data) > MaxFileSize {
		return nil, Diagnostics{{File: path, Severity: SeverityError, Message: "file is larger than 1 MiB"}}
	}
	return Parse(path, data)
}

// Parse parses policy YAML. It returns every rule that could be read, even when
// some diagnostics are errors, so callers can report all problems in one pass.
func Parse(file string, data []byte) ([]*Rule, Diagnostics) {
	var diags Diagnostics
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			diags.errorf(file, Position{}, "", "", "empty policy file")
		} else {
			diags.errorf(file, yamlErrorPos(err), "", "", "invalid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
		}
		return nil, diags
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		diags.errorf(file, nodePos(&extra), "", "", "multiple YAML documents are not supported")
	} else if !errors.Is(err, io.EOF) {
		diags.errorf(file, yamlErrorPos(err), "", "", "invalid YAML: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}

	if n := findAlias(&doc); n != nil {
		diags.errorf(file, nodePos(n), "", "", "YAML anchors, aliases and merge keys are not supported in policy files")
		return nil, diags
	}

	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		diags.errorf(file, nodePos(root), "", "", "top level must be a mapping with a `policies` list")
		return nil, diags
	}

	var policies, profileKey, profileVal *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		switch {
		case k.Value == "policies" && policies == nil:
			policies = v
		case k.Value == "profile" && profileKey == nil:
			profileKey, profileVal = k, v
		case k.Value == "policies" || k.Value == "profile":
			diags.errorf(file, nodePos(k), "", "", "duplicate key `%s`", k.Value)
		default:
			diags.errorf(file, nodePos(k), "", "", "unknown top-level field %q (expected `profile` or `policies`)", k.Value)
		}
	}
	profile := ""
	if profileVal != nil {
		profile = parseProfile(file, profileVal, &diags)
	}
	if policies == nil {
		diags.errorf(file, nodePos(root), "", "", "missing `policies` list")
		return nil, diags
	}
	if policies.Kind != yaml.SequenceNode {
		diags.errorf(file, nodePos(policies), "", "", "`policies` must be a list")
		return nil, diags
	}
	if len(policies.Content) == 0 {
		diags.warnf(file, nodePos(policies), "", "", "`policies` is empty")
	}

	lines := strings.Split(string(data), "\n")
	var rules []*Rule
	for _, item := range policies.Content {
		p := &ruleParser{file: file, lines: lines, diags: &diags}
		if r := p.parse(item); r != nil {
			if profile != "" {
				r.Profile, r.profilePos = profile, nodePos(profileKey)
			}
			rules = append(rules, r)
		}
	}
	return rules, diags
}

// parseProfile validates the optional top-level `profile:` key: the
// UpstreamProfile of the site the file is for. The compiler then warns about
// rules that read fields that profile can never supply. It returns "" when
// the value is invalid.
func parseProfile(file string, v *yaml.Node, diags *Diagnostics) string {
	if v.Kind != yaml.ScalarNode || v.Tag == "!!null" || strings.TrimSpace(v.Value) == "" {
		diags.errorf(file, nodePos(v), "", "profile", "must be a non-empty string")
		return ""
	}
	switch {
	case slices.Contains(CheckedProfiles, v.Value):
		return v.Value
	case slices.Contains(UpstreamProfiles, v.Value):
		diags.warnf(file, nodePos(v), "", "profile", "no field-availability table for profile %q yet (checked profiles: %s); MISSING-field checks are skipped", v.Value, strings.Join(CheckedProfiles, ", "))
		return v.Value
	}
	diags.errorf(file, nodePos(v), "", "profile", "%q is not one of %s", v.Value, strings.Join(UpstreamProfiles, ", "))
	return ""
}

// ruleParser holds the state for parsing one entry of `policies:`.
type ruleParser struct {
	file  string
	lines []string
	diags *Diagnostics
	r     *Rule
}

func (p *ruleParser) parse(n *yaml.Node) *Rule {
	if n.Kind != yaml.MappingNode {
		p.diags.errorf(p.file, nodePos(n), "", "", "each policy must be a mapping")
		return nil
	}
	p.r = &Rule{
		File:     p.file,
		Pos:      nodePos(n),
		FieldPos: make(map[string]Position, len(n.Content)/2),
		Mode:     DefaultMode,
		Rollout:  DefaultRollout,
	}
	// Read the id first so every later diagnostic can name the rule.
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k, v := n.Content[i], n.Content[i+1]; k.Value == "id" && v.Kind == yaml.ScalarNode {
			p.r.ID = v.Value
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			p.diags.errorf(p.file, nodePos(k), p.r.ID, "", "field names must be plain strings")
			continue
		}
		name := k.Value
		if _, dup := p.r.FieldPos[name]; dup {
			p.diags.errorf(p.file, nodePos(k), p.r.ID, name, "duplicate field")
			continue
		}
		p.r.FieldPos[name] = nodePos(k)
		parse, ok := fieldParsers[name]
		if !ok {
			p.diags.errorf(p.file, nodePos(k), p.r.ID, "", "unknown field %q (known fields: %s)", name, strings.Join(knownFields, ", "))
			continue
		}
		parse(p, v)
	}

	for _, req := range []string{"id", "phase", "expr", "action"} {
		if _, ok := p.r.FieldPos[req]; !ok {
			p.diags.errorf(p.file, p.r.Pos, p.r.ID, req, "required field is missing")
		}
	}
	if p.r.Temporary && p.r.ExpiresAt == nil {
		if _, ok := p.r.FieldPos["expires_at"]; !ok {
			p.diags.errorf(p.file, p.r.posOf("temporary"), p.r.ID, "expires_at", "required when `temporary: true`")
		}
	}
	return p.r
}

func (p *ruleParser) errf(field string, v *yaml.Node, format string, args ...any) {
	p.diags.errorf(p.file, nodePos(v), p.r.ID, field, format, args...)
}

// scalar returns v if it is a non-null scalar, reporting an error otherwise.
func (p *ruleParser) scalar(field string, v *yaml.Node) (*yaml.Node, bool) {
	switch {
	case v.Kind != yaml.ScalarNode:
		p.errf(field, v, "must be a scalar value, not a %s", kindName(v.Kind))
		return nil, false
	case v.Tag == "!!null":
		p.errf(field, v, "must not be empty")
		return nil, false
	}
	return v, true
}

func (p *ruleParser) str(field string, v *yaml.Node) (string, bool) {
	if _, ok := p.scalar(field, v); !ok {
		return "", false
	}
	if strings.TrimSpace(v.Value) == "" {
		p.errf(field, v, "must not be empty")
		return "", false
	}
	return v.Value, true
}

func (p *ruleParser) enum(field string, v *yaml.Node, allowed []string) (string, bool) {
	s, ok := p.str(field, v)
	if !ok {
		return "", false
	}
	if !slices.Contains(allowed, s) {
		p.errf(field, v, "%q is not one of %s", s, strings.Join(allowed, ", "))
		return "", false
	}
	return s, true
}

func (p *ruleParser) integer(field string, v *yaml.Node, lo, hi int64) (int64, bool) {
	if _, ok := p.scalar(field, v); !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(v.Value, 10, 64)
	if v.Tag != "!!int" || err != nil {
		p.errf(field, v, "must be a decimal integer, got %q", v.Value)
		return 0, false
	}
	if n < lo || n > hi {
		p.errf(field, v, "must be between %d and %d, got %d", lo, hi, n)
		return 0, false
	}
	return n, true
}

func (p *ruleParser) boolean(field string, v *yaml.Node) (bool, bool) {
	if _, ok := p.scalar(field, v); !ok {
		return false, false
	}
	if v.Tag != "!!bool" {
		p.errf(field, v, "must be true or false, got %q", v.Value)
		return false, false
	}
	var b bool
	if err := v.Decode(&b); err != nil {
		p.errf(field, v, "must be true or false, got %q", v.Value)
		return false, false
	}
	return b, true
}

// params accepts a flat mapping of lower_snake_case keys to scalar values.
// Values are kept as strings, matching map<string,string> in CompiledRule.
func (p *ruleParser) params(v *yaml.Node) {
	if v.Kind != yaml.MappingNode {
		p.errf("params", v, "must be a mapping, not a %s", kindName(v.Kind))
		return
	}
	out := make(map[string]string, len(v.Content)/2)
	for i := 0; i+1 < len(v.Content); i += 2 {
		k, val := v.Content[i], v.Content[i+1]
		if k.Kind != yaml.ScalarNode || !paramKeyPattern.MatchString(k.Value) {
			p.errf("params", k, "key %q must match %s", k.Value, paramKeyPattern)
			continue
		}
		field := "params." + k.Value
		if _, dup := out[k.Value]; dup {
			p.errf(field, k, "duplicate key")
			continue
		}
		if _, ok := p.scalar(field, val); !ok {
			continue
		}
		out[k.Value] = val.Value
	}
	p.r.Params = out
}

// exprLocation returns where the expression text starts and whether it sits on
// a single line verbatim, so that CEL columns can be added to it.
func exprLocation(lines []string, v *yaml.Node) (Position, bool) {
	pos := nodePos(v)
	if v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		// Block scalar: content starts on the line after the indicator.
		return Position{Line: pos.Line + 1}, false
	}
	if pos.Line < 1 || pos.Line > len(lines) || pos.Col < 1 {
		return pos, false
	}
	rest := lines[pos.Line-1]
	if pos.Col-1 > len(rest) {
		return pos, false
	}
	rest = rest[pos.Col-1:]
	switch {
	case v.Style&yaml.DoubleQuotedStyle != 0:
		return Position{pos.Line, pos.Col + 1}, strings.HasPrefix(rest, `"`+v.Value+`"`)
	case v.Style&yaml.SingleQuotedStyle != 0:
		return Position{pos.Line, pos.Col + 1}, strings.HasPrefix(rest, `'`+v.Value+`'`)
	default:
		return pos, strings.HasPrefix(rest, v.Value)
	}
}

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

func nodePos(n *yaml.Node) Position {
	return Position{Line: n.Line, Col: n.Column}
}

func yamlErrorPos(err error) Position {
	if m := yamlLinePattern.FindStringSubmatch(err.Error()); m != nil {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil {
			return Position{Line: n}
		}
	}
	return Position{}
}

func kindName(k yaml.Kind) string {
	switch k {
	case yaml.MappingNode:
		return "mapping"
	case yaml.SequenceNode:
		return "list"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "document"
	}
}
