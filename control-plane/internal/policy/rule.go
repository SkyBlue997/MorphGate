// Package policy parses, validates and type-checks MorphGate policy files
// (docs/06-policy-console-observability.md §1-§2).
//
// Phase 0 scope: YAML schema validation, CEL compilation with cel-go against the
// declared request context, output-type and cost checks, compile-time warnings
// (fields that are always MISSING under the file's declared `profile:` and read
// without a has() guard; allow / block rules that rely on Cloudflare's
// verified-bot flag alone), and a JSON listing of checked rules. Lowering CEL
// to the restricted IR consumed by the Rust Decision Core, and the
// evaluation-time MISSING ("unknown") semantics, are Phase 1; until then
// CheckedRule carries IRVersion 0 and no IR bytes.
package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Phases in evaluation order (docs/06 §1).
var Phases = []string{"identity", "protocol", "rate_limit", "bot", "custom", "default"}

// Actions a rule may take. Names are the lower-case form of morphgate.v1.Action.
var Actions = []string{"allow", "log", "tag", "rate_limit", "challenge", "tarpit", "block"}

// Modes a rule may run in.
var Modes = []string{"enforce", "dry_run", "disabled"}

// ChallengeTypes accepted in params.type of a challenge rule. Names are the
// lower-case form of morphgate.v1.ChallengeType.
var ChallengeTypes = []string{"invisible", "pow", "interactive", "attestation", "step_up"}

// Default values applied when a field is omitted.
const (
	DefaultMode    = "enforce"
	DefaultRollout = 100
)

// Rule is one entry of `policies:` as written by the owner, after schema
// validation but before CEL compilation.
type Rule struct {
	// Profile is the UpstreamProfile the rule's file declares with the
	// top-level `profile:` key ("" when the file declares none).
	Profile string

	ID          string
	Phase       string
	Priority    int32
	Expr        string
	Action      string
	Params      map[string]string
	Mode        string
	Rollout     int
	Temporary   bool
	ExpiresAt   *time.Time
	Locked      bool
	Owner       string
	Description string

	// Source location of the rule and of each field key, for diagnostics.
	File     string
	Pos      Position
	FieldPos map[string]Position

	// exprPos is where the expression text starts in the file. When exprInline
	// is true the expression sits on one line exactly as written, so CEL
	// columns map onto file columns; otherwise (block scalars, escapes, line
	// folding) diagnostics carry the CEL-relative location instead.
	exprPos    Position
	exprInline bool

	// profilePos is where the file declares `profile:`.
	profilePos Position
}

// Position is a 1-based line/column in a policy file. Zero means unknown.
type Position struct {
	Line int
	Col  int
}

// posOf returns the position of a field key, falling back to the rule itself.
func (r *Rule) posOf(field string) Position {
	if p, ok := r.FieldPos[field]; ok {
		return p
	}
	return r.Pos
}

// Severity of a diagnostic.
type Severity int

const (
	SeverityError Severity = iota
	SeverityWarning
)

func (s Severity) String() string {
	if s == SeverityWarning {
		return "warning"
	}
	return "error"
}

// Diagnostic is one problem found in a policy file.
type Diagnostic struct {
	File     string
	Pos      Position
	RuleID   string // empty when the problem is not inside a rule
	Field    string // empty when the problem is not tied to a field
	Severity Severity
	Message  string
}

// String renders the diagnostic as `file:line:col: severity: rule "id": field: message`.
func (d Diagnostic) String() string {
	var b strings.Builder
	b.WriteString(d.File)
	if d.Pos.Line > 0 {
		fmt.Fprintf(&b, ":%d", d.Pos.Line)
		if d.Pos.Col > 0 {
			fmt.Fprintf(&b, ":%d", d.Pos.Col)
		}
	}
	fmt.Fprintf(&b, ": %s: ", d.Severity)
	if d.RuleID != "" {
		fmt.Fprintf(&b, "rule %q: ", d.RuleID)
	}
	if d.Field != "" {
		b.WriteString(d.Field)
		b.WriteString(": ")
	}
	b.WriteString(d.Message)
	return b.String()
}

// Diagnostics is an ordered list of problems.
type Diagnostics []Diagnostic

// HasErrors reports whether any diagnostic is an error (warnings do not count).
func (ds Diagnostics) HasErrors() bool {
	return slices.ContainsFunc(ds, func(d Diagnostic) bool { return d.Severity == SeverityError })
}

// Errors returns only the error-severity diagnostics.
func (ds Diagnostics) Errors() Diagnostics {
	var out Diagnostics
	for _, d := range ds {
		if d.Severity == SeverityError {
			out = append(out, d)
		}
	}
	return out
}

func (ds *Diagnostics) add(sev Severity, file string, pos Position, ruleID, field, format string, args ...any) {
	*ds = append(*ds, Diagnostic{
		File: file, Pos: pos, RuleID: ruleID, Field: field,
		Severity: sev, Message: fmt.Sprintf(format, args...),
	})
}

func (ds *Diagnostics) errorf(file string, pos Position, ruleID, field, format string, args ...any) {
	ds.add(SeverityError, file, pos, ruleID, field, format, args...)
}

func (ds *Diagnostics) warnf(file string, pos Position, ruleID, field, format string, args ...any) {
	ds.add(SeverityWarning, file, pos, ruleID, field, format, args...)
}
