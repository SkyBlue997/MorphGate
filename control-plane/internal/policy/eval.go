package policy

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

// Evaluator runs checked rules against an Input. It defines the reference
// semantics that the Rust IR evaluator (Phase 1) is tested against; the data
// plane never runs cel-go.
//
// Phase 0 limitation: Input has no MISSING state, so every field evaluates to
// its value or zero value and has(x) means "x is not the zero value". Phase 1
// adds the docs/06 §2 semantics here and in the Rust IR evaluator: has(x) is
// false for a MISSING field, a comparison reading it is unknown (absorbed by
// && / || like CEL errors: false && unknown = false, true || unknown = true),
// and a rule whose expression ends up unknown does not match, with dry-run
// logging missing_input and the field names (likely via cel-go partial
// evaluation with unknown attributes).
type Evaluator struct {
	env *cel.Env
}

// NewEvaluator returns an evaluator whose list(name) resolves from lists.
func NewEvaluator(lists map[string][]string) (*Evaluator, error) {
	env, err := newEnv(func(name string) ([]string, bool) {
		l, ok := lists[name]
		return l, ok
	})
	if err != nil {
		return nil, err
	}
	return &Evaluator{env: env}, nil
}

// Eval reports whether the rule's expression matches in. The rule's estimated
// worst-case cost doubles as a runtime cost limit, so inputs larger than the
// size assumptions in env.go (e.g. a path over 8 KiB) fail with a cost error,
// as they would be rejected by the Edge.
func (e *Evaluator) Eval(cr *CheckedRule, in *Input) (bool, error) {
	prg, err := e.env.Program(cr.AST, cel.CostLimit(max(cr.Cost.Max, 1)))
	if err != nil {
		return false, fmt.Errorf("rule %q: %w", cr.ID, err)
	}
	out, _, err := prg.Eval(in.activation())
	if err != nil {
		return false, fmt.Errorf("rule %q: %w", cr.ID, err)
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("rule %q: expression returned %s, not bool", cr.ID, out.Type())
	}
	return bool(b), nil
}
