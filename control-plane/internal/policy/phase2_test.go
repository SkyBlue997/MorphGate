package policy

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// fieldsContract is testdata/policy-ir/fields.json (Phase 2 spec §0.4, §22).
type fieldsContract struct {
	Structs []string `json:"structs"`
	Fields  []struct {
		Path     string `json:"path"`
		Type     string `json:"type"`
		Cap      uint64 `json:"cap"`
		Phase    int    `json:"phase"`
		KeyCap   uint64 `json:"key_cap"`
		ValueCap uint64 `json:"value_cap"`
		ItemCap  uint64 `json:"item_cap"`
	} `json:"fields"`
}

func typeName(sf schemaField) string {
	switch sf.kind {
	case kindList:
		return "list(string)"
	case kindMap:
		return "map(string," + sf.mapValue.String() + ")"
	}
	return sf.kind.String()
}

// Phase 2 spec §22: the Go policy schema (Input and its size caps) agrees
// field for field with the shared contract that the Rust table also reads.
func TestSchemaMatchesFieldsContract(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/policy-ir/fields.json")
	if err != nil {
		t.Fatal(err)
	}
	var c fieldsContract
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	var leaves, structs []string
	for p, sf := range schema {
		if sf.kind == kindStruct {
			structs = append(structs, p)
		} else {
			leaves = append(leaves, p)
		}
	}
	// Top-level namespaces that are not structs (rate, labels) are fields.
	for _, ns := range Namespaces() {
		if schema[ns].kind != kindStruct {
			continue
		}
		if !slices.Contains(c.Structs, ns) {
			t.Errorf("namespace %s is not in fields.json structs", ns)
		}
	}
	slices.Sort(structs)
	wantStructs := slices.Sorted(slices.Values(c.Structs))
	if !slices.Equal(structs, wantStructs) {
		t.Errorf("struct paths:\n got %v\nwant %v", structs, wantStructs)
	}
	var contractPaths, phase2 []string
	for _, f := range c.Fields {
		contractPaths = append(contractPaths, f.Path)
		if f.Phase == 2 {
			phase2 = append(phase2, f.Path)
		}
		sf, ok := schema[f.Path]
		if !ok {
			t.Errorf("%s: in fields.json but not in the Go schema", f.Path)
			continue
		}
		if got := typeName(sf); got != f.Type {
			t.Errorf("%s: Go type %s, contract %s", f.Path, got, f.Type)
		}
		if got := fieldSizeCap(f.Path); got != f.Cap {
			t.Errorf("%s: Go cap %d, contract %d", f.Path, got, f.Cap)
		}
		if f.KeyCap != 0 && sizeHints[f.Path+".@keys"] != f.KeyCap {
			t.Errorf("%s: key cap %d, contract %d", f.Path, sizeHints[f.Path+".@keys"], f.KeyCap)
		}
		if f.ValueCap != 0 && mapValueSizeCap(f.Path) != f.ValueCap {
			t.Errorf("%s: value cap %d, contract %d", f.Path, mapValueSizeCap(f.Path), f.ValueCap)
		}
		if f.ItemCap != 0 && sizeHints[f.Path+".@items"] != f.ItemCap {
			t.Errorf("%s: item cap %d, contract %d", f.Path, sizeHints[f.Path+".@items"], f.ItemCap)
		}
	}
	slices.Sort(leaves)
	slices.Sort(contractPaths)
	if !slices.Equal(leaves, contractPaths) {
		t.Errorf("field paths:\n got %v\nwant %v", leaves, contractPaths)
	}
	slices.Sort(phase2)
	if got := slices.Sorted(slices.Values(Phase2Fields)); !slices.Equal(got, phase2) {
		t.Errorf("Phase2Fields = %v, fields.json phase 2 = %v", got, phase2)
	}
}

// Phase 2 spec §4.2: http.navigation is client-controlled. An allow rule
// conditioned on it is an error, any other rule gets a warning.
func TestNavigationRules(t *testing.T) {
	const src = `policies:
  - {id: nav-allow, phase: bot, expr: 'http.navigation && risk.score < 50', action: allow}
  - {id: nav-allow-has, phase: bot, expr: 'has(http.navigation)', action: allow}
  - {id: nav-allow-negated, phase: bot, expr: '!http.navigation || req.method == "GET"', action: allow}
  - {id: nav-challenge, phase: bot, expr: '!http.navigation && route.name == "api"', action: challenge}
  - {id: nav-tag, phase: bot, expr: 'http.navigation', action: tag, params: {label: nav}}
  - {id: plain-allow, phase: bot, expr: 'risk.score < 10', action: allow}
`
	checked, diags := checkSource(t, Options{}, src)
	errRules := map[string]bool{}
	warnRules := map[string]bool{}
	for _, d := range diags {
		if !strings.Contains(d.Message, NavigationField) {
			continue
		}
		if d.Severity == SeverityError {
			errRules[d.RuleID] = true
		} else {
			warnRules[d.RuleID] = true
		}
	}
	for _, id := range []string{"nav-allow", "nav-allow-has", "nav-allow-negated"} {
		if !errRules[id] {
			t.Errorf("%s: want an error\n  %s", id, strings.Join(diagStrings(diags), "\n  "))
		}
	}
	for _, id := range []string{"nav-challenge", "nav-tag"} {
		if errRules[id] || !warnRules[id] {
			t.Errorf("%s: want a warning only\n  %s", id, strings.Join(diagStrings(diags), "\n  "))
		}
	}
	if errRules["plain-allow"] || warnRules["plain-allow"] {
		t.Error("plain-allow must not be flagged")
	}
	requireDiag(t, diags, `rule "nav-allow": expr: an allow rule must not depend on http.navigation`)
	for _, cr := range checked {
		if strings.HasPrefix(cr.ID, "nav-allow") {
			t.Errorf("%s compiled despite its error", cr.ID)
		}
	}
}

// Phase 2 spec §4.2: block on present-but-invalid proofs gets a hint.
func TestProofBlockHint(t *testing.T) {
	const src = `policies:
  - {id: block-bad-proof, phase: bot, expr: 'identity.proof.present && !identity.proof.valid', action: block}
  - {id: challenge-bad-proof, phase: bot, expr: 'identity.proof.present && !identity.proof.valid', action: challenge}
  - {id: block-replay, phase: bot, expr: 'identity.proof.replayed', action: block}
`
	_, diags := checkSource(t, Options{Profile: "cloudflare"}, src)
	if diags.HasErrors() {
		t.Fatal(diagStrings(diags))
	}
	if got := rulesWithDiags(diags, "session key was cleared"); !slices.Equal(got, []string{"block-bad-proof"}) {
		t.Errorf("hinted rules = %v\n  %s", got, strings.Join(diagStrings(diags), "\n  "))
	}
	if len(diags) != 1 {
		t.Errorf("want exactly the hint, got %v", diagStrings(diags))
	}
}

// The Phase 2 fields compile and evaluate like any other field.
func TestPhase2FieldsEvaluate(t *testing.T) {
	const src = `policies:
  - {id: bound-fresh, phase: bot, expr: 'identity.token.bound && identity.token.level_age < 3600 && identity.token.level == "interactive"', action: log}
`
	checked, diags := checkSource(t, Options{}, src)
	if len(checked) != 1 || len(diags) != 0 {
		t.Fatalf("checked %d, diags %v", len(checked), diagStrings(diags))
	}
	ev, err := NewEvaluator(nil)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Identity: Identity{Token: Token{Level: "interactive", Bound: true, LevelAge: 120}}}
	if got, err := ev.EvalWithMissing(checked[0], &in, nil); err != nil || got != ResultTrue {
		t.Errorf("got %v, %v", got, err)
	}
	in.Identity.Token.LevelAge = 7200
	if got, err := ev.EvalWithMissing(checked[0], &in, nil); err != nil || got != ResultFalse {
		t.Errorf("got %v, %v", got, err)
	}
	if got, err := ev.EvalWithMissing(checked[0], &in, []string{"identity.token"}); err != nil || got != ResultUnknown {
		t.Errorf("MISSING token: got %v, %v", got, err)
	}
}
