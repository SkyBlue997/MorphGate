package cfaudit

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestPlannedChecks(t *testing.T) {
	idPattern := regexp.MustCompile(`^[a-z0-9_]+$`)
	seen := map[string]bool{}
	for _, c := range Planned {
		if !idPattern.MatchString(c.ID) || seen[c.ID] {
			t.Errorf("bad or duplicate check id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Title == "" || c.Expect == "" {
			t.Errorf("check %q lacks title or expectation", c.ID)
		}
	}
	// The checks named in the design brief (B2) must all be planned.
	for _, id := range []string{
		"bot_fight_mode", "cache_bypass_mg", "sbfm_skip", "ai_bot_policy", "rocket_loader",
		"zero_rtt", "pseudo_ipv4", "remove_visitor_ip_headers", "transform_rule_signals",
	} {
		if !seen[id] {
			t.Errorf("planned checks miss %q", id)
		}
	}
}

func TestPrintPlanAndRun(t *testing.T) {
	var b bytes.Buffer
	if err := PrintPlan(&b); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(b.String(), "expect: "); n != len(Planned) {
		t.Errorf("printed %d checks, want %d", n, len(Planned))
	}
	if err := Run(); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("Run() = %v, want ErrNotImplemented", err)
	}
}
