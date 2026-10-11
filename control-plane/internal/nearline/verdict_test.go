package nearline

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestVerdictScriptMatchesSpec: mg_verdict_put is the §14.2 block byte for
// byte (from "-- mg_verdict_put v1" to the closing fence).
func TestVerdictScriptMatchesSpec(t *testing.T) {
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(data)
	start := strings.Index(doc, "```lua\n-- mg_verdict_put v1\n")
	if start < 0 {
		t.Fatal("spec block not found")
	}
	body := doc[start+len("```lua\n"):]
	end := strings.Index(body, "```\n")
	if end < 0 {
		t.Fatal("spec block not closed")
	}
	if body[:end] != VerdictPutLua {
		t.Fatalf("lua/mg_verdict_put.lua differs from docs/impl/phase2-spec.md §14.2")
	}
	if len(VerdictPutSHA) != 40 {
		t.Fatalf("SHA %q", VerdictPutSHA)
	}
}

func verdictJSON(source string, risk int, expiresAtMs int64) string {
	b, _ := json.Marshal(EntityVerdict{Type: "ip", Key: "k", Risk: risk, ExpiresAtMs: expiresAtMs, Source: source, Version: "x", SiteID: "s"})
	return string(b)
}

// TestVerdictPutRules runs mg_verdict_put as the §13.6 ACL user.
func TestVerdictPutRules(t *testing.T) {
	fx := needValkey(t)
	user, password := fx.aclUser()
	s := fx.store(fx.connOptions(user, password), "w")
	if err := s.LoadScript(fx.ctx); err != nil {
		t.Fatal(err)
	}
	const now = int64(1790000000000)
	live, expired := now+60_000, now-1
	k := "mg:v:" + fx.site + ":ip:" + testIPK(5)
	put := func(source string, risk int) bool {
		t.Helper()
		ok, err := s.PutVerdict(fx.ctx, k, verdictJSON(source, risk, now+900_000), 900_000, risk, now, source)
		if err != nil {
			t.Fatalf("PutVerdict: %v", err)
		}
		return ok
	}
	set := func(v string) { fx.t.Helper(); fx.do("SET", k, v) }
	get := func() string { v, _ := fx.do("GET", k).ToString(); return v }

	cases := []struct {
		name    string
		current string // "" = no key
		source  string
		risk    int
		written bool
	}{
		{"empty key", "", "nearline/scanner", 80, true},
		{"owner verdict, live", verdictJSON("owner", 0, live), "nearline/scanner", 100, false},
		{"owner verdict, expired", verdictJSON("owner", 0, expired), "nearline/scanner", 80, true},
		{"owner verdict, no expiry field", `{"risk":0,"labels":[],"source":"owner","version":"owner","reasons":["owner.suppress"]}`, "nearline/scanner", 80, true},
		{"intel feed, live", verdictJSON("feed-x", 10, live), "nearline/scanner", 90, false},
		{"unparseable", "not json", "nearline/scanner", 100, false},
		{"JSON scalar", "5", "nearline/scanner", 100, false},
		{"JSON string", `"x"`, "nearline/scanner", 100, false},
		{"source not a string", `{"source":7,"risk":1,"expires_at_ms":` + fmt.Sprint(live) + `}`, "nearline/scanner", 100, false},
		{"other detector, higher risk", verdictJSON("nearline/shared_token", 85, live), "nearline/scanner", 80, false},
		{"other detector, equal risk", verdictJSON("nearline/high_rate", 80, live), "nearline/scanner", 80, false},
		{"other detector, lower risk", verdictJSON("nearline/challenge_abuse", 70, live), "nearline/scanner", 80, true},
		{"other detector, expired", verdictJSON("nearline/shared_token", 99, expired), "nearline/scanner", 10, true},
		{"same detector refreshes, lower risk", verdictJSON("nearline/scanner", 90, live), "nearline/scanner", 80, true},
		{"prefix only", verdictJSON("nearline", 1, live), "nearline/scanner", 80, false},
	}
	for _, c := range cases {
		fx.del(k)
		if c.current != "" {
			set(c.current)
		}
		got := put(c.source, c.risk)
		if got != c.written {
			t.Errorf("%s: written = %v, want %v", c.name, got, c.written)
			continue
		}
		after := get()
		if c.written {
			if !strings.Contains(after, `"source":"`+c.source+`"`) {
				t.Errorf("%s: value %q", c.name, after)
			}
			pttl, _ := fx.do("PTTL", k).AsInt64()
			if pttl <= 0 || pttl > 900_000 {
				t.Errorf("%s: PTTL %d", c.name, pttl)
			}
		} else if after != c.current {
			t.Errorf("%s: value changed to %q", c.name, after)
		}
	}

	// Concurrent writers of two detectors with equal risk: exactly one wins
	// and the value is never torn.
	fx.del(k)
	var wg sync.WaitGroup
	results := make([]bool, 16)
	for i := range results {
		wg.Go(func() {
			src := []string{"nearline/scanner", "nearline/high_rate"}[i%2]
			ok, err := s.PutVerdict(fx.ctx, k, verdictJSON(src, 75, now+900_000), 900_000, 75, now, src)
			if err != nil {
				t.Error(err)
			}
			results[i] = ok
		})
	}
	wg.Wait()
	var v EntityVerdict
	if err := json.Unmarshal([]byte(get()), &v); err != nil {
		t.Fatalf("final value: %v", err)
	}
	// The first writer's detector holds the key; with equal risk every later
	// write of the other detector is refused and every one of its own is a
	// refresh.
	for i, ok := range results {
		src := []string{"nearline/scanner", "nearline/high_rate"}[i%2]
		if ok != (src == v.Source) {
			t.Errorf("writer %d (%s): written = %v, holder %s", i, src, ok, v.Source)
		}
	}
}
