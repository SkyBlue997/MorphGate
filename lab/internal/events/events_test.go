package events

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// line builders for the §13 record shapes the checks read.

func decision(path, rid, class, verification, action string, claimed bool) string {
	crawler := map[string]any{"claimed": claimed}
	if claimed {
		crawler["operator"] = "googlebot"
		crawler["verification"] = verification
		crawler["verified"] = verification == "verified"
	}
	return mustJSON(map[string]any{
		"kind": "decision", "site": "lab", "ts": 1,
		"ctx": map[string]any{
			"request_id": rid,
			"http":       map[string]any{"method": "GET", "path": path},
			"identity":   map[string]any{"crawler": crawler},
		},
		"risk":     map[string]any{"bot_class": class, "score": 90},
		"decision": map[string]any{"action": action, "dry_run": false, "rule_id": "matrix.x"},
	})
}

func access(path, rid string, status int, action string) string {
	return mustJSON(map[string]any{"kind": "access", "site": "lab", "ts": 1, "path": path,
		"request_id": rid, "status": status, "action": action, "route": "default"})
}

func feedback(outcome string) string {
	return mustJSON(map[string]any{"kind": "feedback", "site": "lab", "ts": 1, "outcome": outcome,
		"type": "pow", "reason_codes": []string{"ic.c_invalid"}})
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func read(t *testing.T, lines ...string) []Record {
	t.Helper()
	recs, err := Read(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestRead(t *testing.T) {
	recs := read(t, access("/a", "1", 200, "allow"), "", "  ", feedback("fail"))
	if len(recs) != 2 || recs[0].Line != 1 || recs[1].Line != 4 || recs[1].Outcome != "fail" {
		t.Fatalf("Read = %+v", recs)
	}
	for in, want := range map[string]string{
		"{\"kind\":\"access\"}\nnot json\n": "line 2",
		"{\"site\":\"lab\"}\n":              "line 1: no kind",
		"[1,2]\n":                           "line 1",
		strings.Repeat("x", MaxLineBytes+1): "longer than",
	} {
		if _, err := Read(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Read(%.40q) = %v, want %q", in, err, want)
		}
	}
}

const (
	imp = "/lab/impersonator/r1/"
	crw = "/lab/crawler/r1/"
)

func goodImpersonatorRun() []string {
	return []string{
		// ip_ranges: settled on the first request.
		decision(imp+"gptbot/1", "a1", "impersonator", "failed", "block", true), access(imp+"gptbot/1", "a1", 403, "block"),
		// rDNS: a pending warm-up, then settled.
		decision(imp+"g/warmup", "a2", "declared_agent", "pending", "allow", true), access(imp+"g/warmup", "a2", 200, "allow"),
		decision(imp+"g/1", "a3", "impersonator", "failed", "block", true), access(imp+"g/1", "a3", 403, "block"),
		// Genuine crawlers.
		decision(crw+"g/warmup", "c1", "declared_agent", "pending", "allow", true),
		decision(crw+"g/1", "c2", "verified_crawler", "verified", "allow", true),
		// Unrelated traffic is ignored.
		decision("/other", "o1", "human_likely", "", "allow", false), access("/other", "o1", 200, "allow"),
	}
}

func TestCheckImpersonatorsPass(t *testing.T) {
	rep := CheckImpersonators(read(t, goodImpersonatorRun()...), ImpersonatorOptions{
		Site: "lab", Impersonators: imp, Crawlers: crw, WantSettled: 2, WantVerified: 1})
	if !rep.OK() || rep.Settled != 2 || rep.Classified != 2 || rep.Pending != 1 || rep.Access != 3 ||
		rep.Verified != 1 || rep.CrawlerPending != 1 || rep.Ratio() != 100 {
		t.Fatalf("report = %+v", rep)
	}
	if s := rep.String(); !strings.Contains(s, "2/2 settled requests classified impersonator (100.0%)") ||
		!strings.Contains(s, "1 pending warm-up(s) excluded (D-22)") {
		t.Errorf("String() = %q", s)
	}
}

func TestCheckImpersonatorsFailures(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		opts  ImpersonatorOptions
		want  string
	}{
		{"misclassified", []string{decision(imp+"x/1", "b1", "automation_likely", "failed", "block", true)},
			ImpersonatorOptions{}, `classified "automation_likely", want impersonator`},
		{"not blocked", []string{decision(imp+"x/1", "b1", "impersonator", "failed", "challenge", true)},
			ImpersonatorOptions{}, "want an enforced block"},
		{"verified fake", []string{decision(imp+"x/1", "b1", "verified_crawler", "verified", "allow", true)},
			ImpersonatorOptions{}, "a fake crawler was verified"},
		{"warm-up verified class", []string{decision(imp+"x/warmup", "b1", "verified_crawler", "pending", "allow", true)},
			ImpersonatorOptions{}, "a fake crawler was verified"},
		{"warm-up class", []string{decision(imp+"x/warmup", "b1", "human_likely", "pending", "allow", true),
			decision(imp+"x/1", "b2", "impersonator", "failed", "block", true)},
			ImpersonatorOptions{}, "want declared_agent (D-22)"},
		{"no claim", []string{decision(imp+"x/1", "b1", "human_likely", "", "allow", false)},
			ImpersonatorOptions{}, "saw no crawler claim"},
		{"access without decision", []string{decision(imp+"x/1", "b1", "impersonator", "failed", "block", true),
			access(imp+"x/2", "b2", 200, "allow")},
			ImpersonatorOptions{}, "no decision event for this impersonator request"},
		{"nothing settled", []string{decision(imp+"x/warmup", "b1", "declared_agent", "pending", "allow", true)},
			ImpersonatorOptions{}, "no settled impersonator request"},
		{"count", []string{decision(imp+"x/1", "b1", "impersonator", "failed", "block", true)},
			ImpersonatorOptions{WantSettled: 2}, "1 settled impersonator requests, want 2"},
		{"genuine not verified", []string{decision(imp+"x/1", "b1", "impersonator", "failed", "block", true),
			decision(crw+"g/1", "c1", "impersonator", "failed", "block", true)},
			ImpersonatorOptions{Crawlers: crw}, "genuine crawler not verified"},
		{"verified count", []string{decision(imp+"x/1", "b1", "impersonator", "failed", "block", true)},
			ImpersonatorOptions{Crawlers: crw, WantVerified: 1}, "0 verified genuine crawler requests, want 1"},
		{"other site only", goodImpersonatorRun(), ImpersonatorOptions{Site: "blog"}, "no settled impersonator request"},
		{"no prefix", goodImpersonatorRun(), ImpersonatorOptions{Impersonators: "-"}, "no impersonator path prefix"},
	}
	for _, tc := range cases {
		o := tc.opts
		switch o.Impersonators {
		case "":
			o.Impersonators = imp
		case "-":
			o.Impersonators = ""
		}
		rep := CheckImpersonators(read(t, tc.lines...), o)
		if rep.OK() || !strings.Contains(strings.Join(rep.Problems, "\n"), tc.want) {
			t.Errorf("%s: problems = %q, want %q", tc.name, rep.Problems, tc.want)
		}
	}
}

func goodClearanceRun() []string {
	return []string{
		decision("/lab/members/r1/home", "m1", "human_likely", "", "challenge", false),
		access("/lab/members/r1/home", "m1", 403, "challenge"),
		access("/__mg/c", "s1", 403, ""), feedback("fail"),
		access("/__mg/c", "s2", 403, ""), feedback("fail"),
		// The foreign-Worker answer has no decision.
		access("/lab/members/r1/home", "w1", 403, ""),
		access("/public", "p1", 200, "allow"),
	}
}

func TestCheckClearance(t *testing.T) {
	o := ClearanceOptions{Site: "lab", Protected: "/lab/members/r1/", WantFeedback: 2}
	rep := CheckClearance(read(t, goodClearanceRun()...), o)
	if !rep.OK() || rep.Feedback != 2 || rep.Passed != 0 || rep.Submissions != 2 || rep.Protected != 2 {
		t.Fatalf("report = %+v", rep)
	}
	if !strings.Contains(rep.String(), "2 challenge submission(s) (0 succeeded), 2 feedback event(s), 0 passed; 2 request(s) to the protected route, 0 forwarded") {
		t.Errorf("String() = %q", rep.String())
	}

	blockedDry := strings.Replace(decision("/lab/members/r1/x", "m9", "human_likely", "", "block", false), `"dry_run":false`, `"dry_run":true`, 1)
	cases := []struct {
		name  string
		extra []string
		opts  ClearanceOptions
		want  string
	}{
		{"passed", []string{feedback("pass")}, o, "challenge submission passed"},
		{"odd outcome", []string{feedback("maybe")}, o, `unexpected feedback outcome "maybe"`},
		{"303", []string{access("/__mg/c", "s9", 303, "")}, o, "challenge submission answered 303"},
		{"forwarded", []string{access("/lab/members/r1/x", "m9", 200, "allow")}, o, "protected request answered 200 (allow)"},
		{"decided allow", []string{decision("/lab/members/r1/x", "m9", "human_likely", "", "allow", false)}, o, `protected request decided "allow"`},
		{"dry run", []string{blockedDry}, o, "in dry run"},
		{"feedback count", nil, ClearanceOptions{Site: "lab", Protected: "/lab/members/r1/", WantFeedback: 3}, "2 feedback events, want 3"},
		{"no protected request", nil, ClearanceOptions{Site: "lab", Protected: "/nothing/"}, "no request to the protected route"},
		{"no prefix", nil, ClearanceOptions{Site: "lab"}, "no protected path prefix"},
	}
	for _, tc := range cases {
		rep := CheckClearance(read(t, append(goodClearanceRun(), tc.extra...)...), tc.opts)
		if rep.OK() || !strings.Contains(strings.Join(rep.Problems, "\n"), tc.want) {
			t.Errorf("%s: problems = %q, want %q", tc.name, rep.Problems, tc.want)
		}
		if tc.name == "forwarded" && rep.Forwarded != 1 || tc.name == "303" && rep.Succeeded != 1 {
			t.Errorf("%s: report = %+v", tc.name, rep)
		}
	}
	o.WantFeedback = 0
	if rep := CheckClearance(read(t, access("/lab/members/r1/x", "m1", 403, "challenge")), o); rep.OK() ||
		!strings.Contains(strings.Join(rep.Problems, "\n"), "no feedback event") {
		t.Errorf("no submissions: %q", rep.Problems)
	}
}

// testdata/phase1-run.jsonl is the event file of a passing
// scripts/lab-e2e.sh run (run id replaced by "sample", "signals" and "hits"
// dropped): it pins the Edge's event fields the checks read.
func TestRecordedRun(t *testing.T) {
	f, err := os.Open("testdata/phase1-run.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	recs, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}
	imp := CheckImpersonators(recs, ImpersonatorOptions{Site: "lab", Impersonators: "/lab/impersonator/sample/",
		Crawlers: "/lab/crawler/sample/", WantSettled: 13, WantVerified: 6})
	if !imp.OK() || imp.Pending != 5 || imp.CrawlerPending != 2 || imp.Access != 18 {
		t.Errorf("impersonator check on the recorded run: %+v", imp)
	}
	clr := CheckClearance(recs, ClearanceOptions{Site: "lab", Protected: "/lab/members/sample/", WantFeedback: 3})
	if !clr.OK() || clr.Submissions != 4 || clr.Protected != 5 {
		t.Errorf("clearance check on the recorded run: %+v", clr)
	}
}

// xorshift is the deterministic generator of the random-input tests
// (docs/impl/phase1-spec.md §2.4 item 3).
type xorshift uint64

func (x *xorshift) next() uint64 {
	v := uint64(*x)
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	*x = xorshift(v)
	return v
}

// Read and the checks return errors or problems, never panic, on mutated
// event lines (wrong types, nulls, truncation, noise).
func TestRandomEventsDoNotPanic(t *testing.T) {
	data, err := os.ReadFile("testdata/phase1-run.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	tokens := []string{"null", "{}", "[]", `"x"`, "1", "-1", "true", `"ctx":null`, `"risk":7`, `"decision":null`, `"crawler":null`, `"/lab/`, "}", "{", ",", `"`, "\n"}
	x := xorshift(0x2545f4914f6cdd1d)
	readable := 0
	for i := 0; i < 10000; i++ {
		var in string
		switch x.next() % 4 {
		case 0: // noise
			b := make([]byte, x.next()%256)
			for j := range b {
				b[j] = byte(x.next())
			}
			in = string(b)
		case 1: // truncated line
			l := lines[x.next()%uint64(len(lines))]
			in = l[:x.next()%uint64(len(l))]
		default: // splices
			l := lines[x.next()%uint64(len(lines))]
			for n := x.next()%3 + 1; n > 0; n-- {
				j := int(x.next() % uint64(len(l)+1))
				l = l[:j] + tokens[x.next()%uint64(len(tokens))] + l[j:]
			}
			in = l
		}
		recs, err := Read(strings.NewReader(in))
		if err != nil {
			continue
		}
		readable++
		_ = CheckImpersonators(recs, ImpersonatorOptions{Impersonators: "/lab/", Crawlers: "/lab/crawler/"})
		_ = CheckClearance(recs, ClearanceOptions{Protected: "/lab/"})
	}
	if readable < 100 {
		t.Errorf("only %d of 10000 inputs were readable: the checks are untested", readable)
	}
}
