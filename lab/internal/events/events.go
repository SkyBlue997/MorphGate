// Package events checks the Edge's JSONL event file (edge.toml
// [events] file, docs/impl/phase1-spec.md §13) after a Validation Lab run.
//
// It only reads a local file: it sends no traffic. The checks implement the
// Phase 1 acceptance items of spec §18 for WP-L1:
//
//   - Impersonators: every request from a fake crawler whose verification
//     has settled is classified risk.bot_class == "impersonator" (100 %,
//     counted as D-22 prescribes: an rDNS-mode operator's warm-up request is
//     still pending, must be DECLARED_AGENT and never VERIFIED_CRAWLER, and
//     is left out of the ratio).
//   - Clearance: a client that does not run JavaScript never obtains a
//     clearance: no feedback event with outcome "pass", no successful
//     /__mg/c answer, and no request on a protected route forwarded.
//
// Which requests are impersonators (the ground truth) comes from the
// scenario: its requests use distinct path prefixes, passed to the checks.
package events

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxLineBytes bounds one event line.
const MaxLineBytes = 1 << 20

// Record is the subset of an event line the checks read. Field names follow
// spec §13.2-§13.4.
type Record struct {
	Line int    `json:"-"`
	Kind string `json:"kind"`
	Site string `json:"site"`

	// kind=decision
	Ctx      *DecisionCtx  `json:"ctx"`
	Risk     *Risk         `json:"risk"`
	Decision *DecisionPart `json:"decision"`

	// kind=access
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Action    string `json:"action"`
	Route     string `json:"route"`
	RequestID string `json:"request_id"`

	// kind=feedback
	Outcome     string   `json:"outcome"`
	Type        string   `json:"type"`
	ReasonCodes []string `json:"reason_codes"`
}

// DecisionCtx is the part of RequestContext the checks read.
type DecisionCtx struct {
	RequestID string `json:"request_id"`
	RouteID   string `json:"route_id"`
	HTTP      struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	} `json:"http"`
	Identity struct {
		Crawler Crawler `json:"crawler"`
	} `json:"identity"`
}

// Crawler is ctx.identity.crawler.
type Crawler struct {
	Claimed       bool   `json:"claimed"`
	Operator      string `json:"operator"`
	Verified      bool   `json:"verified"`
	Verification  string `json:"verification"` // verified | failed | pending | unverifiable
	Method        string `json:"method"`
	OutsideRanges bool   `json:"outside_ranges"`
}

// Risk is the decision event's risk assessment.
type Risk struct {
	BotClass string  `json:"bot_class"`
	Score    float64 `json:"score"`
}

// DecisionPart is the decision event's decision.
type DecisionPart struct {
	Action string `json:"action"`
	DryRun bool   `json:"dry_run"`
	RuleID string `json:"rule_id"`
}

// Read parses a JSONL event file. Empty lines are skipped; any other line
// that is not a JSON object is an error naming its line number.
func Read(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLineBytes)
	var out []Record
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("line %d: %v", n, err)
		}
		if rec.Kind == "" {
			return nil, fmt.Errorf("line %d: no kind", n)
		}
		rec.Line = n
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("an event line is longer than %d bytes", MaxLineBytes)
		}
		return nil, err
	}
	return out, nil
}

func (r *Record) decisionPath() string {
	if r.Ctx == nil {
		return ""
	}
	return r.Ctx.HTTP.Path
}

func (r *Record) botClass() string {
	if r.Risk == nil {
		return ""
	}
	return r.Risk.BotClass
}

func (r *Record) action() (string, bool) {
	if r.Decision == nil {
		return "", false
	}
	return r.Decision.Action, r.Decision.DryRun
}

func (r *Record) requestID() string {
	if r.Kind == "decision" && r.Ctx != nil {
		return r.Ctx.RequestID
	}
	return r.RequestID
}

func (r *Record) describe() string {
	path := r.Path
	if r.Kind == "decision" {
		path = r.decisionPath()
	}
	return fmt.Sprintf("line %d (%s %s, request %s)", r.Line, r.Kind, path, r.requestID())
}

// ImpersonatorOptions selects the requests of the impersonator scenario.
type ImpersonatorOptions struct {
	Site string
	// Impersonators is the path prefix of every request from a fake crawler.
	Impersonators string
	// Crawlers is the path prefix of the genuine crawlers' requests
	// (optional).
	Crawlers string
	// WantSettled is the exact number of settled impersonator requests
	// expected (0: at least one).
	WantSettled int
	// WantVerified is the exact number of verified genuine crawler requests
	// expected (0: no count check).
	WantVerified int
}

// ImpersonatorReport is the outcome of CheckImpersonators.
type ImpersonatorReport struct {
	// Settled impersonator requests (verification failed, D-22) and how
	// many of them were classified impersonator.
	Settled, Classified int
	// Pending impersonator warm-up requests (excluded from the ratio).
	Pending int
	// Access records under the impersonator prefix.
	Access int
	// Genuine crawler requests: verified, and pending warm-ups.
	Verified, CrawlerPending int
	Problems                 []string
}

// OK reports whether the check passed.
func (r ImpersonatorReport) OK() bool { return len(r.Problems) == 0 }

// Ratio is Classified / Settled in percent (0 when nothing settled).
func (r ImpersonatorReport) Ratio() float64 {
	if r.Settled == 0 {
		return 0
	}
	return 100 * float64(r.Classified) / float64(r.Settled)
}

func (r ImpersonatorReport) String() string {
	return fmt.Sprintf("impersonators: %d/%d settled requests classified impersonator (%.1f%%), %d pending warm-up(s) excluded (D-22); genuine crawlers: %d verified, %d pending warm-up(s)",
		r.Classified, r.Settled, r.Ratio(), r.Pending, r.Verified, r.CrawlerPending)
}

// CheckImpersonators applies the D-22 accounting to the decision events of
// the impersonator scenario.
//
// Per impersonator request (decision events whose path starts with
// o.Impersonators): the Edge must have seen the crawler claim; a request
// whose verification is still "pending" is a warm-up and must be
// declared_agent; every other request is settled and must be classified
// impersonator and blocked. Never may a fake crawler be verified. Every
// access record under the prefix must have its decision event (so no request
// escapes the ratio, e.g. by sampling). Genuine crawlers (o.Crawlers) must
// end up verified_crawler and allowed.
func CheckImpersonators(recs []Record, o ImpersonatorOptions) ImpersonatorReport {
	var rep ImpersonatorReport
	problem := func(format string, args ...any) { rep.Problems = append(rep.Problems, fmt.Sprintf(format, args...)) }
	if o.Impersonators == "" {
		problem("no impersonator path prefix given")
		return rep
	}
	decided := map[string]bool{}
	for i := range recs {
		r := &recs[i]
		if r.Kind != "decision" || (o.Site != "" && r.Site != o.Site) {
			continue
		}
		path := r.decisionPath()
		switch {
		case strings.HasPrefix(path, o.Impersonators):
			decided[r.requestID()] = true
			checkImpersonator(r, &rep, problem)
		case o.Crawlers != "" && strings.HasPrefix(path, o.Crawlers):
			checkCrawler(r, &rep, problem)
		}
	}
	for i := range recs {
		r := &recs[i]
		if r.Kind != "access" || (o.Site != "" && r.Site != o.Site) || !strings.HasPrefix(r.Path, o.Impersonators) {
			continue
		}
		rep.Access++
		if !decided[r.RequestID] {
			problem("%s: no decision event for this impersonator request", r.describe())
		}
	}
	switch {
	case o.WantSettled > 0 && rep.Settled != o.WantSettled:
		problem("%d settled impersonator requests, want %d", rep.Settled, o.WantSettled)
	case rep.Settled == 0:
		problem("no settled impersonator request under %q", o.Impersonators)
	}
	if o.WantVerified > 0 && rep.Verified != o.WantVerified {
		problem("%d verified genuine crawler requests, want %d", rep.Verified, o.WantVerified)
	}
	return rep
}

func checkImpersonator(r *Record, rep *ImpersonatorReport, problem func(string, ...any)) {
	c := r.Ctx.Identity.Crawler
	class := r.botClass()
	action, dry := r.action()
	switch {
	case !c.Claimed:
		problem("%s: the Edge saw no crawler claim (class %q)", r.describe(), class)
	case c.Verified || c.Verification == "verified" || class == "verified_crawler":
		problem("%s: a fake crawler was verified (%s, class %q)", r.describe(), c.Operator, class)
	case c.Verification == "pending":
		rep.Pending++
		if class != "declared_agent" {
			problem("%s: pending warm-up classified %q, want declared_agent (D-22)", r.describe(), class)
		}
	default:
		rep.Settled++
		if class == "impersonator" {
			rep.Classified++
		} else {
			problem("%s: settled (%s) impersonator classified %q, want impersonator", r.describe(), c.Verification, class)
		}
		if action != "block" || dry {
			problem("%s: impersonator answered %q (dry_run %v), want an enforced block", r.describe(), action, dry)
		}
	}
}

func checkCrawler(r *Record, rep *ImpersonatorReport, problem func(string, ...any)) {
	c := r.Ctx.Identity.Crawler
	class := r.botClass()
	action, _ := r.action()
	switch {
	case c.Verification == "pending":
		rep.CrawlerPending++
		if class != "declared_agent" {
			problem("%s: pending genuine crawler classified %q, want declared_agent (D-22)", r.describe(), class)
		}
	case c.Verified && class == "verified_crawler":
		rep.Verified++
		if action != "allow" {
			problem("%s: verified crawler answered %q, want allow", r.describe(), action)
		}
	default:
		problem("%s: genuine crawler not verified (%q, class %q)", r.describe(), c.Verification, class)
	}
}

// ClearanceOptions selects the requests of the non-JS clearance scenario.
type ClearanceOptions struct {
	Site string
	// Protected is the path prefix of the require_clearance route the
	// scenario requests.
	Protected string
	// WantFeedback is the exact number of challenge submissions (feedback
	// events) expected (0: at least one).
	WantFeedback int
}

// ClearanceReport is the outcome of CheckClearance.
type ClearanceReport struct {
	// Feedback events and how many of them passed.
	Feedback, Passed int
	// Access records of POST /__mg/c and of the protected route.
	Submissions, Protected int
	// Protected requests the Edge let through (allow / log / tag, or a
	// status below 400) and submissions answered with a success status.
	Forwarded, Succeeded int
	Problems             []string
}

// OK reports whether the check passed.
func (r ClearanceReport) OK() bool { return len(r.Problems) == 0 }

func (r ClearanceReport) String() string {
	return fmt.Sprintf("clearance: %d challenge submission(s) (%d succeeded), %d feedback event(s), %d passed; %d request(s) to the protected route, %d forwarded",
		r.Submissions, r.Succeeded, r.Feedback, r.Passed, r.Protected, r.Forwarded)
}

// submitPath is the challenge submission endpoint (spec §10.3).
const submitPath = "/__mg/c"

// CheckClearance checks that no clearance was issued: every feedback event
// failed, no POST /__mg/c got a success answer (303 or 200), and no request
// to the protected route was forwarded to the origin (decision allow, log or
// tag, or an access status below 400).
func CheckClearance(recs []Record, o ClearanceOptions) ClearanceReport {
	var rep ClearanceReport
	problem := func(format string, args ...any) { rep.Problems = append(rep.Problems, fmt.Sprintf(format, args...)) }
	if o.Protected == "" {
		problem("no protected path prefix given")
		return rep
	}
	for i := range recs {
		r := &recs[i]
		if o.Site != "" && r.Site != o.Site {
			continue
		}
		switch r.Kind {
		case "feedback":
			rep.Feedback++
			if r.Outcome == "pass" {
				rep.Passed++
				problem("%s: challenge submission passed (%s)", r.describe(), r.Type)
			} else if r.Outcome != "fail" {
				problem("%s: unexpected feedback outcome %q", r.describe(), r.Outcome)
			}
		case "access":
			switch {
			case r.Path == submitPath:
				rep.Submissions++
				if r.Status < 400 {
					rep.Succeeded++
					problem("%s: challenge submission answered %d", r.describe(), r.Status)
				}
			case strings.HasPrefix(r.Path, o.Protected):
				rep.Protected++
				if r.Status < 400 || r.Action == "allow" || r.Action == "log" || r.Action == "tag" {
					rep.Forwarded++
					problem("%s: protected request answered %d (%s)", r.describe(), r.Status, r.Action)
				}
			}
		case "decision":
			if !strings.HasPrefix(r.decisionPath(), o.Protected) {
				continue
			}
			switch action, dry := r.action(); {
			case dry:
				problem("%s: protected request decided %q in dry run (monitor), want enforce", r.describe(), action)
			case action == "allow" || action == "log" || action == "tag":
				problem("%s: protected request decided %q", r.describe(), action)
			}
		}
	}
	switch {
	case o.WantFeedback > 0 && rep.Feedback != o.WantFeedback:
		problem("%d feedback events, want %d (one per challenge submission)", rep.Feedback, o.WantFeedback)
	case rep.Feedback == 0:
		problem("no feedback event: no challenge submission reached the Edge")
	}
	if rep.Protected == 0 {
		problem("no request to the protected route %q", o.Protected)
	}
	return rep
}
