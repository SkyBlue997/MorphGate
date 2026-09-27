// Package cfaudit describes the Cloudflare zone audit run by `mgctl cf audit`
// (design brief B2, docs/08-upstream-and-cloudflare.md).
//
// Phase 0 ships only the list of planned checks. Phase 1 implements them
// against the Cloudflare API with a least-privilege, read-only API token. This
// package makes no network calls.
package cfaudit

import (
	"errors"
	"fmt"
	"io"

	"morphgate/control-plane/internal/cli"
)

// ErrNotImplemented is returned by Run until Phase 1.
var ErrNotImplemented = errors.New("not implemented until Phase 1")

// Check is one planned zone setting check.
type Check struct {
	ID     string // stable identifier used in audit output
	Title  string
	Expect string // the setting MorphGate needs
}

// Planned is the Phase 1 check list, in the order it will run.
var Planned = []Check{
	{"bot_fight_mode", "Bot Fight Mode (Free zones)",
		"off: it cannot be skipped per path and would challenge /__mg/* before MorphGate"},
	{"cache_bypass_mg", "Cache Rule for /__mg/",
		"a Bypass cache rule for /__mg/ exists and is the last cache rule (last match wins)"},
	{"sbfm_skip", "Super Bot Fight Mode (Pro and above)",
		"groups set to Allow, or a Skip rule for /__mg/ covering SBFM, BIC and Security Level; it must not skip rate limiting (http_ratelimit) while a /__mg/ flood rate limiting rule exists"},
	{"ai_bot_policy", "AI bot policies",
		"Allow while MorphGate is authoritative, or mirrors the MorphGate crawler policy"},
	{"rocket_loader", "Rocket Loader",
		"off, or the SDK tag carries data-cfasync=\"false\""},
	{"zero_rtt", "0-RTT",
		"off (otherwise Early-Data: 1 state-changing requests must be treated as replayable)"},
	{"pseudo_ipv4", "Pseudo IPv4",
		"off (with Overwrite the Edge must read CF-Connecting-IPv6)"},
	{"remove_visitor_ip_headers", "Managed Transform: Remove visitor IP headers",
		"off: CF-Connecting-IP must reach the Edge"},
	{"transform_rule_signals", "Request Header Transform Rule for x-mg-cf-*",
		"present and complete (all Tier 0 x-mg-cf-* headers), plus \"Add visitor location headers\" on"},
}

// PrintPlan writes the planned checks as a numbered list.
func PrintPlan(w io.Writer) error {
	if _, err := fmt.Fprintln(w, "mgctl cf audit: planned checks (Phase 1):"); err != nil {
		return err
	}
	for i, c := range Planned {
		if _, err := fmt.Fprintf(w, "  %d. [%s] %s\n     expect: %s\n", i+1, c.ID, c.Title, c.Expect); err != nil {
			return err
		}
	}
	return nil
}

// Run will audit a zone. Until Phase 1 it only returns ErrNotImplemented.
func Run() error {
	return ErrNotImplemented
}

// RunCLI implements `mgctl cf audit <args>` (args exclude "cf audit"). Until
// work package WP-G3 replaces it (docs/impl/phase1-spec.md §10.4) it prints the
// planned checks and reports "not implemented".
func RunCLI(args []string, env cli.Env) int {
	if err := PrintPlan(env.Stdout); err != nil {
		return cli.ExitInternal
	}
	if err := Run(); errors.Is(err, ErrNotImplemented) {
		fmt.Fprintf(env.Stderr, "mgctl cf audit: %v\n", err)
		return cli.ExitUsage
	}
	return cli.ExitOK
}
