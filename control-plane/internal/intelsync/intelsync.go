// Package intelsync fetches and validates the intelligence artifacts that
// mgctl publishes with the site bundles: the Cloudflare IP ranges
// (`mgctl cf ips sync`) and the crawler registry with the operators' official
// IP ranges (`mgctl crawler sync`). Artifact formats: docs/impl/phase1-spec.md §12.
//
// Implemented by Phase 1 work package WP-G3; until then both entry points
// report "not implemented".
package intelsync

import "morphgate/control-plane/internal/cli"

// RunCFIPs implements `mgctl cf ips <args>` (args start with "sync").
func RunCFIPs(args []string, env cli.Env) int {
	return cli.NotImplemented(env, "cf ips", "WP-G3")
}

// RunCrawler implements `mgctl crawler <args>` (args start with "sync").
func RunCrawler(args []string, env cli.Env) int {
	return cli.NotImplemented(env, "crawler", "WP-G3")
}
