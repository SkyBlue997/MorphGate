// Package cli is the contract between the mgctl dispatcher (internal/mgctl)
// and the packages that implement mgctl subcommands in their own Phase 1 work
// packages (docs/impl/phase1-spec.md §14.1). It has no logic of its own
// beyond small helpers, so every package can depend on it without depending
// on the dispatcher.
package cli

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// Exit codes shared by every mgctl subcommand.
const (
	ExitOK       = 0 // success
	ExitFailed   = 1 // the command ran and found problems (invalid input, failed checks)
	ExitUsage    = 2 // usage error or command not implemented yet
	ExitInternal = 3 // I/O or internal error (including a failed audit append)
)

// Env is everything a subcommand may use from the outside world. Tests build
// their own Env; the dispatcher builds the real one.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	// Now is the clock; never call time.Now directly in subcommands.
	Now func() time.Time
	// HTTP is the client for outbound requests (Cloudflare API, official IP
	// range URLs). Tests inject a client that talks to httptest servers.
	HTTP *http.Client
	// Getenv reads environment variables (e.g. CLOUDFLARE_API_TOKEN,
	// MGCTL_PASSPHRASE_FILE); tests inject a map.
	Getenv func(string) string
	// Audit appends one record to the local hash-chained audit log
	// (docs/06 §6). Every command that writes keys, bundles or artifacts
	// calls it once after the write succeeded; a non-nil error must make the
	// command exit with ExitInternal.
	Audit AuditFunc
	// AuditReady confirms that the audit log behind Audit is usable (the
	// dispatcher opens it). Every write command calls it before it writes
	// any file; a non-nil error must make the command exit with ExitInternal
	// without writing anything (ruling I-27). nil means nothing to check
	// (tests that supply their own Audit).
	AuditReady func() error
}

// AuditEvent is what a subcommand reports to the audit log; the log adds id,
// timestamp, actor and the hash chain fields.
type AuditEvent struct {
	Action       string    // dotted verb, e.g. "bundle.sign", "cf.ips.sync"
	ResourceType string    // e.g. "bundle", "artifact", "owner_key", "site_key"
	ResourceID   string    // e.g. "blog@1790000000", "cloudflare-ips", "owner-2026"
	Site         string    // site id, or "" for owner-level resources
	Diff         any       // JSON-serialisable summary of the change; nil if none. Never key material.
	Reason       string    // optional free text (--reason)
	ConfirmText  string    // typed confirmation, if the command required one
	EffectiveAt  time.Time // zero means "now"
}

// AuditFunc appends one audit record.
type AuditFunc func(AuditEvent) error

// Handler runs one mgctl command group; args exclude the group name(s).
type Handler func(args []string, env Env) int

// NotImplemented reports a command whose work package has not landed yet.
func NotImplemented(env Env, command, workPackage string) int {
	fmt.Fprintf(env.Stderr, "mgctl %s: not implemented yet (Phase 1 %s, docs/impl/phase1-spec.md)\n", command, workPackage)
	return ExitUsage
}
