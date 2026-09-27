// Package intelsync fetches and validates the intelligence artifacts that
// mgctl publishes with the site bundles: the Cloudflare IP ranges
// (`mgctl cf ips sync`) and the crawler registry with the operators' official
// IP ranges (`mgctl crawler sync`). Artifact formats and commands:
// docs/impl/phase1-spec.md §12.2, §12.3, §14.4, §14.5.
//
// Every download is https only (redirects too), size- and time-limited, and
// validated entry by entry before anything is written; artifacts are written
// atomically as canonical JSON (§12.0). Change protection refuses large
// changes of the ranges unless the owner passes --accept-change: the ranges
// decide which requests the Edge trusts as Cloudflare or as a verified
// crawler, so a compromised or broken upstream list must not silently widen
// them (D-36).
package intelsync

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"morphgate/control-plane/internal/cli"
)

// exitError carries the mgctl exit code for an error (§14.1).
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usageErr(err error) error    { return &exitError{cli.ExitUsage, err} }
func invalidErr(err error) error  { return &exitError{cli.ExitFailed, err} }
func ioErr(err error) error       { return &exitError{cli.ExitInternal, err} }
func internalErr(err error) error { return &exitError{cli.ExitInternal, err} }

// ExitCode maps an error returned by this package to an mgctl exit code.
func ExitCode(err error) int {
	if err == nil {
		return cli.ExitOK
	}
	var e *exitError
	if errors.As(err, &e) {
		return e.code
	}
	return cli.ExitInternal
}

func envNow(env cli.Env) time.Time {
	if env.Now != nil {
		return env.Now()
	}
	return time.Now()
}

func audit(env cli.Env, ev cli.AuditEvent) error {
	if env.Audit == nil {
		return errors.New("no audit log configured")
	}
	return env.Audit(ev)
}

func stderr(env cli.Env) io.Writer {
	if env.Stderr != nil {
		return env.Stderr
	}
	return io.Discard
}

func stdout(env cli.Env) io.Writer {
	if env.Stdout != nil {
		return env.Stdout
	}
	return io.Discard
}

func newFlagSet(name string, env cli.Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr(env))
	return fs
}

// auditLogFlag accepts --audit-log on write commands (§14.1). The mgctl
// dispatcher (internal/mgctl) resolves the audit log and binds env.Audit to
// it; this package only has to accept the flag.
func auditLogFlag(fs *flag.FlagSet) {
	fs.String("audit-log", "", "audit log path (handled by mgctl; default $MGCTL_AUDIT_LOG or the XDG state dir)")
}

// RunCFIPs implements `mgctl cf ips <args>`; args start with "sync".
func RunCFIPs(args []string, env cli.Env) int {
	if len(args) == 0 || args[0] != "sync" {
		fmt.Fprintln(stderr(env), "mgctl cf ips: expected the subcommand: sync")
		return cli.ExitUsage
	}
	env.Stderr, env.Stdout = stderr(env), stdout(env)
	fs := newFlagSet("mgctl cf ips sync", env)
	var o CFIPsOptions
	fs.StringVar(&o.Out, "out", "", "artifact to write (required); <out>.state.json records the last success")
	fs.StringVar(&o.URL, "url", DefaultCloudflareIPURL, "Cloudflare IP ranges API (https only)")
	fs.StringVar(&o.Previous, "previous", "", "artifact to compare with (default: the existing --out file)")
	fs.BoolVar(&o.AcceptChange, "accept-change", false, "accept an IPv4 or IPv6 entry count change of more than 30%")
	fs.StringVar(&o.MetricsTextfile, "metrics-textfile", "", "node_exporter textfile to update with mg_cf_ips_sync_timestamp_seconds")
	auditLogFlag(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "mgctl cf ips sync: unexpected arguments %q\n", fs.Args())
		return cli.ExitUsage
	}
	if o.Out == "" {
		fmt.Fprintln(env.Stderr, "mgctl cf ips sync: --out is required")
		return cli.ExitUsage
	}
	fc := fetchConfig{client: env.HTTP, timeout: defaultFetchTimeout}
	res, err := SyncCloudflareIPs(context.Background(), env, fc, o)
	if err != nil {
		fmt.Fprintf(env.Stderr, "mgctl cf ips sync: %v\n", err)
		return ExitCode(err)
	}
	a := res.Artifact
	if res.Changed {
		fmt.Fprintf(env.Stdout, "cloudflare-ips: wrote %s: %d IPv4, %d IPv6 ranges, etag %s, sha256 %s\n",
			o.Out, len(a.IPv4CIDRs), len(a.IPv6CIDRs), a.ETag, res.SHA256)
	} else {
		fmt.Fprintf(env.Stdout, "cloudflare-ips: unchanged %s (etag %s, sha256 %s)\n", o.Out, a.ETag, res.SHA256)
	}
	return cli.ExitOK
}

// RunCrawler implements `mgctl crawler <args>`; args start with "sync".
func RunCrawler(args []string, env cli.Env) int {
	if len(args) == 0 || args[0] != "sync" {
		fmt.Fprintln(stderr(env), "mgctl crawler: expected the subcommand: sync")
		return cli.ExitUsage
	}
	env.Stderr, env.Stdout = stderr(env), stdout(env)
	fs := newFlagSet("mgctl crawler sync", env)
	var o CrawlerOptions
	fs.StringVar(&o.Registry, "registry", "", "registry source YAML, e.g. deploy/intel/crawler-registry.yaml (required)")
	fs.StringVar(&o.Out, "out", "", "artifact to write (required)")
	fs.StringVar(&o.Previous, "previous", "", "artifact to compare with and fall back on (default: the existing --out file)")
	fs.BoolVar(&o.AcceptChange, "accept-change", false, "accept changes beyond the D-36 change protection")
	auditLogFlag(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "mgctl crawler sync: unexpected arguments %q\n", fs.Args())
		return cli.ExitUsage
	}
	if o.Registry == "" || o.Out == "" {
		fmt.Fprintln(env.Stderr, "mgctl crawler sync: --registry and --out are required")
		return cli.ExitUsage
	}
	fc := fetchConfig{client: env.HTTP, timeout: defaultFetchTimeout}
	res, err := SyncCrawlers(context.Background(), env, fc, o)
	if err != nil {
		fmt.Fprintf(env.Stderr, "mgctl crawler sync: %v\n", err)
		return ExitCode(err)
	}
	for _, op := range res.Registry.Operators {
		stale := ""
		for _, s := range res.Stale {
			if s == op.ID {
				stale = " (stale: previous ranges kept)"
			}
		}
		fmt.Fprintf(env.Stdout, "  %-16s %-14s %5d CIDR(s)%s\n", op.ID, op.Purpose, len(op.CIDRs), stale)
	}
	if res.Changed {
		fmt.Fprintf(env.Stdout, "crawler-registry: wrote %s (sha256 %s)\n", o.Out, res.SHA256)
	} else {
		fmt.Fprintf(env.Stdout, "crawler-registry: unchanged %s (sha256 %s)\n", o.Out, res.SHA256)
	}
	if len(res.Stale) > 0 {
		fmt.Fprintf(env.Stderr, "warning: %d operator(s) kept stale ranges; the sync will retry them next run\n", len(res.Stale))
	}
	return cli.ExitOK
}
