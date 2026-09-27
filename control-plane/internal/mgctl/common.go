package mgctl

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"morphgate/control-plane/internal/audit"
	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/keys"
)

// randReader is the entropy source for key generation (crypto/rand; tests
// may substitute a deterministic stream).
var randReader io.Reader = rand.Reader

// auditor is the audit log behind cli.Env.Audit: the path comes from
// --audit-log, else MGCTL_AUDIT_LOG / XDG_STATE_HOME / HOME (§12.8).
type auditor struct {
	override string
	getenv   func(string) string
	now      func() time.Time
	log      *audit.Log
}

// open resolves the path and opens the log (idempotent). Write commands call
// it before they change anything, so an unusable log fails the command with
// exit code 3 before any key or bundle is written.
func (a *auditor) open() error {
	if a.log != nil {
		return nil
	}
	path := a.override
	if path == "" {
		p, err := audit.DefaultPath(a.getenv)
		if err != nil {
			return err
		}
		path = p
	}
	l, err := audit.Open(path)
	if err != nil {
		return err
	}
	a.log = l
	return nil
}

func (a *auditor) append(ev cli.AuditEvent) error {
	if err := a.open(); err != nil {
		return err
	}
	_, err := a.log.Append(ev, a.now())
	return err
}

// runner carries one mgctl invocation.
type runner struct {
	env   cli.Env
	audit *auditor // nil when the caller supplied env.Audit (tests)
	// auditPath is --audit-log, for `mgctl audit verify`.
	auditPath string
}

// preflightAudit opens the audit log before a write command changes anything.
func (r *runner) preflightAudit(cmd string) bool {
	if r.audit == nil {
		return true
	}
	if err := r.audit.open(); err != nil {
		r.errf(cmd, "audit log: %v", err)
		return false
	}
	return true
}

// record appends the audit record of a successful write; false means the
// command must exit with code 3.
func (r *runner) record(cmd string, ev cli.AuditEvent) bool {
	if err := r.env.Audit(ev); err != nil {
		r.errf(cmd, "the change was made but the audit record could not be written: %v", err)
		return false
	}
	return true
}

func (r *runner) errf(cmd, format string, args ...any) {
	fmt.Fprintf(r.env.Stderr, "mgctl %s: %s\n", cmd, fmt.Sprintf(format, args...))
}

// extractAuditLog removes the global --audit-log flag (any position before
// "--") so that every subcommand, including other work packages', writes to
// the same log without declaring the flag.
func extractAuditLog(args []string) (rest []string, path string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(rest, args[i:]...), path, nil
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "audit-log" {
			rest = append(rest, a)
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				return nil, "", errors.New("flag needs an argument: --audit-log")
			}
			i++
			value = args[i]
		}
		if value == "" {
			return nil, "", errors.New("--audit-log: empty path")
		}
		path = value
	}
	return rest, path, nil
}

// flags creates a FlagSet for "mgctl <cmd>" whose errors go to stderr.
func (r *runner) flags(cmd string) *flag.FlagSet {
	fl := flag.NewFlagSet("mgctl "+cmd, flag.ContinueOnError)
	fl.SetOutput(r.env.Stderr)
	return fl
}

// parse parses flags and rejects positional arguments.
func (r *runner) parse(fl *flag.FlagSet, args []string) bool {
	if err := fl.Parse(args); err != nil {
		return false
	}
	if fl.NArg() > 0 {
		fmt.Fprintf(r.env.Stderr, "%s: unexpected argument %q (all inputs are flags)\n", fl.Name(), fl.Arg(0))
		return false
	}
	return true
}

// required reports missing required flags.
func (r *runner) required(cmd string, pairs ...string) bool {
	ok := true
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] == "" {
			r.errf(cmd, "--%s is required", pairs[i])
			ok = false
		}
	}
	return ok
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// keyDate is --date YYYYMMDD (00:00:00 UTC of that day) or now.
func (r *runner) keyDate(cmd, s string) (time.Time, bool) {
	if s == "" {
		return r.env.Now().UTC(), true
	}
	d, err := time.Parse("20060102", s)
	if err != nil {
		r.errf(cmd, "--date %q is not YYYYMMDD", s)
		return time.Time{}, false
	}
	return d, true
}

// workFactor reads MGCTL_AGE_WORK_FACTOR and prints the insecure-key warning.
func (r *runner) workFactor(cmd string, insecure bool) (int, bool) {
	wf, err := keys.WorkFactor(r.env.Getenv, insecure)
	if err != nil {
		r.errf(cmd, "%v", err)
		return 0, false
	}
	if insecure {
		fmt.Fprintf(r.env.Stderr, "mgctl %s: WARNING: --insecure-test-key: age work factor %d; use such keys for tests only\n", cmd, wf)
	}
	return wf, true
}

// workFactorDiff is the audit diff part that records the work factor (§12.6).
func workFactorDiff(diff map[string]any, wf int, insecure bool) map[string]any {
	diff["work_factor"] = wf
	if insecure {
		diff["insecure_test_key"] = true
	}
	return diff
}

// passphrase reads the passphrase; errors are usage errors (exit 2).
func (r *runner) passphrase(cmd string, confirm bool) ([]byte, bool) {
	p, err := keys.ReadPassphrase(r.env, confirm)
	if err != nil {
		r.errf(cmd, "%v", err)
		return nil, false
	}
	return p, true
}

// mustNotExist refuses to overwrite key files before asking for a passphrase.
func (r *runner) mustNotExist(cmd string, paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			r.errf(cmd, "%s already exists; key files are never overwritten", p)
			return false
		} else if !errors.Is(err, fs.ErrNotExist) {
			r.errf(cmd, "%v", err)
			return false
		}
	}
	return true
}

// exitFor maps a write error to an exit code: an existing file is the
// caller's problem (1), anything else is I/O (3).
func exitFor(err error) int {
	if errors.Is(err, fs.ErrExist) {
		return cli.ExitFailed
	}
	return cli.ExitInternal
}

// sha256Hex is the lower-case hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// isTerminal reports whether w is a terminal.
func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// confirmSite returns --confirm, else asks on a terminal stdin (§14.1).
func (r *runner) confirmSite(cmd, flagValue string) (string, int) {
	if flagValue != "" {
		return flagValue, cli.ExitOK
	}
	if !isTerminal(r.env.Stdin) {
		r.errf(cmd, "--confirm <site> is required when stdin is not a terminal")
		return "", cli.ExitUsage
	}
	fmt.Fprint(r.env.Stderr, "Type the site id to confirm: ")
	line, err := bufio.NewReader(r.env.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		r.errf(cmd, "reading confirmation: %v", err)
		return "", cli.ExitInternal
	}
	return strings.TrimSpace(line), cli.ExitOK
}
