// Package mgctl implements the mgctl command line. It is a library so the
// whole CLI can be exercised from tests; cmd/mgctl only calls Run.
package mgctl

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"morphgate/control-plane/internal/cfaudit"
	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/intelsync"
	"morphgate/control-plane/internal/policy"
	"morphgate/control-plane/internal/version"
)

// Exit codes.
const (
	ExitOK       = 0
	ExitInvalid  = 1 // policy errors
	ExitUsage    = 2 // usage errors and not-yet-implemented commands
	exitInternal = 3
)

const usage = `mgctl - MorphGate operations CLI

Usage:
  mgctl version
  mgctl policy check   [flags] <file.yaml|dir>...
  mgctl policy compile [flags] [-o out.json] <file.yaml|dir>...
  mgctl site check --site-config <site.yaml>
  mgctl bundle build --site-config <site.yaml> --out-dir <dir> [--version N]
  mgctl bundle sign --in <site.sitebundle.pb> --key <kid>.key.age --out <file.bundle>
  mgctl bundle verify --in <file.bundle> --pub <kid>.pub... [--site <id>] [--json]
  mgctl bundle publish --in <file.bundle> --artifacts <dir> --dest <dir> --pub <kid>.pub... --confirm <site> [--metrics-textfile <path>]
  mgctl keys gen --kid <kid> --out-dir <dir> [--insecure-test-key]
  mgctl keys gen-pseudo --out <file.json.age> [--insecure-test-key]
  mgctl keys gen-upstream --out <file.json.age> [--rotate] [--insecure-test-key]
  mgctl keys export --in <file.json.age> [--out <file> | -]
  mgctl site keys gen --site <id> --out-dir <dir> [--date YYYYMMDD] [--insecure-test-key]
  mgctl site keys rotate-token --site <id> --file <token.keys.json.age> [--date YYYYMMDD]
  mgctl site keys rotate-seal --site <id> --file <seal.root.json.age> --step add|promote|retire [--date YYYYMMDD]
  mgctl verdict key --pseudo-key <file.json.age> --site <id|all> --type ip|prefix|asn|session --value <v>
  mgctl audit verify
  mgctl cf audit [flags]
  mgctl cf ips sync [flags]
  mgctl crawler sync [flags]

policy flags:
  -profile cloudflare|direct_tls   UpstreamProfile for files without a top-level profile: key
  -max-cost N                      worst-case CEL cost budget per rule (default %d)

A policy file may declare its site's UpstreamProfile with a top-level profile: key;
rules that read fields that profile never supplies, without a has() guard, get a
warning. Directories are expanded to their *.yaml and *.yml files. Flags go before files.

Global flag: --audit-log <path> (default $MGCTL_AUDIT_LOG, else
$XDG_STATE_HOME/morphgate/audit.jsonl or ~/.local/state/morphgate/audit.jsonl):
the hash-chained log every write command appends to.
Passphrases for age key files come from the first line of $MGCTL_PASSPHRASE_FILE
or the terminal; MGCTL_AGE_WORK_FACTOR (10-22, default 18; below 18 only with
--insecure-test-key) sets the scrypt work factor of new files.
Exit status: 0 ok, 1 invalid input or failed check, 2 usage error or command not
implemented yet, 3 I/O or internal error (including a failed audit append).
`

// Run executes mgctl with args (without the program name) and returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunEnv(args, newEnv(stdout, stderr))
}

// RunEnv executes mgctl in env. When env.Audit is nil it is wired to the
// local audit log (--audit-log, else MGCTL_AUDIT_LOG, XDG_STATE_HOME, HOME)
// and env.AuditReady to opening it: every write command, including the
// intelligence syncs of internal/intelsync, opens the log before it writes
// anything, so an unusable log fails the command with exit code 3 and no
// file changed (ruling I-27).
func RunEnv(args []string, env cli.Env) int {
	args, auditPath, err := extractAuditLog(args)
	if err != nil {
		fmt.Fprintf(env.Stderr, "mgctl: %v\n", err)
		return ExitUsage
	}
	r := &runner{env: env, auditPath: auditPath}
	if r.env.Now == nil {
		r.env.Now = time.Now
	}
	if r.env.Getenv == nil {
		r.env.Getenv = func(string) string { return "" }
	}
	if r.env.Audit == nil {
		a := &auditor{override: auditPath, getenv: r.env.Getenv, now: r.env.Now}
		r.env.Audit, r.env.AuditReady = a.append, a.open
	}
	stdout, stderr := r.env.Stdout, r.env.Stderr
	if len(args) == 0 {
		fmt.Fprintf(stderr, usage, policy.DefaultMaxCost)
		return ExitUsage
	}
	switch args[0] {
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, version.String("mgctl"))
		return ExitOK
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, usage, policy.DefaultMaxCost)
		return ExitOK
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "site":
		return r.runSite(args[1:])
	case "bundle":
		return r.runBundle(args[1:])
	case "keys":
		return r.runKeys(args[1:])
	case "verdict":
		return r.verdictKey(args[1:])
	case "audit":
		return r.auditVerify(args[1:])
	case "cf":
		return runCF(args[1:], r.env)
	case "crawler":
		return intelsync.RunCrawler(args[1:], r.env)
	}
	fmt.Fprintf(stderr, "mgctl: unknown command %q\n\n", args[0])
	fmt.Fprintf(stderr, usage, policy.DefaultMaxCost)
	return ExitUsage
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "mgctl policy: expected a subcommand: check | compile")
		return ExitUsage
	}
	sub := args[0]
	if sub != "check" && sub != "compile" {
		fmt.Fprintf(stderr, "mgctl policy: unknown subcommand %q (expected check | compile)\n", sub)
		return ExitUsage
	}
	fs := flag.NewFlagSet("mgctl policy "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "UpstreamProfile for files that do not declare one (cloudflare | direct_tls)")
	maxCost := fs.Uint64("max-cost", policy.DefaultMaxCost, "worst-case CEL cost budget per rule")
	var outPath *string
	if sub == "compile" {
		outPath = fs.String("o", "", "write JSON to this file instead of stdout")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if fs.NArg() == 0 {
		fmt.Fprintf(stderr, "mgctl policy %s: no policy files given\n", sub)
		return ExitUsage
	}
	files, err := expandFiles(fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "mgctl policy %s: %v\n", sub, err)
		return ExitUsage
	}

	compiler, err := policy.NewCompiler(policy.Options{MaxCost: *maxCost, Profile: *profile})
	if err != nil {
		fmt.Fprintf(stderr, "mgctl policy %s: %v\n", sub, err)
		return ExitUsage
	}
	var rules []*policy.Rule
	var diags policy.Diagnostics
	for _, f := range files {
		rs, ds := policy.ParseFile(f)
		rules = append(rules, rs...)
		diags = append(diags, ds...)
	}
	checked, ds := compiler.Check(rules)
	diags = append(diags, ds...)
	for _, d := range diags {
		fmt.Fprintln(stderr, d.String())
	}

	nerr := len(diags.Errors())
	if nerr > 0 {
		fmt.Fprintf(stderr, "mgctl policy %s: %d error(s), %d warning(s) in %d file(s)\n", sub, nerr, len(diags)-nerr, len(files))
		return ExitInvalid
	}

	if sub == "check" {
		fmt.Fprintf(stdout, "ok: %d rule(s) in %d file(s), %d warning(s)\n", len(checked), len(files), len(diags))
		return ExitOK
	}

	out := make([]policy.CompiledRuleJSON, 0, len(checked))
	for _, cr := range checked {
		out = append(out, cr.JSON())
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep && and < readable in expr_source
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "mgctl policy compile: %v\n", err)
		return exitInternal
	}
	data := buf.Bytes()
	if policy.IRVersion == 0 {
		fmt.Fprintf(stderr, "note: ir_version %d: expr_ir is omitted because CEL-to-IR lowering is implemented in Phase 1\n", policy.IRVersion)
	}
	if *outPath == "" {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "mgctl policy compile: %v\n", err)
			return exitInternal
		}
		return ExitOK
	}
	if err := writeFileAtomic(*outPath, data); err != nil {
		fmt.Fprintf(stderr, "mgctl policy compile: %v\n", err)
		return exitInternal
	}
	fmt.Fprintf(stderr, "wrote %d rule(s) to %s\n", len(out), *outPath)
	return ExitOK
}

// newEnv builds the environment handed to subcommand packages
// (internal/cli). Audit stays nil: RunEnv wires it to the local hash-chained
// audit log (docs/impl/phase1-spec.md §12.8, §14.2).
func newEnv(stdout, stderr io.Writer) cli.Env {
	return cli.Env{
		Stdout: stdout,
		Stderr: stderr,
		Stdin:  os.Stdin,
		Now:    time.Now,
		HTTP:   &http.Client{Timeout: 30 * time.Second},
		Getenv: os.Getenv,
	}
}

// runCF dispatches `mgctl cf <subcommand>` to the packages that own them.
func runCF(args []string, env cli.Env) int {
	if len(args) == 0 {
		fmt.Fprintln(env.Stderr, "mgctl cf: expected a subcommand: audit | ips")
		return ExitUsage
	}
	switch args[0] {
	case "audit":
		return cfaudit.RunCLI(args[1:], env)
	case "ips":
		return intelsync.RunCFIPs(args[1:], env)
	}
	fmt.Fprintf(env.Stderr, "mgctl cf: unknown subcommand %q (expected audit | ips)\n", args[0])
	return ExitUsage
}

// expandFiles replaces directories by their *.yaml / *.yml entries (sorted,
// non-recursive) and keeps plain files as given.
func expandFiles(args []string) ([]string, error) {
	var files []string
	for _, a := range args {
		st, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			files = append(files, a)
			continue
		}
		entries, err := os.ReadDir(a)
		if err != nil {
			return nil, err
		}
		var found []string
		for _, e := range entries {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if !e.IsDir() && (ext == ".yaml" || ext == ".yml") {
				found = append(found, filepath.Join(a, e.Name()))
			}
		}
		if len(found) == 0 {
			return nil, fmt.Errorf("%s: no .yaml or .yml files", a)
		}
		slices.Sort(found)
		files = append(files, found...)
	}
	return files, nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
