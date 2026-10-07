package mgctl

import (
	"fmt"
	"os"
	"path/filepath"

	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/keys"
)

// runKeys dispatches `mgctl keys <subcommand>` (§14.1).
func (r *runner) runKeys(args []string) int {
	if len(args) == 0 {
		r.errf("keys", "expected a subcommand: gen | gen-pseudo | gen-upstream | export")
		return cli.ExitUsage
	}
	switch args[0] {
	case "gen":
		return r.keysGen(args[1:])
	case "gen-pseudo":
		return r.keysGenPseudo(args[1:])
	case "gen-upstream":
		return r.keysGenUpstream(args[1:])
	case "export":
		return r.keysExport(args[1:])
	}
	r.errf("keys", "unknown subcommand %q (expected gen | gen-pseudo | gen-upstream | export)", args[0])
	return cli.ExitUsage
}

// keysGen: mgctl keys gen --kid <kid> --out-dir <dir> [--insecure-test-key]
func (r *runner) keysGen(args []string) int {
	const cmd = "keys gen"
	fl := r.flags(cmd)
	kid := fl.String("kid", "", "owner key id, e.g. owner-2026")
	outDir := fl.String("out-dir", "", "directory for <kid>.key.age and <kid>.pub")
	insecure := fl.Bool("insecure-test-key", false, "allow MGCTL_AGE_WORK_FACTOR below 18 (tests only)")
	if !r.parse(fl, args) || !r.required(cmd, "kid", *kid, "out-dir", *outDir) {
		return cli.ExitUsage
	}
	if !keys.KIDPattern.MatchString(*kid) {
		r.errf(cmd, "--kid %q does not match %s", *kid, keys.KIDPattern)
		return cli.ExitUsage
	}
	wf, ok := r.workFactor(cmd, *insecure)
	if !ok {
		return cli.ExitUsage
	}
	if !r.mustNotExist(cmd, filepath.Join(*outDir, *kid+".key.age"), filepath.Join(*outDir, *kid+".pub")) {
		return cli.ExitFailed
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	pass, ok := r.passphrase(cmd, true)
	if !ok {
		return cli.ExitUsage
	}
	k, err := keys.GenerateOwnerKey(*kid, r.env.Now(), randReader)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	keyPath, pubPath, err := keys.WriteOwnerKey(*outDir, k, pass, wf)
	if err != nil {
		r.errf(cmd, "%v", err)
		return exitFor(err)
	}
	if !r.record(cmd, cli.AuditEvent{
		Action: "keys.gen", ResourceType: "owner_key", ResourceID: *kid,
		Diff: workFactorDiff(map[string]any{"kid": *kid, "public_key_sha256": sha256Hex(k.Public().Public)}, wf, *insecure),
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stdout, "wrote %s (age-encrypted, 0600) and %s\nadd %s to [trust] owner_keys on every Edge\n", keyPath, pubPath, pubPath)
	return cli.ExitOK
}

// keysGenPseudo: mgctl keys gen-pseudo --out <file.json.age> [--insecure-test-key]
func (r *runner) keysGenPseudo(args []string) int {
	const cmd = "keys gen-pseudo"
	fl := r.flags(cmd)
	out := fl.String("out", "", "output file, e.g. pseudo.key.json.age")
	insecure := fl.Bool("insecure-test-key", false, "allow MGCTL_AGE_WORK_FACTOR below 18 (tests only)")
	if !r.parse(fl, args) || !r.required(cmd, "out", *out) {
		return cli.ExitUsage
	}
	wf, ok := r.workFactor(cmd, *insecure)
	if !ok {
		return cli.ExitUsage
	}
	if !r.mustNotExist(cmd, *out) {
		return cli.ExitFailed
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	pass, ok := r.passphrase(cmd, true)
	if !ok {
		return cli.ExitUsage
	}
	plain, err := keys.GeneratePseudoKey(r.env.Now(), randReader)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	info, _ := keys.Inspect(plain)
	if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	if err := keys.EncryptFile(*out, plain, pass, wf); err != nil {
		r.errf(cmd, "%v", err)
		return exitFor(err)
	}
	if !r.record(cmd, cli.AuditEvent{
		Action: "keys.gen_pseudo", ResourceType: "pseudo_key", ResourceID: info.IDs[0],
		Diff: workFactorDiff(map[string]any{"id": info.IDs[0], "file": filepath.Base(*out)}, wf, *insecure),
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stdout, "wrote %s (pseudonymisation key %s)\n", *out, info.IDs[0])
	return cli.ExitOK
}

// keysGenUpstream: mgctl keys gen-upstream --out <file.json.age> [--rotate] [--insecure-test-key]
// Prints values[0], the static value of the Cloudflare rule that sets x-mg-upstream-key.
func (r *runner) keysGenUpstream(args []string) int {
	const cmd = "keys gen-upstream"
	fl := r.flags(cmd)
	out := fl.String("out", "", "upstream key file, e.g. upstream-keys.json.age")
	rotate := fl.Bool("rotate", false, "rotate the existing file: new value first, keep the previous one")
	insecure := fl.Bool("insecure-test-key", false, "allow MGCTL_AGE_WORK_FACTOR below 18 (tests only)")
	if !r.parse(fl, args) || !r.required(cmd, "out", *out) {
		return cli.ExitUsage
	}
	wf, ok := r.workFactor(cmd, *insecure)
	if !ok {
		return cli.ExitUsage
	}
	if !*rotate && !r.mustNotExist(cmd, *out) {
		return cli.ExitFailed
	}
	if *rotate {
		if _, err := os.Stat(*out); err != nil {
			r.errf(cmd, "--rotate: %v", err)
			return cli.ExitFailed
		}
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	pass, ok := r.passphrase(cmd, !*rotate)
	if !ok {
		return cli.ExitUsage
	}
	var previous []byte
	if *rotate {
		var err error
		if previous, err = keys.DecryptFile(*out, pass); err != nil {
			r.errf(cmd, "%v", err)
			return cli.ExitFailed
		}
	}
	plain, err := keys.GenerateUpstreamKeys(previous, r.env.Now(), randReader)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if *rotate {
		err = keys.ReEncryptFile(*out, plain, pass, wf)
	} else if err = os.MkdirAll(filepath.Dir(*out), 0o700); err == nil {
		err = keys.EncryptFile(*out, plain, pass, wf)
	}
	if err != nil {
		r.errf(cmd, "%v", err)
		return exitFor(err)
	}
	value, _ := keys.UpstreamPrimaryValue(plain)
	values := 1
	if previous != nil {
		values = 2
	}
	if !r.record(cmd, cli.AuditEvent{
		Action: "keys.gen_upstream", ResourceType: "upstream_keys", ResourceID: filepath.Base(*out),
		Diff: workFactorDiff(map[string]any{"rotate": *rotate, "values": values}, wf, *insecure),
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stderr, "wrote %s; the value below goes into the Cloudflare rule that sets x-mg-upstream-key\n", *out)
	fmt.Fprintln(r.env.Stdout, value)
	return cli.ExitOK
}

// keysExport: mgctl keys export --in <file.json.age> [--out <file> | -]
// Writes the plaintext to stdout (for systemd-creds encrypt, §17) or to a new
// 0600 file.
func (r *runner) keysExport(args []string) int {
	const cmd = "keys export"
	fl := r.flags(cmd)
	in := fl.String("in", "", "age-encrypted site, pseudonymisation or upstream key file")
	out := fl.String("out", "-", "plaintext output file (created 0600, never overwritten), or - for stdout")
	if !r.parse(fl, args) || !r.required(cmd, "in", *in, "out", *out) {
		return cli.ExitUsage
	}
	if *out != "-" && !r.mustNotExist(cmd, *out) {
		return cli.ExitFailed
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	pass, ok := r.passphrase(cmd, false)
	if !ok {
		return cli.ExitUsage
	}
	plain, err := keys.DecryptFile(*in, pass)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	info, err := keys.Inspect(plain)
	if err != nil {
		r.errf(cmd, "%s: %v", *in, err)
		return cli.ExitFailed
	}
	target := "file"
	if *out == "-" {
		target = "pipe"
		if isTerminal(r.env.Stdout) {
			target = "terminal"
			fmt.Fprintf(r.env.Stderr, "mgctl %s: WARNING: writing key material to a terminal; pipe it to systemd-creds encrypt instead\n", cmd)
		}
		if _, err := r.env.Stdout.Write(plain); err != nil {
			r.errf(cmd, "%v", err)
			return cli.ExitInternal
		}
	} else if err := keys.WriteNewFile(*out, plain, 0o600); err != nil {
		r.errf(cmd, "%v", err)
		return exitFor(err)
	}
	// §12.8: only the file kind, its key ids and the output target.
	diff := map[string]any{"kind": info.Kind, "target": target}
	if len(info.IDs) > 0 {
		diff["ids"] = info.IDs
	}
	if !r.record(cmd, cli.AuditEvent{
		Action: "keys.export", ResourceType: resourceTypeOf(info.Kind), ResourceID: filepath.Base(*in), Site: info.Site, Diff: diff,
	}) {
		return cli.ExitInternal
	}
	if target == "file" {
		fmt.Fprintf(r.env.Stderr, "wrote %s (0600 plaintext %s)\n", *out, info.Kind)
	}
	return cli.ExitOK
}

func resourceTypeOf(kind string) string {
	switch kind {
	case keys.KindTokenKeys, keys.KindSealRoot:
		return "site_key"
	case keys.KindPseudoKey:
		return "pseudo_key"
	case keys.KindUpstreamKeys:
		return "upstream_keys"
	}
	return "key"
}
