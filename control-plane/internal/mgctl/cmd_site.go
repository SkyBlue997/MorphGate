package mgctl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"morphgate/control-plane/internal/bundle"
	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/keys"
	"morphgate/control-plane/internal/sitecfg"
)

// runSite dispatches `mgctl site check` and `mgctl site keys ...` (§14.1).
func (r *runner) runSite(args []string) int {
	if len(args) == 0 {
		r.errf("site", "expected a subcommand: check | keys")
		return cli.ExitUsage
	}
	switch args[0] {
	case "check":
		return r.siteCheck(args[1:])
	case "keys":
		if len(args) < 2 {
			r.errf("site keys", "expected a subcommand: gen | rotate-token | rotate-seal")
			return cli.ExitUsage
		}
		switch args[1] {
		case "gen":
			return r.siteKeysGen(args[2:])
		case "rotate-token":
			return r.siteKeysRotateToken(args[2:])
		case "rotate-seal":
			return r.siteKeysRotateSeal(args[2:])
		}
		r.errf("site keys", "unknown subcommand %q (expected gen | rotate-token | rotate-seal)", args[1])
		return cli.ExitUsage
	}
	r.errf("site", "unknown subcommand %q (expected check | keys)", args[0])
	return cli.ExitUsage
}

// loadSite loads and validates a site YAML, printing diagnostics; code != 0
// means the caller must exit with it.
func (r *runner) loadSite(cmd, path string) (*sitecfg.Site, int) {
	site, diags, err := sitecfg.Load(path)
	if err != nil {
		r.errf(cmd, "%v", err)
		if errors.Is(err, os.ErrNotExist) {
			return nil, cli.ExitFailed
		}
		return nil, cli.ExitInternal
	}
	for _, d := range diags {
		fmt.Fprintln(r.env.Stderr, d.String())
	}
	if sitecfg.HasErrors(diags) {
		r.errf(cmd, "%s is invalid", path)
		return nil, cli.ExitFailed
	}
	return site, cli.ExitOK
}

// build runs bundle.Build and prints warnings and problems.
func (r *runner) build(cmd string, site *sitecfg.Site, opts bundle.BuildOptions) (*bundle.BuildResult, int) {
	res, err := bundle.Build(site, opts)
	if err != nil {
		var be *bundle.BuildError
		if errors.As(err, &be) {
			for _, p := range be.Problems {
				fmt.Fprintf(r.env.Stderr, "error: %s\n", p)
			}
			r.errf(cmd, "%d problem(s) in %s", len(be.Problems), site.File)
			return nil, cli.ExitFailed
		}
		r.errf(cmd, "%v", err)
		return nil, cli.ExitInternal
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(r.env.Stderr, "warning: %s\n", w)
	}
	return res, cli.ExitOK
}

// siteCheck: mgctl site check --site-config <site.yaml>
// Validates the site YAML, its policies, lists and artifacts without writing.
func (r *runner) siteCheck(args []string) int {
	const cmd = "site check"
	fl := r.flags(cmd)
	cfg := fl.String("site-config", "", "site YAML")
	maxCost := fl.Uint64("max-cost", 0, "cel-go cost budget per rule (default: the policy default)")
	if !r.parse(fl, args) || !r.required(cmd, "site-config", *cfg) {
		return cli.ExitUsage
	}
	site, code := r.loadSite(cmd, *cfg)
	if code != cli.ExitOK {
		return code
	}
	res, code := r.build(cmd, site, bundle.BuildOptions{Version: 1, Now: r.env.Now(), MaxCost: *maxCost})
	if code != cli.ExitOK {
		return code
	}
	sum := bundle.Summarize(res.Bundle, res.Bytes, nil, nil)
	fmt.Fprintf(r.env.Stdout, "ok: site %s (%s): %d environment(s), %d rule(s), %d artifact(s), %d list(s), %d warning(s)\n",
		sum.Site, sum.Profile, len(sum.Environments), sum.Rules, len(sum.Artifacts), sum.Lists, len(res.Warnings))
	return cli.ExitOK
}

// siteKeysGen: mgctl site keys gen --site <id> --out-dir <dir> [--date YYYYMMDD] [--insecure-test-key]
func (r *runner) siteKeysGen(args []string) int {
	const cmd = "site keys gen"
	fl := r.flags(cmd)
	site := fl.String("site", "", "site id")
	outDir := fl.String("out-dir", "", "directory for token.keys.json.age and seal.root.json.age")
	date := fl.String("date", "", "key date YYYYMMDD used in the key ids and created_at (default: today, UTC)")
	insecure := fl.Bool("insecure-test-key", false, "allow MGCTL_AGE_WORK_FACTOR below 18 (tests only)")
	if !r.parse(fl, args) || !r.required(cmd, "site", *site, "out-dir", *outDir) {
		return cli.ExitUsage
	}
	if !keys.SitePattern.MatchString(*site) {
		r.errf(cmd, "--site %q does not match %s", *site, keys.SitePattern)
		return cli.ExitUsage
	}
	d, ok := r.keyDate(cmd, *date)
	if !ok {
		return cli.ExitUsage
	}
	wf, ok := r.workFactor(cmd, *insecure)
	if !ok {
		return cli.ExitUsage
	}
	tokenPath, sealPath := filepath.Join(*outDir, "token.keys.json.age"), filepath.Join(*outDir, "seal.root.json.age")
	if !r.mustNotExist(cmd, tokenPath, sealPath) {
		return cli.ExitFailed
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	pass, ok := r.passphrase(cmd, true)
	if !ok {
		return cli.ExitUsage
	}
	tokenJSON, sealJSON, err := keys.GenerateSiteKeys(*site, d, randReader)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	if err := keys.EncryptFile(tokenPath, tokenJSON, pass, wf); err != nil {
		r.errf(cmd, "%v", err)
		return exitFor(err)
	}
	if err := keys.EncryptFile(sealPath, sealJSON, pass, wf); err != nil {
		os.Remove(tokenPath)
		r.errf(cmd, "%v", err)
		return exitFor(err)
	}
	token, _ := keys.Inspect(tokenJSON)
	seal, _ := keys.Inspect(sealJSON)
	if !r.record(cmd, cli.AuditEvent{
		Action: "site_keys.gen", ResourceType: "site_key", ResourceID: *site, Site: *site,
		Diff: workFactorDiff(map[string]any{"token_kid": token.IDs[0], "seal_root_id": seal.IDs[0]}, wf, *insecure),
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stdout, "wrote %s (kid %s) and %s (root %s)\nset token.active_kid: %s in the site YAML\n",
		tokenPath, token.IDs[0], sealPath, seal.IDs[0], token.IDs[0])
	return cli.ExitOK
}

// openSiteKeyFile decrypts a site key file and checks its kind and site.
func (r *runner) openSiteKeyFile(cmd, path, site, kind string, pass []byte) ([]byte, int) {
	plain, err := keys.DecryptFile(path, pass)
	if err != nil {
		r.errf(cmd, "%v", err)
		return nil, cli.ExitFailed
	}
	info, err := keys.Inspect(plain)
	switch {
	case err != nil:
		r.errf(cmd, "%s: %v", path, err)
		return nil, cli.ExitFailed
	case info.Kind != kind:
		r.errf(cmd, "%s is a %s file, want %s", path, info.Kind, kind)
		return nil, cli.ExitFailed
	case info.Site != site:
		r.errf(cmd, "%s belongs to site %q, not %q", path, info.Site, site)
		return nil, cli.ExitFailed
	}
	return plain, cli.ExitOK
}

// siteKeysRotateToken: mgctl site keys rotate-token --site <id> --file <token.keys.json.age> [--date YYYYMMDD]
func (r *runner) siteKeysRotateToken(args []string) int {
	const cmd = "site keys rotate-token"
	fl := r.flags(cmd)
	site := fl.String("site", "", "site id")
	file := fl.String("file", "", "token.keys.json.age to rotate in place")
	date := fl.String("date", "", "key date YYYYMMDD of the new kid (default: today, UTC)")
	insecure := fl.Bool("insecure-test-key", false, "allow MGCTL_AGE_WORK_FACTOR below 18 (tests only)")
	if !r.parse(fl, args) || !r.required(cmd, "site", *site, "file", *file) {
		return cli.ExitUsage
	}
	d, ok := r.keyDate(cmd, *date)
	if !ok {
		return cli.ExitUsage
	}
	wf, ok := r.workFactor(cmd, *insecure)
	if !ok {
		return cli.ExitUsage
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	pass, ok := r.passphrase(cmd, false)
	if !ok {
		return cli.ExitUsage
	}
	plain, code := r.openSiteKeyFile(cmd, *file, *site, keys.KindTokenKeys, pass)
	if code != cli.ExitOK {
		return code
	}
	next, kid, err := keys.RotateTokenKey(plain, d, randReader)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if err := keys.ReEncryptFile(*file, next, pass, wf); err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	info, _ := keys.Inspect(next)
	if !r.record(cmd, cli.AuditEvent{
		Action: "site_keys.rotate_token", ResourceType: "site_key", ResourceID: *site, Site: *site,
		Diff: workFactorDiff(map[string]any{"new_kid": kid, "kids": info.IDs}, wf, *insecure),
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintln(r.env.Stdout, kid)
	fmt.Fprintf(r.env.Stderr, "rotated %s: kids %v; deploy it to every Edge before making %s the active_kid (§17)\n", *file, info.IDs, kid)
	return cli.ExitOK
}

// siteKeysRotateSeal: mgctl site keys rotate-seal --site <id> --file <seal.root.json.age> --step add|promote|retire [--date YYYYMMDD]
func (r *runner) siteKeysRotateSeal(args []string) int {
	const cmd = "site keys rotate-seal"
	fl := r.flags(cmd)
	site := fl.String("site", "", "site id")
	file := fl.String("file", "", "seal.root.json.age to rotate in place")
	step := fl.String("step", "", "add | promote | retire")
	date := fl.String("date", "", "key date YYYYMMDD of a new root (add; default: today, UTC)")
	insecure := fl.Bool("insecure-test-key", false, "allow MGCTL_AGE_WORK_FACTOR below 18 (tests only)")
	if !r.parse(fl, args) || !r.required(cmd, "site", *site, "file", *file, "step", *step) {
		return cli.ExitUsage
	}
	if !slices.Contains([]string{keys.SealStepAdd, keys.SealStepPromote, keys.SealStepRetire}, *step) {
		r.errf(cmd, "--step %q is not one of add, promote, retire", *step)
		return cli.ExitUsage
	}
	d, ok := r.keyDate(cmd, *date)
	if !ok {
		return cli.ExitUsage
	}
	wf, ok := r.workFactor(cmd, *insecure)
	if !ok {
		return cli.ExitUsage
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	pass, ok := r.passphrase(cmd, false)
	if !ok {
		return cli.ExitUsage
	}
	plain, code := r.openSiteKeyFile(cmd, *file, *site, keys.KindSealRoot, pass)
	if code != cli.ExitOK {
		return code
	}
	next, err := keys.RotateSealRoot(plain, *step, d, randReader)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if err := keys.ReEncryptFile(*file, next, pass, wf); err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	info, _ := keys.Inspect(next)
	if !r.record(cmd, cli.AuditEvent{
		Action: "site_keys.rotate_seal", ResourceType: "site_key", ResourceID: *site, Site: *site,
		Diff: workFactorDiff(map[string]any{"step": *step, "root_ids": info.IDs}, wf, *insecure),
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stdout, "%s: roots %v (roots[0] seals, all open)\n", *step, info.IDs)
	return cli.ExitOK
}

// verdictKey: mgctl verdict key --pseudo-key <file.json.age> --site <id|all> --type ip|prefix|asn|session --value <v>
// Read-only: prints the Valkey key the owner SETs by hand (D-10); no audit record.
func (r *runner) verdictKey(args []string) int {
	const cmd = "verdict key"
	if len(args) == 0 || args[0] != "key" {
		r.errf("verdict", "expected a subcommand: key")
		return cli.ExitUsage
	}
	fl := r.flags(cmd)
	pseudo := fl.String("pseudo-key", "", "pseudo.key.json.age")
	site := fl.String("site", "", "site id, or all")
	typ := fl.String("type", "", "ip | prefix | asn | session")
	value := fl.String("value", "", "IP address, prefix, ASN or session id")
	if !r.parse(fl, args[1:]) || !r.required(cmd, "pseudo-key", *pseudo, "site", *site, "type", *typ, "value", *value) {
		return cli.ExitUsage
	}
	pass, ok := r.passphrase(cmd, false)
	if !ok {
		return cli.ExitUsage
	}
	plain, err := keys.DecryptFile(*pseudo, pass)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	key, err := keys.VerdictKey(plain, *site, *typ, *value)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	fmt.Fprintln(r.env.Stdout, key)
	return cli.ExitOK
}
