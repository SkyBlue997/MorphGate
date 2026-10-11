package mgctl

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/keys"
	"morphgate/control-plane/internal/turnstile"
)

// EnvCFAPIBase overrides the Cloudflare API base URL (tests: httptest).
const EnvCFAPIBase = "MGCTL_CF_API_BASE"

// turnstileTimeout bounds one mgctl turnstile command's API calls.
const turnstileTimeout = 60 * time.Second

// runTurnstile dispatches `mgctl turnstile ...` (Phase 2 spec §16).
func (r *runner) runTurnstile(args []string) int {
	if len(args) == 0 {
		r.errf("turnstile", "expected a subcommand: widgets | secret")
		return cli.ExitUsage
	}
	switch args[0] {
	case "widgets":
		return r.turnstileWidgets(args[1:])
	case "secret":
		if len(args) < 2 {
			r.errf("turnstile secret", "expected a subcommand: import | rotate | drop-previous")
			return cli.ExitUsage
		}
		switch args[1] {
		case "import":
			return r.turnstileImport(args[2:])
		case "rotate":
			return r.turnstileRotate(args[2:])
		case "drop-previous":
			return r.turnstileDropPrevious(args[2:])
		}
		r.errf("turnstile secret", "unknown subcommand %q (expected import | rotate | drop-previous)", args[1])
		return cli.ExitUsage
	}
	r.errf("turnstile", "unknown subcommand %q (expected widgets | secret)", args[0])
	return cli.ExitUsage
}

// checkIDs rejects malformed --account / --sitekey values as usage errors.
func (r *runner) checkIDs(cmd, account, sitekey string) bool {
	if err := turnstile.CheckIDs(account, sitekey); err != nil {
		r.errf(cmd, "%v", err)
		return false
	}
	return true
}

// turnstileClient decrypts --cf-token-file (age, passphrase) and builds the
// API client. The token is only ever sent as a bearer token to the API base.
func (r *runner) turnstileClient(cmd, tokenFile string) (*turnstile.Client, int) {
	pass, ok := r.passphrase(cmd, false)
	if !ok {
		return nil, cli.ExitUsage
	}
	plain, err := keys.DecryptFile(tokenFile, pass)
	if err != nil {
		r.errf(cmd, "--cf-token-file: %v", err)
		return nil, cli.ExitFailed
	}
	token := strings.TrimSpace(string(plain))
	c, err := turnstile.New(r.env.Getenv(EnvCFAPIBase), token, r.env.HTTP)
	if err != nil {
		r.errf(cmd, "%v", err)
		return nil, cli.ExitFailed
	}
	return c, cli.ExitOK
}

// apiExit maps an API error to an exit code: a rejected request is a failed
// check (1), a transport problem is I/O (3).
func apiExit(err error) int {
	var ae *turnstile.APIError
	if errors.As(err, &ae) {
		return cli.ExitFailed
	}
	return cli.ExitInternal
}

// turnstileWidgets: mgctl turnstile widgets --account <id> --cf-token-file <file.age>
func (r *runner) turnstileWidgets(args []string) int {
	const cmd = "turnstile widgets"
	fl := r.flags(cmd)
	account := fl.String("account", "", "Cloudflare account id")
	tokenFile := fl.String("cf-token-file", "", "age-encrypted Cloudflare API token (Account > Turnstile > Edit)")
	if !r.parse(fl, args) || !r.required(cmd, "account", *account, "cf-token-file", *tokenFile) || !r.checkIDs(cmd, *account, "") {
		return cli.ExitUsage
	}
	c, code := r.turnstileClient(cmd, *tokenFile)
	if code != cli.ExitOK {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), turnstileTimeout)
	defer cancel()
	ws, err := c.Widgets(ctx, *account)
	if err != nil {
		r.errf(cmd, "%v", err)
		return apiExit(err)
	}
	for _, w := range ws {
		fmt.Fprintf(r.env.Stdout, "%s  mode %s  domains %s  name %q  modified %s\n", w.Sitekey, w.Mode, strings.Join(w.Domains, ","), w.Name, w.ModifiedOn)
	}
	fmt.Fprintf(r.env.Stderr, "%d widget(s)\n", len(ws))
	return cli.ExitOK
}

// turnstileImport: mgctl turnstile secret import --account <id> --sitekey <k> --site <site> --out <file> --cf-token-file <file.age>
// Reads the widget (the response holds the secret) and writes a new 0600
// mg-turnstile-keys file with the current value only.
func (r *runner) turnstileImport(args []string) int {
	const cmd = "turnstile secret import"
	fl := r.flags(cmd)
	account := fl.String("account", "", "Cloudflare account id")
	sitekey := fl.String("sitekey", "", "widget sitekey")
	site := fl.String("site", "", "site id ([[sites]] id in edge.toml)")
	out := fl.String("out", "", "new mg-turnstile-keys file (0600; never overwritten)")
	tokenFile := fl.String("cf-token-file", "", "age-encrypted Cloudflare API token (Account > Turnstile > Edit)")
	if !r.parse(fl, args) || !r.required(cmd, "account", *account, "sitekey", *sitekey, "site", *site, "out", *out, "cf-token-file", *tokenFile) ||
		!r.checkIDs(cmd, *account, *sitekey) {
		return cli.ExitUsage
	}
	if !keys.SitePattern.MatchString(*site) {
		r.errf(cmd, "--site %q does not match %s", *site, keys.SitePattern)
		return cli.ExitUsage
	}
	if !r.mustNotExist(cmd, *out) {
		return cli.ExitFailed
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	c, code := r.turnstileClient(cmd, *tokenFile)
	if code != cli.ExitOK {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), turnstileTimeout)
	defer cancel()
	w, err := c.Widget(ctx, *account, *sitekey)
	if err != nil {
		r.errf(cmd, "%v", err)
		return apiExit(err)
	}
	data, err := (&keys.TurnstileKeys{Site: *site, Values: []string{w.Secret}}).Marshal()
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if err := keys.WriteNewFile(*out, data, 0o600); err != nil {
		r.errf(cmd, "%v", err)
		return exitFor(err)
	}
	if !r.record(cmd, cli.AuditEvent{
		Action: "turnstile.secret.import", ResourceType: "turnstile_widget", ResourceID: *sitekey, Site: *site,
		Diff: map[string]any{"sitekey": *sitekey, "values": 1},
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stdout, "wrote %s: the current secret of widget %s for site %s\n", *out, *sitekey, *site)
	fmt.Fprintf(r.env.Stderr, "deliver it as the Edge credential named in edge.toml [[sites]] turnstile_keys (systemd-creds encrypt), then systemctl reload mg-edge\n")
	return cli.ExitOK
}

// checkWritableDir confirms that a file can be replaced in dir before the
// rotation changes anything at Cloudflare.
func checkWritableDir(path string) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// turnstileRotate: mgctl turnstile secret rotate --account <id> --sitekey <k> --keys <file> [--invalidate-immediately] --cf-token-file <file.age>
// Calls rotate_secret with invalidate_immediately always explicit and
// replaces the keys file with [new, old] (new only with
// --invalidate-immediately: the old secret no longer verifies).
func (r *runner) turnstileRotate(args []string) int {
	const cmd = "turnstile secret rotate"
	fl := r.flags(cmd)
	account := fl.String("account", "", "Cloudflare account id")
	sitekey := fl.String("sitekey", "", "widget sitekey")
	keysPath := fl.String("keys", "", "the site's mg-turnstile-keys file (replaced)")
	invalidate := fl.Bool("invalidate-immediately", false, "invalidate the old secret at once (suspected leak); default: Cloudflare keeps it valid for 2 hours")
	tokenFile := fl.String("cf-token-file", "", "age-encrypted Cloudflare API token (Account > Turnstile > Edit)")
	if !r.parse(fl, args) || !r.required(cmd, "account", *account, "sitekey", *sitekey, "keys", *keysPath, "cf-token-file", *tokenFile) ||
		!r.checkIDs(cmd, *account, *sitekey) {
		return cli.ExitUsage
	}
	current, err := keys.ReadTurnstileKeysFile(*keysPath)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if err := checkWritableDir(*keysPath); err != nil {
		r.errf(cmd, "cannot replace %s: %v", *keysPath, err)
		return cli.ExitInternal
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	c, code := r.turnstileClient(cmd, *tokenFile)
	if code != cli.ExitOK {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), turnstileTimeout)
	defer cancel()
	// The file's current value must be the widget's current secret, else
	// the file would pair the new secret with a stale one.
	w, err := c.Widget(ctx, *account, *sitekey)
	if err != nil {
		r.errf(cmd, "%v", err)
		return apiExit(err)
	}
	if subtle.ConstantTimeCompare([]byte(w.Secret), []byte(current.Values[0])) != 1 {
		r.errf(cmd, "the current value in %s is not the current secret of widget %s; nothing rotated (re-import it with mgctl turnstile secret import)", *keysPath, *sitekey)
		return cli.ExitFailed
	}
	rotated, err := c.RotateSecret(ctx, *account, *sitekey, *invalidate)
	if err != nil {
		r.errf(cmd, "%v", err)
		return apiExit(err)
	}
	if subtle.ConstantTimeCompare([]byte(rotated.Secret), []byte(current.Values[0])) == 1 {
		r.errf(cmd, "rotate_secret returned the old secret; %s unchanged", *keysPath)
		return cli.ExitFailed
	}
	values := []string{rotated.Secret, current.Values[0]}
	if *invalidate {
		values = values[:1]
	}
	data, err := (&keys.TurnstileKeys{Site: current.Site, Values: values}).Marshal()
	writeErr := err
	if err == nil {
		writeErr = keys.ReplaceFile(*keysPath, data, 0o600)
	}
	if !r.record(cmd, cli.AuditEvent{
		Action: "turnstile.secret.rotate", ResourceType: "turnstile_widget", ResourceID: *sitekey, Site: current.Site,
		Diff: map[string]any{"sitekey": *sitekey, "invalidate_immediately": *invalidate, "values": len(values), "keys_file_written": writeErr == nil},
	}) {
		return cli.ExitInternal
	}
	if writeErr != nil {
		r.errf(cmd, "the secret was rotated at Cloudflare but %s could not be written: %v; recover with mgctl turnstile secret import into a new file", *keysPath, writeErr)
		return cli.ExitInternal
	}
	if *invalidate {
		fmt.Fprintf(r.env.Stdout, "rotated widget %s and invalidated the old secret; %s holds the new secret only\n", *sitekey, *keysPath)
		fmt.Fprintf(r.env.Stderr, "deploy %s to the Edge and systemctl reload mg-edge now: until then Turnstile verification fails and visitors fall back to self_hold\n", *keysPath)
	} else {
		fmt.Fprintf(r.env.Stdout, "rotated widget %s; %s holds [new, previous] (the previous secret stays valid for 2 hours)\n", *sitekey, *keysPath)
		fmt.Fprintf(r.env.Stderr, "deploy %s to the Edge and systemctl reload mg-edge, then run mgctl turnstile secret drop-previous --keys %s\n", *keysPath, *keysPath)
	}
	return cli.ExitOK
}

// turnstileDropPrevious: mgctl turnstile secret drop-previous --keys <file>
func (r *runner) turnstileDropPrevious(args []string) int {
	const cmd = "turnstile secret drop-previous"
	fl := r.flags(cmd)
	keysPath := fl.String("keys", "", "the site's mg-turnstile-keys file (replaced)")
	if !r.parse(fl, args) || !r.required(cmd, "keys", *keysPath) {
		return cli.ExitUsage
	}
	current, err := keys.ReadTurnstileKeysFile(*keysPath)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if len(current.Values) == 1 {
		fmt.Fprintf(r.env.Stdout, "%s already holds the current secret only; nothing to do\n", *keysPath)
		return cli.ExitOK
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	data, err := (&keys.TurnstileKeys{Site: current.Site, Values: current.Values[:1]}).Marshal()
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if err := keys.ReplaceFile(*keysPath, data, 0o600); err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	if !r.record(cmd, cli.AuditEvent{
		Action: "turnstile.secret.drop_previous", ResourceType: "turnstile_keys", ResourceID: current.Site, Site: current.Site,
		Diff: map[string]any{"values": 1},
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stdout, "%s now holds the current secret only; deploy it and systemctl reload mg-edge\n", *keysPath)
	return cli.ExitOK
}
