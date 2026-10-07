package mgctl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/audit"
	"morphgate/control-plane/internal/bundle"
	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/keys"
	"morphgate/control-plane/internal/sitecfg"
)

// runBundle dispatches `mgctl bundle <subcommand>` (§14.1).
func (r *runner) runBundle(args []string) int {
	if len(args) == 0 {
		r.errf("bundle", "expected a subcommand: build | sign | verify | publish")
		return cli.ExitUsage
	}
	switch args[0] {
	case "build":
		return r.bundleBuild(args[1:])
	case "sign":
		return r.bundleSign(args[1:])
	case "verify":
		return r.bundleVerify(args[1:])
	case "publish":
		return r.bundlePublish(args[1:])
	}
	r.errf("bundle", "unknown subcommand %q (expected build | sign | verify | publish)", args[0])
	return cli.ExitUsage
}

// bundleBuild: mgctl bundle build --site-config <site.yaml> --out-dir <dir> [--version N]
// Writes <dir>/<site>.sitebundle.pb, <dir>/<site>.sitebundle.json (protojson,
// for humans only) and <dir>/artifacts/<sha256>.
func (r *runner) bundleBuild(args []string) int {
	const cmd = "bundle build"
	fl := r.flags(cmd)
	cfg := fl.String("site-config", "", "site YAML")
	outDir := fl.String("out-dir", "", "output directory")
	version := fl.Uint64("version", 0, "bundle version (default: the build time in Unix seconds)")
	maxCost := fl.Uint64("max-cost", 0, "cel-go cost budget per rule (default: the policy default)")
	if !r.parse(fl, args) || !r.required(cmd, "site-config", *cfg, "out-dir", *outDir) {
		return cli.ExitUsage
	}
	site, code := r.loadSite(cmd, *cfg)
	if code != cli.ExitOK {
		return code
	}
	res, code := r.build(cmd, site, bundle.BuildOptions{Version: *version, Now: r.env.Now(), MaxCost: *maxCost})
	if code != cli.ExitOK {
		return code
	}
	artDir := filepath.Join(*outDir, "artifacts")
	if err := os.MkdirAll(artDir, 0o755); err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	for sum, src := range res.Artifacts {
		if err := copyArtifact(src, filepath.Join(artDir, sum), sum); err != nil {
			r.errf(cmd, "%v", err)
			return cli.ExitInternal
		}
	}
	pbPath := filepath.Join(*outDir, site.ID+".sitebundle.pb")
	jsonPath := filepath.Join(*outDir, site.ID+".sitebundle.json")
	human, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(res.Bundle)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	for path, data := range map[string][]byte{pbPath: res.Bytes, jsonPath: append(human, '\n')} {
		if err := keys.ReplaceFile(path, data, 0o644); err != nil {
			r.errf(cmd, "%v", err)
			return cli.ExitInternal
		}
	}
	sum := bundle.Summarize(res.Bundle, res.Bytes, nil, nil)
	fmt.Fprintf(r.env.Stdout, "built %s version %d: %d environment(s), %d rule(s), %d artifact(s), sha256 %s\nwrote %s, %s and %s/\n",
		sum.Site, sum.Version, len(sum.Environments), sum.Rules, len(sum.Artifacts), sum.BundleSHA256, pbPath, jsonPath, artDir)
	return cli.ExitOK
}

// copyArtifact copies a content-addressed artifact unless an identical copy exists.
func copyArtifact(src, dst, sum string) error {
	if data, err := os.ReadFile(dst); err == nil {
		if sha256Hex(data) == sum {
			return nil
		}
		return fmt.Errorf("%s exists with other content; remove it", dst)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if sha256Hex(data) != sum {
		return fmt.Errorf("%s changed during the build", src)
	}
	return keys.WriteNewFile(dst, data, 0o644)
}

// bundleSign: mgctl bundle sign --in <pb> --key <kid>.key.age --out <file.bundle>
func (r *runner) bundleSign(args []string) int {
	const cmd = "bundle sign"
	fl := r.flags(cmd)
	in := fl.String("in", "", "<site>.sitebundle.pb from bundle build")
	keyPath := fl.String("key", "", "owner signing key <kid>.key.age")
	out := fl.String("out", "", "signed bundle file, e.g. blog.bundle")
	if !r.parse(fl, args) || !r.required(cmd, "in", *in, "key", *keyPath, "out", *out) {
		return cli.ExitUsage
	}
	data, err := keys.ReadFileLimit(*in, bundle.MaxBundleSize)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	var sb morphgatev1.SiteBundle
	if err := proto.Unmarshal(data, &sb); err != nil || sb.SchemaVersion != bundle.SchemaVersion || !sitecfg.SitePattern.MatchString(sb.SiteId) {
		r.errf(cmd, "%s is not a schema_version %d SiteBundle (%v)", *in, bundle.SchemaVersion, err)
		return cli.ExitFailed
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	pass, ok := r.passphrase(cmd, false)
	if !ok {
		return cli.ExitUsage
	}
	key, err := keys.LoadOwnerKey(*keyPath, pass)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	signed, err := bundle.Sign(data, key)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	file, err := bundle.MarshalSigned(signed)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	if err := keys.ReplaceFile(*out, file, 0o644); err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	sum := bundle.Summarize(&sb, data, signed, file)
	if !r.record(cmd, cli.AuditEvent{
		Action: "bundle.sign", ResourceType: "bundle", ResourceID: fmt.Sprintf("%s@%d", sb.SiteId, sb.Version), Site: sb.SiteId,
		Diff: map[string]any{"version": sb.Version, "sha256": sum.BundleSHA256, "rules": sum.Rules, "monitor_only": sb.MonitorOnly, "key_id": key.KID},
	}) {
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stdout, "signed %s version %d with %s: %s (sha256 %s)\n", sb.SiteId, sb.Version, key.KID, *out, sum.FileSHA256)
	return cli.ExitOK
}

// loadTrusted reads the --pub files. A missing flag is a usage error (2); an
// unreadable or invalid key file is invalid input (1).
func (r *runner) loadTrusted(cmd string, paths []string) ([]*keys.OwnerPublicKey, int) {
	if len(paths) == 0 {
		r.errf(cmd, "at least one --pub <kid>.pub is required")
		return nil, cli.ExitUsage
	}
	var out []*keys.OwnerPublicKey
	for _, p := range paths {
		k, err := keys.LoadOwnerPublicKey(p)
		if err != nil {
			r.errf(cmd, "%v", err)
			return nil, cli.ExitFailed
		}
		out = append(out, k)
	}
	return out, cli.ExitOK
}

// bundleVerify: mgctl bundle verify --in <file.bundle> --pub <kid>.pub... [--site <id>] [--json]
func (r *runner) bundleVerify(args []string) int {
	const cmd = "bundle verify"
	fl := r.flags(cmd)
	in := fl.String("in", "", "signed bundle file")
	var pubs stringList
	fl.Var(&pubs, "pub", "trusted owner public key <kid>.pub (repeatable)")
	site := fl.String("site", "", "expected site id")
	asJSON := fl.Bool("json", false, "print the summary as JSON")
	if !r.parse(fl, args) || !r.required(cmd, "in", *in) {
		return cli.ExitUsage
	}
	trusted, code := r.loadTrusted(cmd, pubs)
	if code != cli.ExitOK {
		return code
	}
	file, err := keys.ReadFileLimit(*in, bundle.MaxBundleSize+4096)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	signed, sb, err := bundle.VerifyFile(file, trusted)
	if err != nil {
		r.errf(cmd, "%s: %v", *in, err)
		return cli.ExitFailed
	}
	if *site != "" && sb.SiteId != *site {
		r.errf(cmd, "%s is a bundle for site %q, not %q", *in, sb.SiteId, *site)
		return cli.ExitFailed
	}
	sum := bundle.Summarize(sb, signed.Bundle, signed, file)
	if *asJSON {
		enc := json.NewEncoder(r.env.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(sum); err != nil {
			return cli.ExitInternal
		}
		return cli.ExitOK
	}
	w := r.env.Stdout
	fmt.Fprintf(w, "ok: signature by %s verifies\n", sum.KeyID)
	fmt.Fprintf(w, "site %s  version %d  created %s  profile %s  monitor_only %v\n", sum.Site, sum.Version, sum.CreatedAt, sum.Profile, sum.MonitorOnly)
	if sum.NotBefore != "" {
		fmt.Fprintf(w, "not before %s\n", sum.NotBefore)
	}
	fmt.Fprintf(w, "hosts %s  listeners %s  token kids %s\n", strings.Join(sum.Hosts, ","), strings.Join(sum.AllowedListeners, ","), strings.Join(sum.TokenKeyIDs, ","))
	for _, e := range sum.Environments {
		fmt.Fprintf(w, "env %-10s hosts %s  routes %d  rules %d  rate limits %d\n", e.Name, strings.Join(e.Hosts, ","), e.Routes, e.Rules, e.RateLimits)
	}
	for _, a := range sum.Artifacts {
		fmt.Fprintf(w, "artifact %-16s %s  %d bytes  %s\n", a.Name, a.SHA256, a.Size, a.Version)
	}
	fmt.Fprintf(w, "file sha256 %s\nbundle sha256 %s\nsource digest %s\n", sum.FileSHA256, sum.BundleSHA256, sum.SourceDigest)
	return cli.ExitOK
}

// bundlePublish: mgctl bundle publish --in <file.bundle> --artifacts <dir> --dest <dir> --pub <kid>.pub... --confirm <site> [--metrics-textfile <path>]
func (r *runner) bundlePublish(args []string) int {
	const cmd = "bundle publish"
	fl := r.flags(cmd)
	in := fl.String("in", "", "signed bundle file")
	artifacts := fl.String("artifacts", "", "directory holding the bundle's artifacts/<sha256> (the build's <out-dir>/artifacts)")
	dest := fl.String("dest", "", "publication root: bundles/ and artifacts/ are written below it")
	var pubs stringList
	fl.Var(&pubs, "pub", "trusted owner public key <kid>.pub (repeatable)")
	confirm := fl.String("confirm", "", "site id, typed to confirm the publication")
	metrics := fl.String("metrics-textfile", "", "node_exporter textfile for mg_bundle_published_version{site}")
	if !r.parse(fl, args) || !r.required(cmd, "in", *in, "artifacts", *artifacts, "dest", *dest) {
		return cli.ExitUsage
	}
	trusted, code := r.loadTrusted(cmd, pubs)
	if code != cli.ExitOK {
		return code
	}
	confirmed, code := r.confirmSite(cmd, *confirm)
	if code != cli.ExitOK {
		return code
	}
	file, err := keys.ReadFileLimit(*in, bundle.MaxBundleSize+4096)
	if err != nil {
		r.errf(cmd, "%v", err)
		return cli.ExitFailed
	}
	if !r.preflightAudit(cmd) {
		return cli.ExitInternal
	}
	res, err := bundle.Publish(file, *artifacts, *dest, trusted, confirmed)
	if err != nil {
		r.errf(cmd, "%v", err)
		var pe *fs.PathError
		if errors.As(err, &pe) && !errors.Is(err, fs.ErrNotExist) {
			return cli.ExitInternal
		}
		return cli.ExitFailed
	}
	_, sb, _ := bundle.VerifyFile(file, trusted)
	if !r.record(cmd, cli.AuditEvent{
		Action: "bundle.publish", ResourceType: "bundle", ResourceID: fmt.Sprintf("%s@%d", sb.SiteId, sb.Version), Site: sb.SiteId,
		ConfirmText: confirmed,
		Diff: map[string]any{"version": sb.Version, "previous_version": res.PreviousVersion, "file_sha256": sha256Hex(file),
			"artifacts_written": res.ArtifactsWritten, "artifacts_skipped": res.ArtifactsSkipped, "dest": *dest},
	}) {
		return cli.ExitInternal
	}
	if *metrics != "" {
		if err := bundle.WritePublishedVersion(*metrics, sb.SiteId, sb.Version); err != nil {
			r.errf(cmd, "published, but the metrics textfile failed: %v", err)
			return cli.ExitInternal
		}
	}
	fmt.Fprintf(r.env.Stdout, "published %s version %d (previous %d) to %s: %d artifact(s) written, %d already present\n",
		sb.SiteId, sb.Version, res.PreviousVersion, res.BundlePath, res.ArtifactsWritten, res.ArtifactsSkipped)
	fmt.Fprintf(r.env.Stderr, "copy artifacts before bundles: rsync -a %s/artifacts/ <brain>:/srv/mg/artifacts/ && rsync -a %s/bundles/ <brain>:/srv/mg/bundles/\n", *dest, *dest)
	return cli.ExitOK
}

// auditVerify: mgctl audit verify [--audit-log <path>]
func (r *runner) auditVerify(args []string) int {
	const cmd = "audit verify"
	if len(args) == 0 || args[0] != "verify" {
		r.errf("audit", "expected a subcommand: verify")
		return cli.ExitUsage
	}
	fl := r.flags(cmd)
	if !r.parse(fl, args[1:]) {
		return cli.ExitUsage
	}
	path := r.auditPath
	if path == "" {
		p, err := audit.DefaultPath(r.env.Getenv)
		if err != nil {
			r.errf(cmd, "%v", err)
			return cli.ExitUsage
		}
		path = p
	}
	count, last, err := audit.Verify(path)
	var ve *audit.VerifyError
	switch {
	case errors.As(err, &ve):
		r.errf(cmd, "%s: chain broken at %v (%d record(s) before it verify)", path, ve, count)
		return cli.ExitFailed
	case errors.Is(err, fs.ErrNotExist):
		r.errf(cmd, "no audit log at %s", path)
		return cli.ExitFailed
	case err != nil:
		r.errf(cmd, "%v", err)
		return cli.ExitInternal
	}
	fmt.Fprintf(r.env.Stdout, "ok: %s: %d record(s), last hash %s\n", path, count, last)
	return cli.ExitOK
}
