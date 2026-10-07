// Package cfaudit implements `mgctl cf audit` (docs/impl/phase1-spec.md
// §14.3, docs/08-upstream-and-cloudflare.md §2.10): 21 read-only checks of the
// owner's Cloudflare zone that MorphGate depends on, from origin protection
// and the Tier 0 signal Transform Rule to cache and skip rules, plus runtime
// evidence from VictoriaMetrics and the age of the Cloudflare IP snapshot.
//
// The audit uses a read-only API token (CLOUDFLARE_API_TOKEN, the `cf-audit`
// token of docs/06 §8) and never changes the zone. Checks it cannot read
// (HTTP 401 / 403) are reported as `manual`; the owner confirms them in the
// dashboard and records that with --ack.
package cfaudit

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"morphgate/control-plane/internal/cfapi"
	"morphgate/control-plane/internal/cli"
	"morphgate/control-plane/internal/intelsync"
)

// Report is the audit result; with --json it is printed as
// {"zone","plan","checks":[{"n","id","level","status","detail"}],"errors":N}.
type Report struct {
	Zone   string   `json:"zone"`
	Plan   string   `json:"plan"`
	Checks []Result `json:"checks"`
	// Errors counts error-level checks that failed (and, with --strict,
	// error-level checks left manual); the exit code is 1 when it is not 0.
	Errors int `json:"errors"`
}

// Run audits the site's zone. It returns an error only when the zone itself
// cannot be read; every check-level problem is a Result.
func Run(ctx context.Context, api *cfapi.Client, opts Options) (*Report, error) {
	if opts.Site == nil || opts.Site.Cloudflare == nil {
		return nil, errors.New("no site configuration")
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now()
	}
	zone, err := api.FindZone(ctx, opts.Site.Cloudflare.Zone)
	if err != nil {
		return nil, err
	}
	a := &auditor{
		ctx: ctx, api: api, opts: opts, site: opts.Site, cf: opts.Site.Cloudflare,
		zone: zone, plan: zone.Plan.LegacyID, cache: map[string]cached{},
	}
	rep := &Report{Zone: zone.Name, Plan: zone.Plan.LegacyID}
	for _, def := range Checks {
		r := checkFuncs[def.ID](a, def)
		r.N, r.ID, r.Level = def.N, def.ID, def.Level
		if r.Status == StatusManual {
			if note, ok := opts.Acks[def.ID]; ok {
				r.Status = StatusPass
				r.Detail = fmt.Sprintf("acknowledged: %s (was manual: %s)", note, r.Detail)
			}
		}
		if def.Level == LevelError && (r.Status == StatusFail || (opts.Strict && r.Status == StatusManual)) {
			rep.Errors++
		}
		rep.Checks = append(rep.Checks, r)
	}
	return rep, nil
}

// ackFlag collects repeated --ack <check>[:<rule ref>]=<note> values.
type ackFlag map[string]string

func (f ackFlag) String() string { return "" }

func (f ackFlag) Set(v string) error {
	key, note, ok := strings.Cut(v, "=")
	note = strings.TrimSpace(note)
	if !ok || note == "" {
		return errors.New("want <check>=<note>")
	}
	id, ref, hasRef := strings.Cut(key, ":")
	if _, known := checkByID(id); !known {
		return fmt.Errorf("unknown check %q", id)
	}
	if hasRef && (id != "ttl_override_trap" || ref == "") {
		return errors.New("only ttl_override_trap:<rule ref>=<note> takes a rule ref")
	}
	f[key] = note
	return nil
}

const usageText = `Usage: mgctl cf audit --site-config <site.yaml> [flags]

Audits the site's Cloudflare zone with a read-only API token from
CLOUDFLARE_API_TOKEN (MGCTL_CF_API_BASE overrides the API URL). Exit status:
0 no error-level failure, 1 an error-level check failed (or is manual with
--strict) or the input is invalid, 2 usage error, 3 I/O or API error.

Flags:
`

// RunCLI implements `mgctl cf audit <args>` (args exclude "cf audit").
func RunCLI(args []string, env cli.Env) int {
	stdout, stderr := env.Stdout, env.Stderr
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	fs := flag.NewFlagSet("mgctl cf audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "\nChecks:")
		for _, c := range Checks {
			fmt.Fprintf(stderr, "  %2d %-26s %-7s %s\n", c.N, c.ID, c.Level, c.Title)
		}
	}
	siteConfig := fs.String("site-config", "", "site YAML (reads site, hosts, profile, cloudflare.* and route paths)")
	cfIPs := fs.String("cf-ips", "", "cloudflare-ips artifact; its <artifact>.state.json dates the last sync (check 19)")
	vmURL := fs.String("vm-url", "", "VictoriaMetrics base URL for the runtime metrics check (check 18)")
	sdkDir := fs.String("sdk-dir", "", "SDK directory with challenge.html (check 15)")
	acks := ackFlag{}
	fs.Var(acks, "ack", "record a manual `check=note` as confirmed (repeatable); ttl_override_trap:<rule ref>=<note> accepts one reviewed cache rule")
	strict := fs.Bool("strict", false, "treat manual error-level checks as failures")
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	metrics := fs.String("metrics-textfile", "", "node_exporter textfile for mg_cf_audit_failed_checks and mg_cf_audit_last_run_timestamp_seconds")
	if err := fs.Parse(args); err != nil {
		return cli.ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "mgctl cf audit: unexpected arguments %q\n", fs.Args())
		return cli.ExitUsage
	}
	if *siteConfig == "" {
		fmt.Fprintln(stderr, "mgctl cf audit: --site-config is required")
		return cli.ExitUsage
	}
	if *vmURL != "" {
		if u, err := url.Parse(*vmURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			fmt.Fprintf(stderr, "mgctl cf audit: --vm-url %q must be an http(s) URL without credentials\n", *vmURL)
			return cli.ExitUsage
		}
	}
	token := getenv("CLOUDFLARE_API_TOKEN")
	if token == "" {
		fmt.Fprintln(stderr, "mgctl cf audit: CLOUDFLARE_API_TOKEN is not set (use the read-only cf-audit token)")
		return cli.ExitUsage
	}
	site, err := LoadSite(*siteConfig)
	if err != nil {
		fmt.Fprintf(stderr, "mgctl cf audit: %v\n", err)
		return cli.ExitFailed
	}
	api, err := cfapi.New(getenv("MGCTL_CF_API_BASE"), token, env.HTTP)
	if err != nil {
		fmt.Fprintf(stderr, "mgctl cf audit: %v\n", err)
		return cli.ExitUsage
	}
	now := time.Now()
	if env.Now != nil {
		now = env.Now()
	}
	rep, err := Run(context.Background(), api, Options{
		Site: site, CFIPs: *cfIPs, VMURL: *vmURL, SDKDir: *sdkDir,
		Acks: acks, Strict: *strict, Now: now, HTTP: env.HTTP,
	})
	if err != nil {
		fmt.Fprintf(stderr, "mgctl cf audit: %v\n", err)
		var ae *cfapi.APIError
		if errors.As(err, &ae) || errors.Is(err, cfapi.ErrZoneNotFound) {
			return cli.ExitFailed
		}
		return cli.ExitInternal
	}
	for key := range acks {
		id, _, _ := strings.Cut(key, ":")
		for _, r := range rep.Checks {
			if r.ID == id && key == id && !strings.HasPrefix(r.Detail, "acknowledged: ") {
				fmt.Fprintf(stderr, "note: --ack %s had no effect: the check is %s\n", id, r.Status)
			}
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(rep); err != nil {
			return cli.ExitInternal
		}
	} else {
		printTable(stdout, site, rep, *strict)
	}
	if *metrics != "" {
		if err := intelsync.WriteTextfile(*metrics, metricFamilies(rep, now, *strict)); err != nil {
			fmt.Fprintf(stderr, "mgctl cf audit: writing %s: %v\n", *metrics, err)
			return cli.ExitInternal
		}
	}
	if rep.Errors > 0 {
		return cli.ExitFailed
	}
	return cli.ExitOK
}

func printTable(w io.Writer, site *Site, rep *Report, strict bool) {
	fmt.Fprintf(w, "mgctl cf audit: site %s, zone %s (plan %s, origin %s)\n\n", site.Site, rep.Zone, orUnknown(rep.Plan), site.Cloudflare.OriginMode)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tID\tLEVEL\tSTATUS\tDETAIL")
	counts := map[Status]int{}
	for _, r := range rep.Checks {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", r.N, r.ID, r.Level, r.Status, r.Detail)
		counts[r.Status]++
	}
	_ = tw.Flush()
	var parts []string
	for _, st := range []Status{StatusPass, StatusFail, StatusWarn, StatusManual, StatusSkip} {
		if counts[st] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[st], st))
		}
	}
	mode := ""
	if strict {
		mode = " (strict)"
	}
	fmt.Fprintf(w, "\n%s; %d error-level failure(s)%s\n", strings.Join(parts, ", "), rep.Errors, mode)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// metricFamilies renders §13.7's control plane metrics: one 0/1 series per
// check (1 = fail or warn, and manual under --strict) and the run time.
func metricFamilies(rep *Report, now time.Time, strict bool) []intelsync.MetricFamily {
	failedChecks := intelsync.MetricFamily{
		Name: "mg_cf_audit_failed_checks",
		Help: "1 if the check failed in the last mgctl cf audit run (fail or warn; manual too with --strict).",
		Type: "gauge",
	}
	checks := append([]Result(nil), rep.Checks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].N < checks[j].N })
	for _, r := range checks {
		v := 0.0
		if r.Status == StatusFail || r.Status == StatusWarn || (strict && r.Status == StatusManual) {
			v = 1
		}
		failedChecks.Metrics = append(failedChecks.Metrics, intelsync.Metric{
			Labels: [][2]string{{"zone", rep.Zone}, {"check", r.ID}}, Value: v,
		})
	}
	return []intelsync.MetricFamily{failedChecks, {
		Name:    "mg_cf_audit_last_run_timestamp_seconds",
		Help:    "Unix time of the last completed mgctl cf audit run.",
		Type:    "gauge",
		Metrics: []intelsync.Metric{{Labels: [][2]string{{"zone", rep.Zone}}, Value: float64(now.Unix())}},
	}}
}
