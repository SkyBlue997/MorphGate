// Package cli implements the mglab command line; cmd/mglab only calls Run.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"morphgate/lab/internal/events"
	"morphgate/lab/internal/guard"
	"morphgate/lab/internal/replay"
)

// Exit codes.
const (
	ExitOK     = 0
	ExitDenied = 1 // target denied, replay had failures, or an event check failed
	ExitUsage  = 2 // usage or configuration error
)

const usage = `mglab - MorphGate Validation Lab (sends traffic only to allowlisted targets)

Usage:
  mglab check  [-config lab.yaml] [-map-host name=ip]... [-resolve] <url>
  mglab replay [-config lab.yaml] [-map-host name=ip]... [-base URL] [-rps N]
               [-var name=value]... <scenario.yaml>
  mglab events impersonator [-site ID] -impersonators PREFIX [-crawlers PREFIX]
               [-want-settled N] [-want-verified N] <events.jsonl>
  mglab events clearance [-site ID] -protected PREFIX [-want-feedback N] <events.jsonl>
  mglab events providers [-site ID] -route ID [-offer CC,...] [-provider ID]
               [-want-offered N] [-want-withheld N] <events.jsonl>
  mglab events nearline [-site ID] [-detector NAME] -after PREFIX -shadow-ip IP
               -enforce-ip IP [-fresh-ip IP] [-max-latency-ms N] <events.jsonl>...

Without -config the built-in allowlist is used: localhost, *.test, *.localhost,
127.0.0.0/8 and ::1 (see lab/config/lab.example.yaml).

  check    print whether the URL is allowed and why; -resolve also resolves the
           host and validates every address (no connection is made)
  replay   send the scenario's recorded requests one by one to the base URL,
           rate-capped (default 5 req/s, hard maximum 50); -var sets a
           variable the scenario declares (e.g. a port or run id)
  events   check the Edge's JSONL event file after a replay (reads local
           files, sends nothing): "impersonator" requires every settled fake
           crawler request to be classified impersonator (D-22), "clearance"
           requires that no challenge submission or renewal passed and that
           no request to the protected route was forwarded, "providers"
           requires that only the -offer countries got a C offering the
           external provider on the route, "nearline" (the Edge's events plus
           mg-nearline's kind=verdict lines) requires a shadow verdict that
           was not written, an enforce verdict that was, and the enforce
           address's later request challenged with that verdict while the
           controls are forwarded

-map-host name=ip answers the lookup of an allowlisted name with a fixed
address (like curl --resolve), e.g. site.lab.test=127.0.0.1 for a *.test site
served by a loopback Edge. The address is validated like any DNS answer, so
it must still be one the allowlist admits for that name.

Exit status: 0 allowed / all requests as expected / checks passed, 1 denied,
failures or failed checks, 2 usage or configuration error.
`

// Run executes mglab with args (without the program name).
func Run(args []string, stdout, stderr io.Writer) int {
	return run(context.Background(), args, stdout, stderr, nil)
}

// run takes guard options so tests can inject resolvers.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, opts []guard.Option) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	switch args[0] {
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr, opts)
	case "replay":
		return runReplay(ctx, args[1:], stdout, stderr, opts)
	case "events":
		return runEvents(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	}
	fmt.Fprintf(stderr, "mglab: unknown command %q\n\n%s", args[0], usage)
	return ExitUsage
}

func loadConfig(path string) (guard.Config, error) {
	if path == "" {
		return guard.DefaultConfig(), nil
	}
	return guard.LoadConfig(path)
}

// hostMap collects repeated -map-host name=ip flags.
type hostMap map[string][]netip.Addr

func (m hostMap) String() string { return "" }

func (m hostMap) Set(s string) error {
	name, addr, err := guard.ParseHostMapping(s)
	if err != nil {
		return err
	}
	m[name] = append(m[name], addr)
	return nil
}

// varMap collects repeated -var name=value flags.
type varMap map[string]string

func (m varMap) String() string { return "" }

func (m varMap) Set(s string) error {
	name, value, ok := strings.Cut(s, "=")
	if !ok || name == "" {
		return fmt.Errorf("-var %q: want name=value", s)
	}
	if _, dup := m[name]; dup {
		return fmt.Errorf("-var %s given twice", name)
	}
	m[name] = value
	return nil
}

// newGuard builds the guard from -config and the -map-host entries. Every
// mapped name must itself pass the allowlist.
func newGuard(cfgPath string, rps float64, hosts hostMap, opts []guard.Option) (*guard.Guard, error) {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if rps != 0 {
		cfg.RateRPS = rps
	}
	if len(hosts) > 0 {
		opts = append(append([]guard.Option(nil), opts...), guard.WithStaticHosts(hosts))
	}
	g, err := guard.New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	for name := range hosts {
		if _, err := g.CheckURL("http://" + name + "/"); err != nil {
			return nil, fmt.Errorf("-map-host %s: %v", name, reason(err))
		}
	}
	return g, nil
}

func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer, opts []guard.Option) int {
	fs := flag.NewFlagSet("mglab check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "allowlist config (YAML); default: built-in local-only allowlist")
	resolve := fs.Bool("resolve", false, "also resolve the host and validate every address")
	hosts := hostMap{}
	fs.Var(hosts, "map-host", "name=ip: fixed address for an allowlisted host name (repeatable)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "mglab check: expected exactly one URL")
		return ExitUsage
	}
	g, err := newGuard(*cfgPath, 0, hosts, opts)
	if err != nil {
		fmt.Fprintf(stderr, "mglab check: %v\n", err)
		return ExitUsage
	}

	raw := fs.Arg(0)
	t, err := g.CheckURL(raw)
	if err != nil {
		fmt.Fprintf(stdout, "deny   %s\n       %v\n", raw, reason(err))
		return ExitDenied
	}
	if *resolve {
		rctx, cancel := context.WithTimeout(ctx, guard.DialTimeout)
		defer cancel()
		addrs, err := g.Resolve(rctx, "tcp", t.Host)
		if err != nil {
			fmt.Fprintf(stdout, "deny   %s\n       %v\n", raw, reason(err))
			return ExitDenied
		}
		fmt.Fprintf(stdout, "allow  %s\n       %s; resolves to %v\n", t.URL, t.Reason, addrs)
		return ExitOK
	}
	fmt.Fprintf(stdout, "allow  %s\n       %s\n", t.URL, t.Reason)
	return ExitOK
}

func reason(err error) string {
	var d *guard.DeniedError
	if errors.As(err, &d) {
		return d.Reason
	}
	return err.Error()
}

func runReplay(ctx context.Context, args []string, stdout, stderr io.Writer, opts []guard.Option) int {
	fs := flag.NewFlagSet("mglab replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "allowlist config (YAML); default: built-in local-only allowlist")
	base := fs.String("base", "", "base URL (overrides the scenario's base_url)")
	rps := fs.Float64("rps", 0, fmt.Sprintf("request rate cap (default from config, %.0f if unset; max %.0f)", guard.DefaultRateRPS, guard.MaxRateRPS))
	hosts := hostMap{}
	fs.Var(hosts, "map-host", "name=ip: fixed address for an allowlisted host name (repeatable)")
	vars := varMap{}
	fs.Var(vars, "var", "name=value: set a variable the scenario declares (repeatable)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "mglab replay: expected exactly one scenario file")
		return ExitUsage
	}
	g, err := newGuard(*cfgPath, *rps, hosts, opts)
	if err != nil {
		fmt.Fprintf(stderr, "mglab replay: %v\n", err)
		return ExitUsage
	}
	s, err := replay.Load(fs.Arg(0))
	if err == nil {
		s, err = s.Resolve(vars)
	}
	if err != nil {
		fmt.Fprintf(stderr, "mglab replay: %v\n", err)
		return ExitUsage
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	start := time.Now()
	sum, err := replay.Run(ctx, g, s, *base, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "mglab replay: %v\n", err)
		return ExitDenied
	}
	fmt.Fprintf(stderr, "mglab replay: finished in %s\n", time.Since(start).Round(time.Millisecond))
	if !sum.OK() {
		return ExitDenied
	}
	return ExitOK
}

// csvList collects a comma-separated flag value.
type csvList []string

func (l *csvList) String() string { return strings.Join(*l, ",") }

func (l *csvList) Set(s string) error {
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*l = append(*l, v)
		}
	}
	return nil
}

func runEvents(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "mglab events: expected impersonator, clearance, providers or nearline")
		return ExitUsage
	}
	mode := args[0]
	fs := flag.NewFlagSet("mglab events "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var imp events.ImpersonatorOptions
	var clr events.ClearanceOptions
	var prv events.ProvidersOptions
	var nl events.NearlineOptions
	var offer csvList
	var counts []*int
	required := map[string]*string{}
	maxFiles := 1
	switch mode {
	case "impersonator":
		fs.StringVar(&imp.Site, "site", "", "only events of this site id")
		fs.StringVar(&imp.Impersonators, "impersonators", "", "path prefix of the fake crawlers' requests (required)")
		fs.StringVar(&imp.Crawlers, "crawlers", "", "path prefix of the genuine crawlers' requests")
		fs.IntVar(&imp.WantSettled, "want-settled", 0, "exact number of settled impersonator requests (0: at least one)")
		fs.IntVar(&imp.WantVerified, "want-verified", 0, "exact number of verified genuine crawler requests (0: not checked)")
		required["-impersonators"] = &imp.Impersonators
		counts = []*int{&imp.WantSettled, &imp.WantVerified}
	case "clearance":
		fs.StringVar(&clr.Site, "site", "", "only events of this site id")
		fs.StringVar(&clr.Protected, "protected", "", "path prefix of the require_clearance route (required)")
		fs.IntVar(&clr.WantFeedback, "want-feedback", 0, "exact number of challenge submissions (0: at least one)")
		required["-protected"] = &clr.Protected
		counts = []*int{&clr.WantFeedback}
	case "providers":
		fs.StringVar(&prv.Site, "site", "", "only events of this site id")
		fs.StringVar(&prv.Route, "route", "", "route id that offers the provider (required)")
		fs.Var(&offer, "offer", "comma-separated countries that must be offered the provider; all others must not")
		fs.StringVar(&prv.Provider, "provider", "turnstile", "external provider id")
		fs.IntVar(&prv.WantOffered, "want-offered", 0, "exact number of challenges for allowed countries (0: at least one)")
		fs.IntVar(&prv.WantWithheld, "want-withheld", 0, "exact number of challenges for other countries (0: at least one)")
		required["-route"] = &prv.Route
		counts = []*int{&prv.WantOffered, &prv.WantWithheld}
	case "nearline":
		fs.StringVar(&nl.Site, "site", "", "only events of this site id")
		fs.StringVar(&nl.Detector, "detector", "scanner", "near-line detector")
		fs.StringVar(&nl.After, "after", "", "path prefix of the requests sent after the verdicts (required)")
		fs.StringVar(&nl.ShadowIP, "shadow-ip", "", "address that sent the baits in shadow mode (required)")
		fs.StringVar(&nl.EnforceIP, "enforce-ip", "", "address that sent the baits in enforce mode (required)")
		fs.StringVar(&nl.FreshIP, "fresh-ip", "", "address that sent no bait")
		fs.Int64Var(&nl.MaxLatencyMS, "max-latency-ms", 0, "bound from the triggering request to its verdict (0: not checked)")
		required["-after"], required["-shadow-ip"], required["-enforce-ip"] = &nl.After, &nl.ShadowIP, &nl.EnforceIP
		maxFiles = 8
	default:
		fmt.Fprintf(stderr, "mglab events: unknown check %q (impersonator, clearance, providers or nearline)\n", mode)
		return ExitUsage
	}
	if err := fs.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if fs.NArg() < 1 || fs.NArg() > maxFiles {
		if maxFiles == 1 {
			fmt.Fprintf(stderr, "mglab events %s: expected exactly one event file\n", mode)
		} else {
			fmt.Fprintf(stderr, "mglab events %s: expected 1-%d event files\n", mode, maxFiles)
		}
		return ExitUsage
	}
	for _, name := range sortedFlags(required) {
		if *required[name] == "" {
			fmt.Fprintf(stderr, "mglab events %s: %s is required\n", mode, name)
			return ExitUsage
		}
	}
	for _, c := range counts {
		if *c < 0 {
			fmt.Fprintf(stderr, "mglab events %s: counts must not be negative\n", mode)
			return ExitUsage
		}
	}
	if nl.MaxLatencyMS < 0 {
		fmt.Fprintf(stderr, "mglab events %s: -max-latency-ms must not be negative\n", mode)
		return ExitUsage
	}
	prv.Offer = offer
	recs, err := events.ReadFiles(fs.Args()...)
	if err != nil {
		fmt.Fprintf(stderr, "mglab events %s: %v\n", mode, err)
		return ExitUsage
	}
	var summary fmt.Stringer
	var problems []string
	switch mode {
	case "impersonator":
		rep := events.CheckImpersonators(recs, imp)
		summary, problems = rep, rep.Problems
	case "clearance":
		rep := events.CheckClearance(recs, clr)
		summary, problems = rep, rep.Problems
	case "providers":
		rep := events.CheckProviders(recs, prv)
		summary, problems = rep, rep.Problems
	default:
		rep := events.CheckNearline(recs, nl)
		summary, problems = rep, rep.Problems
	}
	for _, p := range problems {
		fmt.Fprintf(stdout, "FAIL  %s\n", p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(stdout, "FAIL  %s\n", summary)
		return ExitDenied
	}
	fmt.Fprintf(stdout, "PASS  %s\n", summary)
	return ExitOK
}

func sortedFlags(m map[string]*string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
