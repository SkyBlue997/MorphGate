// Package cli implements the mglab command line; cmd/mglab only calls Run.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"morphgate/lab/internal/guard"
	"morphgate/lab/internal/replay"
)

// Exit codes.
const (
	ExitOK     = 0
	ExitDenied = 1 // target denied or replay had failures
	ExitUsage  = 2 // usage or configuration error
)

const usage = `mglab - MorphGate Validation Lab (sends traffic only to allowlisted targets)

Usage:
  mglab check  [-config lab.yaml] [-resolve] <url>
  mglab replay [-config lab.yaml] [-base URL] [-rps N] <scenario.yaml>

Without -config the built-in allowlist is used: localhost, *.test, *.localhost,
127.0.0.0/8 and ::1 (see lab/config/lab.example.yaml).

  check    print whether the URL is allowed and why; -resolve also resolves the
           host and validates every address (no connection is made)
  replay   send the scenario's recorded requests one by one to the base URL,
           rate-capped (default 5 req/s, hard maximum 50)

Exit status: 0 allowed / all requests as expected, 1 denied or failures,
2 usage or configuration error.
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

func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer, opts []guard.Option) int {
	fs := flag.NewFlagSet("mglab check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "allowlist config (YAML); default: built-in local-only allowlist")
	resolve := fs.Bool("resolve", false, "also resolve the host and validate every address")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "mglab check: expected exactly one URL")
		return ExitUsage
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "mglab check: %v\n", err)
		return ExitUsage
	}
	g, err := guard.New(cfg, opts...)
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
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "mglab replay: expected exactly one scenario file")
		return ExitUsage
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "mglab replay: %v\n", err)
		return ExitUsage
	}
	if *rps != 0 {
		cfg.RateRPS = *rps
	}
	g, err := guard.New(cfg, opts...)
	if err != nil {
		fmt.Fprintf(stderr, "mglab replay: %v\n", err)
		return ExitUsage
	}
	s, err := replay.Load(fs.Arg(0))
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
