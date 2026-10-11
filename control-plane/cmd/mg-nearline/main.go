// Command mg-nearline is the MorphGate near-line worker: it consumes the mg:ev
// stream (consumer group nl), runs the v1 detectors and writes risk-raising
// verdicts through the mg_verdict_put script (docs/impl/phase2-spec.md §13).
//
// Usage:
//
//	mg-nearline [--config /etc/morphgate/mg-nearline.yaml]
//	mg-nearline --check-config [--config ...]
//	mg-nearline --version
//
// Exit status: 0 on a clean stop (SIGINT / SIGTERM) or a passed
// --check-config; 1 when Valkey or the metrics listener cannot be used;
// 2 for an invalid configuration or command line.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"morphgate/control-plane/internal/nearline"
	"morphgate/control-plane/internal/version"
)

// DefaultConfigPath is the configuration file the systemd unit uses.
const DefaultConfigPath = "/etc/morphgate/mg-nearline.yaml"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("mg-nearline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", DefaultConfigPath, "configuration file (YAML)")
	checkConfig := fs.Bool("check-config", false, "validate the configuration, connect to Valkey, load the script, then exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "mg-nearline: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version.String("mg-nearline"))
		return 0
	}
	cfg, err := nearline.LoadConfig(*configPath, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "mg-nearline: %v\n", err)
		return 2
	}
	password, err := nearline.LoadPassword(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "mg-nearline: %v\n", err)
		return 2
	}
	if *checkConfig {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := nearline.CheckValkey(ctx, cfg, password); err != nil {
			fmt.Fprintf(stderr, "mg-nearline: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "mg-nearline: configuration OK (%d site(s); Valkey reachable; mg_verdict_put %s)\n", len(cfg.Sites), nearline.VerdictPutSHA)
		return 0
	}

	log := slog.New(slog.NewJSONHandler(stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for _, d := range nearline.Detectors {
		log.Info("detector", "name", d, "mode", cfg.Detectors.Mode(d))
	}
	if err := nearline.Serve(ctx, cfg, password, log); err != nil {
		log.Error("mg-nearline failed", "err", err)
		return 1
	}
	log.Info("mg-nearline stopped")
	return 0
}
