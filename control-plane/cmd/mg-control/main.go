// Command mg-control is the MorphGate control-plane service.
//
// Phase 0: health check and a reserved bundle endpoint only. Phase 3 adds the
// admin API, PostgreSQL/SQLite storage and signed bundle distribution.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"morphgate/control-plane/internal/server"
	"morphgate/control-plane/internal/version"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "listen address (host:port)")
	shutdown := flag.Duration("shutdown-timeout", 10*time.Second, "grace period for in-flight requests on SIGINT/SIGTERM")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String("mg-control"))
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen failed", "addr", *listen, "err", err)
		os.Exit(1)
	}
	if err := server.Serve(ctx, ln, server.Config{ShutdownTimeout: *shutdown, Logger: log}); err != nil {
		log.Error("server failed", "err", err)
		os.Exit(1)
	}
	log.Info("mg-control stopped")
}
