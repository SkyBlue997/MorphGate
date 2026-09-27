// Package server is the mg-control HTTP API.
//
// Phase 0 serves only a health check and a placeholder for bundle
// distribution. Phase 3 implements signed SiteBundle distribution: the Edge
// long-polls GET /v1/bundles/{site} with ETag over mTLS or WireGuard
// (docs/06 §3, design brief B6).
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Config for the HTTP server.
type Config struct {
	// ShutdownTimeout bounds how long in-flight requests may take to finish
	// after the context is cancelled.
	ShutdownTimeout time.Duration
	Logger          *slog.Logger
}

// Handler returns the API routes.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	// Bundle distribution is implemented in Phase 3. The path is reserved now
	// so the Edge's pull client (Phase 1) can already treat 404 as "no bundle"
	// and stay on its last-known-good configuration.
	mux.HandleFunc("GET /v1/bundles/{site}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotFound, struct {
			Error string `json:"error"`
			Phase int    `json:"phase"`
		}{"not_implemented", 3})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Serve serves the API on ln until ctx is cancelled, then shuts down
// gracefully: it stops accepting connections and waits up to
// cfg.ShutdownTimeout for in-flight requests.
func Serve(ctx context.Context, ln net.Listener, cfg Config) error {
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 10 * time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	srv := &http.Server{
		Handler:           Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("mg-control listening", "addr", ln.Addr().String())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	log.Info("mg-control shutting down", "timeout", cfg.ShutdownTimeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
