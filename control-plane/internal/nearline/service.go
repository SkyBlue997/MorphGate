package nearline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// ClientName is sent with HELLO (CLIENT SETNAME) so that CLIENT LIST shows
// the worker's connections.
const ClientName = "mg-nearline"

// ConnOptionsFor returns the connection options of cfg with password (read
// from valkey.password_file by the caller; "" when there is none).
func ConnOptionsFor(cfg *Config, password string) (ConnOptions, error) {
	addr, err := ParseValkeyURL(cfg.Valkey.URL)
	if err != nil {
		return ConnOptions{}, fmt.Errorf("valkey.url: %w", err)
	}
	return ConnOptions{Addr: addr, User: cfg.Valkey.User, Password: password, ClientName: ClientName}, nil
}

// LoadPassword reads valkey.password_file when it is set.
func LoadPassword(cfg *Config) (string, error) {
	if cfg.Valkey.PasswordFile == "" {
		return "", nil
	}
	return ReadPassword(cfg.Valkey.PasswordFile)
}

// CheckValkey connects as the configured user, checks PING and loads
// mg_verdict_put (mg-nearline --check-config).
func CheckValkey(ctx context.Context, cfg *Config, password string) error {
	o, err := ConnOptionsFor(cfg, password)
	if err != nil {
		return err
	}
	return CheckValkeyWith(ctx, o, cfg)
}

// CheckValkeyWith is CheckValkey with explicit connection options.
func CheckValkeyWith(ctx context.Context, o ConnOptions, cfg *Config) error {
	s, err := Dial(ctx, o, cfg.Stream.Key, cfg.Stream.Group, ConsumerName())
	if err != nil {
		return err
	}
	defer s.Close()
	return s.LoadScript(ctx)
}

// Serve runs the worker until ctx is cancelled: /metrics, the optional
// VictoriaLogs sink, and the consumer, which (re)connects to Valkey with
// backoff so that a Valkey restart never stops the unit.
func Serve(ctx context.Context, cfg *Config, password string, log *slog.Logger) error {
	ln, err := net.Listen("tcp", cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("metrics_listen: %w", err)
	}
	return serve(ctx, cfg, password, log, ln)
}

func serve(ctx context.Context, cfg *Config, password string, log *slog.Logger, ln net.Listener) error {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	m := NewMetrics(cfg)
	var err error
	srv := &http.Server{
		Handler:           m.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("mg-nearline metrics listening", "addr", ln.Addr().String())

	var vl *VLSink
	if cfg.VerdictEvents.VLMain != "" {
		if vl, err = NewVLSink(cfg.VerdictEvents.VLMain, m, log); err != nil {
			return fmt.Errorf("verdict_events.vl_main: %w", err)
		}
		vctx, cancel := context.WithCancel(context.Background())
		go vl.Run(vctx)
		defer func() { cancel(); <-vl.Done() }()
	}

	o, err := ConnOptionsFor(cfg, password)
	if err != nil {
		return err
	}
	consumer := ConsumerName()
	backoff := time.Second
	for ctx.Err() == nil {
		store, err := Dial(ctx, o, cfg.Stream.Key, cfg.Stream.Group, consumer)
		if err == nil {
			w := NewWorker(cfg, store, m, log, vl, time.Now)
			if err = w.Start(ctx); err == nil {
				log.Info("mg-nearline consuming", "stream", cfg.Stream.Key, "group", cfg.Stream.Group, "consumer", consumer, "sites", cfg.Sites)
				backoff = time.Second
				w.Run(ctx)
				store.Close()
				break
			}
			store.Close()
		} else {
			m.Error(OpConnect)
		}
		if ctx.Err() != nil {
			break
		}
		log.Warn("valkey not ready, retrying", "err", err, "in", backoff.String())
		sleep(ctx, backoff)
		backoff = min(2*backoff, 30*time.Second)
	}
	select {
	case err := <-srvErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("metrics server: %w", err)
		}
	default:
	}
	return nil
}
