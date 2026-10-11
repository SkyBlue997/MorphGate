package nearline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// UserAgent of every outbound request (Phase 1 rulings I-7 / I-15).
const UserAgent = "morphgate-dev-tooling"

// VL sink limits.
const (
	vlQueue      = 1024
	vlMaxBatch   = 256
	vlTimeout    = 5 * time.Second
	vlFlushAfter = time.Second
)

// vlBackoff is the wait before each retry of a batch (the Edge's §9.11
// schedule); after the last one the batch is dropped.
var vlBackoff = []time.Duration{200 * time.Millisecond, time.Second, 5 * time.Second}

// VLSink sends kind=verdict lines to VictoriaLogs vl-main. Enqueue never
// blocks: a full queue drops the line and counts mg_nl_errors_total{op="vl"}.
type VLSink struct {
	url     string
	http    *http.Client
	ch      chan []byte
	metrics *Metrics
	log     *slog.Logger
	backoff []time.Duration
	done    chan struct{}
}

// NewVLSink validates base (verdict_events.vl_main) and returns a sink;
// call Run to start sending.
func NewVLSink(base string, m *Metrics, log *slog.Logger) (*VLSink, error) {
	u, err := VLInsertURL(base)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &VLSink{
		url: u,
		http: &http.Client{
			Timeout:   vlTimeout,
			Transport: &http.Transport{Proxy: nil, MaxIdleConns: 2, IdleConnTimeout: time.Minute},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ch:      make(chan []byte, vlQueue),
		metrics: m,
		log:     log,
		backoff: vlBackoff,
		done:    make(chan struct{}),
	}, nil
}

// Enqueue queues one JSON line.
func (s *VLSink) Enqueue(line []byte) {
	select {
	case s.ch <- line:
	default:
		s.metrics.Error(OpVL)
	}
}

// Run sends batches until ctx is cancelled, then sends what is queued once
// more and returns. Done is closed when it returns.
func (s *VLSink) Run(ctx context.Context) {
	defer close(s.done)
	for {
		var batch [][]byte
		select {
		case <-ctx.Done():
			s.flushQueued()
			return
		case l := <-s.ch:
			batch = append(batch, l)
		}
		deadline := time.NewTimer(vlFlushAfter)
	collect:
		for len(batch) < vlMaxBatch {
			select {
			case l := <-s.ch:
				batch = append(batch, l)
			case <-deadline.C:
				break collect
			case <-ctx.Done():
				break collect
			}
		}
		deadline.Stop()
		s.post(ctx, batch)
	}
}

// Done is closed when Run has returned.
func (s *VLSink) Done() <-chan struct{} { return s.done }

func (s *VLSink) flushQueued() {
	var batch [][]byte
	for {
		select {
		case l := <-s.ch:
			batch = append(batch, l)
			continue
		default:
		}
		break
	}
	if len(batch) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.send(ctx, bytes.Join(batch, []byte("\n")))
	}
}

func (s *VLSink) post(ctx context.Context, batch [][]byte) {
	body := append(bytes.Join(batch, []byte("\n")), '\n')
	for attempt := 0; ; attempt++ {
		err := s.send(ctx, body)
		if err == nil {
			return
		}
		var perm permanentError
		if errors.As(err, &perm) || attempt >= len(s.backoff) || ctx.Err() != nil {
			s.metrics.Error(OpVL)
			s.log.Warn("verdict events dropped", "lines", len(batch), "err", err)
			return
		}
		sleep(ctx, s.backoff[attempt])
	}
}

type permanentError struct{ status int }

func (e permanentError) Error() string { return fmt.Sprintf("HTTP %d", e.status) }

func (s *VLSink) send(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return permanentError{}
	}
	req.Header.Set("Content-Type", vlJSONContentType)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	default:
		return permanentError{resp.StatusCode}
	}
}
