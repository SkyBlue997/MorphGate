package nearline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"
)

// VerdictVersion is the version field of every near-line verdict (§13.4).
const VerdictVersion = "p2.1"

// Intervals of the background duties (spec §13.3, §13.7).
const (
	StatusEvery = 15 * time.Second
	SharesEvery = time.Minute
)

// EntityVerdict is mg_core::EntityVerdict (Phase 1 format), in its field
// order; labels and reasons are omitted when empty, as serde does.
type EntityVerdict struct {
	Type        string   `json:"type"`
	Key         string   `json:"key"`
	Risk        int      `json:"risk"`
	Labels      []string `json:"labels,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
	ExpiresAtMs int64    `json:"expires_at_ms"`
	Source      string   `json:"source"`
	Version     string   `json:"version"`
	SiteID      string   `json:"site_id"`
}

// verdictLine is a kind=verdict event (spec §15.3): the envelope keys first
// (kind, site, ts, msg), then the EntityVerdict fields, then detector, mode,
// written and evidence. Pseudonymous keys only, never an IP.
type verdictLine struct {
	Kind string `json:"kind"`
	Site string `json:"site"`
	TS   int64  `json:"ts"`
	Msg  string `json:"msg"`
	EntityVerdict
	Detector string         `json:"detector"`
	Mode     string         `json:"mode"`
	Written  bool           `json:"written"`
	Evidence map[string]any `json:"evidence"`
}

// Worker is the near-line consumer (spec §13.2).
type Worker struct {
	cfg     *Config
	store   *Store
	proc    *Processor
	metrics *Metrics
	log     *slog.Logger
	vl      *VLSink
	now     func() time.Time

	caughtUpMs  atomic.Int64 // send time of the last read that left nothing undelivered
	lastBacklog int64        // PollStatus only
}

// NewWorker returns a worker. vl may be nil (no verdict_events.vl_main);
// now is the clock (time.Now in production).
func NewWorker(cfg *Config, store *Store, m *Metrics, log *slog.Logger, vl *VLSink, now func() time.Time) *Worker {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if now == nil {
		now = time.Now
	}
	return &Worker{cfg: cfg, store: store, metrics: m, log: log, vl: vl, now: now, proc: NewProcessor(cfg, m.Dropped)}
}

// Processor returns the worker's detector state (tests).
func (w *Worker) Processor() *Processor { return w.proc }

// ConsumerName returns "<hostname>-<pid>" (spec §13.2).
func ConsumerName() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "mg-nearline"
	}
	return h + "-" + strconv.Itoa(os.Getpid())
}

// Start prepares the group: loads the script, creates the group at the
// stream's end when it does not exist, deletes earlier consumers without
// pending entries and claims entries left idle by earlier processes.
func (w *Worker) Start(ctx context.Context) error {
	if err := w.store.LoadScript(ctx); err != nil {
		w.metrics.Error(OpVerdict)
		return err
	}
	created, err := w.store.EnsureGroup(ctx)
	if err != nil {
		w.metrics.Error(OpGroup)
		return err
	}
	if created {
		w.log.Info("created consumer group", "stream", w.cfg.Stream.Key, "group", w.cfg.Stream.Group)
	}
	// A failed reclaim (for example a verdict write that keeps failing) must
	// not keep the worker from consuming; the next period retries it.
	if err := w.Reclaim(ctx); err != nil && ctx.Err() == nil {
		w.log.Warn("reclaim failed", "err", err)
	}
	return ctx.Err()
}

// Run consumes until ctx is cancelled. Start must have succeeded. The
// stream status is polled on its own goroutine, so the gauges stay current
// while the consumer loop waits on Valkey.
func (w *Worker) Run(ctx context.Context) {
	// One read first, so that the status poller knows when the group was
	// last caught up (see PollStatus).
	if err := w.Step(ctx); err != nil && ctx.Err() == nil {
		w.log.Warn("consume failed", "err", err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			if err := w.PollStatus(ctx); err != nil && ctx.Err() == nil {
				w.log.Warn("stream status failed", "err", err)
			}
			sleep(ctx, StatusEvery)
			if ctx.Err() != nil {
				return
			}
		}
	})
	defer wg.Wait()
	reclaimEvery := time.Duration(w.cfg.Stream.ReclaimEveryS) * time.Second
	now := w.now()
	nextReclaim, nextShares := now.Add(reclaimEvery), now
	for ctx.Err() == nil {
		now = w.now()
		if !now.Before(nextReclaim) {
			nextReclaim = now.Add(reclaimEvery)
			if err := w.Reclaim(ctx); err != nil && ctx.Err() == nil {
				w.log.Warn("reclaim failed", "err", err)
			}
		}
		if !now.Before(nextShares) {
			nextShares = now.Add(SharesEvery)
			w.UpdateShares()
		}
		if err := w.Step(ctx); err != nil && ctx.Err() == nil {
			w.log.Warn("consume failed", "err", err)
			sleep(ctx, time.Second)
		}
	}
}

// Step reads one batch (blocking up to block_ms) and handles it.
func (w *Worker) Step(ctx context.Context) error {
	sent := w.now()
	entries, err := w.store.ReadGroup(ctx, w.cfg.Stream.Batch, w.cfg.Stream.BlockMs)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		w.metrics.Error(OpRead)
		if ve := (*valkey.ValkeyError)(nil); errors.As(err, &ve) && strings.HasPrefix(ve.Error(), "NOGROUP") {
			// The stream or the group was deleted: start again at its end.
			if _, gerr := w.store.EnsureGroup(ctx); gerr != nil {
				w.metrics.Error(OpGroup)
			}
		}
		return err
	}
	w.metrics.SetLastBatch(float64(w.now().UnixMilli()) / 1000)
	if len(entries) < w.cfg.Stream.Batch {
		w.caughtUpMs.Store(sent.UnixMilli())
	}
	return w.Handle(ctx, entries)
}

// Reclaim claims entries idle for reclaim_idle_ms (XAUTOCLAIM, including
// those of exited consumers), handles them, then deletes the other
// consumers that no longer have pending entries.
func (w *Worker) Reclaim(ctx context.Context) error {
	start := "0-0"
	for range 10_000 {
		next, entries, err := w.store.AutoClaim(ctx, int64(w.cfg.Stream.ReclaimIdleMs), start, w.cfg.Stream.Batch)
		if err != nil {
			w.metrics.Error(OpAutoclaim)
			return err
		}
		if len(entries) > 0 {
			if err := w.Handle(ctx, entries); err != nil {
				return err
			}
		}
		if next == "0-0" || next == "" {
			break
		}
		start = next
	}
	deleted, err := w.store.DeleteIdleConsumers(ctx)
	if err != nil {
		w.metrics.Error(OpConsumers)
		return err
	}
	if len(deleted) > 0 {
		w.log.Info("deleted idle consumers", "consumers", deleted)
	}
	return nil
}

// errVerdictWrite leaves a batch unacknowledged.
var errVerdictWrite = errors.New("a verdict could not be written; the batch stays pending")

// Handle parses and processes entries, writes or logs the verdicts they
// trigger, then acknowledges them. Unparseable entries and entries of other
// sites are acknowledged too. When a verdict write fails, nothing is
// acknowledged: XAUTOCLAIM delivers the batch again (at-least-once; the
// windows tolerate the duplicates).
func (w *Worker) Handle(ctx context.Context, entries []StreamEntry) error {
	nowMs := w.now().UnixMilli()
	ids := make([]string, 0, len(entries))
	var verdicts []Verdict
	for _, se := range entries {
		ids = append(ids, se.ID)
		e, err := ParseEntry(se.Fields)
		if err != nil {
			w.metrics.ParseError()
			continue
		}
		if !w.proc.HasSite(e.Site) {
			continue
		}
		w.metrics.Entry(e.Site, e.Kind)
		verdicts = append(verdicts, w.proc.Process(&e, nowMs)...)
	}
	failed := false
	for i := range verdicts {
		if !w.emit(ctx, &verdicts[i], nowMs) {
			failed = true
		}
	}
	if failed {
		return errVerdictWrite
	}
	if err := w.store.Ack(ctx, ids); err != nil {
		w.metrics.Error(OpAck)
		return err
	}
	return nil
}

// emit writes (enforce) or only reports (shadow) one verdict. It returns
// false when the enforce write failed.
func (w *Worker) emit(ctx context.Context, v *Verdict, nowMs int64) bool {
	ttlMs := int64(v.TTL / time.Millisecond)
	ev := EntityVerdict{
		Type: v.Type, Key: v.Key, Risk: v.Risk, Labels: v.Labels, Reasons: v.Reasons,
		ExpiresAtMs: nowMs + ttlMs, Source: v.Source(), Version: VerdictVersion, SiteID: v.Site,
	}
	written := false
	if v.Mode == ModeEnforce {
		data, err := json.Marshal(ev)
		if err == nil {
			written, err = w.store.PutVerdict(ctx, v.VerdictKey(), string(data), ttlMs, v.Risk, nowMs, ev.Source)
		}
		if err != nil {
			w.metrics.Error(OpVerdict)
			w.log.Warn("verdict write failed", "site", v.Site, "detector", v.Detector, "type", v.Type, "err", err)
			v.Rearm()
			return false
		}
	}
	w.metrics.Verdict(v.Site, v.Detector, v.Mode)
	w.log.Info("nearline verdict", "site", v.Site, "detector", v.Detector, "mode", v.Mode,
		"type", v.Type, "key", v.Key, "risk", v.Risk, "ttl_ms", ttlMs, "written", written, "evidence", v.Evidence)
	if w.vl != nil {
		line, err := json.Marshal(verdictLine{
			Kind: "verdict", Site: v.Site, TS: nowMs,
			Msg:           fmt.Sprintf("verdict %s %s %s risk=%d", ev.Source, v.Type, v.Mode, v.Risk),
			EntityVerdict: ev, Detector: v.Detector, Mode: v.Mode, Written: written, Evidence: v.Evidence,
		})
		if err == nil {
			w.vl.Enqueue(line)
		}
	}
	return true
}

// PollStatus updates mg_nl_backlog, mg_nl_pending and mg_nl_lag_seconds
// (spec §13.7).
//
// The worker's ACL has no XRANGE, so the ts of the oldest undelivered entry
// is bounded from below instead of read: such an entry was added after the
// last delivered ID and after the last read that left nothing undelivered.
// The lag is thus never under-reported, and it is 0 whenever the group has
// caught up (lag = 0 and nothing pending), however long the stream was idle.
// Stream IDs are XADD's own millisecond clock (the Edge adds with "*"), which
// stands in for the entry's ts field.
func (w *Worker) PollStatus(ctx context.Context) error {
	g, err := w.store.Group(ctx)
	if err != nil {
		w.metrics.Error(OpStatus)
		return err
	}
	pending, minID, err := w.store.PendingSummary(ctx)
	if err != nil {
		w.metrics.Error(OpStatus)
		return err
	}
	nowMs := w.now().UnixMilli()
	oldest := int64(-1)
	if pending > 0 {
		if ms, ok := IDMillis(minID); ok {
			oldest = ms
		}
	}
	backlog := g.Lag
	if !g.LagKnown {
		// Valkey cannot tell (entries deleted in the middle, XSETID): keep
		// the last value and assume a backlog for the lag.
		backlog = w.lastBacklog
		w.metrics.Error(OpStatus)
	}
	w.lastBacklog = backlog
	if !g.LagKnown || g.Lag > 0 {
		est := w.caughtUpMs.Load()
		if ms, ok := IDMillis(g.LastDelivered); ok && ms > est {
			est = ms
		}
		// est = 0: nothing was ever delivered and no read has completed
		// yet (only possible before the first read); no bound is known.
		if est > 0 && (oldest < 0 || est < oldest) {
			oldest = est
		}
	}
	lag := 0.0
	if oldest >= 0 && nowMs > oldest {
		lag = float64(nowMs-oldest) / 1000
	}
	w.metrics.SetStatus(lag, backlog, pending)
	return nil
}

// UpdateShares recomputes the acceptance shares of every site.
func (w *Worker) UpdateShares() {
	nowMs := w.now().UnixMilli()
	for _, s := range w.cfg.Sites {
		w.metrics.SetShares(s, w.proc.Shares(s, nowMs))
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
