package nearline

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Error ops of mg_nl_errors_total.
const (
	OpConnect   = "connect"
	OpGroup     = "group"
	OpRead      = "read"
	OpAutoclaim = "autoclaim"
	OpAck       = "ack"
	OpVerdict   = "verdict"
	OpConsumers = "consumers"
	OpStatus    = "status"
	OpVL        = "vl"
)

var errorOps = []string{OpConnect, OpGroup, OpRead, OpAutoclaim, OpAck, OpVerdict, OpConsumers, OpStatus, OpVL}

// Metrics are the worker's metrics (spec §13.7), served in the Prometheus
// text format. All label values are bounded: configured sites, the four
// detectors, the two modes and the fixed ops.
type Metrics struct {
	mu          sync.Mutex
	entries     map[[2]string]uint64 // site, kind
	parseErrors uint64
	verdicts    map[[3]string]uint64 // site, detector, mode
	dropped     map[string]uint64
	errors      map[string]uint64
	lagSeconds  float64
	backlog     float64
	pending     float64
	lastBatch   float64
	visitor     map[string]float64
	abandon     map[string]float64
}

// NewMetrics returns metrics with every bounded series present at zero.
func NewMetrics(cfg *Config) *Metrics {
	m := &Metrics{
		entries:  map[[2]string]uint64{},
		verdicts: map[[3]string]uint64{},
		dropped:  map[string]uint64{},
		errors:   map[string]uint64{},
		visitor:  map[string]float64{},
		abandon:  map[string]float64{},
	}
	for _, s := range cfg.Sites {
		m.entries[[2]string{s, "decision"}] = 0
		m.entries[[2]string{s, "feedback"}] = 0
		for _, d := range Detectors {
			m.verdicts[[3]string{s, d, cfg.Detectors.Mode(d)}] = 0
		}
	}
	for _, d := range Detectors {
		m.dropped[d] = 0
	}
	for _, op := range errorOps {
		m.errors[op] = 0
	}
	return m
}

// Entry counts one processed entry of a configured site.
func (m *Metrics) Entry(site string, k Kind) {
	m.mu.Lock()
	m.entries[[2]string{site, k.String()}]++
	m.mu.Unlock()
}

// ParseError counts one unparseable entry.
func (m *Metrics) ParseError() {
	m.mu.Lock()
	m.parseErrors++
	m.mu.Unlock()
}

// Verdict counts one verdict.
func (m *Metrics) Verdict(site, detector, mode string) {
	m.mu.Lock()
	m.verdicts[[3]string{site, detector, mode}]++
	m.mu.Unlock()
}

// Dropped counts one key a full window refused.
func (m *Metrics) Dropped(detector string) {
	m.mu.Lock()
	m.dropped[detector]++
	m.mu.Unlock()
}

// Error counts one failed operation.
func (m *Metrics) Error(op string) {
	m.mu.Lock()
	m.errors[op]++
	m.mu.Unlock()
}

// SetStatus sets the group status gauges.
func (m *Metrics) SetStatus(lagSeconds float64, backlog, pending int64) {
	m.mu.Lock()
	m.lagSeconds, m.backlog, m.pending = lagSeconds, float64(backlog), float64(pending)
	m.mu.Unlock()
}

// SetLastBatch sets mg_nl_last_batch_timestamp_seconds (Unix seconds).
func (m *Metrics) SetLastBatch(unixSeconds float64) {
	m.mu.Lock()
	m.lastBatch = unixSeconds
	m.mu.Unlock()
}

// SetShares sets (or, when unavailable, removes) a site's acceptance shares.
func (m *Metrics) SetShares(site string, s Shares) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.HasVisitor {
		m.visitor[site] = s.Visitor
	} else {
		delete(m.visitor, site)
	}
	if s.HasAbandon {
		m.abandon[site] = s.Abandon
	} else {
		delete(m.abandon, site)
	}
}

// WriteText writes every family in the Prometheus text format.
func (m *Metrics) WriteText(w io.Writer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := bufio.NewWriter(w)
	family := func(name, typ, help string) {
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	sample := func(name string, labels []string, v float64) {
		b.WriteString(name)
		if len(labels) > 0 {
			b.WriteByte('{')
			for i := 0; i < len(labels); i += 2 {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(labels[i])
				b.WriteString(`="`)
				b.WriteString(escapeLabel(labels[i+1]))
				b.WriteByte('"')
			}
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
		b.WriteByte('\n')
	}

	family("mg_nl_entries_total", "counter", "mg:ev entries processed, by site and kind.")
	for _, k := range sortedKeys(m.entries, func(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) }) {
		sample("mg_nl_entries_total", []string{"site", k[0], "kind", k[1]}, float64(m.entries[k]))
	}
	family("mg_nl_parse_errors_total", "counter", "mg:ev entries that could not be parsed (acknowledged and skipped).")
	sample("mg_nl_parse_errors_total", nil, float64(m.parseErrors))
	family("mg_nl_verdicts_total", "counter", "Verdicts produced, by site, detector and mode.")
	for _, k := range sortedKeys(m.verdicts, func(a, b [3]string) int {
		return strings.Compare(strings.Join(a[:], "\x00"), strings.Join(b[:], "\x00"))
	}) {
		sample("mg_nl_verdicts_total", []string{"site", k[0], "detector", k[1], "mode", k[2]}, float64(m.verdicts[k]))
	}
	family("mg_nl_lag_seconds", "gauge", "Age of the oldest unacknowledged or undelivered entry; 0 when the group has caught up.")
	sample("mg_nl_lag_seconds", nil, m.lagSeconds)
	family("mg_nl_backlog", "gauge", "Entries not yet delivered to the group (XINFO GROUPS lag).")
	sample("mg_nl_backlog", nil, m.backlog)
	family("mg_nl_pending", "gauge", "Entries delivered but not acknowledged (XPENDING).")
	sample("mg_nl_pending", nil, m.pending)
	family("mg_nl_window_dropped_total", "counter", "New keys refused because a detector window was full.")
	for _, k := range sortedKeys(m.dropped, strings.Compare) {
		sample("mg_nl_window_dropped_total", []string{"detector", k}, float64(m.dropped[k]))
	}
	family("mg_nl_errors_total", "counter", "Failed operations, by op.")
	for _, k := range sortedKeys(m.errors, strings.Compare) {
		sample("mg_nl_errors_total", []string{"op", k}, float64(m.errors[k]))
	}
	family("mg_nl_last_batch_timestamp_seconds", "gauge", "Unix time of the last completed stream read (empty reads included).")
	sample("mg_nl_last_batch_timestamp_seconds", nil, m.lastBatch)
	family("mg_nl_interactive_visitor_share", "gauge", "7-day share of visitors (ipk with an HTML response) that got an interactive challenge.")
	for _, k := range sortedKeys(m.visitor, strings.Compare) {
		sample("mg_nl_interactive_visitor_share", []string{"site", k}, m.visitor[k])
	}
	family("mg_nl_interactive_abandon_share", "gauge", "7-day share of interactively challenged visitors that did not pass within 10 minutes.")
	for _, k := range sortedKeys(m.abandon, strings.Compare) {
		sample("mg_nl_interactive_abandon_share", []string{"site", k}, m.abandon[k])
	}
	return b.Flush()
}

func sortedKeys[K comparable, V any](m map[K]V, cmp func(a, b K) int) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, cmp)
	return keys
}

func escapeLabel(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// Handler serves GET /metrics.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = m.WriteText(w)
	})
	return mux
}
