package intelsync

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"morphgate/control-plane/internal/cli"
)

// Paths relative to this package directory.
const (
	phase1Artifacts = "../../../testdata/phase1/artifacts"
	intelFixtures   = "../../testdata/intel"
)

// fakeResp is one canned response of the fake internet.
type fakeResp struct {
	status   int
	body     []byte
	location string        // redirect target
	delay    time.Duration // before answering
}

// fakeNet is an in-process TLS server that answers for every host name: the
// client it returns dials the server for any URL and verifies the httptest
// certificate, so tests use the real https URLs of the spec without touching
// the network.
type fakeNet struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	routes map[string]fakeResp // "host/path"
	hits   map[string]int
	uas    []string
}

func newFakeNet(t *testing.T) *fakeNet {
	t.Helper()
	f := &fakeNet{t: t, routes: map[string]fakeResp{}, hits: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNet) set(hostPath string, r fakeResp) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.status == 0 {
		r.status = http.StatusOK
	}
	f.routes[hostPath] = r
}

func (f *fakeNet) setFile(hostPath, file string) {
	f.t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		f.t.Fatal(err)
	}
	f.set(hostPath, fakeResp{body: b})
}

func (f *fakeNet) serve(w http.ResponseWriter, r *http.Request) {
	key := r.Host + r.URL.Path
	f.mu.Lock()
	resp, ok := f.routes[key]
	f.hits[key]++
	f.uas = append(f.uas, r.Header.Get("User-Agent"))
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if resp.delay > 0 {
		select {
		case <-time.After(resp.delay):
		case <-r.Context().Done():
			return
		}
	}
	if resp.location != "" {
		w.Header().Set("Location", resp.location)
	}
	w.WriteHeader(resp.status)
	_, _ = w.Write(resp.body)
}

func (f *fakeNet) hitCount(hostPath string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[hostPath]
}

// client returns an http.Client whose every connection goes to the fake.
func (f *fakeNet) client() *http.Client {
	tr := f.srv.Client().Transport.(*http.Transport).Clone()
	addr := f.srv.Listener.Addr().String()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	tr.TLSClientConfig.ServerName = "example.com" // the httptest certificate's name
	return &http.Client{Transport: tr}
}

// testEnv is a cli.Env with captured output and audit events.
type testEnv struct {
	env    cli.Env
	out    *bytes.Buffer
	errb   *bytes.Buffer
	audits []cli.AuditEvent
}

func newTestEnv(now time.Time, hc *http.Client) *testEnv {
	te := &testEnv{out: &bytes.Buffer{}, errb: &bytes.Buffer{}}
	te.env = cli.Env{
		Stdout: te.out,
		Stderr: te.errb,
		Now:    func() time.Time { return now },
		HTTP:   hc,
		Getenv: func(string) string { return "" },
		Audit: func(ev cli.AuditEvent) error {
			te.audits = append(te.audits, ev)
			return nil
		},
	}
	return te
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustGlob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil || len(m) == 0 {
		t.Fatalf("glob %s: %v (%d matches)", pattern, err, len(m))
	}
	return m
}

// xorshift64 is the deterministic generator of the §2.4 random-input tests.
type xorshift64 uint64

func (x *xorshift64) next() uint64 {
	v := uint64(*x)
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	*x = xorshift64(v)
	return v
}

// mutate returns a random edit of seed: byte flips, truncation, splices of
// interesting tokens, or pure noise.
func (x *xorshift64) mutate(seed []byte) []byte {
	tokens := [][]byte{
		[]byte(`"`), []byte(`{`), []byte(`}`), []byte(`[`), []byte(`]`), []byte(`,`), []byte(`:`),
		[]byte(`null`), []byte(`true`), []byte(`-1`), []byte(`1e999`), []byte(`"\u0000"`),
		[]byte(`/0`), []byte(`/129`), []byte(`::`), []byte(`0.0.0.0`), []byte("\n"), []byte(`&a`), []byte(`*a`),
	}
	switch x.next() % 5 {
	case 0: // noise
		n := int(x.next() % 256)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(x.next())
		}
		return b
	case 1: // truncate
		if len(seed) == 0 {
			return nil
		}
		return append([]byte(nil), seed[:x.next()%uint64(len(seed))]...)
	default: // flips and splices
		b := append([]byte(nil), seed...)
		for n := 1 + int(x.next()%4); n > 0 && len(b) > 0; n-- {
			i := int(x.next() % uint64(len(b)))
			if x.next()%2 == 0 {
				b[i] = byte(x.next())
			} else {
				tok := tokens[x.next()%uint64(len(tokens))]
				b = append(b[:i], append(append([]byte(nil), tok...), b[i:]...)...)
			}
		}
		return b
	}
}
