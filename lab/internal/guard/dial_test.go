package guard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// fakeResolver answers from a table; each host may have a sequence of answers
// (one per lookup) to simulate DNS rebinding.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]string
	calls   []string
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, host)
	seq, ok := r.answers[host]
	if !ok || len(seq) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	ans := seq[0]
	if len(seq) > 1 {
		r.answers[host] = seq[1:]
	}
	out := make([]netip.Addr, len(ans))
	for i, s := range ans {
		out[i] = netip.MustParseAddr(s)
	}
	return out, nil
}

// recordingDialer never touches the network; it records what would be dialled.
type recordingDialer struct {
	mu    sync.Mutex
	dials []string
}

func (d *recordingDialer) dial(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, address)
	d.mu.Unlock()
	c1, c2 := net.Pipe()
	c2.Close()
	return c1, nil
}

func TestDialContext(t *testing.T) {
	cases := []struct {
		name     string
		address  string
		answers  []string // resolver answer for the host
		wantDial string   // expected dialled address; "" = must be denied
		reason   string
	}{
		{"suffix host to loopback", "app.test:80", []string{"127.0.0.1"}, "127.0.0.1:80", ""},
		{"suffix host to private", "db.test:5432", []string{"10.1.2.3"}, "10.1.2.3:5432", ""},
		{"suffix host to docker net", "origin.test:8081", []string{"172.18.0.4"}, "172.18.0.4:8081", ""},
		{"suffix host to ULA", "v6.test:443", []string{"fd00::1"}, "[fd00::1]:443", ""},
		{"suffix host to mapped loopback", "mapped.test:80", []string{"::ffff:127.0.0.1"}, "127.0.0.1:80", ""},
		{"exact host", "localhost:8080", []string{"::1", "127.0.0.1"}, "[::1]:8080", ""},
		{"owner host inside expected CIDR", "staging.example.com:443", []string{"203.0.113.5"}, "203.0.113.5:443", ""},

		{"suffix host to public IP", "evil.test:80", []string{"93.184.216.34"}, "", "resolved to 93.184.216.34"},
		{"suffix host to metadata", "meta.test:80", []string{"169.254.169.254"}, "", "resolved to 169.254.169.254"},
		{"suffix host to mapped public", "mapped.test:80", []string{"::ffff:8.8.8.8"}, "", "resolved to ::ffff:8.8.8.8"},
		{"suffix host to unspecified", "zero.test:80", []string{"0.0.0.0"}, "", "resolved to 0.0.0.0"},
		{"mixed local and public", "mixed.test:80", []string{"127.0.0.1", "8.8.8.8"}, "", "resolved to 8.8.8.8"},
		{"owner host outside expected CIDR", "staging.example.com:443", []string{"203.0.113.99"}, "", "expected_cidrs"},
		{"owner host to loopback", "staging.example.com:443", []string{"127.0.0.1"}, "", "expected_cidrs"},
		{"unlisted host", "example.com:80", []string{"127.0.0.1"}, "", "not in the lab allowlist"},
		{"unlisted IP", "8.8.8.8:53", nil, "", "not inside allow_cidrs"},
		{"numeric trick public", "134744072:80", nil, "", "of 8.8.8.8 is not inside allow_cidrs"},

		{"IP literal", "127.0.0.1:18081", nil, "127.0.0.1:18081", ""},
		{"IPv6 literal", "[::1]:18081", nil, "[::1]:18081", ""},
		{"numeric trick loopback", "2130706433:80", nil, "127.0.0.1:80", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, _, _ := net.SplitHostPort(tc.address)
			res := &fakeResolver{answers: map[string][][]string{}}
			if tc.answers != nil {
				res.answers[host] = [][]string{tc.answers}
			}
			rec := &recordingDialer{}
			g := mustGuard(t, ownerConfig(), WithResolver(res), WithDialFunc(rec.dial))

			conn, err := g.DialContext(context.Background(), "tcp", tc.address)
			if tc.wantDial == "" {
				if err == nil {
					conn.Close()
					t.Fatalf("dial %s allowed, want denied", tc.address)
				}
				if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), tc.reason) {
					t.Errorf("error %q, want ErrDenied containing %q", err, tc.reason)
				}
				if len(rec.dials) != 0 {
					t.Errorf("denied destination was dialled: %v", rec.dials)
				}
				return
			}
			if err != nil {
				t.Fatalf("dial %s: %v", tc.address, err)
			}
			conn.Close()
			if len(rec.dials) == 0 || rec.dials[0] != tc.wantDial {
				t.Errorf("dialled %v, want %s first", rec.dials, tc.wantDial)
			}
			if tc.answers == nil && len(res.calls) != 0 {
				t.Errorf("IP literal triggered DNS lookups: %v", res.calls)
			}
		})
	}
}

func TestDialUnlistedHostDoesNotResolve(t *testing.T) {
	res := &fakeResolver{answers: map[string][][]string{"example.com": {{"127.0.0.1"}}}}
	g := mustGuard(t, DefaultConfig(), WithResolver(res), WithDialFunc((&recordingDialer{}).dial))
	if _, err := g.DialContext(context.Background(), "tcp", "example.com:80"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v, want denied", err)
	}
	if len(res.calls) != 0 {
		t.Errorf("unlisted host was resolved: %v", res.calls)
	}
}

func TestDialRebinding(t *testing.T) {
	// First lookup answers loopback, the second a public address.
	res := &fakeResolver{answers: map[string][][]string{
		"rebind.test": {{"127.0.0.1"}, {"93.184.216.34"}},
	}}
	rec := &recordingDialer{}
	g := mustGuard(t, DefaultConfig(), WithResolver(res), WithDialFunc(rec.dial))

	conn, err := g.DialContext(context.Background(), "tcp", "rebind.test:80")
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	conn.Close()
	if _, err := g.DialContext(context.Background(), "tcp", "rebind.test:80"); !errors.Is(err, ErrDenied) {
		t.Fatalf("second dial after rebinding: %v, want denied", err)
	}
	if len(rec.dials) != 1 || rec.dials[0] != "127.0.0.1:80" {
		t.Errorf("dials = %v, want only 127.0.0.1:80", rec.dials)
	}
}

func TestDialErrors(t *testing.T) {
	g := mustGuard(t, DefaultConfig(), WithResolver(&fakeResolver{answers: map[string][][]string{}}),
		WithDialFunc((&recordingDialer{}).dial))
	if _, err := g.DialContext(context.Background(), "udp", "127.0.0.1:53"); !errors.Is(err, ErrDenied) {
		t.Errorf("udp: %v, want denied", err)
	}
	if _, err := g.DialContext(context.Background(), "tcp", "no-port"); !errors.Is(err, ErrDenied) {
		t.Errorf("missing port: %v, want denied", err)
	}
	_, err := g.DialContext(context.Background(), "tcp", "missing.test:80")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Errorf("resolver failure not propagated: %v", err)
	}
}

func TestControlHook(t *testing.T) {
	control := controlFor(isLocal)
	for addr, ok := range map[string]bool{
		"127.0.0.1:80":        true,
		"[::1]:80":            true,
		"10.0.0.8:80":         true,
		"93.184.216.34:80":    false,
		"169.254.169.254:80":  false,
		"[::ffff:8.8.8.8]:80": false,
		"garbage":             false,
	} {
		err := control("tcp", addr, nil)
		if (err == nil) != ok {
			t.Errorf("control(%s) = %v, want allowed=%v", addr, err, ok)
		}
		if err != nil && !errors.Is(err, ErrDenied) {
			t.Errorf("control(%s) error %v is not ErrDenied", addr, err)
		}
	}
}

func TestRealDialerUsesControlHook(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	// The resolver lies: "app.test" -> 127.0.0.1 is fine, and the real
	// net.Dialer path (with the Control hook) must connect.
	res := &fakeResolver{answers: map[string][][]string{"app.test": {{"127.0.0.1"}}}}
	g := mustGuard(t, DefaultConfig(), WithResolver(res))
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	conn, err := g.DialContext(context.Background(), "tcp", net.JoinHostPort("app.test", port))
	if err != nil {
		t.Fatalf("real dial: %v", err)
	}
	conn.Close()
}

func TestResolveForCheck(t *testing.T) {
	res := &fakeResolver{answers: map[string][][]string{"app.test": {{"127.0.0.1", "::1"}}}}
	g := mustGuard(t, DefaultConfig(), WithResolver(res))
	addrs, err := g.Resolve(context.Background(), "tcp", "app.test")
	if err != nil || len(addrs) != 2 {
		t.Fatalf("Resolve = %v, %v", addrs, err)
	}
}
