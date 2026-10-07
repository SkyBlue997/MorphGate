package guard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestParseHostMapping(t *testing.T) {
	good := []struct{ in, name, addr string }{
		{"site.lab.test=127.0.0.1", "site.lab.test", "127.0.0.1"},
		{"Site.Lab.Test.=127.0.0.2", "site.lab.test", "127.0.0.2"},
		{"app.localhost=::1", "app.localhost", "::1"},
		{"db.test=::ffff:10.0.0.5", "db.test", "10.0.0.5"}, // unmapped
		// Anything else is judged when the name is used, like a DNS answer.
		{"site.lab.test=93.184.216.34", "site.lab.test", "93.184.216.34"},
	}
	for _, tc := range good {
		name, addr, err := ParseHostMapping(tc.in)
		if err != nil || name != tc.name || addr != netip.MustParseAddr(tc.addr) {
			t.Errorf("ParseHostMapping(%q) = %q, %v, %v; want %q, %s", tc.in, name, addr, err, tc.name, tc.addr)
		}
	}
	bad := []struct{ in, want string }{
		{"site.lab.test", "want name=address"},
		{"=127.0.0.1", "want name=address"},
		{"site.lab.test=", "want name=address"},
		{"127.0.0.1=127.0.0.1", "is an IP address, not a host name"},
		{"2130706433=127.0.0.1", "is an IP address, not a host name"},
		{"site.lab.test=localhost", "is not an IP address"},
		{"site.lab.test=fe80::1%lo0", "is not an IP address"},
		{"site.lab.test=169.254.169.254", "never a lab target"},
		{"site.lab.test=fd00:ec2::254", "never a lab target"},
		{"site.lab.test=64:ff9b::7f00:1", "never a lab target"},
		{"bad host.test=127.0.0.1", "invalid character"},
	}
	for _, tc := range bad {
		if _, _, err := ParseHostMapping(tc.in); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseHostMapping(%q) = %v, want an error containing %q", tc.in, err, tc.want)
		}
	}
}

func staticGuard(t *testing.T, hosts map[string][]netip.Addr, opts ...Option) (*Guard, *recordingDialer) {
	t.Helper()
	d := &recordingDialer{}
	opts = append(opts, WithStaticHosts(hosts), WithDialFunc(d.dial))
	g, err := New(DefaultConfig(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return g, d
}

// A mapping only replaces the lookup: the allowlist and the address policy
// for the name still decide, so a mapping never reaches a refused target.
func TestStaticHostsStayInsideTheAllowlist(t *testing.T) {
	next := &fakeResolver{answers: map[string][][]string{"other.test": {{"10.1.2.3"}}}}
	g, d := staticGuard(t, map[string][]netip.Addr{
		"site.lab.test":   {netip.MustParseAddr("127.0.0.1")},
		"public.lab.test": {netip.MustParseAddr("93.184.216.34")},
		"mixed.lab.test":  {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("8.8.8.8")},
		"v6.lab.test":     {netip.MustParseAddr("::1")},
		"evil.com":        {netip.MustParseAddr("127.0.0.1")},
	}, WithResolver(next))
	ctx := context.Background()

	if _, err := g.DialContext(ctx, "tcp", "site.lab.test:8080"); err != nil {
		t.Fatalf("mapped loopback name: %v", err)
	}
	if got := d.dials; len(got) != 1 || got[0] != "127.0.0.1:8080" {
		t.Fatalf("dials = %v, want [127.0.0.1:8080]", got)
	}

	for _, host := range []string{"public.lab.test", "mixed.lab.test"} {
		_, err := g.DialContext(ctx, "tcp", host+":80")
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s: DialContext = %v, want ErrDenied", host, err)
		}
	}
	// Not allowlisted: denied before any lookup, mapping or not.
	if _, err := g.DialContext(ctx, "tcp", "evil.com:80"); !errors.Is(err, ErrDenied) {
		t.Errorf("evil.com: DialContext = %v, want ErrDenied", err)
	}
	if len(d.dials) != 1 {
		t.Errorf("a refused mapping was dialled: %v", d.dials)
	}

	// Unmapped names fall through to the next resolver.
	if addrs, err := g.Resolve(ctx, "tcp", "other.test"); err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("10.1.2.3") {
		t.Errorf("unmapped name: %v, %v", addrs, err)
	}
	if strings.Join(next.calls, ",") != "other.test" {
		t.Errorf("next resolver saw %v, want only other.test", next.calls)
	}

	// The network family filters mapped addresses.
	if _, err := g.Resolve(ctx, "tcp4", "v6.lab.test"); err == nil {
		t.Error("tcp4 lookup of an IPv6-only mapping succeeded")
	}
	if addrs, err := g.Resolve(ctx, "tcp6", "V6.Lab.Test."); err != nil || addrs[0] != netip.MustParseAddr("::1") {
		t.Errorf("tcp6 lookup: %v, %v", addrs, err)
	}
}

// Without a next resolver, an unmapped name fails instead of using DNS.
func TestStaticHostsWithoutNext(t *testing.T) {
	s := &staticHosts{hosts: map[string][]netip.Addr{}}
	if _, err := s.LookupNetIP(context.Background(), "ip", "x.test"); err == nil {
		t.Error("unmapped name resolved without a next resolver")
	}
}

// The guarded client reaches a loopback server under a *.test name and
// sends that name in Host, as the Edge needs to pick the site.
func TestStaticHostsClient(t *testing.T) {
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	cfg := DefaultConfig()
	cfg.RateRPS = MaxRateRPS
	g, err := New(cfg, WithStaticHosts(map[string][]netip.Addr{"site.lab.test": {netip.MustParseAddr("127.0.0.1")}}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := g.Client().Get("http://site.lab.test:" + u.Port() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if want := "site.lab.test:" + u.Port(); host != want {
		t.Errorf("Host = %q, want %q", host, want)
	}
}

// ParseHostMapping returns errors, never panics, on arbitrary input
// (docs/impl/phase1-spec.md §2.4 item 3).
func TestRandomHostMappingsDoNotPanic(t *testing.T) {
	x := uint64(0xda942042e4dd58b5)
	next := func() uint64 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return x
	}
	alphabet := "ab.-=:%[]@1270xX\x00\xff é"
	for i := 0; i < 10000; i++ {
		b := make([]byte, next()%40)
		for j := range b {
			b[j] = alphabet[next()%uint64(len(alphabet))]
		}
		_, _, _ = ParseHostMapping(string(b))
		_, _, _ = ParseHostMapping("site.lab.test=" + string(b))
	}
}
