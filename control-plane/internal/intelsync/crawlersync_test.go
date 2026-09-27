package intelsync

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"morphgate/control-plane/internal/cli"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

// Host/path keys of the fixture source's range lists.
const (
	googleRanges  = "developers.google.com/static/crawling/ipranges/common-crawlers.json"
	gptbotRanges  = "openai.com/gptbot.json"
	archiveRanges = "ranges.example.net/archivebot.txt"
	archiveExtra  = "ranges.example.net/archivebot-extra.txt"
)

func crawlerFakeNet(t *testing.T) *fakeNet {
	fn := newFakeNet(t)
	dir := filepath.Join(intelFixtures, "crawler/ranges")
	fn.setFile(googleRanges, filepath.Join(dir, "common-crawlers.json"))
	fn.setFile(gptbotRanges, filepath.Join(dir, "gptbot.json"))
	fn.setFile(archiveRanges, filepath.Join(dir, "archivebot.txt"))
	fn.setFile(archiveExtra, filepath.Join(dir, "archivebot-extra.txt"))
	return fn
}

func runCrawler(t *testing.T, te *testEnv, args ...string) int {
	t.Helper()
	return RunCrawler(append([]string{"sync"}, args...), te.env)
}

var crawlerSource = filepath.Join(intelFixtures, "crawler/source.yaml")

// §14.5: both formats, merge and dedupe, normalisation, rDNS-only operators,
// canonical output; the result is pinned by a golden file.
func TestCrawlerSyncWritesRegistry(t *testing.T) {
	fn := crawlerFakeNet(t)
	out := filepath.Join(t.TempDir(), "crawler-registry.json")
	te := newTestEnv(syncTime, fn.client())
	if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, te.errb)
	}
	got := mustRead(t, out)
	golden := filepath.Join(intelFixtures, "crawler/expected-registry.json")
	if *updateGolden {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want := mustRead(t, golden); !bytes.Equal(got, want) {
		t.Errorf("registry differs from %s (rerun with -update after checking):\n%s", golden, got)
	}
	r, err := ParseCrawlerRegistry(got)
	if err != nil {
		t.Fatal(err)
	}
	arch := r.find("archivebot")
	if arch == nil || !slices.Equal(arch.CIDRs, []string{"207.241.224.0/20", "208.70.24.0/21", "2620:0:9c0::/48"}) {
		t.Errorf("archivebot cidrs merged wrong: %+v", arch)
	}
	if arch != nil && (len(arch.Sources) != 2 || arch.Sources[0].CreationTime != "" || arch.Sources[1].Format != FormatCIDRText) {
		t.Errorf("archivebot sources: %+v", arch.Sources)
	}
	if rd := r.find("rdnsbot"); rd == nil || len(rd.CIDRs) != 0 || len(rd.Sources) != 0 {
		t.Errorf("rdnsbot: %+v", rd)
	}
	g := r.find("googlebot")
	if g == nil || g.Sources[0].SHA256 != sha256Hex(mustRead(t, filepath.Join(intelFixtures, "crawler/ranges/common-crawlers.json"))) ||
		g.Sources[0].CreationTime != "2026-09-25T14:49:23.000000" || g.Sources[0].FetchedAt != "2026-09-27T10:00:00Z" {
		t.Errorf("googlebot source: %+v", g)
	}
	if len(te.audits) != 1 || te.audits[0].Action != "crawler.sync" || te.audits[0].ResourceID != "crawler-registry" {
		t.Errorf("audits: %+v", te.audits)
	}
	for _, ua := range fn.uas {
		if ua != UserAgent {
			t.Errorf("User-Agent %q", ua)
		}
	}
	// Syncing again with the same upstream data keeps the file byte for byte
	// (stable artifact hash) and is not audited.
	te2 := newTestEnv(syncTime.Add(24*time.Hour), fn.client())
	if code := runCrawler(t, te2, "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
		t.Fatalf("second sync: %d %s", code, te2.errb)
	}
	if !bytes.Equal(mustRead(t, out), got) || len(te2.audits) != 0 || !strings.Contains(te2.out.String(), "unchanged") {
		t.Errorf("unchanged sync rewrote or audited: %s", te2.out)
	}
}

// §14.5: an operator whose download fails keeps its previous ranges (stale);
// without previous ranges the whole sync fails.
func TestCrawlerSyncOperatorFailure(t *testing.T) {
	fn := crawlerFakeNet(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "crawler-registry.json")
	if code := runCrawler(t, newTestEnv(syncTime, fn.client()), "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
		t.Fatal("seed sync failed")
	}
	seeded, _ := ParseCrawlerRegistry(mustRead(t, out))
	if err := os.WriteFile(filepath.Join(dir, "seed.json"), mustRead(t, out), 0o644); err != nil {
		t.Fatal(err)
	}

	failures := map[string]fakeResp{
		"http 503":   {status: 503},
		"bad cidr":   {body: []byte(`{"prefixes":[{"ipv4Prefix":"20.171.206.0/24"},{"ipv4Prefix":"0.0.0.0/0"}]}`)},
		"host bits":  {body: []byte(`{"prefixes":[{"ipv4Prefix":"20.171.206.1/24"}]}`)},
		"private":    {body: []byte(`{"prefixes":[{"ipv4Prefix":"10.0.0.0/16"}]}`)},
		"empty list": {body: []byte(`{"prefixes":[]}`)},
		"not json":   {body: []byte(`<html>`)},
		"oversized":  {body: bytes.Repeat([]byte(" "), maxCrawlerRegistrySize+1)},
	}
	for name, resp := range failures {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(out, mustRead(t, filepath.Join(dir, "seed.json")), 0o644); err != nil {
				t.Fatal(err)
			}
			fn.set(gptbotRanges, resp)
			defer fn.setFile(gptbotRanges, filepath.Join(intelFixtures, "crawler/ranges/gptbot.json"))
			te := newTestEnv(syncTime.Add(time.Hour), fn.client())
			if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
				t.Fatalf("exit %d: %s", code, te.errb)
			}
			if !strings.Contains(te.errb.String(), "warning: gptbot") || !strings.Contains(te.errb.String(), "stale") {
				t.Errorf("no stale warning: %s", te.errb)
			}
			r, err := ParseCrawlerRegistry(mustRead(t, out))
			if err != nil {
				t.Fatal(err)
			}
			g := r.find("gptbot")
			if !slices.Equal(g.CIDRs, seeded.find("gptbot").CIDRs) || !g.Sources[0].Stale {
				t.Errorf("gptbot = %+v, want previous CIDRs marked stale", g)
			}
			if r.find("googlebot").Sources[0].Stale {
				t.Error("healthy operator marked stale")
			}
			if len(te.audits) != 1 {
				t.Error("stale change not audited")
			}
		})
	}

	// No previous registry: the command fails and writes nothing.
	fn.set(gptbotRanges, fakeResp{status: 503})
	fresh := filepath.Join(dir, "fresh.json")
	te := newTestEnv(syncTime, fn.client())
	if code := runCrawler(t, te, "--registry", crawlerSource, "--out", fresh); code != cli.ExitFailed {
		t.Fatalf("exit %d, want %d", code, cli.ExitFailed)
	}
	if !strings.Contains(te.errb.String(), "gptbot") {
		t.Errorf("stderr: %s", te.errb)
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Error("artifact written although an operator has no ranges")
	}
}

// §14.5: range downloads follow at most three https redirects.
func TestCrawlerSyncRedirects(t *testing.T) {
	fn := crawlerFakeNet(t)
	gpt := mustRead(t, filepath.Join(intelFixtures, "crawler/ranges/gptbot.json"))
	fn.set(gptbotRanges, fakeResp{status: 301, location: "https://cdn.example.net/1"})
	fn.set("cdn.example.net/1", fakeResp{status: 302, location: "https://cdn.example.net/2"})
	fn.set("cdn.example.net/2", fakeResp{status: 308, location: "https://cdn.example.net/gptbot.json"})
	fn.set("cdn.example.net/gptbot.json", fakeResp{body: gpt})
	dir := t.TempDir()
	out := filepath.Join(dir, "crawler-registry.json")
	te := newTestEnv(syncTime, fn.client())
	if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
		t.Fatalf("three redirects: exit %d %s", code, te.errb)
	}
	r, _ := ParseCrawlerRegistry(mustRead(t, out))
	if g := r.find("gptbot"); g == nil || len(g.CIDRs) != 2 || g.Sources[0].URL != "https://openai.com/gptbot.json" {
		t.Errorf("gptbot after redirects: %+v", g)
	}
	// A fourth redirect, or one to http, fails the operator (here: stale).
	for name, loc := range map[string]string{"four": "https://cdn.example.net/0", "http": "http://cdn.example.net/gptbot.json"} {
		fn.set("cdn.example.net/0", fakeResp{status: 302, location: "https://cdn.example.net/1"})
		fn.set(gptbotRanges, fakeResp{status: 302, location: loc})
		te = newTestEnv(syncTime.Add(time.Hour), fn.client())
		if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
			t.Fatalf("%s: exit %d %s", name, code, te.errb)
		}
		if !strings.Contains(te.errb.String(), "redirect") || !strings.Contains(te.errb.String(), "stale") {
			t.Errorf("%s: stderr %s", name, te.errb)
		}
	}
}

// D-36 change protection: count changes over 50% and newly covered address
// space larger than the previous total are refused without --accept-change.
func TestCrawlerSyncChangeProtection(t *testing.T) {
	fn := crawlerFakeNet(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "crawler-registry.json")
	if code := runCrawler(t, newTestEnv(syncTime, fn.client()), "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
		t.Fatal("seed sync failed")
	}
	seeded := mustRead(t, out)

	cases := map[string]struct {
		body   string
		ok     bool
		errHas string
	}{
		// googlebot had 3 CIDRs (2 x /27 IPv4 = 64 addresses, one IPv6 /64).
		"one more /27":  {`{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv4Prefix":"66.249.64.32/27"},{"ipv4Prefix":"66.249.64.64/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}`, true, ""},
		"count halved":  {`{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"}]}`, false, "CIDR count 3 -> 1"},
		"count doubled": {`{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv4Prefix":"66.249.64.32/27"},{"ipv4Prefix":"66.249.65.0/27"},{"ipv4Prefix":"66.249.66.0/27"},{"ipv4Prefix":"66.249.67.0/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}`, false, "CIDR count 3 -> 6"},
		// Same count, but one /27 replaced by a /16: 65,536 new addresses > 64.
		"wider range": {`{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv4Prefix":"66.250.0.0/16"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}`, false, "newly covered IPv4 addresses 65536 exceed the previous total 64"},
		// Merging the two /27 into their /26 covers nothing new.
		"merged":   {`{"prefixes":[{"ipv4Prefix":"66.249.64.0/26"},{"ipv4Prefix":"66.249.64.0/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}`, true, ""},
		"wider v6": {`{"prefixes":[{"ipv4Prefix":"66.249.64.0/27"},{"ipv4Prefix":"66.249.64.32/27"},{"ipv6Prefix":"2001:4860:4801::/48"}]}`, false, "newly covered IPv6 addresses"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(out, seeded, 0o644); err != nil {
				t.Fatal(err)
			}
			fn.set(googleRanges, fakeResp{body: []byte(tc.body)})
			te := newTestEnv(syncTime.Add(time.Hour), fn.client())
			code := runCrawler(t, te, "--registry", crawlerSource, "--out", out)
			if tc.ok {
				if code != cli.ExitOK {
					t.Fatalf("exit %d: %s", code, te.errb)
				}
				return
			}
			if code != cli.ExitFailed {
				t.Fatalf("exit %d, want %d", code, cli.ExitFailed)
			}
			if !strings.Contains(te.errb.String(), tc.errHas) || !strings.Contains(te.errb.String(), "--accept-change") {
				t.Errorf("stderr lacks %q:\n%s", tc.errHas, te.errb)
			}
			if !strings.Contains(te.errb.String(), "  googlebot: 3 -> ") {
				t.Errorf("no diff printed:\n%s", te.errb)
			}
			if !bytes.Equal(mustRead(t, out), seeded) {
				t.Error("refused change modified the artifact")
			}
			te = newTestEnv(syncTime.Add(time.Hour), fn.client())
			if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out, "--accept-change"); code != cli.ExitOK {
				t.Fatalf("--accept-change: exit %d %s", code, te.errb)
			}
			if bytes.Equal(mustRead(t, out), seeded) {
				t.Error("--accept-change did not write")
			}
		})
	}
}

// A previous registry for the other test mode, or an invalid previous file,
// is refused.
func TestCrawlerSyncPreviousChecks(t *testing.T) {
	fn := crawlerFakeNet(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "crawler-registry.json")
	prevTest := filepath.Join(phase1Artifacts, "crawler-registry.test.json")
	te := newTestEnv(syncTime, fn.client())
	if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out, "--previous", prevTest); code != cli.ExitFailed ||
		!strings.Contains(te.errb.String(), "test=true") {
		t.Errorf("test/non-test mix: exit %d %s", code, te.errb)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, mustRead(t, filepath.Join(phase1Artifacts, "invalid/crawler-registry.slash-zero.json")), 0o644); err != nil {
		t.Fatal(err)
	}
	te = newTestEnv(syncTime, fn.client())
	if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out, "--previous", bad); code != cli.ExitFailed {
		t.Errorf("invalid previous: exit %d", code)
	}
	te = newTestEnv(syncTime, fn.client())
	if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out, "--previous", filepath.Join(dir, "missing.json")); code != cli.ExitFailed {
		t.Errorf("missing explicit previous: exit %d", code)
	}
	te = newTestEnv(syncTime, fn.client())
	if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out, "--previous", bad, "--accept-change"); code != cli.ExitOK {
		t.Errorf("invalid previous with --accept-change: exit %d %s", code, te.errb)
	}
}

// A "test": true source may use documentation ranges; a normal one may not.
func TestCrawlerSyncTestRegistry(t *testing.T) {
	fn := newFakeNet(t)
	fn.set("ranges.example.net/lab.json", fakeResp{body: []byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.0/25"},{"ipv6Prefix":"2001:db8:4860::/48"}]}`)})
	src := `version: 1
test: %s
operators:
  - id: googlebot
    name: Googlebot
    purpose: search
    ua_tokens: [Googlebot]
    verify:
      mode: ip_ranges_or_rdns
      rdns_suffixes: [.googlebot.com]
      ip_ranges:
        - url: https://ranges.example.net/lab.json
          format: prefixes_json
`
	dir := t.TempDir()
	for _, test := range []string{"true", "false"} {
		path := filepath.Join(dir, "src-"+test+".yaml")
		if err := os.WriteFile(path, []byte(strings.Replace(src, "%s", test, 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "out-"+test+".json")
		te := newTestEnv(syncTime, fn.client())
		code := runCrawler(t, te, "--registry", path, "--out", out)
		if test == "true" {
			if code != cli.ExitOK {
				t.Fatalf("test registry: exit %d %s", code, te.errb)
			}
			if !bytes.Contains(mustRead(t, out), []byte(`"test": true`)) {
				t.Error(`artifact lacks "test": true`)
			}
		} else if code != cli.ExitFailed || !strings.Contains(te.errb.String(), "documentation") {
			t.Errorf("documentation ranges in a normal registry: exit %d %s", code, te.errb)
		}
	}
}

func TestCrawlerFlags(t *testing.T) {
	te := newTestEnv(syncTime, nil)
	for _, args := range [][]string{{}, {"--registry", crawlerSource}, {"--out", "x"}, {"--registry", crawlerSource, "--out", "x", "more"}} {
		te.errb.Reset()
		if code := runCrawler(t, te, args...); code != cli.ExitUsage || te.errb.Len() == 0 {
			t.Errorf("%v: exit %d %q", args, code, te.errb)
		}
	}
	if code := RunCrawler([]string{"list"}, te.env); code != cli.ExitUsage {
		t.Errorf("unknown subcommand: %d", code)
	}
	if code := runCrawler(t, te, "--registry", filepath.Join(t.TempDir(), "none.yaml"), "--out", "x"); code != cli.ExitFailed {
		t.Errorf("missing source: %d", code)
	}
}

func TestIntervalMath(t *testing.T) {
	v4, v6 := intervalsOf([]string{"10.0.0.0/24", "10.0.0.128/25", "10.0.1.0/24", "10.0.3.0/24", "2001:db8::/127", "1.2.3.4"})
	if len(v4) != 3 || size(v4).Int64() != 256*3+1 {
		t.Errorf("v4 merge: %d intervals, %s addresses", len(v4), size(v4))
	}
	if size(v6).Int64() != 2 {
		t.Errorf("v6 size %s", size(v6))
	}
	a, _ := intervalsOf([]string{"10.0.0.0/23"})
	b, _ := intervalsOf([]string{"10.0.1.0/24", "10.0.2.0/24"})
	if got := size(intersect(a, b)).Int64(); got != 256 {
		t.Errorf("intersection %d", got)
	}
}

// §12.0: after a successful sync the file at --out is canonical JSON, even
// when the ranges did not change: an existing file that another tool or an
// editor rewrote (here: compact JSON) is replaced rather than kept.
func TestCrawlerSyncCanonicalisesUnchangedFile(t *testing.T) {
	fn := crawlerFakeNet(t)
	out := filepath.Join(t.TempDir(), "crawler-registry.json")
	if code := runCrawler(t, newTestEnv(syncTime, fn.client()), "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
		t.Fatal("seed sync failed")
	}
	canonical := mustRead(t, out)
	var compact bytes.Buffer
	if err := json.Compact(&compact, canonical); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, compact.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	te := newTestEnv(syncTime.Add(time.Hour), fn.client())
	if code := runCrawler(t, te, "--registry", crawlerSource, "--out", out); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, te.errb)
	}
	got := mustRead(t, out)
	if _, err := ParseCrawlerRegistry(got); err != nil || !bytes.HasSuffix(got, []byte("}\n")) || bytes.Equal(got, compact.Bytes()) {
		t.Errorf("non-canonical file kept:\n%s", got)
	}
}
