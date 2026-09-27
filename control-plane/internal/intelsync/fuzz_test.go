package intelsync

import (
	"path/filepath"
	"testing"
	"time"
)

// §2.4 item 3: every parser returns errors, never panics, on 10,000+
// deterministic pseudo-random inputs derived from valid samples.
func TestParsersRandomInputs(t *testing.T) {
	const rounds = 12000
	seeds := map[string][]byte{
		"cf-ips":        mustRead(t, filepath.Join(phase1Artifacts, "cloudflare-ips.json")),
		"cf-api":        mustRead(t, filepath.Join(intelFixtures, "cloudflare/api-ips.json")),
		"registry":      mustRead(t, filepath.Join(phase1Artifacts, "crawler-registry.test.json")),
		"source":        mustRead(t, filepath.Join(intelFixtures, "crawler/source.yaml")),
		"prefixes_json": mustRead(t, filepath.Join(intelFixtures, "crawler/ranges/common-crawlers.json")),
		"cidr_text":     mustRead(t, filepath.Join(intelFixtures, "crawler/ranges/archivebot.txt")),
		"state":         []byte(`{"v": 1, "last_success": "2026-09-27T10:00:00Z", "etag": "abc"}`),
		"cidr":          []byte("2001:4860:4801:10::/64"),
	}
	parsers := map[string]func([]byte){
		"cf-ips":   func(b []byte) { _, _ = ParseCloudflareIPs(b) },
		"cf-api":   func(b []byte) { _, _ = ArtifactFromAPI(b, DefaultCloudflareIPURL, time.Unix(0, 0)) },
		"registry": func(b []byte) { _, _ = ParseCrawlerRegistry(b) },
		"source":   func(b []byte) { _, _ = ParseRegistrySource("fuzz.yaml", b) },
		"prefixes_json": func(b []byte) {
			if e, _, err := parsePrefixesJSON(b); err == nil {
				_, _ = normalizeEntries(e, false)
			}
		},
		"cidr_text": func(b []byte) {
			if e, err := parseCIDRText(b); err == nil {
				_, _ = normalizeEntries(e, true)
			}
		},
		"state": func(b []byte) { var s SyncState; _ = decodeStrict(b, &s) },
		"cidr": func(b []byte) {
			_, _ = parseCIDR(string(b), crawlerRules, false)
			_, _ = parseCIDR(string(b), cloudflareIPRules, true)
		},
	}
	for name, parse := range parsers {
		x := xorshift64(0x9e3779b97f4a7c15)
		seed := seeds[name]
		for i := 0; i < rounds; i++ {
			in := x.mutate(seed)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s: panic on input %q: %v", name, in, r)
					}
				}()
				parse(in)
			}()
		}
	}
}
