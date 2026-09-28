package bundle

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func artifactKind(file string) string {
	switch {
	case strings.HasPrefix(file, "cloudflare-ips"):
		return "cloudflare-ips"
	case strings.HasPrefix(file, "crawler-registry"):
		return "crawler-registry"
	case strings.HasPrefix(file, "datacenter-asns"):
		return "datacenter-asns"
	case strings.HasPrefix(file, "tor-exits"):
		return "tor-exits"
	}
	return ""
}

// §12.0: the builder accepts every valid shared artifact sample and rejects
// every sample in artifacts/invalid.
func TestSharedArtifactSamples(t *testing.T) {
	entries, err := os.ReadDir(artifactsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(artifactsDir, e.Name()))
		if _, err := ValidateArtifact(artifactKind(e.Name()), data); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
		}
	}
	invalid, err := os.ReadDir(filepath.Join(artifactsDir, "invalid"))
	if err != nil || len(invalid) == 0 {
		t.Fatalf("no invalid samples: %v", err)
	}
	// Ruling I-22 samples: rejected for the suffix shape, like the Edge does.
	reasons := map[string]string{
		"crawler-registry.suffix-without-dot.json":  "must start with '.' followed by at least two labels",
		"crawler-registry.single-label-suffix.json": "must start with '.' followed by at least two labels",
	}
	for _, e := range invalid {
		data, _ := os.ReadFile(filepath.Join(artifactsDir, "invalid", e.Name()))
		_, err := ValidateArtifact(artifactKind(e.Name()), data)
		switch {
		case err == nil:
			t.Errorf("invalid/%s was accepted", e.Name())
		case reasons[e.Name()] != "" && !strings.Contains(err.Error(), reasons[e.Name()]):
			t.Errorf("invalid/%s: %v, want an error containing %q", e.Name(), err, reasons[e.Name()])
		default:
			t.Logf("invalid/%s: %v", e.Name(), err)
		}
	}
}

func TestRDNSSuffixShape(t *testing.T) {
	for s, want := range map[string]bool{
		".googlebot.com": true, ".a.b": true, ".search.msn.com": true,
		"googlebot.com": false, ".com": false, ".": false, "": false,
		"..googlebot.com": false, ".googlebot..com": false, ".googlebot.com.": false,
	} {
		if got := rdnsSuffixShape(s); got != want {
			t.Errorf("rdnsSuffixShape(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestArtifactVersions(t *testing.T) {
	for file, want := range map[string]string{
		"cloudflare-ips.json":        "2026-09-27T10:00:00Z",
		"crawler-registry.json":      "2026-09-27T10:00:00Z",
		"crawler-registry.test.json": "2026-09-27T10:00:00Z",
		"tor-exits.txt":              "",
	} {
		data, _ := os.ReadFile(filepath.Join(artifactsDir, file))
		if v, err := ValidateArtifact(artifactKind(file), data); err != nil || v != want {
			t.Errorf("%s: version %q %v, want %q", file, v, err, want)
		}
	}
}

// §7.2 / §8.3: MaxMind DBs are verified and their database_type checked;
// the version is the build epoch.
func TestMMDBArtifacts(t *testing.T) {
	const epoch = 1790000000
	for _, tc := range []struct {
		name, dbType string
		ok           bool
	}{
		{"geoip-asn", "GeoLite2-ASN", true},
		{"geoip-asn", "GeoIP2-ISP-ASN", true},
		{"geoip-asn", "GeoLite2-Country", false},
		{"geoip-country", "GeoLite2-Country", true},
		{"geoip-country", "GeoLite2-City", true},
		{"geoip-country", "GeoLite2-ASN", false},
	} {
		v, err := ValidateArtifact(tc.name, testMMDB(tc.dbType, epoch))
		if (err == nil) != tc.ok {
			t.Errorf("%s with database_type %s: %v", tc.name, tc.dbType, err)
		}
		if tc.ok && v != "2026-09-21T14:13:20Z" {
			t.Errorf("version %q", v)
		}
	}
	good := testMMDB("GeoLite2-ASN", epoch)
	for name, bad := range map[string][]byte{
		"empty":         nil,
		"no metadata":   good[:22],
		"bad separator": append(append(bytes.Clone(good[:6]), 1), good[7:]...),
		"json":          []byte(`{"database_type":"ASN"}`),
	} {
		if _, err := ValidateArtifact("geoip-asn", bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestArtifactRules(t *testing.T) {
	cf, _ := os.ReadFile(filepath.Join(artifactsDir, "cloudflare-ips.json"))
	reg, _ := os.ReadFile(filepath.Join(artifactsDir, "crawler-registry.test.json"))
	for _, tc := range []struct {
		name, kind string
		data       []byte
		ok         bool
	}{
		{"unknown field", "cloudflare-ips", bytes.Replace(cf, []byte(`"v": 1,`), []byte(`"v": 1, "extra": 2,`), 1), false},
		{"v6 in v4 list", "cloudflare-ips", bytes.Replace(cf, []byte(`"173.245.48.0/20"`), []byte(`"2a06:98c0::/29"`), 1), false},
		{"uppercase v6", "cloudflare-ips", bytes.Replace(cf, []byte(`"2400:cb00::/32"`), []byte(`"2400:CB00::/32"`), 1), false},
		{"bad fetched_at", "cloudflare-ips", bytes.Replace(cf, []byte(`"fetched_at": "2026-09-27T10:00:00Z"`), []byte(`"fetched_at": "yesterday"`), 1), false},
		{"test registry", "crawler-registry", reg, true},
		{"test registry loopback", "crawler-registry", bytes.Replace(reg, []byte(`"198.51.100.0/25"`), []byte(`"127.0.0.0/16"`), 1), false},
		{"cgnat", "crawler-registry", bytes.Replace(reg, []byte(`"198.51.100.0/25"`), []byte(`"100.64.0.0/16"`), 1), false},
		{"reserved", "crawler-registry", bytes.Replace(reg, []byte(`"198.51.100.0/25"`), []byte(`"240.1.0.0/16"`), 1), false},
		{"single address", "crawler-registry", bytes.Replace(reg, []byte(`"198.51.100.0/25"`), []byte(`"198.51.100.7"`), 1), true},
		{"bad source sha", "crawler-registry", bytes.Replace(reg, []byte(`"sha256": "3b5d`), []byte(`"sha256": "3B5D`), 1), false},
		{"short ua token", "crawler-registry", bytes.Replace(reg, []byte("[\n        \"GPTBot\"\n      ]"), []byte(`["GP"]`), 1), false},
		{"unknown purpose", "crawler-registry", bytes.Replace(reg, []byte(`"purpose": "search"`), []byte(`"purpose": "seo"`), 1), false},
		// mg-intel rejects any suffix with a char::is_uppercase character
		// (Unicode Uppercase: Lu plus Other_Uppercase), also those that
		// strings.ToLower leaves unchanged (U+210B, U+1F130).
		{"suffix upper without lower-case form", "crawler-registry", bytes.Replace(reg, []byte(`".googlebot.com"`), []byte(`".ℋx.googlebot.com"`), 1), false},
		{"suffix other-uppercase", "crawler-registry", bytes.Replace(reg, []byte(`".googlebot.com"`), []byte(`".\ud83c\udd30x.googlebot.com"`), 1), false},
		{"suffix non-ASCII lower-case", "crawler-registry", bytes.Replace(reg, []byte(`".googlebot.com"`), []byte(`".éx.googlebot.com"`), 1), true},
		{"asn with prefix", "datacenter-asns", []byte("AS13335\nas15169 # x\n"), true},
		{"asn zero", "datacenter-asns", []byte("0\n"), false},
		{"asn too large", "datacenter-asns", []byte("4294967296\n"), false},
		{"tor zone", "tor-exits", []byte("fe80::1%eth0\n"), false},
		{"tor host bits", "tor-exits", []byte("192.0.2.1/24\n"), false},
		{"tor invalid utf-8", "tor-exits", []byte("\xff\n"), false},
		// mg-intel (the Edge) rejects IPv6 outside global unicast 2000::/3,
		// the IETF block 2001::/23 and the documentation block 3fff::/20;
		// a bundle whose artifact the Edge cannot parse is rejected whole.
		{"cf teredo", "cloudflare-ips", bytes.Replace(cf, []byte(`"2400:cb00::/32"`), []byte(`"2001::/32"`), 1), false},
		{"cf 3fff documentation", "cloudflare-ips", bytes.Replace(cf, []byte(`"2400:cb00::/32"`), []byte(`"3fff::/32"`), 1), false},
		{"cf outside 2000::/3", "cloudflare-ips", bytes.Replace(cf, []byte(`"2400:cb00::/32"`), []byte(`"4000::/32"`), 1), false},
		{"cf site-local", "cloudflare-ips", bytes.Replace(cf, []byte(`"2400:cb00::/32"`), []byte(`"fec0::/32"`), 1), false},
		{"registry teredo", "crawler-registry", bytes.Replace(reg, []byte(`"198.51.100.0/25"`), []byte(`"2001:0:1::/48"`), 1), false},
		{"registry outside 2000::/3", "crawler-registry", bytes.Replace(reg, []byte(`"198.51.100.0/25"`), []byte(`"a000::/32"`), 1), false},
		{"test registry 3fff", "crawler-registry", bytes.Replace(reg, []byte(`"198.51.100.0/25"`), []byte(`"3fff:1::/32"`), 1), true},
		{"registry 3fff", "crawler-registry", bytes.Replace(bytes.Replace(reg, []byte(`"198.51.100.0/25"`), []byte(`"3fff:1::/32"`), 1), []byte(`"test": true`), []byte(`"test": false`), 1), false},
		// Text lists: the Edge's limits.
		{"asn with 11 digits", "datacenter-asns", []byte("000000015169\n"), false},
		{"asn with sign", "datacenter-asns", []byte("+15169\n"), false},
		{"tor over 1,000,000 entries", "tor-exits", bytes.Repeat([]byte("1.2.3.4\n"), 1_000_001), false},
		{"tor 1,000,000 entries", "tor-exits", bytes.Repeat([]byte("1.2.3.4\n"), 1_000_000), true},
		// RFC 3339 as the Edge reads it: no comma fraction, offsets within ±23:59.
		{"fetched_at comma fraction", "cloudflare-ips", bytes.Replace(cf, []byte(`"2026-09-27T10:00:00Z"`), []byte(`"2026-09-27T10:00:00,5Z"`), 1), false},
		{"fetched_at offset 24h", "cloudflare-ips", bytes.Replace(cf, []byte(`"2026-09-27T10:00:00Z"`), []byte(`"2026-09-27T10:00:00+24:00"`), 1), false},
		{"fetched_at offset minutes", "cloudflare-ips", bytes.Replace(cf, []byte(`"2026-09-27T10:00:00Z"`), []byte(`"2026-09-27T10:00:00+05:60"`), 1), false},
		{"fetched_at offset", "cloudflare-ips", bytes.Replace(cf, []byte(`"2026-09-27T10:00:00Z"`), []byte(`"2026-09-27T12:00:00.25+02:00"`), 1), true},
		{"too big", "cloudflare-ips", make([]byte, 1<<20+1), false},
		{"unknown kind", "geoip-city", cf, false},
	} {
		if _, err := ValidateArtifact(tc.kind, tc.data); (err == nil) != tc.ok {
			t.Errorf("%s: err %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	// Errors name the line of text lists.
	if _, err := ValidateArtifact("tor-exits", []byte("192.0.2.1\n# c\nnope\n")); err == nil || !strings.Contains(err.Error(), "line 3") {
		t.Errorf("line number: %v", err)
	}
}

// §12.0 / §8.3: JSON artifacts are read the way the Edge's serde reader
// (deny_unknown_fields, every field required except the registry's "test")
// reads them. encoding/json alone would accept member names that differ only
// in case, duplicate members, missing members and nulls; a bundle built with
// such an artifact would then be rejected by every Edge.
func TestArtifactJSONIsReadStrictly(t *testing.T) {
	cf, _ := os.ReadFile(filepath.Join(artifactsDir, "cloudflare-ips.json"))
	reg, _ := os.ReadFile(filepath.Join(artifactsDir, "crawler-registry.json"))
	for _, tc := range []struct {
		name, kind string
		data       []byte
	}{
		{"case-variant member", "cloudflare-ips", bytes.Replace(cf, []byte(`"v": 1`), []byte(`"V": 1`), 1)},
		{"case-variant nested member", "crawler-registry", bytes.Replace(reg, []byte(`"mode": `), []byte(`"Mode": `), 1)},
		{"duplicate member", "cloudflare-ips", bytes.Replace(cf, []byte(`"v": 1,`), []byte(`"v": 1, "v": 1,`), 1)},
		{"duplicate nested member", "crawler-registry", bytes.Replace(reg, []byte(`"purpose": "search",`), []byte(`"purpose": "search", "purpose": "search",`), 1)},
		{"missing member", "cloudflare-ips", bytes.Replace(cf, []byte(`"etag": "38f79d050aa027e3be3865e495dcc9bc",`), nil, 1)},
		{"missing nested member", "crawler-registry", bytes.Replace(reg, []byte(`"name": "Googlebot",`), nil, 1)},
		{"null member", "cloudflare-ips", bytes.Replace(cf, []byte(`"etag": "38f79d050aa027e3be3865e495dcc9bc"`), []byte(`"etag": null`), 1)},
		{"null list", "crawler-registry", bytes.Replace(reg, []byte(`"rdns_suffixes": []`), []byte(`"rdns_suffixes": null`), 1)},
		{"null optional member", "crawler-registry", bytes.Replace(reg, []byte(`"generated_at": "2026-09-27T10:00:00Z",`), []byte(`"generated_at": "2026-09-27T10:00:00Z", "test": null,`), 1)},
		{"invalid UTF-8", "cloudflare-ips", bytes.Replace(cf, []byte(`"etag": "38f7`), []byte("\"etag\": \"\xff38f7"), 1)},
	} {
		if !bytes.Contains(tc.data, []byte("\n")) || bytes.Equal(tc.data, cf) || bytes.Equal(tc.data, reg) {
			t.Fatalf("%s: the mutation did not apply", tc.name)
		}
		if _, err := ValidateArtifact(tc.kind, tc.data); err == nil {
			t.Errorf("%s: accepted", tc.name)
		} else {
			t.Logf("%s: %v", tc.name, err)
		}
	}
	// "test" is the only optional member; the valid samples omit it.
	if _, err := ValidateArtifact("crawler-registry", reg); err != nil {
		t.Errorf("registry without \"test\": %v", err)
	}
}

// §2.4 item 3: ≥ 10,000 random inputs to the artifact parsers never panic.
func TestArtifactParsersNeverPanic(t *testing.T) {
	var seeds [][]byte
	var kinds []string
	for _, f := range []string{"cloudflare-ips.json", "crawler-registry.json", "datacenter-asns.txt", "tor-exits.txt"} {
		data, _ := os.ReadFile(filepath.Join(artifactsDir, f))
		seeds, kinds = append(seeds, data), append(kinds, artifactKind(f))
	}
	seeds, kinds = append(seeds, testMMDB("GeoLite2-ASN", 1)), append(kinds, "geoip-asn")
	seeds, kinds = append(seeds, testMMDB("GeoLite2-Country", 1)), append(kinds, "geoip-country")
	x := xorshift(0x853c49e6748fea9b)
	for i := 0; i < 12_000; i++ {
		k := i % len(seeds)
		_, _ = ValidateArtifact(kinds[k], x.mutate(seeds[k]))
	}
}
