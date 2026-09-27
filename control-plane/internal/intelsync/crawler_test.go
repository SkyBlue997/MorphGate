package intelsync

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// §12.0: the valid samples round-trip byte for byte (parse, validate,
// re-encode) and every invalid sample is rejected (§12.3, D-36).
func TestCrawlerRegistrySamples(t *testing.T) {
	for _, name := range []string{"crawler-registry.json", "crawler-registry.test.json"} {
		data := mustRead(t, filepath.Join(phase1Artifacts, name))
		r, err := ParseCrawlerRegistry(data)
		if err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
		enc, err := r.Encode()
		if err != nil || !bytes.Equal(enc, data) {
			t.Errorf("%s does not round-trip:\n%s", name, enc)
		}
	}
	for _, f := range mustGlob(t, filepath.Join(phase1Artifacts, "invalid", "crawler-registry.*.json")) {
		if _, err := ParseCrawlerRegistry(mustRead(t, f)); err == nil {
			t.Errorf("%s: accepted, want rejection", filepath.Base(f))
		} else {
			t.Logf("%s: %v", filepath.Base(f), err)
		}
	}
}

func TestCrawlerRegistryValidation(t *testing.T) {
	load := func() *CrawlerRegistry {
		r, err := ParseCrawlerRegistry(mustRead(t, filepath.Join(phase1Artifacts, "crawler-registry.json")))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	cases := map[string]struct {
		mut    func(r *CrawlerRegistry)
		errHas string
	}{
		"kind":         {func(r *CrawlerRegistry) { r.Kind = "mg-cloudflare-ips" }, "kind"},
		"v":            {func(r *CrawlerRegistry) { r.V = 0 }, "v must be 1"},
		"generated_at": {func(r *CrawlerRegistry) { r.GeneratedAt = "yesterday" }, "generated_at"},
		"no operators": {func(r *CrawlerRegistry) { r.Operators = nil }, "operators"},
		"bad id":       {func(r *CrawlerRegistry) { r.Operators[0].ID = "Google Bot" }, "id"},
		"purpose":      {func(r *CrawlerRegistry) { r.Operators[0].Purpose = "seo" }, "purpose"},
		"no ua tokens": {func(r *CrawlerRegistry) { r.Operators[0].UATokens = nil }, "ua_tokens"},
		"9 ua tokens": {func(r *CrawlerRegistry) {
			r.Operators[0].UATokens = strings.Fields("aaa bbb ccc ddd eee fff ggg hhh iii")
		}, "ua_tokens"},
		"short ua token":   {func(r *CrawlerRegistry) { r.Operators[0].UATokens = []string{"Go"} }, "ua_token"},
		"long ua token":    {func(r *CrawlerRegistry) { r.Operators[0].UATokens = []string{strings.Repeat("x", 65)} }, "ua_token"},
		"control in token": {func(r *CrawlerRegistry) { r.Operators[0].UATokens = []string{"Google\nbot"} }, "printable"},
		"long suffix": {func(r *CrawlerRegistry) {
			r.Operators[0].Verify.RDNSSuffixes = []string{"." + strings.Repeat("a", 253)}
		}, "rdns suffix"},
		"empty suffix": {func(r *CrawlerRegistry) { r.Operators[0].Verify.RDNSSuffixes = []string{""} }, "rdns suffix"},
		"sha256": {func(r *CrawlerRegistry) {
			r.Operators[0].Sources[0].SHA256 = strings.ToUpper(r.Operators[0].Sources[0].SHA256)
		}, "sha256"},
		"fetched_at":    {func(r *CrawlerRegistry) { r.Operators[0].Sources[0].FetchedAt = "2026-09-27" }, "fetched_at"},
		"source format": {func(r *CrawlerRegistry) { r.Operators[0].Sources[0].Format = "csv" }, "format"},
		"source http":   {func(r *CrawlerRegistry) { r.Operators[0].Sources[0].URL = "http://example.com/x.json" }, "https"},
		"too many cidrs": {func(r *CrawlerRegistry) {
			r.Operators[0].CIDRs = make([]string, maxCIDRsPerOperator+1)
		}, "at most"},
		"non-canonical cidr": {func(r *CrawlerRegistry) { r.Operators[0].CIDRs[2] = "2001:4860:4801:0010::/64" }, "canonical"},
		"cgnat":              {func(r *CrawlerRegistry) { r.Operators[1].CIDRs[0] = "100.64.0.0/16" }, "CGNAT"},
		"reserved":           {func(r *CrawlerRegistry) { r.Operators[1].CIDRs[0] = "240.1.0.0/16" }, "reserved"},
	}
	for name, tc := range cases {
		r := load()
		tc.mut(r)
		err := r.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.errHas) {
			t.Errorf("%s: %v, want error containing %q", name, err, tc.errHas)
		}
	}
	// Documentation ranges become valid only with "test": true.
	r := load()
	r.Operators[2].CIDRs = []string{"192.0.2.0/25"}
	if err := r.Validate(); err == nil {
		t.Error("documentation range accepted without test: true")
	}
	r.Test = true
	if err := r.Validate(); err != nil {
		t.Errorf("documentation range with test: true: %v", err)
	}
	// "test" is written only when true.
	enc, _ := load().Encode()
	if bytes.Contains(enc, []byte(`"test"`)) {
		t.Error(`"test": false must be omitted`)
	}
}

func TestRegistrySourceValidation(t *testing.T) {
	good := string(mustRead(t, filepath.Join(intelFixtures, "crawler/source.yaml")))
	if _, err := ParseRegistrySource("source.yaml", []byte(good)); err != nil {
		t.Fatalf("fixture source rejected: %v", err)
	}
	cases := map[string]struct {
		yaml   string
		errHas string
	}{
		"unknown key":       {strings.Replace(good, "purpose: search", "purpose: search\n    priority: 1", 1), "field priority not found"},
		"anchor":            {strings.Replace(good, "ua_tokens: [Googlebot]", "ua_tokens: &t [Googlebot]", 1), "anchors"},
		"two documents":     {good + "\n---\nversion: 1\n", "multiple YAML documents"},
		"version":           {strings.Replace(good, "version: 1", "version: 2", 1), "version must be 1"},
		"duplicate id":      {strings.Replace(good, "id: gptbot", "id: googlebot", 1), "duplicate operator id"},
		"bad id":            {strings.Replace(good, "id: gptbot", "id: GPTBot", 1), "must match"},
		"http url":          {strings.Replace(good, "https://openai.com/gptbot.json", "http://openai.com/gptbot.json", 1), "https"},
		"bad format":        {strings.Replace(good, "format: cidr_text", "format: csv", 1), "format"},
		"mode":              {strings.Replace(good, "mode: rdns\n", "mode: dns\n", 1), "verify.mode"},
		"rdns no suffixes":  {strings.Replace(good, "rdns_suffixes: [.crawl.example.net]", "rdns_suffixes: []", 1), "needs rdns_suffixes"},
		"upper suffix":      {strings.Replace(good, ".crawl.example.net", ".Crawl.example.net", 1), "lower-case"},
		"ip_ranges no urls": {strings.Replace(good, "      ip_ranges:\n        - url: https://openai.com/gptbot.json\n          format: prefixes_json\n", "", 1), "needs verify.ip_ranges"},
		"duplicate url":     {strings.Replace(good, "archivebot-extra.txt", "archivebot.txt", 1), "duplicate ip_ranges url"},
		"empty":             {"", "empty file"},
		"not yaml":          {"version: [", "invalid YAML"},
	}
	for name, tc := range cases {
		if _, err := ParseRegistrySource("source.yaml", []byte(tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.errHas) {
			t.Errorf("%s: %v, want error containing %q", name, err, tc.errHas)
		}
	}
}

// The shipped source (deploy/intel/crawler-registry.yaml) is valid and lists
// the spec's initial operators (§12.3).
func TestShippedRegistrySource(t *testing.T) {
	path := "../../../deploy/intel/crawler-registry.yaml"
	src, err := ParseRegistrySource(path, mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{ purpose, mode, ua string }{
		"googlebot":     {"search", ModeIPRangesOrRDNS, "Googlebot"},
		"bingbot":       {"search", ModeIPRangesOrRDNS, "bingbot"},
		"applebot":      {"search", ModeIPRangesOrRDNS, "Applebot"},
		"gptbot":        {"ai_training", ModeIPRanges, "GPTBot"},
		"oai-searchbot": {"ai_search", ModeIPRanges, "OAI-SearchBot"},
		"chatgpt-user":  {"user_triggered", ModeIPRanges, "ChatGPT-User"},
	}
	if len(src.Operators) != len(want) {
		t.Errorf("%d operators, want %d", len(src.Operators), len(want))
	}
	if src.Test {
		t.Error("the shipped registry must not be a test registry")
	}
	for _, op := range src.Operators {
		w, ok := want[op.ID]
		if !ok {
			t.Errorf("unexpected operator %q", op.ID)
			continue
		}
		if op.Purpose != w.purpose || op.Verify.Mode != w.mode || len(op.UATokens) != 1 || op.UATokens[0] != w.ua {
			t.Errorf("%s: %+v", op.ID, op)
		}
		if len(op.Verify.IPRanges) != 1 || op.Verify.IPRanges[0].Format != FormatPrefixesJSON {
			t.Errorf("%s: ip_ranges %+v", op.ID, op.Verify.IPRanges)
		}
	}
	// UA matching is first match in file order: no token may shadow a later
	// operator's token.
	for i, a := range src.Operators {
		for _, b := range src.Operators[i+1:] {
			for _, ta := range a.UATokens {
				for _, tb := range b.UATokens {
					if strings.Contains(strings.ToLower(tb), strings.ToLower(ta)) {
						t.Errorf("token %q of %s shadows %q of %s", ta, a.ID, tb, b.ID)
					}
				}
			}
		}
	}
}

func TestRangeListParsers(t *testing.T) {
	entries, ct, err := parsePrefixesJSON(mustRead(t, filepath.Join(intelFixtures, "crawler/ranges/common-crawlers.json")))
	if err != nil || ct != "2026-09-25T14:49:23.000000" || len(entries) != 3 {
		t.Errorf("prefixes_json: %v %q %v", entries, ct, err)
	}
	bad := map[string]string{
		`{"prefixes":[{"ipv4Prefix":"2001:db8::/32"}]}`:                           "not an IPv4",
		`{"prefixes":[{"ipv6Prefix":"66.249.64.0/27"}]}`:                          "not an IPv6",
		`{"prefixes":[{}]}`:                                                       "exactly one",
		`{"prefixes":[{"ipv4Prefix":"66.249.64.0/27","ipv6Prefix":"2600::/32"}]}`: "exactly one",
		`{"creationTime":"` + strings.Repeat("x", 65) + `","prefixes":[]}`:        "creationTime",
		`[1,2]`: "invalid prefixes_json",
	}
	for in, want := range bad {
		if _, _, err := parsePrefixesJSON([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", in, err, want)
		}
	}
	got, err := parseCIDRText(mustRead(t, filepath.Join(intelFixtures, "crawler/ranges/archivebot.txt")))
	if err != nil || strings.Join(got, ",") != "207.241.224.0/20,208.70.24.0/21" {
		t.Errorf("cidr_text: %v %v", got, err)
	}
	if _, err := parseCIDRText([]byte("1.2.3.0/24 5.6.7.0/24\n")); err == nil {
		t.Error("two entries on one line accepted")
	}
	if _, err := parseCIDRText(bytes.Repeat([]byte("a"), 5000)); err == nil {
		t.Error("over-long line accepted")
	}
}

// §12.0: the Edge reads artifacts with serde (deny_unknown_fields, every
// member required except the registry's "test"). encoding/json alone accepts
// member names that differ only in case, duplicate members, missing members,
// nulls, non-integer spellings of integers and invalid UTF-8; the Go readers
// must reject all of them, or a sync could keep (and a bundle could carry) a
// file that every Edge rejects.
func TestArtifactReadersRejectLooseJSON(t *testing.T) {
	cf := mustRead(t, filepath.Join(phase1Artifacts, "cloudflare-ips.json"))
	reg := mustRead(t, filepath.Join(phase1Artifacts, "crawler-registry.json"))
	state := []byte("{\n  \"v\": 1,\n  \"last_success\": \"2026-09-27T10:00:00Z\",\n  \"etag\": \"abc\"\n}\n")
	parse := map[string]func([]byte) error{
		"cf":       func(b []byte) error { _, err := ParseCloudflareIPs(b); return err },
		"registry": func(b []byte) error { _, err := ParseCrawlerRegistry(b); return err },
		"state":    func(b []byte) error { _, err := parseSyncState(b); return err },
	}
	for name, b := range map[string][]byte{"cf": cf, "registry": reg, "state": state} {
		if err := parse[name](b); err != nil {
			t.Fatalf("%s: valid input rejected: %v", name, err)
		}
	}
	// "test" is the one optional member, and false may be written out.
	if err := parse["registry"](bytes.Replace(reg, []byte(`"generated_at": "2026-09-27T10:00:00Z",`), []byte(`"generated_at": "2026-09-27T10:00:00Z", "test": false,`), 1)); err != nil {
		t.Errorf(`explicit "test": false: %v`, err)
	}
	// Other spacing and escapes are fine: readers do not depend on the format.
	var compact bytes.Buffer
	if err := json.Compact(&compact, cf); err != nil {
		t.Fatal(err)
	}
	if err := parse["cf"](bytes.Replace(compact.Bytes(), []byte(`"mg-cloudflare-ips"`), []byte(`"mg-cloudflare-ips"`), 1)); err != nil {
		t.Errorf("compact / escaped: %v", err)
	}
	for _, tc := range []struct{ name, kind, from, to string }{
		{"case-variant member", "cf", `"v": 1`, `"V": 1`},
		{"case-variant nested member", "registry", `"mode": `, `"Mode": `},
		{"duplicate member", "cf", `"v": 1,`, `"v": 1, "v": 1,`},
		{"duplicate nested member", "registry", `"purpose": "search",`, `"purpose": "search", "purpose": "search",`},
		{"missing member", "cf", `"etag": "38f79d050aa027e3be3865e495dcc9bc",`, ``},
		{"missing nested member", "registry", `"creation_time": "2026-09-25T14:49:23.000000",`, ``},
		{"missing list", "registry", "\"mode\": \"ip_ranges\",\n        \"rdns_suffixes\": []", `"mode": "ip_ranges"`},
		{"null member", "cf", `"etag": "38f79d050aa027e3be3865e495dcc9bc"`, `"etag": null`},
		{"null list", "registry", `"rdns_suffixes": []`, `"rdns_suffixes": null`},
		{"null optional member", "registry", `"generated_at": "2026-09-27T10:00:00Z",`, `"generated_at": "2026-09-27T10:00:00Z", "test": null,`},
		{"float version", "cf", `"v": 1`, `"v": 1.0`},
		{"invalid UTF-8", "cf", `"etag": "38f7`, "\"etag\": \"\xff38f7"},
		{"state case-variant", "state", `"etag"`, `"ETag"`},
		{"state missing member", "state", `,
  "etag": "abc"`, ``},
	} {
		src := map[string][]byte{"cf": cf, "registry": reg, "state": state}[tc.kind]
		data := bytes.Replace(src, []byte(tc.from), []byte(tc.to), 1)
		if bytes.Equal(data, src) {
			t.Fatalf("%s: the mutation did not apply", tc.name)
		}
		if err := parse[tc.kind](data); err == nil {
			t.Errorf("%s: accepted", tc.name)
		} else {
			t.Logf("%s: %v", tc.name, err)
		}
	}
}

// §12.2 / §12.3: timestamps are checked the way the Edge reads RFC 3339
// (intel/src/text.rs): no comma fraction, offsets within ±23:59. Go's
// time.Parse accepts both, so the Go readers need their own check, or a
// stale fallback could copy such a fetched_at into a new artifact.
func TestTimestampsAreStrictRFC3339(t *testing.T) {
	cf := mustRead(t, filepath.Join(phase1Artifacts, "cloudflare-ips.json"))
	reg := mustRead(t, filepath.Join(phase1Artifacts, "crawler-registry.json"))
	for _, ts := range []string{"2026-09-27T10:00:00,5Z", "2026-09-27T10:00:00+24:00", "2026-09-27T10:00:00+05:60", "2026-09-27T10:00:00", "2026-09-27T10:00:00.Z"} {
		stamp := []byte(`"2026-09-27T10:00:00Z"`)
		bad := []byte(`"` + ts + `"`)
		if _, err := ParseCloudflareIPs(bytes.Replace(cf, stamp, bad, 1)); err == nil {
			t.Errorf("cloudflare-ips fetched_at %s accepted", ts)
		}
		if _, err := ParseCrawlerRegistry(bytes.Replace(reg, stamp, bad, 1)); err == nil {
			t.Errorf("registry generated_at %s accepted", ts)
		}
		// A source's fetched_at (generated_at left valid).
		idx := bytes.Index(reg, []byte(`"fetched_at": "2026-09-27T10:00:00Z"`))
		src := append(append(append([]byte(nil), reg[:idx]...), []byte(`"fetched_at": `+string(bad))...), reg[idx+len(`"fetched_at": "2026-09-27T10:00:00Z"`):]...)
		if _, err := ParseCrawlerRegistry(src); err == nil {
			t.Errorf("registry source fetched_at %s accepted", ts)
		}
		state := []byte(`{"v": 1, "last_success": ` + string(bad) + `, "etag": "abc"}`)
		if _, err := parseSyncState(state); err == nil {
			t.Errorf("state last_success %s accepted", ts)
		}
	}
	for _, ts := range []string{"2026-09-27T10:00:00Z", "2026-09-27T12:00:00.25+02:00", "2026-09-27T10:00:00-23:59"} {
		if !isRFC3339(ts) {
			t.Errorf("%s rejected", ts)
		}
	}
}
