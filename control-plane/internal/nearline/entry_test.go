package nearline

import (
	"math/rand/v2"
	"os"
	"strings"
	"testing"
)

const samplesDir = "../../../testdata/phase2/samples/"

// readSamples returns the entries of an mg:ev sample file: one entry per
// line, fields and values separated by TAB (testdata/phase2/README.md).
func readSamples(t *testing.T, name string) [][]string {
	t.Helper()
	data, err := os.ReadFile(samplesDir + name)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for line := range strings.SplitSeq(strings.TrimSuffix(string(data), "\n"), "\n") {
		out = append(out, strings.Split(line, "\t"))
	}
	return out
}

func mustParse(t *testing.T, fv []string) Entry {
	t.Helper()
	e, err := ParseEntry(fv)
	if err != nil {
		t.Fatalf("ParseEntry(%q): %v", strings.Join(fv, " "), err)
	}
	return e
}

func TestParseV2Samples(t *testing.T) {
	entries := readSamples(t, "mg-ev-v2.txt")
	if len(entries) != 17 {
		t.Fatalf("mg-ev-v2.txt: %d entries, want 17", len(entries))
	}
	var got []Entry
	for _, fv := range entries {
		got = append(got, mustParse(t, fv))
	}
	ipk := "083956bb9c00bbcfdac40338c45b515a" // ipk of 203.0.113.7 (Phase 1 kat entity_key)
	e := got[0]
	if e.Version != 2 || e.Kind != KindDecision || e.Site != "blog" || e.TS != 1790000000123 ||
		!e.HasIPK || e.IPK.String() != ipk || !e.HasPFK || e.ASN != 64500 || e.Status != 200 ||
		e.Method != "GET" || !e.HasPH || e.PH != 0x19a177d106aca712 || e.CT != 'h' || e.BT || e.XS || e.TK ||
		e.PF != '-' || e.UF != "chrome" || e.Fam != 4 || e.CType != "" || e.Sess != "" || e.Dry || e.Score != 12 ||
		e.Action != "allow" || e.Class != "human_likely" || e.Route != "default" {
		t.Errorf("entry 0: %+v", e)
	}
	// Every ct, pf, xs, tk, bt, fam and ctype value of the file.
	want := []struct {
		ct    byte
		pf    byte
		bt    bool
		xs    bool
		tk    bool
		fam   int
		ctype string
	}{
		{'h', '-', false, false, false, 4, ""},
		{'j', 'v', false, false, true, 4, ""},
		{0, '-', false, false, false, 6, "interactive"},
		{0, '-', true, false, false, 4, ""},
		{0, '-', false, false, false, 0, ""},
		{'h', '-', false, false, false, 4, ""},
		{'a', '-', false, true, false, 4, ""},
		{0, 'u', false, false, true, 4, "pow"},
		{0, 'j', false, false, true, 4, ""},
		{0, 'r', false, false, true, 4, ""},
		{'o', 'x', false, false, false, 4, ""},
	}
	for i, w := range want {
		e := got[i]
		if e.Kind != KindDecision || e.CT != w.ct || e.PF != w.pf || e.BT != w.bt || e.XS != w.xs || e.TK != w.tk || e.Fam != w.fam || e.CType != w.ctype {
			t.Errorf("decision %d: ct=%q pf=%q bt=%v xs=%v tk=%v fam=%d ctype=%q, want %+v", i, e.CT, e.PF, e.BT, e.XS, e.TK, e.Fam, e.CType, w)
		}
	}
	if u := got[4]; u.HasIPK || u.HasPFK || u.ASN != 0 || u.Status != 429 || !u.Dry {
		t.Errorf("unknown-IP entry: %+v", u)
	}
	if got[8].Sess != "GcggTvfWoD-zjDkB79TKXw" || got[10].Method != "patch" || got[7].Method != "DELETE" {
		t.Errorf("sess / method: %q %q %q", got[8].Sess, got[10].Method, got[7].Method)
	}
	outcomes := []string{"pass", "fail", "pass", "pass", "renew_rebind", "unavailable"}
	providers := []string{"self_hold", "pow_a11y", "turnstile", "", "self_hold", "turnstile"}
	for i := range outcomes {
		e := got[11+i]
		if e.Kind != KindFeedback || e.Outcome != outcomes[i] || e.Provider != providers[i] || !e.HasIPK || !e.HasPFK {
			t.Errorf("feedback %d: %+v", i, e)
		}
	}
	if f := got[11]; f.Sess != "6byK5RR2J5ey78l-WoxOUA" || f.Lvl != "interactive" || f.Type != "interactive" || f.Route != "login" {
		t.Errorf("feedback 0: %+v", f)
	}
	if got[13].Lvl != "interactive_ext:turnstile" || got[12].Lvl != "" || got[12].Sess != "" {
		t.Errorf("feedback lvl / sess: %+v %+v", got[13], got[12])
	}
}

func TestParseV1Samples(t *testing.T) {
	entries := readSamples(t, "mg-ev-v1.txt")
	if len(entries) != 3 {
		t.Fatalf("mg-ev-v1.txt: %d entries, want 3", len(entries))
	}
	d := mustParse(t, entries[0])
	if d.Version != 1 || d.Kind != KindDecision || !d.HasIPK || d.Status != 200 || d.CT != 0 || d.PF != 0 || d.Fam != 0 || d.HasPH {
		t.Errorf("v1 decision: %+v", d)
	}
	d2 := mustParse(t, entries[1])
	if d2.Sess != "g6XcQzXkzzk8B1Z_53YC9A" || !d2.Dry || d2.HasIPK || d2.Action != "challenge" {
		t.Errorf("v1 decision 2: %+v", d2)
	}
	f := mustParse(t, entries[2])
	if f.Version != 1 || f.Kind != KindFeedback || f.Outcome != "pass" || f.Type != "pow" || !f.HasPFK || f.HasIPK || f.Provider != "" {
		t.Errorf("v1 feedback: %+v", f)
	}
}

func TestParseRejects(t *testing.T) {
	good := decisionFV("blog", 1790000000000, nil)
	set := func(field, val string) []string {
		out := append([]string(nil), good...)
		for i := 0; i < len(out); i += 2 {
			if out[i] == field {
				out[i+1] = val
			}
		}
		return out
	}
	drop := func(field string) []string {
		var out []string
		for i := 0; i < len(good); i += 2 {
			if good[i] != field {
				out = append(out, good[i], good[i+1])
			}
		}
		return out
	}
	if _, err := ParseEntry(good); err != nil {
		t.Fatalf("good entry: %v", err)
	}
	if _, err := ParseEntry(append(append([]string(nil), good...), "future", "x")); err != nil {
		t.Errorf("an unknown field must be ignored: %v", err)
	}
	cases := map[string][]string{
		"empty":        nil,
		"odd":          good[:len(good)-1],
		"dup":          append(append([]string(nil), good...), "ts", "1"),
		"version 3":    set("v", "3"),
		"kind":         set("kind", "access"),
		"site":         set("site", "Blog"),
		"site empty":   set("site", ""),
		"ts sign":      set("ts", "-1"),
		"ts lead 0":    set("ts", "0123"),
		"ts text":      set("ts", "12a"),
		"score":        set("score", "101"),
		"dry":          set("dry", "2"),
		"ipk short":    set("ipk", "abc"),
		"ipk upper":    set("ipk", strings.ToUpper(testIPK(0xabcdef))),
		"pfk":          set("pfk", "zz"+testIPK(1)[2:]),
		"asn":          set("asn", "4294967296"),
		"status":       set("status", "1000"),
		"ph":           set("ph", "0123"),
		"ct":           set("ct", "x"),
		"bt":           set("bt", ""),
		"pf":           set("pf", ""),
		"fam":          set("fam", "5"),
		"ctype":        set("ctype", "turnstile"),
		"uf long":      set("uf", strings.Repeat("a", 17)),
		"m long":       set("m", strings.Repeat("A", 17)),
		"sess":         set("sess", "a b"),
		"missing ph":   drop("ph"),
		"missing ts":   drop("ts"),
		"missing ctyp": drop("ctype"),
		"long value":   set("route", strings.Repeat("r", 300)),
		"empty name":   append(append([]string(nil), good...), "", "x"),
	}
	for name, fv := range cases {
		if _, err := ParseEntry(fv); err == nil {
			t.Errorf("%s: parsed, want an error", name)
		} else if strings.Contains(err.Error(), "203.0.113") {
			t.Errorf("%s: error text leaks a value", name)
		}
	}
	// A v1 decision entry needs only the v1 fields.
	v1 := append([]string(nil), good[:30]...)
	v1[1] = "1"
	if e, err := ParseEntry(v1); err != nil || e.Version != 1 {
		t.Errorf("v1 subset: %v", err)
	}
}

// TestParseRandomNeverPanics feeds 30,000 seeded random and mutated entries
// to the parser and every parsed one to the detectors (spec §2.4 item 9).
func TestParseRandomNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261012, 13))
	var seeds [][]string
	seeds = append(seeds, readSamples(t, "mg-ev-v2.txt")...)
	seeds = append(seeds, readSamples(t, "mg-ev-v1.txt")...)
	alphabet := []string{"", "0", "1", "2", "6", "-", "j", "h", "blog", "decision", "feedback", "pass", "fail",
		"99999999999999999999", "18446744073709551616", testIPK(3), "ffffffffffffffff", "\x00", "é", "${x}", " ", "\t"}
	names := []string{"v", "kind", "site", "ts", "rid", "sess", "route", "action", "dry", "class", "score", "ipk",
		"pfk", "asn", "status", "m", "ph", "ct", "bt", "xs", "tk", "pf", "uf", "fam", "ctype", "outcome", "type", "p", "lvl", "zz"}
	randStr := func() string {
		if rng.IntN(3) == 0 {
			return alphabet[rng.IntN(len(alphabet))]
		}
		b := make([]byte, rng.IntN(40))
		for i := range b {
			b[i] = byte(rng.IntN(256))
		}
		return string(b)
	}
	cfg := DefaultConfig()
	cfg.Sites = []string{"blog"}
	cfg.Windows.MaxKeys = 1000
	cfg.Acceptance.MaxKeysPerDay = 1000
	p := NewProcessor(&cfg, nil)
	parsed := 0
	const n = 30_000
	for i := range n {
		var fv []string
		switch i % 3 {
		case 0: // mutate a sample
			fv = append([]string(nil), seeds[rng.IntN(len(seeds))]...)
			for range 1 + rng.IntN(3) {
				switch j := rng.IntN(len(fv)); rng.IntN(4) {
				case 0:
					fv[j] = randStr()
				case 1:
					fv = append(fv[:j], fv[j+1:]...)
				case 2:
					fv = append(fv, names[rng.IntN(len(names))], randStr())
				default:
					if j%2 == 1 {
						fv[j] = alphabet[rng.IntN(len(alphabet))]
					}
				}
				if len(fv) == 0 {
					break
				}
			}
		case 1: // a sample with one value replaced by a plausible one
			fv = append([]string(nil), seeds[rng.IntN(len(seeds))]...)
			fv[1+2*rng.IntN(len(fv)/2)] = alphabet[rng.IntN(len(alphabet))]
		default: // random names and values
			for range rng.IntN(70) {
				fv = append(fv, names[rng.IntN(len(names))], randStr())
			}
		}
		e, err := ParseEntry(fv)
		if err != nil {
			continue
		}
		parsed++
		if !sitePattern.MatchString(e.Site) || e.Score < 0 || e.Score > 100 || e.Status < 0 || e.Status > 999 ||
			(e.Version != 1 && e.Version != 2) || (e.Kind != KindDecision && e.Kind != KindFeedback) || len(e.UF) > 16 {
			t.Fatalf("parsed entry breaks an invariant: %+v", e)
		}
		p.Process(&e, 1790000000000+int64(i)*10)
	}
	if parsed < n/10 {
		t.Errorf("only %d of %d inputs parsed; the generator should exercise the success path more", parsed, n)
	}
}
