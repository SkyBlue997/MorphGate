package keys

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const turnstileSamples = "../../../testdata/phase2/samples/keys"

type turnstileCases struct {
	Site  string `json:"site"`
	Valid []struct {
		File   string `json:"file"`
		Values int    `json:"values"`
	} `json:"valid"`
	Invalid []struct {
		File string `json:"file"`
	} `json:"invalid"`
}

func loadTurnstileCases(t *testing.T) turnstileCases {
	t.Helper()
	data, err := os.ReadFile(turnstileSamples + "/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var c turnstileCases
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Valid) == 0 || len(c.Invalid) == 0 {
		t.Fatal("no samples")
	}
	return c
}

// Phase 2 spec §8.7: the shared samples. Valid files parse and re-marshal
// to the same bytes (the writer's canonical form); invalid ones are
// rejected, site-mismatch.json only for the site it does not name.
func TestTurnstileKeysSamples(t *testing.T) {
	c := loadTurnstileCases(t)
	for _, v := range c.Valid {
		t.Run(v.File, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(turnstileSamples, v.File))
			if err != nil {
				t.Fatal(err)
			}
			k, err := ParseTurnstileKeysFor(data, c.Site)
			if err != nil {
				t.Fatal(err)
			}
			if len(k.Values) != v.Values {
				t.Errorf("%d values, want %d", len(k.Values), v.Values)
			}
			out, err := k.Marshal()
			if err != nil || !bytes.Equal(out, data) {
				t.Errorf("Marshal differs from the sample (%v):\n%s", err, out)
			}
			path := filepath.Join(t.TempDir(), "k.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadTurnstileKeysFile(path); err != nil {
				t.Error(err)
			}
		})
	}
	for _, v := range c.Invalid {
		t.Run(v.File, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(turnstileSamples, v.File))
			if err != nil {
				t.Fatal(err)
			}
			k, err := ParseTurnstileKeysFor(data, c.Site)
			if err == nil {
				t.Fatalf("accepted: %v", k)
			}
			if strings.Contains(err.Error(), "kat-test-secret") {
				t.Errorf("error repeats a secret: %v", err)
			}
			if v.File == "invalid/site-mismatch.json" {
				if _, err := ParseTurnstileKeys(data); err != nil {
					t.Errorf("site-mismatch.json is well-formed: %v", err)
				}
				if !strings.Contains(err.Error(), `the file is for "shop", not "blog"`) {
					t.Errorf("error %v", err)
				}
			}
		})
	}
}

func TestTurnstileKeysLimitsAndSecrecy(t *testing.T) {
	k := &TurnstileKeys{Site: "blog", Values: []string{"0x4AAAAAAAsecret-current", "0x4AAAAAAAsecret-previous"}}
	for _, s := range []string{k.String(), fmt.Sprintf("%v", k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k)} {
		if strings.Contains(s, "secret-") {
			t.Errorf("formatting shows a secret: %s", s)
		}
	}
	// 64 KiB size cap (§8.7), exceeded by whitespace only.
	data, _ := k.Marshal()
	big := append(bytes.Repeat([]byte(" "), MaxTurnstileKeysFile), data...)
	if _, err := ParseTurnstileKeys(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTurnstileKeysFile(path); err == nil {
		t.Error("ReadTurnstileKeysFile accepted an oversized file")
	}
	for _, bad := range []*TurnstileKeys{
		{Site: "blog"},
		{Site: "blog", Values: []string{"a", "b", "c"}},
		{Site: "Blog", Values: []string{"a"}},
		{Site: "blog", Values: []string{strings.Repeat("a", 257)}},
		{Site: "blog", Values: []string{"a\tb"}},
	} {
		if _, err := bad.Marshal(); err == nil {
			t.Errorf("Marshal accepted %v", bad.Values)
		}
	}
	if err := ValidTurnstileSecret(strings.Repeat("~", 256)); err != nil {
		t.Error(err)
	}
}

// §2.4 item 9: ≥ 10,000 seeded random inputs never panic, and whatever
// parses also re-marshals to a file that parses to the same values.
func TestTurnstileKeysRandomInputs(t *testing.T) {
	c := loadTurnstileCases(t)
	var seeds [][]byte
	for _, v := range c.Valid {
		data, err := os.ReadFile(filepath.Join(turnstileSamples, v.File))
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, data)
	}
	x := uint64(0x9e3779b97f4a7c15)
	next := func() uint64 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return x
	}
	for i := 0; i < 12_000; i++ {
		b := bytes.Clone(seeds[i%len(seeds)])
		for range 1 + next()%4 {
			if len(b) == 0 {
				break
			}
			j := next() % uint64(len(b))
			switch next() % 4 {
			case 0:
				b[j] = byte(next())
			case 1:
				b = append(b[:j:j], append([]byte{"{}[]\",: \\u00\x00"[next()%13]}, b[j:]...)...)
			case 2:
				b = append(b[:j:j], b[min(uint64(len(b)), j+next()%16):]...)
			default:
				b = b[:j]
			}
		}
		k, err := ParseTurnstileKeys(b)
		if err != nil {
			continue
		}
		out, err := k.Marshal()
		if err != nil {
			t.Fatalf("parsed but does not marshal: %v", err)
		}
		k2, err := ParseTurnstileKeys(out)
		if err != nil || k2.Site != k.Site || strings.Join(k2.Values, "\n") != strings.Join(k.Values, "\n") {
			t.Fatalf("round trip: %v", err)
		}
	}
}
