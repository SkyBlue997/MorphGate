package keys

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"morphgate/control-plane/internal/cli"
)

const fixtures = "../../../testdata/phase1/keys"

var (
	t0 = time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	t1 = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seq returns the bytes from, from+1, ..., from+n-1.
func seq(from byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = from + byte(i)
	}
	return b
}

func stream(parts ...[]byte) io.Reader { return bytes.NewReader(bytes.Join(parts, nil)) }

func assertBytes(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the shared fixture:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// §12.0 / §15 WP-G2: fixed random streams and times reproduce
// testdata/phase1/keys/* byte for byte (inputs: testdata/phase1/README.md).
func TestGeneratorsReproduceSharedFixtures(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60") // RFC 8032 §7.1 test 1
	owner, err := GenerateOwnerKey("owner-test", t0, bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, _ := MarshalOwnerKey(owner)
	pubJSON, _ := MarshalOwnerPublicKey(owner.Public())
	assertBytes(t, "owner-test.key.json", keyJSON, fixture(t, "owner-test.key.json"))
	assertBytes(t, "owner-test.pub", pubJSON, fixture(t, "owner-test.pub"))
	if got := hex.EncodeToString(owner.Public().Public); !strings.HasPrefix(got, "d75a98") || !strings.HasSuffix(got, "511a") {
		t.Errorf("public key %s is not the RFC 8032 test 1 key", got)
	}

	token, seal, err := GenerateSiteKeys("blog", t0, stream(seq(0x20, 32), bytes.Repeat([]byte{1}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, "token.keys.json", token, fixture(t, "token.keys.json"))
	assertBytes(t, "seal.root.json", seal, fixture(t, "seal.root.json"))

	rotated, kid, err := RotateTokenKey(token, t1, stream(seq(0x40, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if kid != "blog-t-20260928" {
		t.Errorf("new kid %q", kid)
	}
	assertBytes(t, "token.keys.rotated.json", rotated, fixture(t, "token.keys.rotated.json"))

	added, err := RotateSealRoot(seal, SealStepAdd, time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC), stream(bytes.Repeat([]byte{2}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	promoted, err := RotateSealRoot(added, SealStepPromote, t1, stream())
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, "seal.root.rotating.json", promoted, fixture(t, "seal.root.rotating.json"))

	pseudo, err := GeneratePseudoKey(t0, stream(seq(0x00, 32)))
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, "pseudo.key.json", pseudo, fixture(t, "pseudo.key.json"))

	up, err := GenerateUpstreamKeys(nil, t0, stream(seq(0x60, 32)))
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, "upstream-keys.json", up, fixture(t, "upstream-keys.json"))
	upRotated, err := GenerateUpstreamKeys(up, t1, stream(seq(0x80, 32)))
	if err != nil {
		t.Fatal(err)
	}
	assertBytes(t, "upstream-keys.rotated.json", upRotated, fixture(t, "upstream-keys.rotated.json"))
	if v, _ := UpstreamPrimaryValue(upRotated); len(v) != 43 || v != "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8" {
		t.Errorf("values[0] = %q", v)
	}
}

// §12.0: readers accept every valid fixture.
func TestParseValidFixtures(t *testing.T) {
	if k, err := ParseOwnerKey(fixture(t, "owner-test.key.json")); err != nil || k.KID != "owner-test" {
		t.Errorf("owner key: %v %v", k, err)
	}
	if k, err := ParseOwnerPublicKey(fixture(t, "owner-test.pub")); err != nil || k.KID != "owner-test" {
		t.Errorf("owner pub: %v %v", k, err)
	}
	for name, want := range map[string]FileInfo{
		"token.keys.json":            {Kind: KindTokenKeys, Site: "blog", IDs: []string{"blog-t-20260927"}},
		"token.keys.rotated.json":    {Kind: KindTokenKeys, Site: "blog", IDs: []string{"blog-t-20260928", "blog-t-20260927"}},
		"seal.root.json":             {Kind: KindSealRoot, Site: "blog", IDs: []string{"blog-r-20260927"}},
		"seal.root.rotating.json":    {Kind: KindSealRoot, Site: "blog", IDs: []string{"blog-r-20261027", "blog-r-20260927"}},
		"pseudo.key.json":            {Kind: KindPseudoKey, IDs: []string{"pseudo-20260927"}},
		"upstream-keys.json":         {Kind: KindUpstreamKeys},
		"upstream-keys.rotated.json": {Kind: KindUpstreamKeys},
	} {
		got, err := Inspect(fixture(t, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if fmt.Sprint(*got) != fmt.Sprint(want) {
			t.Errorf("%s: %+v, want %+v", name, *got, want)
		}
	}
}

// §12.0: readers reject every sample in keys/invalid (token.keys.site-shop.json
// is only invalid for site blog: the site check is the caller's).
func TestRejectInvalidFixtures(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(fixtures, "invalid"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no invalid fixtures")
	}
	for _, e := range entries {
		data := fixture(t, filepath.Join("invalid", e.Name()))
		var err error
		switch {
		case strings.HasPrefix(e.Name(), "owner-test.pub"):
			_, err = ParseOwnerPublicKey(data)
		case e.Name() == "token.keys.site-shop.json":
			info, ierr := Inspect(data)
			if ierr == nil && info.Site != "blog" {
				err = fmt.Errorf("site %q is not blog", info.Site)
			}
		default:
			_, err = Inspect(data)
		}
		if err == nil {
			t.Errorf("%s was accepted", e.Name())
		} else {
			t.Logf("%s: %v", e.Name(), err)
		}
	}
}

func TestParseRejectsMalformedFiles(t *testing.T) {
	good := string(fixture(t, "token.keys.json"))
	for name, data := range map[string]string{
		"trailing data":  good + "{}",
		"not json":       "v: 1",
		"array":          "[]",
		"padded key":     strings.Replace(good, `Pj8"`, `Pj8="`, 1),
		"std base64 key": strings.Replace(good, "ICEiIyQl", "ICEi+yQl", 1),
		"bad created_at": strings.Replace(good, "2026-09-27T10:00:00Z", "2026-09-27 10:00", 1),
		"bad site":       strings.Replace(good, `"site": "blog"`, `"site": "Blog"`, 1),
		"owner key kind": strings.Replace(good, KindTokenKeys, KindOwnerKey, 1),
		// §12.0: what the Edge's serde readers reject, encoding/json alone accepts.
		"case-variant member":    strings.Replace(good, `"site"`, `"Site"`, 1),
		"case-variant nested":    strings.Replace(good, `"kid"`, `"KID"`, 1),
		"duplicate member":       strings.Replace(good, `"site": "blog",`, `"site": "blog", "site": "blog",`, 1),
		"duplicate nested":       strings.Replace(good, `"kid": "blog-t-20260927",`, `"kid": "blog-t-20260927", "kid": "blog-t-20260927",`, 1),
		"null member":            strings.Replace(good, `"v": 1`, `"v": null`, 1),
		"created_at offset 24 h": strings.Replace(good, "2026-09-27T10:00:00Z", "2026-09-27T10:00:00+24:00", 1),
		"created_at comma":       strings.Replace(good, "2026-09-27T10:00:00Z", "2026-09-27T10:00:00,5Z", 1),
		"invalid UTF-8":          strings.Replace(good, `"site": "blog"`, "\"site\": \"blog\xff\"", 1),
	} {
		if data == good {
			t.Fatalf("%s: the mutation did not apply", name)
		}
		if _, err := Inspect([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	pub := string(fixture(t, "owner-test.pub"))
	if _, err := ParseOwnerPublicKey([]byte(strings.Replace(pub, "owner-test", "Owner", 1))); err == nil {
		t.Error("bad owner kid accepted")
	}
	if _, err := ParseOwnerKey([]byte(strings.Replace(string(fixture(t, "owner-test.key.json")), `"v": 1`, `"v": 2`, 1))); err == nil {
		t.Error("owner key v 2 accepted")
	}
	// Owner signing keys are never exported in plaintext.
	if _, err := Inspect(fixture(t, "owner-test.key.json")); err == nil || !strings.Contains(err.Error(), "never exported") {
		t.Errorf("Inspect(owner key) = %v", err)
	}
}

func TestRotateTokenKeyLimitAndSameDaySuffix(t *testing.T) {
	cur := fixture(t, "token.keys.rotated.json") // blog-t-20260928, blog-t-20260927
	next, kid, err := RotateTokenKey(cur, t1.Add(time.Hour), stream(seq(0xa0, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if kid != "blog-t-20260928-2" {
		t.Errorf("same-day kid = %q", kid)
	}
	next, kid, err = RotateTokenKey(next, t1.Add(2*time.Hour), stream(seq(0xc0, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if kid != "blog-t-20260928-3" {
		t.Errorf("second same-day kid = %q", kid)
	}
	info, err := Inspect(next)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"blog-t-20260928-3", "blog-t-20260928-2", "blog-t-20260928"}
	if fmt.Sprint(info.IDs) != fmt.Sprint(want) {
		t.Errorf("kids after rotation = %v, want %v (new first, at most 3)", info.IDs, want)
	}
	if _, _, err := RotateTokenKey(fixture(t, "invalid/token.keys.too-many.json"), t1, stream(seq(0, 32))); err == nil {
		t.Error("rotating an invalid file succeeded")
	}
	if _, _, err := RotateTokenKey(cur, t1, stream(seq(0, 8))); err == nil {
		t.Error("short random stream accepted")
	}
}

// §17 / D-30: add, promote, retire and their preconditions.
func TestRotateSealRootSteps(t *testing.T) {
	one := fixture(t, "seal.root.json")
	two := fixture(t, "seal.root.rotating.json")
	d := time.Date(2026, 9, 27, 23, 0, 0, 0, time.UTC)

	added, err := RotateSealRoot(one, SealStepAdd, d, stream(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := Inspect(added)
	if fmt.Sprint(info.IDs) != "[blog-r-20260927 blog-r-20260927-2]" {
		t.Errorf("add: roots %v (the new root goes second; same-day id gets -2)", info.IDs)
	}
	retired, err := RotateSealRoot(two, SealStepRetire, d, stream())
	if err != nil {
		t.Fatal(err)
	}
	info, _ = Inspect(retired)
	if fmt.Sprint(info.IDs) != "[blog-r-20261027]" {
		t.Errorf("retire: roots %v", info.IDs)
	}
	for _, tc := range []struct {
		name string
		in   []byte
		step string
	}{
		{"add to two roots", two, SealStepAdd},
		{"promote one root", one, SealStepPromote},
		{"retire one root", one, SealStepRetire},
		{"unknown step", one, "rotate"},
	} {
		if _, err := RotateSealRoot(tc.in, tc.step, d, stream(seq(0, 32))); err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}
}

func TestGenerateSiteKeysValidation(t *testing.T) {
	if _, _, err := GenerateSiteKeys("Blog", t0, stream(seq(0, 64))); err == nil {
		t.Error("bad site id accepted")
	}
	long := strings.Repeat("a", 60)
	if _, _, err := GenerateSiteKeys(long, t0, stream(seq(0, 64))); err == nil {
		t.Error("site id too long for its kid accepted")
	}
	if _, err := GenerateOwnerKey("Owner!", t0, stream(seq(0, 32))); err == nil {
		t.Error("bad owner kid accepted")
	}
}

type katEntity struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	KeyHex string `json:"key_hex"`
}

func readKAT(t *testing.T) (entity []katEntity, kPseudo []byte, ipEntity []struct{ IP, Entity, Prefix string }) {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/phase1/kat.json")
	if err != nil {
		t.Fatal(err)
	}
	var kat struct {
		EntityKey struct {
			KPseudoHex string      `json:"k_pseudo_hex"`
			Cases      []katEntity `json:"cases"`
		} `json:"entity_key"`
		IPEntity struct {
			Cases []struct{ IP, Entity, Prefix string } `json:"cases"`
		} `json:"ip_entity"`
	}
	if err := json.Unmarshal(data, &kat); err != nil {
		t.Fatal(err)
	}
	k, _ := hex.DecodeString(kat.EntityKey.KPseudoHex)
	return kat.EntityKey.Cases, k, kat.IPEntity.Cases
}

// §9.7: kh() equals every kat.json entity_key vector.
func TestKHMatchesKAT(t *testing.T) {
	cases, k, _ := readKAT(t)
	if len(cases) == 0 {
		t.Fatal("no kat cases")
	}
	for _, c := range cases {
		if got := KH(k, c.Domain, c.Type, c.Value); got != c.KeyHex {
			t.Errorf("kh(%s, %s, %s) = %s, want %s", c.Domain, c.Type, c.Value, got, c.KeyHex)
		}
	}
}

// D-24: ip entity and prefix equal kat.json ip_entity.
func TestEntityAndPrefixMatchKAT(t *testing.T) {
	_, _, cases := readKAT(t)
	for _, c := range cases {
		ip := netip.MustParseAddr(c.IP)
		if got := EntityOf(ip); got != c.Entity {
			t.Errorf("EntityOf(%s) = %s, want %s", c.IP, got, c.Entity)
		}
		if got := PrefixOf(ip); got != c.Prefix {
			t.Errorf("PrefixOf(%s) = %s, want %s", c.IP, got, c.Prefix)
		}
	}
}

// §14.1 `verdict key`: the key part equals kat.json entity_key, and ip goes
// through the ip entity first.
func TestVerdictKeyMatchesKAT(t *testing.T) {
	cases, _, _ := readKAT(t)
	pseudo := fixture(t, "pseudo.key.json") // k_pseudo = 0x00..0x1f, the kat key
	want := map[string]string{}
	for _, c := range cases {
		if c.Domain == "mg-ent-v1" {
			want[c.Type+" "+c.Value] = c.KeyHex
		}
	}
	for _, tc := range []struct{ site, typ, value, key string }{
		{"blog", "ip", "203.0.113.7", "mg:v:blog:ip:" + want["ip 203.0.113.7"]},
		{"blog", "ip", "::ffff:203.0.113.7", "mg:v:blog:ip:" + want["ip 203.0.113.7"]},
		{"all", "ip", "2001:db8::1", "mg:v:all:ip:" + want["ip 2001:db8::/64"]},
		{"all", "ip", "2001:db8::ffff:1", "mg:v:all:ip:" + want["ip 2001:db8::/64"]},
		{"blog", "prefix", "203.0.113.0/24", "mg:v:blog:prefix:" + want["prefix 203.0.113.0/24"]},
		{"blog", "prefix", "203.0.113.99", "mg:v:blog:prefix:" + want["prefix 203.0.113.0/24"]},
		{"blog", "asn", "64500", "mg:v:blog:asn:64500"},
		{"all", "asn", "AS64500", "mg:v:all:asn:64500"},
		{"blog", "session", "AAECAwQFBgcICQoLDA0ODw", "mg:v:blog:session:AAECAwQFBgcICQoLDA0ODw"},
	} {
		got, err := VerdictKey(pseudo, tc.site, tc.typ, tc.value)
		if err != nil || got != tc.key {
			t.Errorf("VerdictKey(%s, %s, %s) = %q, %v; want %q", tc.site, tc.typ, tc.value, got, err, tc.key)
		}
	}
	for _, tc := range []struct{ site, typ, value string }{
		{"Blog", "ip", "203.0.113.7"},
		{"blog", "ip", "203.0.113.0/24"},
		{"blog", "ip", "fe80::1%eth0"},
		{"blog", "prefix", "203.0.113.0/25"},
		{"blog", "prefix", "203.0.113.1/24"},
		{"blog", "prefix", "2001:db8::/64"},
		{"blog", "asn", "0"},
		{"blog", "asn", "4294967296"},
		{"blog", "asn", "0064500"},
		{"blog", "session", "short"},
		{"all", "session", "AAECAwQFBgcICQoLDA0ODw"},
		{"blog", "device", "x"},
	} {
		if got, err := VerdictKey(pseudo, tc.site, tc.typ, tc.value); err == nil {
			t.Errorf("VerdictKey(%s, %s, %s) = %q, want an error", tc.site, tc.typ, tc.value, got)
		}
	}
	if _, err := VerdictKey(fixture(t, "token.keys.json"), "blog", "asn", "1"); err == nil {
		t.Error("a token key file was accepted as the pseudonymisation key")
	}
}

// §12.6: age round trip at work factor 10, wrong passphrase, no overwrite.
func TestAgeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token.keys.json.age")
	plain := fixture(t, "token.keys.json")
	if err := EncryptFile(path, plain, []byte("correct horse"), 10); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if !bytes.HasPrefix(raw, []byte("age-encryption.org/v1\n")) || bytes.Contains(raw, []byte("blog-t-")) {
		t.Error("the file is not an age file or leaks plaintext")
	}
	got, err := DecryptFile(path, []byte("correct horse"))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := DecryptFile(path, []byte("wrong")); err == nil {
		t.Error("wrong passphrase accepted")
	}
	if err := EncryptFile(path, plain, []byte("x"), 10); !errors.Is(err, fs.ErrExist) {
		t.Errorf("overwrite: %v, want ErrExist", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, raw) {
		t.Error("a refused write changed the file")
	}
	if err := ReEncryptFile(path, []byte("{}\n"), []byte("new pass"), 10); err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptFile(path, []byte("new pass")); err != nil || string(got) != "{}\n" {
		t.Errorf("after re-encryption: %q %v", got, err)
	}
	if err := ReEncryptFile(filepath.Join(dir, "missing.age"), plain, []byte("x"), 10); err == nil {
		t.Error("ReEncryptFile created a new file")
	}
	for _, wf := range []int{9, 23} {
		if _, err := Encrypt(plain, []byte("x"), wf); err == nil {
			t.Errorf("work factor %d accepted", wf)
		}
	}
	if _, err := Encrypt(plain, nil, 10); err == nil {
		t.Error("empty passphrase accepted")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*tmp*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestOwnerKeyFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	k, err := GenerateOwnerKey("owner-2026", t0, stream(seq(7, 32)))
	if err != nil {
		t.Fatal(err)
	}
	keyPath, pubPath, err := WriteOwnerKey(dir, k, []byte("pw"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(keyPath) != "owner-2026.key.age" || filepath.Base(pubPath) != "owner-2026.pub" {
		t.Errorf("paths %s %s", keyPath, pubPath)
	}
	for p, mode := range map[string]fs.FileMode{keyPath: 0o600, pubPath: 0o644} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: mode %v (%v), want %v", p, st.Mode().Perm(), err, mode)
		}
	}
	loaded, err := LoadOwnerKey(keyPath, []byte("pw"))
	if err != nil || !loaded.Private.Equal(k.Private) || loaded.KID != k.KID {
		t.Fatalf("LoadOwnerKey: %v", err)
	}
	pub, err := LoadOwnerPublicKey(pubPath)
	if err != nil || !pub.Public.Equal(k.Public().Public) {
		t.Fatalf("LoadOwnerPublicKey: %v", err)
	}
	if _, _, err := WriteOwnerKey(dir, k, []byte("pw"), 10); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second WriteOwnerKey: %v, want ErrExist", err)
	}
	if _, err := LoadOwnerKey(keyPath, []byte("nope")); err == nil {
		t.Error("wrong passphrase accepted")
	}
}

// §2.4 item 4: fmt output never contains key material.
func TestKeysAreRedactedInFmt(t *testing.T) {
	k, _ := GenerateOwnerKey("owner-test", t0, stream(seq(0x55, 32)))
	pk, _ := ParsePseudoKey(fixture(t, "pseudo.key.json"))
	for _, v := range []any{k, pk, *k, *pk, []*OwnerKey{k}, struct{ K *PseudoKey }{pk}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(verb, v)
			for _, secret := range [][]byte{k.Private.Seed(), pk.Key} {
				decimal := strings.Trim(fmt.Sprint(secret[:6]), "[]") // e.g. "85 86 87 88 89 90"
				if strings.Contains(out, encodeKey(secret)) || strings.Contains(out, hex.EncodeToString(secret[:6])) ||
					strings.Contains(out, decimal) || !strings.Contains(out, "redacted") {
					t.Errorf("%s of %T leaks key material: %s", verb, v, out)
				}
			}
		}
	}
}

func TestWorkFactor(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == EnvWorkFactor {
				return v
			}
			return ""
		}
	}
	for _, tc := range []struct {
		val      string
		insecure bool
		want     int
		usage    bool
	}{
		{"", false, 18, false},
		{"20", false, 20, false},
		{"22", false, 22, false},
		{"10", true, 10, false},
		{"10", false, 0, true},
		{"17", false, 0, true},
		{"9", true, 0, true},
		{"23", true, 0, true},
		{"x", true, 0, true},
	} {
		got, err := WorkFactor(env(tc.val), tc.insecure)
		if got != tc.want || (err != nil) != tc.usage || (err != nil && !errors.Is(err, ErrUsage)) {
			t.Errorf("WorkFactor(%q, %v) = %d, %v", tc.val, tc.insecure, got, err)
		}
	}
}

func TestReadPassphrase(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var errb bytes.Buffer
	envFor := func(path string) cli.Env {
		return cli.Env{Stderr: &errb, Stdin: strings.NewReader(""), Getenv: func(k string) string {
			if k == EnvPassphraseFile {
				return path
			}
			return ""
		}}
	}
	for content, want := range map[string]string{
		"secret\n":         "secret",
		"secret":           "secret",
		"secret\r\nnext\n": "secret",
		" spaced pass \n":  " spaced pass ",
	} {
		got, err := ReadPassphrase(envFor(write("p", content)), true)
		if err != nil || string(got) != want {
			t.Errorf("file %q: %q %v, want %q", content, got, err, want)
		}
	}
	if _, err := ReadPassphrase(envFor(write("empty", "\nsecond\n")), false); err == nil {
		t.Error("empty first line accepted")
	}
	if _, err := ReadPassphrase(envFor(filepath.Join(dir, "missing")), false); err == nil {
		t.Error("missing passphrase file accepted")
	}
	// No MGCTL_PASSPHRASE_FILE and no terminal: an error, never a prompt on a pipe.
	old := openTTY
	openTTY = func() (*os.File, error) { return nil, errors.New("no tty") }
	defer func() { openTTY = old }()
	if _, err := ReadPassphrase(envFor(""), false); err == nil || !strings.Contains(err.Error(), EnvPassphraseFile) {
		t.Errorf("without a terminal: %v", err)
	}
}

func TestWriteNewFileAndReplaceFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteNewFile(p, []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewFile(p, []byte("two"), 0o640); !errors.Is(err, fs.ErrExist) {
		t.Errorf("second write: %v", err)
	}
	if err := ReplaceFile(p, []byte("three"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "three" {
		t.Errorf("content %q", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	if _, err := ReadFileLimit(p, 2); err == nil {
		t.Error("ReadFileLimit ignored the limit")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("leftover files: %v", entries)
	}
}

// xorshift64 is the deterministic generator of §2.4 item 3.
type xorshift uint64

func (x *xorshift) next() uint64 {
	*x ^= *x << 13
	*x ^= *x >> 7
	*x ^= *x << 17
	return uint64(*x)
}

// mutate returns a random variation of seed: random bytes, a bit flip, a
// truncation, a duplicated or deleted range.
func (x *xorshift) mutate(seed []byte) []byte {
	b := bytes.Clone(seed)
	switch x.next() % 5 {
	case 0:
		n := int(x.next() % 256)
		b = make([]byte, n)
		for i := range b {
			b[i] = byte(x.next())
		}
	case 1:
		if len(b) > 0 {
			i := int(x.next() % uint64(len(b)))
			b[i] ^= 1 << (x.next() % 8)
		}
	case 2:
		if len(b) > 0 {
			b = b[:x.next()%uint64(len(b))]
		}
	case 3:
		if len(b) > 0 {
			i := int(x.next() % uint64(len(b)))
			b = append(b[:i:i], append([]byte(`{"",[1,`), b[i:]...)...)
		}
	default:
		if len(b) > 2 {
			i := int(x.next() % uint64(len(b)-1))
			j := i + 1 + int(x.next()%uint64(len(b)-i-1))
			b = append(b[:i:i], b[j:]...)
		}
	}
	return b
}

// §2.4 item 3: ≥ 10,000 deterministic random inputs to every key file parser
// return errors, never panic.
func TestParsersNeverPanic(t *testing.T) {
	var seeds [][]byte
	entries, _ := os.ReadDir(fixtures)
	for _, e := range entries {
		if !e.IsDir() {
			seeds = append(seeds, fixture(t, e.Name()))
		}
	}
	x := xorshift(0x9e3779b97f4a7c15)
	pseudo := fixture(t, "pseudo.key.json")
	for i := 0; i < 12_000; i++ {
		in := x.mutate(seeds[i%len(seeds)])
		_, _ = ParseOwnerKey(in)
		_, _ = ParseOwnerPublicKey(in)
		_, _ = Inspect(in)
		_, _ = ParsePseudoKey(in)
		_, _, _ = RotateTokenKey(in, t0, stream(seq(0, 32)))
		_, _ = RotateSealRoot(in, SealStepAdd, t0, stream(seq(0, 32)))
		_, _ = GenerateUpstreamKeys(in, t0, stream(seq(0, 32)))
		_, _ = VerdictKey(pseudo, "blog", VerdictTypes[i%len(VerdictTypes)], string(in))
		// Random ciphertext: never scrypt with an attacker-chosen work factor
		// above the cap, never a panic.
		_, _ = Decrypt(append([]byte("age-encryption.org/v1\n"), in...), []byte("pw"))
	}
}
