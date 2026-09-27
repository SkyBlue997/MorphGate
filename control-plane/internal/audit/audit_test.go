package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"morphgate/control-plane/internal/cli"
)

var now = time.Date(2026, 9, 27, 10, 0, 0, 123456789, time.UTC)

func event(action string, diff any) cli.AuditEvent {
	return cli.AuditEvent{Action: action, ResourceType: "bundle", ResourceID: "blog@1790000000", Site: "blog", Diff: diff}
}

func newLog(t *testing.T) *Log {
	t.Helper()
	l, err := Open(filepath.Join(t.TempDir(), "state", "morphgate", "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func appendN(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := range n {
		if _, err := l.Append(event("bundle.sign", map[string]any{"version": 1790000000 + i, "rules": 12, "monitor_only": true}), now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
}

func lines(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n"))
}

// §12.8: record layout, key order, first prev_hash, hash formula.
func TestRecordFormatAndChain(t *testing.T) {
	l := newLog(t)
	rec, err := l.Append(cli.AuditEvent{
		Action: "bundle.sign", ResourceType: "bundle", ResourceID: "blog@1790000000", Site: "blog",
		Diff:   map[string]any{"version": 1790000000, "sha256": "ab", "rules": 12, "monitor_only": true, "note": "<&>"},
		Reason: "weekly", ConfirmText: "blog",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PrevHash != GenesisHash || len(rec.Hash) != 64 {
		t.Errorf("first record: prev %s hash %s", rec.PrevHash, rec.Hash)
	}
	ls := lines(t, l.Path())
	if len(ls) != 1 {
		t.Fatalf("%d lines", len(ls))
	}
	line := string(ls[0])
	want := regexp.MustCompile(`^\{"id":"[0-9a-f]{32}","ts":"2026-09-27T10:00:00\.123456789Z","actor":"owner","actor_kind":"owner","auth":"local",` +
		`"reauth_at":null,"actor_ip":"","site":"blog","action":"bundle\.sign","resource_type":"bundle","resource_id":"blog@1790000000",` +
		`"diff":\{"monitor_only":true,"note":"<&>","rules":12,"sha256":"ab","version":1790000000\},"reason":"weekly","confirm_text":"blog",` +
		`"effective_at":"2026-09-27T10:00:00\.123456789Z","request_id":"","prev_hash":"0{64}","hash":"([0-9a-f]{64})"\}$`)
	m := want.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("unexpected record layout:\n%s", line)
	}
	// Independent recomputation: canonical = the line without its trailing hash member.
	canonical := strings.TrimSuffix(line, `,"hash":"`+m[1]+`"}`) + "}"
	sum := sha256.Sum256([]byte(GenesisHash + "\n" + canonical))
	if hex.EncodeToString(sum[:]) != m[1] {
		t.Errorf("hash %s != sha256(prev || \\n || canonical)", m[1])
	}

	appendN(t, l, 3)
	count, last, err := Verify(l.Path())
	if err != nil || count != 4 {
		t.Fatalf("Verify = %d, %s, %v", count, last, err)
	}
	ls = lines(t, l.Path())
	if !strings.Contains(string(ls[3]), `"hash":"`+last+`"`) {
		t.Errorf("last hash %s is not the hash of the last line", last)
	}
	for i := 1; i < len(ls); i++ {
		prev := regexp.MustCompile(`"hash":"([0-9a-f]{64})"`).FindSubmatch(ls[i-1])[1]
		if !bytes.Contains(ls[i], []byte(`"prev_hash":"`+string(prev)+`"`)) {
			t.Errorf("line %d does not chain to line %d", i+1, i)
		}
	}
	for _, st := range []struct {
		path string
		mode os.FileMode
	}{{l.Path(), 0o600}, {filepath.Dir(l.Path()), 0o700}} {
		info, err := os.Stat(st.path)
		if err != nil || info.Mode().Perm() != st.mode {
			t.Errorf("%s: mode %v, want %v", st.path, info.Mode().Perm(), st.mode)
		}
	}
}

func TestNilDiffAndEffectiveAt(t *testing.T) {
	l := newLog(t)
	eff := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	rec, err := l.Append(cli.AuditEvent{Action: "keys.gen", ResourceType: "owner_key", ResourceID: "owner-2026", EffectiveAt: eff}, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(rec.Diff) != "null" || rec.EffectiveAt != "2026-10-01T00:00:00.000000000Z" || rec.Site != "" {
		t.Errorf("record %+v", rec)
	}
	if n, _, err := Verify(l.Path()); err != nil || n != 1 {
		t.Errorf("Verify: %d %v", n, err)
	}
}

// §15 WP-G2: tampering with any single byte is detected and located to its line.
func TestVerifyLocatesEveryTamperedByte(t *testing.T) {
	l := newLog(t)
	appendN(t, l, 3)
	orig, _ := os.ReadFile(l.Path())
	lineOf := func(i int) int { return bytes.Count(orig[:i], []byte("\n")) + 1 }
	tampered := filepath.Join(t.TempDir(), "t.jsonl")
	for i := range orig {
		for _, mask := range []byte{0x01, 0x20} {
			b := bytes.Clone(orig)
			b[i] ^= mask
			if err := os.WriteFile(tampered, b, 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := Verify(tampered)
			var ve *VerifyError
			if !errors.As(err, &ve) {
				t.Fatalf("byte %d ^ %#x not detected (err %v)", i, mask, err)
			}
			if ve.Line != lineOf(i) {
				t.Fatalf("byte %d ^ %#x: reported line %d, want %d (%v)", i, mask, ve.Line, lineOf(i), err)
			}
		}
	}
}

func TestVerifyDetectsRemovedAndReorderedLines(t *testing.T) {
	l := newLog(t)
	appendN(t, l, 4)
	ls := lines(t, l.Path())
	write := func(ls ...[]byte) string {
		p := filepath.Join(t.TempDir(), "x.jsonl")
		os.WriteFile(p, append(bytes.Join(ls, []byte("\n")), '\n'), 0o600)
		return p
	}
	var ve *VerifyError
	if _, _, err := Verify(write(ls[0], ls[2], ls[3])); !errors.As(err, &ve) || ve.Line != 2 {
		t.Errorf("removed line: %v", err)
	}
	if _, _, err := Verify(write(ls[0], ls[2], ls[1], ls[3])); !errors.As(err, &ve) || ve.Line != 2 {
		t.Errorf("reordered lines: %v", err)
	}
	if _, _, err := Verify(write(ls[1], ls[2])); !errors.As(err, &ve) || ve.Line != 1 {
		t.Errorf("removed first line: %v", err)
	}
	// An extra space is still a changed byte even though the JSON is equivalent.
	spaced := bytes.Replace(ls[1], []byte(`"actor":"owner"`), []byte(`"actor": "owner"`), 1)
	if _, _, err := Verify(write(ls[0], spaced)); !errors.As(err, &ve) || ve.Line != 2 {
		t.Errorf("whitespace change: %v", err)
	}
	if n, h, err := Verify(write()); err == nil {
		t.Errorf("a lone empty line verified: %d %s", n, h)
	}
	empty := filepath.Join(t.TempDir(), "empty.jsonl")
	os.WriteFile(empty, nil, 0o600)
	if n, h, err := Verify(empty); err != nil || n != 0 || h != GenesisHash {
		t.Errorf("empty log: %d %s %v", n, h, err)
	}
	if _, _, err := Verify(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing log verified")
	}
}

// Appending never extends a chain whose tail is broken or incomplete.
func TestAppendRefusesBrokenTail(t *testing.T) {
	l := newLog(t)
	appendN(t, l, 2)
	data, _ := os.ReadFile(l.Path())
	lastRules := bytes.LastIndex(data, []byte(`"rules":12`))
	tampered := bytes.Clone(data)
	tampered[lastRules+len(`"rules":1`)] = '3'
	for name, mutated := range map[string][]byte{
		"incomplete": data[:len(data)-1],
		"tampered":   tampered,
		"garbage":    append(bytes.Clone(data), []byte("not json\n")...),
	} {
		os.WriteFile(l.Path(), mutated, 0o600)
		if _, err := l.Append(event("bundle.sign", nil), now); err == nil {
			t.Errorf("%s: append succeeded", name)
		}
		if _, err := Open(l.Path()); err == nil {
			t.Errorf("%s: Open succeeded", name)
		}
		if after, _ := os.ReadFile(l.Path()); !bytes.Equal(after, mutated) {
			t.Errorf("%s: the log changed", name)
		}
	}
}

func TestConcurrentAppendsKeepTheChain(t *testing.T) {
	l := newLog(t)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other, err := Open(l.Path())
			if err != nil {
				t.Error(err)
				return
			}
			for i := range 10 {
				if _, err := other.Append(event("keys.gen", map[string]int{"g": g, "i": i}), now); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if n, _, err := Verify(l.Path()); err != nil || n != 80 {
		t.Errorf("Verify after concurrent appends: %d %v", n, err)
	}
}

func TestDefaultPath(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	for _, tc := range []struct {
		env  func(string) string
		want string
	}{
		{env(EnvAuditLog, "/a/log.jsonl", "XDG_STATE_HOME", "/x", "HOME", "/h"), "/a/log.jsonl"},
		{env("XDG_STATE_HOME", "/x", "HOME", "/h"), "/x/morphgate/audit.jsonl"},
		{env("HOME", "/h"), "/h/.local/state/morphgate/audit.jsonl"},
	} {
		if got, err := DefaultPath(tc.env); err != nil || got != tc.want {
			t.Errorf("DefaultPath = %q, %v; want %q", got, err, tc.want)
		}
	}
	if _, err := DefaultPath(env()); err == nil {
		t.Error("no location: no error")
	}
	// XDG Base Directory spec: a relative path is invalid and ignored, so the
	// §12.8 fallback (~/.local/state) applies instead of failing the command.
	if got, err := DefaultPath(env("XDG_STATE_HOME", "rel", "HOME", "/h")); err != nil || got != "/h/.local/state/morphgate/audit.jsonl" {
		t.Errorf("relative XDG_STATE_HOME: %q, %v", got, err)
	}
	if _, err := DefaultPath(env("XDG_STATE_HOME", "rel")); err == nil {
		t.Error("relative XDG_STATE_HOME without HOME: no error")
	}
}

func TestOpenFailsWhenTheDirectoryCannotBeCreated(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := Open(filepath.Join(file, "audit.jsonl")); err == nil {
		t.Error("Open under a regular file succeeded")
	}
	if _, err := Open(""); err == nil {
		t.Error("empty path accepted")
	}
}

type xorshift uint64

func (x *xorshift) next() uint64 {
	*x ^= *x << 13
	*x ^= *x >> 7
	*x ^= *x << 17
	return uint64(*x)
}

// §2.4 item 3: ≥ 10,000 deterministic random lines never panic the parser.
func TestParserNeverPanics(t *testing.T) {
	l := newLog(t)
	appendN(t, l, 1)
	seed := lines(t, l.Path())[0]
	x := xorshift(88172645463325252)
	p := filepath.Join(t.TempDir(), "r.jsonl")
	for i := 0; i < 10_000; i++ {
		b := bytes.Clone(seed)
		switch x.next() % 4 {
		case 0:
			b = make([]byte, x.next()%300)
			for j := range b {
				b[j] = byte(x.next())
			}
		case 1:
			b[x.next()%uint64(len(b))] = byte(x.next())
		case 2:
			b = b[:x.next()%uint64(len(b))]
		default:
			j := x.next() % uint64(len(b))
			b = append(b[:j:j], append([]byte(`{"diff":[{`), b[j:]...)...)
		}
		if _, err := parseLine(b); err == nil && !bytes.Equal(b, seed) {
			t.Fatalf("mutated line accepted: %s", b)
		}
		if i%50 == 0 {
			os.WriteFile(p, append(b, '\n'), 0o600)
			_, _, _ = Verify(p)
		}
	}
}
