package nearline

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// Kind is the kind of an mg:ev entry.
type Kind uint8

// Entry kinds (docs/impl/phase2-spec.md §13.1).
const (
	KindDecision Kind = iota + 1
	KindFeedback
)

// String returns the wire name ("decision" / "feedback").
func (k Kind) String() string {
	switch k {
	case KindDecision:
		return "decision"
	case KindFeedback:
		return "feedback"
	}
	return "unknown"
}

// Key16 is a 16-byte pseudonymous key: the 32-hex-digit kh value of an ipk
// or pfk field (Phase 1 spec §9.7). Held as bytes so window maps stay small.
type Key16 [16]byte

// String returns the lower-case hex form, as written in the entry.
func (k Key16) String() string { return hex.EncodeToString(k[:]) }

// Entry is one parsed mg:ev entry, v1 or v2 (spec §13.1). Fields a v1 entry
// does not carry keep their zero value ("missing"): CT 0, PF 0, Fam 0, no PH.
type Entry struct {
	Version int
	Kind    Kind
	Site    string
	TS      int64 // Unix ms, as written by the Edge
	RID     string
	Route   string

	Sess   string // decision: sub of the valid clearance; feedback v2: sub of the new clearance
	IPK    Key16  // valid when HasIPK
	HasIPK bool
	PFK    Key16 // valid when HasPFK
	HasPFK bool
	ASN    uint32

	// Decision entries.
	Action string
	Dry    bool
	Class  string
	Score  int
	Status int
	Method string // v2
	PH     uint64 // v2; valid when HasPH
	HasPH  bool
	CT     byte // v2: 'h', 'a', 'j', 'o', or 0 (no origin response, or v1)
	BT     bool // v2
	XS     bool // v2
	TK     bool // v2
	PF     byte // v2: '-', 'v', 'u', 'j', 'r', 'x'; 0 for v1
	UF     string
	Fam    int    // v2: 4, 6, or 0 (client IP unknown, or v1)
	CType  string // v2: "invisible", "pow", "interactive" or ""

	// Feedback entries.
	Outcome  string
	Type     string
	Provider string // v2
	Lvl      string // v2
}

// Parse limits. The stream is written by the Edge only (its ACL user is the
// only one with XADD), but the worker still treats it as untrusted input.
const (
	maxEntryFields = 64  // field/value pairs
	maxFieldName   = 32  // bytes
	maxFieldValue  = 256 // bytes
)

var (
	sitePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	tokenPattern = regexp.MustCompile(`^[a-z0-9_:.-]{1,64}$`)
	sessPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// Fields of each entry shape, in XADD order (spec §13.1, Phase 1 spec
// §13.6). All of them are required; unknown extra fields are ignored.
var (
	decisionV1 = []string{"v", "kind", "site", "ts", "rid", "sess", "route", "action", "dry", "class", "score", "ipk", "pfk", "asn", "status"}
	decisionV2 = append(append([]string(nil), decisionV1...), "m", "ph", "ct", "bt", "xs", "tk", "pf", "uf", "fam", "ctype")
	feedbackV1 = []string{"v", "kind", "site", "ts", "rid", "route", "outcome", "type", "pfk", "asn"}
	feedbackV2 = append(append([]string(nil), feedbackV1...), "p", "ipk", "sess", "lvl")
)

// errEntry is the parse error of one entry; its text never contains a
// field value.
type errEntry struct{ msg string }

func (e *errEntry) Error() string { return "mg:ev entry: " + e.msg }

func entryErr(format string, args ...any) error { return &errEntry{fmt.Sprintf(format, args...)} }

// ErrNilEntry is returned for a stream entry without fields (an entry that
// was deleted while it was pending).
var ErrNilEntry = errors.New("mg:ev entry: no fields")

// ParseEntry parses the alternating field/value list of one mg:ev entry.
// Duplicate fields, a missing field of the entry's version and kind, and a
// malformed value are errors; unknown fields are ignored.
func ParseEntry(fv []string) (Entry, error) {
	var e Entry
	if len(fv) == 0 {
		return e, ErrNilEntry
	}
	if len(fv)%2 != 0 {
		return e, entryErr("odd number of fields and values (%d)", len(fv))
	}
	if len(fv)/2 > maxEntryFields {
		return e, entryErr("more than %d fields", maxEntryFields)
	}
	m := make(map[string]string, len(fv)/2)
	for i := 0; i < len(fv); i += 2 {
		name, val := fv[i], fv[i+1]
		if name == "" || len(name) > maxFieldName {
			return e, entryErr("field %d: bad field name length %d", i/2, len(name))
		}
		if len(val) > maxFieldValue {
			return e, entryErr("field %q: value longer than %d bytes", name, maxFieldValue)
		}
		if _, dup := m[name]; dup {
			return e, entryErr("duplicate field %q", name)
		}
		m[name] = val
	}
	switch m["v"] {
	case "1":
		e.Version = 1
	case "2":
		e.Version = 2
	default:
		return e, entryErr("unsupported version")
	}
	var required []string
	switch m["kind"] {
	case "decision":
		e.Kind = KindDecision
		required = decisionV1
		if e.Version == 2 {
			required = decisionV2
		}
	case "feedback":
		e.Kind = KindFeedback
		required = feedbackV1
		if e.Version == 2 {
			required = feedbackV2
		}
	default:
		return e, entryErr("unknown kind")
	}
	for _, f := range required {
		if _, ok := m[f]; !ok {
			return e, entryErr("missing field %q", f)
		}
	}
	p := fieldParser{m: m}
	e.Site = p.match("site", sitePattern, false)
	e.TS = p.int("ts", 0, 1<<53)
	e.RID = p.str("rid", 64, false)
	e.Route = p.str("route", 64, true)
	e.PFK, e.HasPFK = p.key16("pfk")
	e.ASN = uint32(p.int("asn", 0, 1<<32-1))
	if e.Kind == KindDecision {
		e.Sess = p.match("sess", sessPattern, true)
		e.Action = p.match("action", tokenPattern, false)
		e.Dry = p.bit("dry")
		e.Class = p.match("class", tokenPattern, false)
		e.Score = int(p.int("score", 0, 100))
		e.IPK, e.HasIPK = p.key16("ipk")
		e.Status = int(p.int("status", 0, 999))
		if e.Version == 2 {
			e.Method = p.str("m", 16, false)
			e.PH, e.HasPH = p.ph()
			e.CT = p.oneOf("ct", "", "h", "a", "j", "o")
			e.BT = p.bit("bt")
			e.XS = p.bit("xs")
			e.TK = p.bit("tk")
			e.PF = p.oneOf("pf", "-", "v", "u", "j", "r", "x")
			e.UF = p.str("uf", 16, true)
			switch p.oneOf("fam", "", "4", "6") {
			case '4':
				e.Fam = 4
			case '6':
				e.Fam = 6
			}
			switch v := m["ctype"]; v {
			case "", "invisible", "pow", "interactive":
				e.CType = v
			default:
				p.fail("ctype")
			}
		}
	} else {
		e.Outcome = p.match("outcome", tokenPattern, false)
		e.Type = p.match("type", tokenPattern, true)
		if e.Version == 2 {
			e.Provider = p.match("p", tokenPattern, true)
			e.IPK, e.HasIPK = p.key16("ipk")
			e.Sess = p.match("sess", sessPattern, true)
			e.Lvl = p.match("lvl", tokenPattern, true)
		}
	}
	if p.err != nil {
		return Entry{}, p.err
	}
	return e, nil
}

// fieldParser reads typed values out of the field map and keeps the first
// error.
type fieldParser struct {
	m   map[string]string
	err error
}

func (p *fieldParser) fail(name string) {
	if p.err == nil {
		p.err = entryErr("malformed field %q", name)
	}
}

func (p *fieldParser) str(name string, max int, emptyOK bool) string {
	v := p.m[name]
	if len(v) > max || (v == "" && !emptyOK) {
		p.fail(name)
		return ""
	}
	return v
}

func (p *fieldParser) match(name string, re *regexp.Regexp, emptyOK bool) string {
	v := p.m[name]
	if v == "" && emptyOK {
		return ""
	}
	if !re.MatchString(v) {
		p.fail(name)
		return ""
	}
	return v
}

// int parses a plain decimal integer (no sign, no leading zeros except "0").
func (p *fieldParser) int(name string, lo, hi int64) int64 {
	v := p.m[name]
	if v == "" || len(v) > 19 || (len(v) > 1 && v[0] == '0') {
		p.fail(name)
		return 0
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			p.fail(name)
			return 0
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < lo || n > hi {
		p.fail(name)
		return 0
	}
	return n
}

func (p *fieldParser) bit(name string) bool {
	switch p.m[name] {
	case "0":
		return false
	case "1":
		return true
	}
	p.fail(name)
	return false
}

// oneOf returns the single byte of an allowed value, 0 for "".
func (p *fieldParser) oneOf(name string, allowed ...string) byte {
	v := p.m[name]
	for _, a := range allowed {
		if v == a {
			if v == "" {
				return 0
			}
			return v[0]
		}
	}
	p.fail(name)
	return 0
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// key16 parses "" (absent) or 32 lower-case hex digits.
func (p *fieldParser) key16(name string) (Key16, bool) {
	var k Key16
	v := p.m[name]
	if v == "" {
		return k, false
	}
	if len(v) != 32 || !isLowerHex(v) {
		p.fail(name)
		return k, false
	}
	_, _ = hex.Decode(k[:], []byte(v))
	return k, true
}

// ph parses "" (absent) or 16 lower-case hex digits.
func (p *fieldParser) ph() (uint64, bool) {
	v := p.m["ph"]
	if v == "" {
		return 0, false
	}
	if len(v) != 16 || !isLowerHex(v) {
		p.fail("ph")
		return 0, false
	}
	n, err := strconv.ParseUint(v, 16, 64)
	if err != nil {
		p.fail("ph")
		return 0, false
	}
	return n, true
}
