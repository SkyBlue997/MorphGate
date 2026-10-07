package intelsync

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// EncodeCanonical renders v as canonical JSON (docs/impl/phase1-spec.md
// §12.0): two-space indent, no HTML escaping, keys in struct field order, one
// trailing newline.
func EncodeCanonical(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// decodeStrict decodes exactly one JSON value into v (a pointer to a struct)
// the way the Edge's serde reader does (§12.0: deny_unknown_fields, every
// member required): the input must be valid UTF-8; member names must match
// v's JSON names exactly (encoding/json alone matches them ignoring case) and
// be unique within their object; every member must be present and not null,
// except `omitempty` members, which may be absent; unknown members and
// trailing data are errors. Spacing and escapes are free, so readers do not
// depend on the canonical form.
func decodeStrict(data []byte, v any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	if err := duplicateMember(data); err != nil {
		return err
	}
	var generic any
	g := json.NewDecoder(bytes.NewReader(data))
	g.UseNumber()
	if err := g.Decode(&generic); err != nil {
		return err
	}
	return checkShape(generic, reflect.TypeOf(v), "")
}

// duplicateMember reports the first object member name that occurs twice in
// one object (encoding/json silently keeps the last one).
func duplicateMember(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		keys      map[string]bool // nil for arrays
		expectKey bool
	}
	var stack []*frame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].keys != nil {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n := len(stack); n > 0 && stack[n-1].keys != nil && stack[n-1].expectKey {
			if k, ok := tok.(string); ok {
				if stack[n-1].keys[k] {
					return fmt.Errorf("duplicate member %q", k)
				}
				stack[n-1].keys[k] = true
				stack[n-1].expectKey = false
				continue
			}
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{keys: map[string]bool{}, expectKey: true})
		case json.Delim('['):
			stack = append(stack, &frame{})
		case json.Delim('}'), json.Delim(']'):
			if len(stack) == 0 {
				return errors.New("unbalanced JSON")
			}
			stack = stack[:len(stack)-1]
			valueDone()
		default:
			valueDone()
		}
	}
}

// checkShape compares a generically decoded JSON value with the Go type it
// was decoded into: exact member names, every non-omitempty member present,
// no nulls.
func checkShape(val any, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	at := func() string {
		if path == "" {
			return "top level"
		}
		return path
	}
	switch t.Kind() {
	case reflect.Struct:
		obj, ok := val.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want an object", at())
		}
		known := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if !f.IsExported() || tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if name == "" {
				name = f.Name
			}
			known[name] = true
			member, present := obj[name]
			switch {
			case !present && strings.Contains(","+opts+",", ",omitempty,"):
				continue
			case !present:
				return fmt.Errorf("%s: missing member %q", at(), name)
			case member == nil:
				return fmt.Errorf("%s: member %q is null", at(), name)
			}
			if err := checkShape(member, f.Type, strings.TrimPrefix(path+"."+name, ".")); err != nil {
				return err
			}
		}
		names := make([]string, 0, len(obj))
		for k := range obj {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if !known[k] {
				return fmt.Errorf("%s: unknown member %q (member names are case-sensitive)", at(), k)
			}
		}
	case reflect.Slice:
		arr, ok := val.([]any)
		if !ok {
			return fmt.Errorf("%s: want an array", at())
		}
		for i, e := range arr {
			p := fmt.Sprintf("%s[%d]", path, i)
			if e == nil {
				return fmt.Errorf("%s: null element", p)
			}
			if err := checkShape(e, t.Elem(), p); err != nil {
				return err
			}
		}
	}
	return nil
}

// WriteFileAtomic writes data to a temporary file next to path and renames it
// into place (§14.1), so readers never see a partial file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// readLimited reads a whole file, refusing files larger than limit bytes.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return data, nil
}

// Metric is one sample of a node_exporter textfile (§13.7).
type Metric struct {
	Labels [][2]string // name, value
	Value  float64
}

// MetricFamily is one metric name with its HELP / TYPE lines and samples.
type MetricFamily struct {
	Name, Help, Type string
	Metrics          []Metric
}

// FormatTextfile renders families in the Prometheus text exposition format.
func FormatTextfile(fams []MetricFamily) []byte {
	var b strings.Builder
	for _, f := range fams {
		fmt.Fprintf(&b, "# HELP %s %s\n", f.Name, escapeHelp(f.Help))
		fmt.Fprintf(&b, "# TYPE %s %s\n", f.Name, f.Type)
		for _, m := range f.Metrics {
			b.WriteString(f.Name)
			if len(m.Labels) > 0 {
				b.WriteByte('{')
				for i, l := range m.Labels {
					if i > 0 {
						b.WriteByte(',')
					}
					fmt.Fprintf(&b, "%s=\"%s\"", l[0], escapeLabel(l[1]))
				}
				b.WriteByte('}')
			}
			b.WriteByte(' ')
			b.WriteString(formatValue(m.Value))
			b.WriteByte('\n')
		}
	}
	return []byte(b.String())
}

// WriteTextfile atomically replaces a node_exporter textfile (0644).
func WriteTextfile(path string, fams []MetricFamily) error {
	return WriteFileAtomic(path, FormatTextfile(fams), 0o644)
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

// SyncState is `<artifact>.state.json` (§14.4): the time and etag of the last
// successful `mgctl cf ips sync`, written whether or not the artifact changed.
// `mgctl cf audit` check 19 (ip_snapshot_age) reads it.
type SyncState struct {
	V           int    `json:"v"`
	LastSuccess string `json:"last_success"`
	ETag        string `json:"etag"`
}

// StatePath returns the state file that belongs to an artifact.
func StatePath(artifact string) string { return artifact + ".state.json" }

// ReadSyncState reads and checks a state file.
func ReadSyncState(path string) (*SyncState, time.Time, error) {
	data, err := readLimited(path, 64<<10)
	if err != nil {
		return nil, time.Time{}, err
	}
	st, err := parseSyncState(data)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", path, err)
	}
	t, _ := time.Parse(time.RFC3339, st.LastSuccess)
	return st, t, nil
}

// parseSyncState decodes and checks the contents of a state file.
func parseSyncState(data []byte) (*SyncState, error) {
	var st SyncState
	if err := decodeStrict(data, &st); err != nil {
		return nil, err
	}
	if st.V != 1 {
		return nil, errors.New("v must be 1")
	}
	if !isRFC3339(st.LastSuccess) {
		return nil, errors.New("last_success is not RFC 3339")
	}
	return &st, nil
}

var rfc3339Pattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$`)

// isRFC3339 accepts the RFC 3339 timestamps the Edge accepts
// (intel/src/text.rs) and no others: time.Parse alone also takes a comma
// before the fraction and offsets such as +24:00 or +05:60.
func isRFC3339(s string) bool {
	m := rfc3339Pattern.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	if m[1] != "" && (m[1] > "23" || m[2] > "59") {
		return false
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

// sortedCopy returns a sorted copy of s.
func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}
