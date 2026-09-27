package keys

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"
)

// DecodeStrictJSON decodes exactly one JSON value into v and rejects
// everything the Edge's readers (serde with deny_unknown_fields, spec §12.0)
// reject but encoding/json alone would accept: unknown members, members that
// match a field only case-insensitively, duplicate members, missing members
// (other than those named in optional), null values, invalid UTF-8 and
// trailing data. A file mgctl accepts therefore also loads on every Edge.
//
// v must point to a struct whose fields all carry json tags without
// omitempty, so that re-encoding it names every member the file must have.
func DecodeStrictJSON(data []byte, v any, optional ...string) error {
	if !utf8.Valid(data) {
		return errors.New("invalid JSON: not valid UTF-8")
	}
	if err := checkMembers(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON: trailing data after the value")
	}
	// Exact member names: compare the input's members with those of v
	// re-encoded (DisallowUnknownFields matches names case-insensitively,
	// and a missing member simply leaves the zero value).
	canonical, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var got, want any
	if err := json.Unmarshal(data, &got); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := json.Unmarshal(canonical, &want); err != nil {
		return err
	}
	return sameMembers(got, want, "", optional)
}

// checkMembers walks the token stream and rejects duplicate member names
// within one object and null values anywhere.
func checkMembers(data []byte) error {
	type frame struct {
		object  bool
		wantKey bool
		keys    map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*frame
	// valueDone marks the end of a member value in the enclosing object.
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].wantKey {
			top := stack[n-1]
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:n-1]
				valueDone()
				continue
			}
			key, _ := tok.(string)
			if top.keys[key] {
				return fmt.Errorf("invalid JSON: duplicate member %q", key)
			}
			top.keys[key] = true
			top.wantKey = false
			continue
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, &frame{object: true, wantKey: true, keys: map[string]bool{}})
			case '[':
				stack = append(stack, &frame{})
			default: // ']' (a '}' is handled above)
				stack = stack[:len(stack)-1]
				valueDone()
			}
		case nil:
			return errors.New("invalid JSON: null value")
		default:
			valueDone()
		}
	}
}

// sameMembers reports the first object member of got that want does not
// have (a name that differs only in case) or that got lacks.
func sameMembers(got, want any, path string, optional []string) error {
	switch g := got.(type) {
	case map[string]any:
		w, ok := want.(map[string]any)
		if !ok {
			return nil
		}
		for _, k := range slices.Sorted(maps.Keys(g)) {
			wv, ok := w[k]
			if !ok {
				return fmt.Errorf("invalid JSON: unknown member %q", path+k)
			}
			if err := sameMembers(g[k], wv, path+k+".", optional); err != nil {
				return err
			}
		}
		for _, k := range slices.Sorted(maps.Keys(w)) {
			if _, ok := g[k]; !ok && !slices.Contains(optional, k) {
				return fmt.Errorf("invalid JSON: missing member %q", path+k)
			}
		}
	case []any:
		w, ok := want.([]any)
		if !ok || len(w) != len(g) {
			return nil
		}
		for i := range g {
			if err := sameMembers(g[i], w[i], fmt.Sprintf("%s%d.", path, i), optional); err != nil {
				return err
			}
		}
	}
	return nil
}

// rfc3339Syntax is the RFC 3339 date-time the Edge's readers accept (upper-
// case T and Z; offsets within ±23:59; '.' before a fraction).
var rfc3339Syntax = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

// ValidRFC3339 reports whether s is an RFC 3339 timestamp in the form the
// Edge accepts. time.Parse alone also takes a ',' before the fraction and
// offsets such as +24:00 or +05:60.
func ValidRFC3339(s string) bool {
	if !rfc3339Syntax.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}
