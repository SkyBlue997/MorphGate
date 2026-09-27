// Package keys creates, parses, encrypts and rotates MorphGate's key files
// (docs/impl/phase1-spec.md §12.6, §12.7, §14.2):
//
//   - the owner's Ed25519 bundle-signing key (<kid>.key.age, <kid>.pub);
//   - per-site clearance token keys (token.keys.json) and challenge sealing
//     roots (seal.root.json);
//   - the owner-level pseudonymisation key (pseudo.key.json) used to hash
//     identifying parts of Valkey keys;
//   - the upstream secret header values (upstream-keys.json).
//
// Every plaintext file is canonical JSON (§12.0): Go encoding/json with
// two-space indentation, no HTML escaping, keys in the order of the spec and
// one trailing newline; binary values are base64url without padding.
// Generators draw their random bytes from the io.Reader they are given, in the
// order documented in testdata/phase1/README.md, so fixed inputs reproduce the
// shared fixtures in testdata/phase1/keys byte for byte. Readers reject unknown
// fields and every value outside the documented ranges.
//
// On the owner's workstation the plaintext never touches the disk: files are
// written age-encrypted (scrypt passphrase recipient) and only `mgctl keys
// export` decrypts them, to stdout by default.
package keys

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
)

// File kinds (the "kind" member of every key file).
const (
	KindOwnerKey     = "mg-owner-ed25519"
	KindOwnerPub     = "mg-owner-ed25519-pub"
	KindTokenKeys    = "mg-site-token-keys"
	KindSealRoot     = "mg-site-seal-root"
	KindPseudoKey    = "mg-pseudo-key"
	KindUpstreamKeys = "mg-upstream-keys"
)

// Size and count limits of the key files (§12.7).
const (
	// SecretSize is the length of every symmetric key and upstream secret value.
	SecretSize = 32
	// MaxTokenKeys is the number of clearance token keys a site keeps (new first).
	MaxTokenKeys = 3
	// MaxSealRoots is the number of sealing roots during a rotation (D-30).
	MaxSealRoots = 2
	// MaxUpstreamValues is the number of accepted upstream secret values.
	MaxUpstreamValues = 2
	// maxKeyFileSize bounds every key file mgctl reads (plaintext or age).
	maxKeyFileSize = 64 << 10
)

var (
	// KIDPattern is the syntax of key ids (owner kid, token kid, seal root id,
	// pseudonymisation key id).
	KIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// SitePattern is the syntax of site ids.
	SitePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

var b64 = base64.RawURLEncoding.Strict()

// encodeKey encodes key material as base64url without padding.
func encodeKey(b []byte) string { return b64.EncodeToString(b) }

// decodeKey decodes a canonical base64url (no padding) value of exactly n bytes.
func decodeKey(field, s string, n int) ([]byte, error) {
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s: not base64url without padding", field)
	}
	if len(b) != n {
		return nil, fmt.Errorf("%s: %d bytes, want %d", field, len(b), n)
	}
	return b, nil
}

// canonicalJSON renders v as canonical JSON (§12.0).
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// strictDecode decodes exactly one JSON value into v the way the Edge's
// readers do (DecodeStrictJSON): every field is required, and unknown,
// case-variant, duplicate or null members are errors.
func strictDecode(data []byte, v any) error {
	if len(data) > maxKeyFileSize {
		return fmt.Errorf("file is larger than %d bytes", maxKeyFileSize)
	}
	return DecodeStrictJSON(data, v)
}

// formatTime renders a creation time as RFC 3339 in UTC with second precision.
func formatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// parseTime parses a required RFC 3339 timestamp (ValidRFC3339).
func parseTime(field, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || !ValidRFC3339(s) {
		return time.Time{}, fmt.Errorf("%s: %q is not an RFC 3339 timestamp", field, s)
	}
	return t, nil
}

// checkHeader validates the v and kind members shared by every key file.
func checkHeader(v int, kind, want string) error {
	if v != 1 {
		return fmt.Errorf("v: %d, want 1", v)
	}
	if kind != want {
		return fmt.Errorf("kind: %q, want %q", kind, want)
	}
	return nil
}

// readSecret draws one SecretSize-byte secret from rnd.
func readSecret(rnd io.Reader) ([]byte, error) {
	b := make([]byte, SecretSize)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return b, nil
}

// dateStamp is the YYYYMMDD form used in key ids.
func dateStamp(t time.Time) string { return t.UTC().Format("20060102") }

// uniqueID returns base, or base-2, base-3, ... whichever is not taken
// (same-day rotations, §12.7).
func uniqueID(base string, taken func(string) bool) (string, error) {
	id := base
	for n := 2; taken(id); n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	if !KIDPattern.MatchString(id) {
		return "", fmt.Errorf("key id %q does not match %s (site id too long?)", id, KIDPattern)
	}
	return id, nil
}
