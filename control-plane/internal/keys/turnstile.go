package keys

import (
	"errors"
	"fmt"
)

// KindTurnstileKeys is the kind of the mg-turnstile-keys file: a site's
// Turnstile widget secret, current value first, the previous one second
// during a rotation (docs/impl/phase2-spec.md §8.7, D-51). The file is a
// deployment credential of the Edge (edge.toml [[sites]] turnstile_keys,
// delivered as a systemd credential); it never enters a bundle.
const KindTurnstileKeys = "mg-turnstile-keys"

// Limits of the mg-turnstile-keys file (§8.7).
const (
	MaxTurnstileValues    = 2
	MaxTurnstileSecretLen = 256
	// MaxTurnstileKeysFile bounds the file (64 KiB, like every key file).
	MaxTurnstileKeysFile = maxKeyFileSize
)

// TurnstileKeys is a parsed mg-turnstile-keys file. Its String form never
// shows the secrets.
type TurnstileKeys struct {
	Site   string
	Values []string // current first; 1-2 entries
}

// String describes the file without its secrets.
func (k *TurnstileKeys) String() string {
	return fmt.Sprintf("mg-turnstile-keys{site: %s, values: %d}", k.Site, len(k.Values))
}

// GoString keeps %#v from printing the secrets.
func (k *TurnstileKeys) GoString() string { return k.String() }

type turnstileKeysFile struct {
	V      int      `json:"v"`
	Kind   string   `json:"kind"`
	Site   string   `json:"site"`
	Values []string `json:"values"`
}

// ValidTurnstileSecret reports whether s is 1-256 visible ASCII characters
// (0x21-0x7e). Errors never repeat the value.
func ValidTurnstileSecret(s string) error {
	if len(s) == 0 || len(s) > MaxTurnstileSecretLen {
		return fmt.Errorf("%d characters, want 1-%d", len(s), MaxTurnstileSecretLen)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return errors.New("not visible ASCII only")
		}
	}
	return nil
}

func (k *TurnstileKeys) validate() error {
	if !SitePattern.MatchString(k.Site) {
		return fmt.Errorf("site: %q does not match %s", k.Site, SitePattern)
	}
	if n := len(k.Values); n < 1 || n > MaxTurnstileValues {
		return fmt.Errorf("values: %d entries, want 1-%d", n, MaxTurnstileValues)
	}
	for i, v := range k.Values {
		if err := ValidTurnstileSecret(v); err != nil {
			return fmt.Errorf("values[%d]: %w", i, err)
		}
	}
	return nil
}

// ParseTurnstileKeys reads an mg-turnstile-keys file the way the Edge does
// (§8.7): at most 64 KiB, strict JSON (unknown, case-variant, duplicate,
// missing and null members are errors), v 1, the right kind, a valid site
// id and 1-2 values of 1-256 visible ASCII characters.
func ParseTurnstileKeys(data []byte) (*TurnstileKeys, error) {
	var f turnstileKeysFile
	if err := strictDecode(data, &f); err != nil {
		return nil, err
	}
	if err := checkHeader(f.V, f.Kind, KindTurnstileKeys); err != nil {
		return nil, err
	}
	k := &TurnstileKeys{Site: f.Site, Values: f.Values}
	if err := k.validate(); err != nil {
		return nil, err
	}
	return k, nil
}

// ParseTurnstileKeysFor parses the file and requires it to belong to site.
func ParseTurnstileKeysFor(data []byte, site string) (*TurnstileKeys, error) {
	k, err := ParseTurnstileKeys(data)
	if err != nil {
		return nil, err
	}
	if k.Site != site {
		return nil, fmt.Errorf("site: the file is for %q, not %q", k.Site, site)
	}
	return k, nil
}

// ReadTurnstileKeysFile reads and parses an mg-turnstile-keys file.
func ReadTurnstileKeysFile(path string) (*TurnstileKeys, error) {
	data, err := ReadFileLimit(path, MaxTurnstileKeysFile)
	if err != nil {
		return nil, err
	}
	k, err := ParseTurnstileKeys(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// Marshal renders the file as canonical JSON (§12.0 of the Phase 1 spec):
// the bytes of testdata/phase2/samples/keys/valid.
func (k *TurnstileKeys) Marshal() ([]byte, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	return canonicalJSON(turnstileKeysFile{V: 1, Kind: KindTurnstileKeys, Site: k.Site, Values: k.Values})
}
