package keys

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// OwnerKey is the owner's bundle-signing key (§12.6). Its fmt output never
// includes the private key.
type OwnerKey struct {
	KID       string
	Private   ed25519.PrivateKey
	CreatedAt time.Time
}

// OwnerPublicKey is a trusted bundle-signing public key (<kid>.pub).
type OwnerPublicKey struct {
	KID       string
	Public    ed25519.PublicKey
	CreatedAt time.Time
}

// Public returns the public half of k.
func (k *OwnerKey) Public() *OwnerPublicKey {
	return &OwnerPublicKey{KID: k.KID, Public: k.Private.Public().(ed25519.PublicKey), CreatedAt: k.CreatedAt}
}

// Format implements fmt.Formatter (on the value, so pointers and copies are
// both covered) so that no verb prints the private key.
func (k OwnerKey) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "OwnerKey{KID: %q, CreatedAt: %s, Private: <redacted>}", k.KID, formatTime(k.CreatedAt))
}

type ownerKeyFile struct {
	V         int    `json:"v"`
	Kind      string `json:"kind"`
	KID       string `json:"kid"`
	Seed      string `json:"seed"`
	CreatedAt string `json:"created_at"`
}

type ownerPubFile struct {
	V         int    `json:"v"`
	Kind      string `json:"kind"`
	KID       string `json:"kid"`
	PublicKey string `json:"public_key"`
	CreatedAt string `json:"created_at"`
}

// GenerateOwnerKey creates an owner signing key whose 32-byte seed is read
// from rnd. The creation time is truncated to whole seconds.
func GenerateOwnerKey(kid string, now time.Time, rnd io.Reader) (*OwnerKey, error) {
	if !KIDPattern.MatchString(kid) {
		return nil, fmt.Errorf("kid %q does not match %s", kid, KIDPattern)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		return nil, fmt.Errorf("reading random bytes: %w", err)
	}
	return &OwnerKey{KID: kid, Private: ed25519.NewKeyFromSeed(seed), CreatedAt: now.UTC().Truncate(time.Second)}, nil
}

// MarshalOwnerKey renders the canonical plaintext of <kid>.key.age.
func MarshalOwnerKey(k *OwnerKey) ([]byte, error) {
	return canonicalJSON(ownerKeyFile{
		V: 1, Kind: KindOwnerKey, KID: k.KID,
		Seed: encodeKey(k.Private.Seed()), CreatedAt: formatTime(k.CreatedAt),
	})
}

// MarshalOwnerPublicKey renders the canonical <kid>.pub file.
func MarshalOwnerPublicKey(k *OwnerPublicKey) ([]byte, error) {
	return canonicalJSON(ownerPubFile{
		V: 1, Kind: KindOwnerPub, KID: k.KID,
		PublicKey: encodeKey(k.Public), CreatedAt: formatTime(k.CreatedAt),
	})
}

// ParseOwnerKey parses the plaintext of <kid>.key.age.
func ParseOwnerKey(data []byte) (*OwnerKey, error) {
	var f ownerKeyFile
	if err := strictDecode(data, &f); err != nil {
		return nil, err
	}
	if err := checkHeader(f.V, f.Kind, KindOwnerKey); err != nil {
		return nil, err
	}
	if !KIDPattern.MatchString(f.KID) {
		return nil, fmt.Errorf("kid: %q does not match %s", f.KID, KIDPattern)
	}
	seed, err := decodeKey("seed", f.Seed, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	created, err := parseTime("created_at", f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &OwnerKey{KID: f.KID, Private: ed25519.NewKeyFromSeed(seed), CreatedAt: created}, nil
}

// ParseOwnerPublicKey parses a <kid>.pub file.
func ParseOwnerPublicKey(data []byte) (*OwnerPublicKey, error) {
	var f ownerPubFile
	if err := strictDecode(data, &f); err != nil {
		return nil, err
	}
	if err := checkHeader(f.V, f.Kind, KindOwnerPub); err != nil {
		return nil, err
	}
	if !KIDPattern.MatchString(f.KID) {
		return nil, fmt.Errorf("kid: %q does not match %s", f.KID, KIDPattern)
	}
	pub, err := decodeKey("public_key", f.PublicKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	created, err := parseTime("created_at", f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &OwnerPublicKey{KID: f.KID, Public: ed25519.PublicKey(pub), CreatedAt: created}, nil
}

// WriteOwnerKey writes <dir>/<kid>.key.age (age-encrypted, 0600) and
// <dir>/<kid>.pub (0644). It refuses to overwrite either file; if the public
// key cannot be written the new private key file is removed again.
func WriteOwnerKey(dir string, k *OwnerKey, passphrase []byte, workFactor int) (keyPath, pubPath string, err error) {
	keyPath = filepath.Join(dir, k.KID+".key.age")
	pubPath = filepath.Join(dir, k.KID+".pub")
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return "", "", fmt.Errorf("%s already exists; refusing to overwrite a key file: %w", p, fs.ErrExist)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", "", err
		}
	}
	keyJSON, err := MarshalOwnerKey(k)
	if err != nil {
		return "", "", err
	}
	pubJSON, err := MarshalOwnerPublicKey(k.Public())
	if err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	if err := EncryptFile(keyPath, keyJSON, passphrase, workFactor); err != nil {
		return "", "", err
	}
	if err := WriteNewFile(pubPath, pubJSON, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return "", "", err
	}
	return keyPath, pubPath, nil
}

// LoadOwnerKey decrypts and parses <kid>.key.age.
func LoadOwnerKey(path string, passphrase []byte) (*OwnerKey, error) {
	plain, err := DecryptFile(path, passphrase)
	if err != nil {
		return nil, err
	}
	k, err := ParseOwnerKey(plain)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

// LoadOwnerPublicKey reads and parses a <kid>.pub file.
func LoadOwnerPublicKey(path string) (*OwnerPublicKey, error) {
	data, err := ReadFileLimit(path, maxKeyFileSize)
	if err != nil {
		return nil, err
	}
	k, err := ParseOwnerPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}
