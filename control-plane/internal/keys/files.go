package keys

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// Work factor bounds of the age scrypt recipient (§12.6).
const (
	DefaultWorkFactor = 18 // filippo.io/age's default
	MinWorkFactor     = 10
	MaxWorkFactor     = 22
	// SafeWorkFactor is the lowest work factor accepted without --insecure-test-key.
	SafeWorkFactor = 18
)

// FileInfo describes a decrypted key file without its key material.
type FileInfo struct {
	Kind string   // one of the Kind* constants
	Site string   // site keys only
	IDs  []string // token kids, seal root ids, the pseudonymisation key id; empty for upstream keys
}

// Inspect validates a plaintext site, pseudonymisation or upstream key file
// and describes it. Owner signing keys are rejected: they never leave the
// workstation in plaintext.
func Inspect(data []byte) (*FileInfo, error) {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	switch head.Kind {
	case KindTokenKeys:
		f, err := parseTokenKeys(data)
		if err != nil {
			return nil, err
		}
		info := &FileInfo{Kind: f.Kind, Site: f.Site}
		for _, k := range f.Keys {
			info.IDs = append(info.IDs, k.KID)
		}
		return info, nil
	case KindSealRoot:
		f, err := parseSealRoot(data)
		if err != nil {
			return nil, err
		}
		info := &FileInfo{Kind: f.Kind, Site: f.Site}
		for _, r := range f.Roots {
			info.IDs = append(info.IDs, r.RootID)
		}
		return info, nil
	case KindPseudoKey:
		k, err := ParsePseudoKey(data)
		if err != nil {
			return nil, err
		}
		return &FileInfo{Kind: KindPseudoKey, IDs: []string{k.ID}}, nil
	case KindUpstreamKeys:
		if _, err := parseUpstreamKeys(data); err != nil {
			return nil, err
		}
		return &FileInfo{Kind: KindUpstreamKeys}, nil
	case KindOwnerKey:
		return nil, errors.New("owner signing keys are never exported in plaintext")
	}
	return nil, fmt.Errorf("kind %q is not a site, pseudonymisation or upstream key file", head.Kind)
}

// Encrypt returns plaintext encrypted to an age scrypt passphrase recipient.
func Encrypt(plaintext, passphrase []byte, workFactor int) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase")
	}
	if workFactor < MinWorkFactor || workFactor > MaxWorkFactor {
		return nil, fmt.Errorf("age work factor %d outside %d-%d", workFactor, MinWorkFactor, MaxWorkFactor)
	}
	r, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, err
	}
	r.SetWorkFactor(workFactor)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts an age scrypt file.
func Decrypt(ciphertext, passphrase []byte) ([]byte, error) {
	id, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, err
	}
	id.SetMaxWorkFactor(MaxWorkFactor)
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt (wrong passphrase, or not an age passphrase file): %w", err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, maxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt: %w", err)
	}
	if len(plain) > maxKeyFileSize {
		return nil, fmt.Errorf("decrypted file is larger than %d bytes", maxKeyFileSize)
	}
	return plain, nil
}

// EncryptFile age-encrypts plaintext (scrypt recipient) into a new 0600 file.
// It never overwrites an existing file.
func EncryptFile(path string, plaintext, passphrase []byte, workFactor int) error {
	data, err := Encrypt(plaintext, passphrase, workFactor)
	if err != nil {
		return err
	}
	return WriteNewFile(path, data, 0o600)
}

// ReEncryptFile atomically replaces an existing age file with a new
// encryption of plaintext (key rotation).
func ReEncryptFile(path string, plaintext, passphrase []byte, workFactor int) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	data, err := Encrypt(plaintext, passphrase, workFactor)
	if err != nil {
		return err
	}
	return ReplaceFile(path, data, 0o600)
}

// DecryptFile reads and decrypts an age scrypt file.
func DecryptFile(path string, passphrase []byte) ([]byte, error) {
	data, err := ReadFileLimit(path, maxKeyFileSize)
	if err != nil {
		return nil, err
	}
	plain, err := Decrypt(data, passphrase)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return plain, nil
}

// ReadFileLimit reads a file of at most limit bytes.
func ReadFileLimit(path string, limit int64) ([]byte, error) {
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
		return nil, fmt.Errorf("%s: file is larger than %d bytes", path, limit)
	}
	return data, nil
}

// WriteNewFile writes data to a new file with the given permissions. The
// file appears complete or not at all (temporary file, fsync, hard link) and
// an existing file is never replaced: the error then wraps fs.ErrExist.
func WriteNewFile(path string, data []byte, perm fs.FileMode) error {
	tmp, err := writeTemp(path, data, perm)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	err = os.Link(tmp, path)
	switch {
	case err == nil:
		syncDir(filepath.Dir(path))
		return nil
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("%s already exists; refusing to overwrite it: %w", path, fs.ErrExist)
	}
	// Hard links unsupported (some non-POSIX file systems): exclusive create.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite it: %w", path, fs.ErrExist)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// ReplaceFile atomically writes data to path (temporary file in the same
// directory, fsync, rename), replacing any existing file.
func ReplaceFile(path string, data []byte, perm fs.FileMode) error {
	tmp, err := writeTemp(path, data, perm)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(path))
	return nil
}

func writeTemp(path string, data []byte, perm fs.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if err := f.Chmod(perm); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// syncDir makes a rename or link in dir durable (best effort: some
// platforms cannot fsync a directory).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
