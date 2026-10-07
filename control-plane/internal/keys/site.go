package keys

import (
	"fmt"
	"io"
	"slices"
	"time"
)

// Seal root rotation steps (§17, D-30).
const (
	SealStepAdd     = "add"     // a new root becomes roots[1] (opens only)
	SealStepPromote = "promote" // swap: the new root seals, the old one still opens
	SealStepRetire  = "retire"  // drop roots[1]
)

type tokenKeysFile struct {
	V    int             `json:"v"`
	Kind string          `json:"kind"`
	Site string          `json:"site"`
	Keys []tokenKeyEntry `json:"keys"`
}

type tokenKeyEntry struct {
	KID       string `json:"kid"`
	Key       string `json:"key"`
	CreatedAt string `json:"created_at"`
}

type sealRootFile struct {
	V     int             `json:"v"`
	Kind  string          `json:"kind"`
	Site  string          `json:"site"`
	Roots []sealRootEntry `json:"roots"`
}

type sealRootEntry struct {
	RootID    string `json:"root_id"`
	Key       string `json:"key"`
	CreatedAt string `json:"created_at"`
}

// GenerateSiteKeys creates a site's token.keys.json (one key, kid
// <site>-t-<YYYYMMDD>) and seal.root.json (one root, id <site>-r-<YYYYMMDD>).
// The token key is drawn from rnd first, then the sealing root.
func GenerateSiteKeys(site string, date time.Time, rnd io.Reader) (tokenJSON, sealJSON []byte, err error) {
	if !SitePattern.MatchString(site) {
		return nil, nil, fmt.Errorf("site %q does not match %s", site, SitePattern)
	}
	kid, err := uniqueID(site+"-t-"+dateStamp(date), func(string) bool { return false })
	if err != nil {
		return nil, nil, err
	}
	rootID, err := uniqueID(site+"-r-"+dateStamp(date), func(string) bool { return false })
	if err != nil {
		return nil, nil, err
	}
	tokenKey, err := readSecret(rnd)
	if err != nil {
		return nil, nil, err
	}
	root, err := readSecret(rnd)
	if err != nil {
		return nil, nil, err
	}
	created := formatTime(date)
	tokenJSON, err = canonicalJSON(tokenKeysFile{V: 1, Kind: KindTokenKeys, Site: site,
		Keys: []tokenKeyEntry{{KID: kid, Key: encodeKey(tokenKey), CreatedAt: created}}})
	if err != nil {
		return nil, nil, err
	}
	sealJSON, err = canonicalJSON(sealRootFile{V: 1, Kind: KindSealRoot, Site: site,
		Roots: []sealRootEntry{{RootID: rootID, Key: encodeKey(root), CreatedAt: created}}})
	if err != nil {
		return nil, nil, err
	}
	return tokenJSON, sealJSON, nil
}

// RotateTokenKey puts a new token key (kid <site>-t-<YYYYMMDD>, with a -2, -3
// ... suffix on a same-day rotation) in front and keeps at most MaxTokenKeys
// keys. It returns the new file and the new kid.
func RotateTokenKey(tokenJSON []byte, date time.Time, rnd io.Reader) (newJSON []byte, newKID string, err error) {
	f, err := parseTokenKeys(tokenJSON)
	if err != nil {
		return nil, "", err
	}
	newKID, err = uniqueID(f.Site+"-t-"+dateStamp(date), func(id string) bool {
		return slices.ContainsFunc(f.Keys, func(k tokenKeyEntry) bool { return k.KID == id })
	})
	if err != nil {
		return nil, "", err
	}
	key, err := readSecret(rnd)
	if err != nil {
		return nil, "", err
	}
	keys := append([]tokenKeyEntry{{KID: newKID, Key: encodeKey(key), CreatedAt: formatTime(date)}}, f.Keys...)
	if len(keys) > MaxTokenKeys {
		keys = keys[:MaxTokenKeys]
	}
	f.Keys = keys
	newJSON, err = canonicalJSON(f)
	if err != nil {
		return nil, "", err
	}
	return newJSON, newKID, nil
}

// RotateSealRoot performs one step of the sealing-root rotation (§17):
// "add" appends a new root as roots[1] (it opens but does not seal yet),
// "promote" swaps the two roots, "retire" drops roots[1]. Only "add" reads
// from rnd.
func RotateSealRoot(sealJSON []byte, step string, date time.Time, rnd io.Reader) ([]byte, error) {
	f, err := parseSealRoot(sealJSON)
	if err != nil {
		return nil, err
	}
	switch step {
	case SealStepAdd:
		if len(f.Roots) != 1 {
			return nil, fmt.Errorf("add: the file has %d roots; finish the running rotation (promote, retire) first", len(f.Roots))
		}
		id, err := uniqueID(f.Site+"-r-"+dateStamp(date), func(id string) bool { return f.Roots[0].RootID == id })
		if err != nil {
			return nil, err
		}
		key, err := readSecret(rnd)
		if err != nil {
			return nil, err
		}
		f.Roots = append(f.Roots, sealRootEntry{RootID: id, Key: encodeKey(key), CreatedAt: formatTime(date)})
	case SealStepPromote:
		if len(f.Roots) != 2 {
			return nil, fmt.Errorf("promote: the file has %d root(s); run the add step first", len(f.Roots))
		}
		f.Roots[0], f.Roots[1] = f.Roots[1], f.Roots[0]
	case SealStepRetire:
		if len(f.Roots) != 2 {
			return nil, fmt.Errorf("retire: the file has %d root(s); there is no second root to retire", len(f.Roots))
		}
		f.Roots = f.Roots[:1]
	default:
		return nil, fmt.Errorf("unknown rotation step %q (want add | promote | retire)", step)
	}
	return canonicalJSON(f)
}

func parseTokenKeys(data []byte) (*tokenKeysFile, error) {
	var f tokenKeysFile
	if err := strictDecode(data, &f); err != nil {
		return nil, err
	}
	if err := checkHeader(f.V, f.Kind, KindTokenKeys); err != nil {
		return nil, err
	}
	if !SitePattern.MatchString(f.Site) {
		return nil, fmt.Errorf("site: %q does not match %s", f.Site, SitePattern)
	}
	if len(f.Keys) < 1 || len(f.Keys) > MaxTokenKeys {
		return nil, fmt.Errorf("keys: %d entries, want 1-%d", len(f.Keys), MaxTokenKeys)
	}
	seen := map[string]bool{}
	for i, k := range f.Keys {
		field := fmt.Sprintf("keys[%d]", i)
		if !KIDPattern.MatchString(k.KID) {
			return nil, fmt.Errorf("%s.kid: %q does not match %s", field, k.KID, KIDPattern)
		}
		if seen[k.KID] {
			return nil, fmt.Errorf("%s.kid: duplicate kid %q", field, k.KID)
		}
		seen[k.KID] = true
		if _, err := decodeKey(field+".key", k.Key, SecretSize); err != nil {
			return nil, err
		}
		if _, err := parseTime(field+".created_at", k.CreatedAt); err != nil {
			return nil, err
		}
	}
	return &f, nil
}

func parseSealRoot(data []byte) (*sealRootFile, error) {
	var f sealRootFile
	if err := strictDecode(data, &f); err != nil {
		return nil, err
	}
	if err := checkHeader(f.V, f.Kind, KindSealRoot); err != nil {
		return nil, err
	}
	if !SitePattern.MatchString(f.Site) {
		return nil, fmt.Errorf("site: %q does not match %s", f.Site, SitePattern)
	}
	if len(f.Roots) < 1 || len(f.Roots) > MaxSealRoots {
		return nil, fmt.Errorf("roots: %d entries, want 1-%d", len(f.Roots), MaxSealRoots)
	}
	seen := map[string]bool{}
	for i, r := range f.Roots {
		field := fmt.Sprintf("roots[%d]", i)
		if !KIDPattern.MatchString(r.RootID) {
			return nil, fmt.Errorf("%s.root_id: %q does not match %s", field, r.RootID, KIDPattern)
		}
		if seen[r.RootID] {
			return nil, fmt.Errorf("%s.root_id: duplicate root id %q", field, r.RootID)
		}
		seen[r.RootID] = true
		if _, err := decodeKey(field+".key", r.Key, SecretSize); err != nil {
			return nil, err
		}
		if _, err := parseTime(field+".created_at", r.CreatedAt); err != nil {
			return nil, err
		}
	}
	return &f, nil
}
