package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/keys"
)

// Publish errors callers may distinguish.
var (
	ErrConfirmMismatch = errors.New("--confirm does not match the bundle's site")
	ErrNotNewer        = errors.New("bundle version is not newer than the published one")
)

// PublishResult reports what Publish wrote.
type PublishResult struct {
	BundlePath                         string
	ArtifactsWritten, ArtifactsSkipped int
	PreviousVersion                    uint64
}

// Publish verifies a signed bundle and writes it to the static tree of spec
// §12.1: first every referenced artifact to <dest>/artifacts/<sha256> (from
// artifactsDir/<sha256>; content-addressed files are never rewritten), then
// the bundle to <dest>/bundles/<site>.bundle (atomic replace). The site must
// equal confirmSite and the version must be greater than the published one.
func Publish(signed []byte, artifactsDir, dest string, trusted []*keys.OwnerPublicKey, confirmSite string) (*PublishResult, error) {
	_, sb, err := VerifyFile(signed, trusted)
	if err != nil {
		return nil, err
	}
	if confirmSite != sb.SiteId {
		return nil, fmt.Errorf("%w: confirmed %q, bundle is for %q", ErrConfirmMismatch, confirmSite, sb.SiteId)
	}
	bundlesDir, artDir := filepath.Join(dest, "bundles"), filepath.Join(dest, "artifacts")
	res := &PublishResult{BundlePath: filepath.Join(bundlesDir, sb.SiteId+".bundle")}

	prev, err := publishedVersion(res.BundlePath)
	if err != nil {
		return nil, err
	}
	res.PreviousVersion = prev
	if sb.Version <= prev {
		return nil, fmt.Errorf("%w: %d <= %d already in %s", ErrNotNewer, sb.Version, prev, res.BundlePath)
	}
	for _, d := range []string{bundlesDir, artDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	for _, a := range sb.Artifacts {
		written, err := publishArtifact(a, artifactsDir, artDir)
		if err != nil {
			return nil, err
		}
		if written {
			res.ArtifactsWritten++
		} else {
			res.ArtifactsSkipped++
		}
	}
	if err := keys.ReplaceFile(res.BundlePath, signed, 0o644); err != nil {
		return nil, err
	}
	return res, nil
}

// publishedVersion reads the version of an existing published bundle (0 if
// none). Its signature is not checked: the owner may have rotated keys; the
// comparison only guards against accidental rollbacks, the Edge enforces
// monotonic versions itself.
func publishedVersion(path string) (uint64, error) {
	data, err := keys.ReadFileLimit(path, maxSignedSize)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	s, err := ParseSigned(data)
	if err != nil {
		return 0, fmt.Errorf("%s: %v; refusing to publish over it", path, err)
	}
	var sb morphgatev1.SiteBundle
	if err := proto.Unmarshal(s.Bundle, &sb); err != nil {
		return 0, fmt.Errorf("%s: not a SiteBundle (%v); refusing to publish over it", path, err)
	}
	return sb.Version, nil
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// publishArtifact copies one artifact unless the destination already holds
// it; both copies are checked against the bundle's hash and size.
func publishArtifact(a *morphgatev1.ArtifactRef, srcDir, dstDir string) (bool, error) {
	if !sha256Hex.MatchString(a.Sha256) || a.Uri != "artifacts/"+a.Sha256 {
		return false, fmt.Errorf("artifact %q: bad sha256 %q or uri %q", a.Name, a.Sha256, a.Uri)
	}
	limit, ok := ArtifactMaxSize[a.Name]
	if !ok {
		return false, fmt.Errorf("unknown artifact %q", a.Name)
	}
	check := func(path string, data []byte) error {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != a.Sha256 || uint64(len(data)) != a.Size {
			return fmt.Errorf("artifact %s: %s does not match the bundle (sha256 or size differs)", a.Name, path)
		}
		return nil
	}
	dst := filepath.Join(dstDir, a.Sha256)
	if data, err := keys.ReadFileLimit(dst, limit); err == nil {
		return false, check(dst, data)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	src := filepath.Join(srcDir, a.Sha256)
	data, err := keys.ReadFileLimit(src, limit)
	if err != nil {
		return false, fmt.Errorf("artifact %s: %w", a.Name, err)
	}
	if err := check(src, data); err != nil {
		return false, err
	}
	if err := keys.WriteNewFile(dst, data, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

const publishedMetric = "mg_bundle_published_version"

var publishedSample = regexp.MustCompile(`^` + publishedMetric + `\{site="([a-z0-9_-]+)"\} ([0-9]+)$`)

// WritePublishedVersion records mg_bundle_published_version{site} in a
// node_exporter textfile (atomic replace). Samples for other sites and
// unrelated lines are kept.
func WritePublishedVersion(path, site string, version uint64) error {
	versions := map[string]string{}
	var other []string
	data, err := keys.ReadFileLimit(path, 1<<20)
	switch {
	case err == nil:
		for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if m := publishedSample.FindStringSubmatch(line); m != nil {
				versions[m[1]] = m[2]
			} else if line != "" && !strings.HasPrefix(line, "# HELP "+publishedMetric+" ") && !strings.HasPrefix(line, "# TYPE "+publishedMetric+" ") {
				other = append(other, line)
			}
		}
	case !errors.Is(err, fs.ErrNotExist):
		return err
	}
	versions[site] = strconv.FormatUint(version, 10)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b bytes.Buffer
	for _, line := range other {
		b.WriteString(line + "\n")
	}
	fmt.Fprintf(&b, "# HELP %s Version of the last bundle published by mgctl for the site.\n", publishedMetric)
	fmt.Fprintf(&b, "# TYPE %s gauge\n", publishedMetric)
	for _, s := range slices.Sorted(maps.Keys(versions)) {
		fmt.Fprintf(&b, "%s{site=%q} %s\n", publishedMetric, s, versions[s])
	}
	return keys.ReplaceFile(path, b.Bytes(), 0o644)
}
