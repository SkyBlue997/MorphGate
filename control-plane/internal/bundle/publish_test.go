package bundle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"morphgate/control-plane/internal/keys"
)

// buildSigned builds full.yaml (stand-in IR) at version, copies its artifacts
// into <dir>/artifacts like `mgctl bundle build` does, and signs it.
func buildSigned(t *testing.T, version uint64, dir string) []byte {
	t.Helper()
	withLowering(t, nil)
	res, err := Build(loadSite(t, fullYAML), BuildOptions{Version: version, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	for sum, src := range res.Artifacts {
		data, _ := os.ReadFile(src)
		dst := filepath.Join(dir, "artifacts", sum)
		if _, err := os.Stat(dst); err != nil {
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	k, _ := ownerTestKey(t)
	s, err := Sign(res.Bytes, k)
	if err != nil {
		t.Fatal(err)
	}
	file, _ := MarshalSigned(s)
	return file
}

// §12.1 / §15 WP-G2: versions only go up, artifacts are written before the
// bundle, --confirm must match, and nothing is written on a refusal.
func TestPublish(t *testing.T) {
	work, dest := t.TempDir(), filepath.Join(t.TempDir(), "srv", "mg")
	_, pub := ownerTestKey(t)
	trusted := []*keys.OwnerPublicKey{pub}
	v1 := buildSigned(t, 100, work)

	if _, err := Publish(v1, filepath.Join(work, "artifacts"), dest, trusted, "shop"); !errors.Is(err, ErrConfirmMismatch) {
		t.Fatalf("wrong --confirm: %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("a refused publish created the destination")
	}
	res, err := Publish(v1, filepath.Join(work, "artifacts"), dest, trusted, "blog")
	if err != nil {
		t.Fatal(err)
	}
	if res.BundlePath != filepath.Join(dest, "bundles", "blog.bundle") || res.ArtifactsWritten != 4 || res.ArtifactsSkipped != 0 || res.PreviousVersion != 0 {
		t.Errorf("first publish %+v", res)
	}
	if got, _ := os.ReadFile(res.BundlePath); !bytes.Equal(got, v1) {
		t.Error("published bundle differs from the signed file")
	}
	entries, _ := os.ReadDir(filepath.Join(dest, "artifacts"))
	if len(entries) != 4 {
		t.Errorf("artifacts %v", entries)
	}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(dest, "artifacts", e.Name()))
		if hexSHA(data) != e.Name() {
			t.Errorf("artifact %s has another hash", e.Name())
		}
	}

	for _, v := range []uint64{100, 99} {
		old := buildSigned(t, v, work)
		if _, err := Publish(old, filepath.Join(work, "artifacts"), dest, trusted, "blog"); !errors.Is(err, ErrNotNewer) {
			t.Errorf("version %d over 100: %v", v, err)
		}
	}
	if got, _ := os.ReadFile(res.BundlePath); !bytes.Equal(got, v1) {
		t.Error("a refused publish replaced the bundle")
	}

	v2 := buildSigned(t, 101, work)
	res, err = Publish(v2, filepath.Join(work, "artifacts"), dest, trusted, "blog")
	if err != nil {
		t.Fatal(err)
	}
	if res.PreviousVersion != 100 || res.ArtifactsWritten != 0 || res.ArtifactsSkipped != 4 {
		t.Errorf("second publish %+v", res)
	}
}

func TestPublishArtifactsBeforeBundle(t *testing.T) {
	work, dest := t.TempDir(), t.TempDir()
	_, pub := ownerTestKey(t)
	file := buildSigned(t, 7, work)
	// One artifact missing from the build output: nothing may reference it.
	entries, _ := os.ReadDir(filepath.Join(work, "artifacts"))
	os.Remove(filepath.Join(work, "artifacts", entries[len(entries)-1].Name()))
	if _, err := Publish(file, filepath.Join(work, "artifacts"), dest, []*keys.OwnerPublicKey{pub}, "blog"); err == nil {
		t.Fatal("publish without an artifact succeeded")
	}
	if _, err := os.Stat(filepath.Join(dest, "bundles", "blog.bundle")); !os.IsNotExist(err) {
		t.Error("the bundle was written although an artifact was missing")
	}

	// A corrupted source artifact is refused as well.
	work2 := t.TempDir()
	file = buildSigned(t, 8, work2)
	entries, _ = os.ReadDir(filepath.Join(work2, "artifacts"))
	os.WriteFile(filepath.Join(work2, "artifacts", entries[0].Name()), []byte("tampered"), 0o644)
	if _, err := Publish(file, filepath.Join(work2, "artifacts"), dest, []*keys.OwnerPublicKey{pub}, "blog"); err == nil || !strings.Contains(err.Error(), "does not match the bundle") {
		t.Errorf("tampered artifact: %v", err)
	}

	// A corrupted artifact already in the destination is reported, never overwritten.
	dest2 := t.TempDir()
	file = buildSigned(t, 9, work)
	os.MkdirAll(filepath.Join(dest2, "artifacts"), 0o755)
	entries, _ = os.ReadDir(filepath.Join(work, "artifacts"))
	bad := filepath.Join(dest2, "artifacts", entries[0].Name())
	os.WriteFile(bad, []byte("rotten"), 0o644)
	if _, err := Publish(file, filepath.Join(work, "artifacts"), dest2, []*keys.OwnerPublicKey{pub}, "blog"); err == nil {
		t.Error("corrupted destination artifact accepted")
	}
	if b, _ := os.ReadFile(bad); string(b) != "rotten" {
		t.Error("a destination artifact was rewritten")
	}
}

func TestPublishRefusesUntrustedOrUnreadable(t *testing.T) {
	work, dest := t.TempDir(), t.TempDir()
	file := buildSigned(t, 3, work)
	other, _ := keys.GenerateOwnerKey("owner-test", buildTime, bytes.NewReader(bytes.Repeat([]byte{9}, 32)))
	if _, err := Publish(file, filepath.Join(work, "artifacts"), dest, []*keys.OwnerPublicKey{other.Public()}, "blog"); !errors.Is(err, ErrBadSignature) {
		t.Errorf("untrusted signature: %v", err)
	}
	_, pub := ownerTestKey(t)
	os.MkdirAll(filepath.Join(dest, "bundles"), 0o755)
	os.WriteFile(filepath.Join(dest, "bundles", "blog.bundle"), []byte("\xff\xff garbage"), 0o644)
	if _, err := Publish(file, filepath.Join(work, "artifacts"), dest, []*keys.OwnerPublicKey{pub}, "blog"); err == nil || !strings.Contains(err.Error(), "refusing to publish over it") {
		t.Errorf("unreadable published bundle: %v", err)
	}
}

func TestWritePublishedVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mg_bundle.prom")
	if err := WritePublishedVersion(p, "blog", 1790000000); err != nil {
		t.Fatal(err)
	}
	if err := WritePublishedVersion(p, "shop", 5); err != nil {
		t.Fatal(err)
	}
	if err := WritePublishedVersion(p, "blog", 1790000001); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	want := `# HELP mg_bundle_published_version Version of the last bundle published by mgctl for the site.
# TYPE mg_bundle_published_version gauge
mg_bundle_published_version{site="blog"} 1790000001
mg_bundle_published_version{site="shop"} 5
`
	if string(got) != want {
		t.Errorf("textfile:\n%s\nwant:\n%s", got, want)
	}
	// Unrelated lines survive.
	os.WriteFile(p, append([]byte("other_metric 1\n"), got...), 0o644)
	WritePublishedVersion(p, "shop", 6)
	got, _ = os.ReadFile(p)
	if !strings.HasPrefix(string(got), "other_metric 1\n# HELP") || !strings.Contains(string(got), `{site="shop"} 6`) {
		t.Errorf("textfile after merge:\n%s", got)
	}
}
