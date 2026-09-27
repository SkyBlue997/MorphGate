package bundle

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"morphgate/control-plane/internal/keys"
)

var update = flag.Bool("update", false, "rewrite the golden bundles in testdata/sites/golden")

const goldenDir = sitesDir + "/golden"

// goldenBundle builds and signs a golden site with version 1790000000 at
// 2026-09-27T10:00:00Z with the testdata/phase1 owner test key.
func goldenBundle(t *testing.T, siteYAML string) []byte {
	t.Helper()
	res, err := Build(loadSite(t, goldenDir+"/"+siteYAML), BuildOptions{Version: 1790000000, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	k, pub := ownerTestKey(t)
	s, err := Sign(res.Bytes, k)
	if err != nil {
		t.Fatal(err)
	}
	file, err := MarshalSigned(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyFile(file, []*keys.OwnerPublicKey{pub}); err != nil {
		t.Fatal(err)
	}
	return file
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := goldenDir + "/" + name
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(got))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/bundle -run TestGolden -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is stale: rebuild differs (run: go test ./internal/bundle -run TestGolden -update)", name)
	}
}

// §14.2 TestGolden: the signed golden bundles that mg-edge verifies and
// decodes in Rust (cross-language signature check, spec §16).
func TestGolden(t *testing.T) {
	compareGolden(t, "golden-norules.bundle", goldenBundle(t, "site.yaml"))
	// WP-G1 has landed (§2.1), so the rules bundle is required as well.
	compareGolden(t, "golden-rules.bundle", goldenBundle(t, "site-rules.yaml"))
}
