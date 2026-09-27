package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/keys"
)

// §3.2 / §15 WP-G2: the signing input carries the kat.json domain prefix.
func TestSigningInputDomainMatchesKAT(t *testing.T) {
	data, err := os.ReadFile(phase1 + "/kat.json")
	if err != nil {
		t.Fatal(err)
	}
	var kat struct {
		BundleSignature struct {
			DomainPrefixHex string `json:"domain_prefix_hex"`
		} `json:"bundle_signature"`
	}
	if err := json.Unmarshal(data, &kat); err != nil {
		t.Fatal(err)
	}
	prefix, _ := hex.DecodeString(kat.BundleSignature.DomainPrefixHex)
	in := SigningInput([]byte{1, 2, 3})
	if !bytes.Equal(in, append(prefix, 1, 2, 3)) || len(prefix) != 13 {
		t.Errorf("SigningInput = %x, want %x010203", in, prefix)
	}
}

func signedMinimal(t *testing.T) ([]byte, *morphgatev1.SignedBundle, *keys.OwnerKey, *keys.OwnerPublicKey) {
	t.Helper()
	k, pub := ownerTestKey(t)
	res, err := Build(loadSite(t, minimalYAML), BuildOptions{Version: 5, Now: buildTime})
	if err != nil {
		t.Fatal(err)
	}
	s, err := Sign(res.Bytes, k)
	if err != nil {
		t.Fatal(err)
	}
	return res.Bytes, s, k, pub
}

// Go signs -> Go verifies; wrong key, tampered bytes and unknown kid are rejected.
func TestSignAndVerify(t *testing.T) {
	bundleBytes, s, k, pub := signedMinimal(t)
	if s.KeyId != "owner-test" || len(s.Ed25519Signature) != 64 || !bytes.Equal(s.Bundle, bundleBytes) {
		t.Fatalf("signed %v", s)
	}
	// Independent check of the signature input.
	if !ed25519.Verify(pub.Public, append([]byte("mg-bundle-v1\x00"), bundleBytes...), s.Ed25519Signature) {
		t.Fatal("signature is not over mg-bundle-v1 || 0x00 || bundle")
	}
	file, err := MarshalSigned(s)
	if err != nil {
		t.Fatal(err)
	}
	signed, sb, err := VerifyFile(file, []*keys.OwnerPublicKey{pub})
	if err != nil || sb.SiteId != "shop" || sb.Version != 5 || signed.KeyId != "owner-test" {
		t.Fatalf("VerifyFile: %v %v", sb, err)
	}

	other, _ := keys.GenerateOwnerKey("owner-test", buildTime, bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
	otherPub := other.Public()
	renamed := *pub
	renamed.KID = "owner-2027"
	otherRenamed := other.Public()
	otherRenamed.KID = "owner-other"
	for _, tc := range []struct {
		name    string
		signed  *morphgatev1.SignedBundle
		trusted []*keys.OwnerPublicKey
		want    error
	}{
		{"wrong key, same kid", s, []*keys.OwnerPublicKey{otherPub}, ErrBadSignature},
		{"unknown kid", s, []*keys.OwnerPublicKey{&renamed}, ErrUnknownKey},
		{"no trusted keys", s, nil, ErrUnknownKey},
		{"tampered bundle", tamper(s, func(c *morphgatev1.SignedBundle) { c.Bundle[len(c.Bundle)-1] ^= 1 }), []*keys.OwnerPublicKey{pub}, ErrBadSignature},
		{"tampered signature", tamper(s, func(c *morphgatev1.SignedBundle) { c.Ed25519Signature[0] ^= 1 }), []*keys.OwnerPublicKey{pub}, ErrBadSignature},
		{"short signature", tamper(s, func(c *morphgatev1.SignedBundle) { c.Ed25519Signature = c.Ed25519Signature[:63] }), []*keys.OwnerPublicKey{pub}, ErrBadSignature},
		{"kid swapped to another trusted key", tamper(s, func(c *morphgatev1.SignedBundle) { c.KeyId = "owner-other" }), []*keys.OwnerPublicKey{pub, otherRenamed}, ErrBadSignature},
	} {
		if _, err := Verify(tc.signed, tc.trusted); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// The trusted list may hold several keys; the matching kid is used.
	decoy := *otherPub
	decoy.KID = "owner-decoy"
	if _, err := Verify(s, []*keys.OwnerPublicKey{&decoy, pub}); err != nil {
		t.Errorf("second trusted key: %v", err)
	}
	if _, err := Sign(nil, k); err == nil {
		t.Error("empty bundle signed")
	}
	if _, err := Sign(bundleBytes, nil); err == nil {
		t.Error("signed without a key")
	}
}

func tamper(s *morphgatev1.SignedBundle, f func(*morphgatev1.SignedBundle)) *morphgatev1.SignedBundle {
	c := proto.Clone(s).(*morphgatev1.SignedBundle)
	f(c)
	return c
}

func TestVerifyChecksDecodedBundle(t *testing.T) {
	k, pub := ownerTestKey(t)
	for name, sb := range map[string]*morphgatev1.SiteBundle{
		"schema 2":   {SchemaVersion: 2, SiteId: "blog", Version: 1},
		"schema 0":   {SiteId: "blog", Version: 1},
		"bad siteid": {SchemaVersion: 1, SiteId: "Blog!", Version: 1},
	} {
		b, _ := proto.Marshal(sb)
		s, err := Sign(b, k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(s, []*keys.OwnerPublicKey{pub}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, _ := Sign([]byte("not a protobuf \xff\xff"), k)
	if _, err := Verify(s, []*keys.OwnerPublicKey{pub}); err == nil {
		t.Error("garbage payload accepted")
	}
	if _, err := ParseSigned(make([]byte, maxSignedSize+1)); err == nil {
		t.Error("oversized file accepted")
	}
}

func TestSummarize(t *testing.T) {
	bundleBytes, s, _, _ := signedMinimal(t)
	file, _ := MarshalSigned(s)
	var sb morphgatev1.SiteBundle
	proto.Unmarshal(bundleBytes, &sb)
	sum := Summarize(&sb, bundleBytes, s, file)
	if sum.Site != "shop" || sum.Version != 5 || sum.KeyID != "owner-test" || sum.Profile != "direct_tls" || !sum.MonitorOnly ||
		sum.CreatedAt != buildTime.Format(time.RFC3339) || len(sum.Environments) != 1 || sum.Environments[0].Routes != 1 ||
		sum.BundleSHA256 != hexSHA(bundleBytes) || sum.FileSHA256 != hexSHA(file) || sum.Rules != 0 {
		t.Errorf("summary %+v", sum)
	}
	if _, err := json.Marshal(sum); err != nil {
		t.Error(err)
	}
}

// §2.4 item 3: ≥ 10,000 random signed-bundle inputs never panic the verifier.
func TestVerifierNeverPanics(t *testing.T) {
	_, s, _, pub := signedMinimal(t)
	file, _ := MarshalSigned(s)
	x := xorshift(0xa0761d6478bd642f)
	for i := 0; i < 10_000; i++ {
		in := x.mutate(file)
		if _, sb, err := VerifyFile(in, []*keys.OwnerPublicKey{pub}); err == nil && !bytes.Equal(in, file) {
			// A mutation can only verify if it left the signed bytes intact
			// (e.g. an appended unknown field outside the bundle).
			if sb.SiteId != "shop" {
				t.Fatalf("mutated input verified to a different bundle: %v", sb)
			}
		}
	}
}
