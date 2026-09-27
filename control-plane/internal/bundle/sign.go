package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/keys"
	"morphgate/control-plane/internal/sitecfg"
)

// SignatureDomain prefixes the signed bytes (spec §3.2, kat.json
// bundle_signature.domain_prefix_hex).
const SignatureDomain = "mg-bundle-v1"

// Verification errors.
var (
	ErrUnknownKey   = errors.New("bundle signed by an untrusted key id")
	ErrBadSignature = errors.New("bundle signature does not verify")
)

// maxSignedSize bounds a SignedBundle file: the bundle plus key id and signature.
const maxSignedSize = MaxBundleSize + 4096

// SigningInput is "mg-bundle-v1" || 0x00 || bundle.
func SigningInput(bundle []byte) []byte {
	out := make([]byte, 0, len(SignatureDomain)+1+len(bundle))
	out = append(out, SignatureDomain...)
	out = append(out, 0)
	return append(out, bundle...)
}

// Sign signs serialized SiteBundle bytes with the owner key.
func Sign(bundle []byte, key *keys.OwnerKey) (*morphgatev1.SignedBundle, error) {
	if key == nil || len(key.Private) != ed25519.PrivateKeySize {
		return nil, errors.New("no owner signing key")
	}
	if len(bundle) == 0 || len(bundle) > MaxBundleSize {
		return nil, fmt.Errorf("bundle is %d bytes, want 1-%d", len(bundle), MaxBundleSize)
	}
	return &morphgatev1.SignedBundle{
		Bundle:           bundle,
		KeyId:            key.KID,
		Ed25519Signature: ed25519.Sign(key.Private, SigningInput(bundle)),
	}, nil
}

// Verify checks the signature against the trusted owner keys (by key id) and
// decodes the SiteBundle, which must have schema_version 1 and a valid site id.
func Verify(signed *morphgatev1.SignedBundle, trusted []*keys.OwnerPublicKey) (*morphgatev1.SiteBundle, error) {
	if signed == nil {
		return nil, errors.New("no signed bundle")
	}
	if n := len(signed.Bundle); n == 0 || n > MaxBundleSize {
		return nil, fmt.Errorf("bundle is %d bytes, want 1-%d", n, MaxBundleSize)
	}
	var pub ed25519.PublicKey
	for _, k := range trusted {
		if k != nil && k.KID == signed.KeyId {
			pub = k.Public
			break
		}
	}
	if pub == nil {
		return nil, fmt.Errorf("%w %q", ErrUnknownKey, signed.KeyId)
	}
	if len(pub) != ed25519.PublicKeySize || len(signed.Ed25519Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, SigningInput(signed.Bundle), signed.Ed25519Signature) {
		return nil, ErrBadSignature
	}
	var sb morphgatev1.SiteBundle
	if err := proto.Unmarshal(signed.Bundle, &sb); err != nil {
		return nil, fmt.Errorf("signed bytes are not a SiteBundle: %w", err)
	}
	if sb.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("schema_version %d, want %d", sb.SchemaVersion, SchemaVersion)
	}
	if !sitecfg.SitePattern.MatchString(sb.SiteId) {
		return nil, fmt.Errorf("site_id %q is not a valid site id", sb.SiteId)
	}
	return &sb, nil
}

// MarshalSigned serializes a SignedBundle deterministically (the .bundle file).
func MarshalSigned(s *morphgatev1.SignedBundle) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(s)
}

// ParseSigned decodes a .bundle file.
func ParseSigned(data []byte) (*morphgatev1.SignedBundle, error) {
	if len(data) > maxSignedSize {
		return nil, fmt.Errorf("signed bundle is %d bytes, at most %d", len(data), maxSignedSize)
	}
	var s morphgatev1.SignedBundle
	if err := proto.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("not a SignedBundle: %w", err)
	}
	return &s, nil
}

// VerifyFile parses and verifies .bundle bytes.
func VerifyFile(data []byte, trusted []*keys.OwnerPublicKey) (*morphgatev1.SignedBundle, *morphgatev1.SiteBundle, error) {
	signed, err := ParseSigned(data)
	if err != nil {
		return nil, nil, err
	}
	sb, err := Verify(signed, trusted)
	if err != nil {
		return nil, nil, err
	}
	return signed, sb, nil
}

// Summary describes a bundle for `mgctl bundle verify` and the audit log.
type Summary struct {
	Site             string            `json:"site"`
	Version          uint64            `json:"version"`
	CreatedAt        string            `json:"created_at"`
	NotBefore        string            `json:"not_before,omitempty"`
	KeyID            string            `json:"key_id,omitempty"`
	FileSHA256       string            `json:"file_sha256,omitempty"`   // the .bundle file (Edge ETag for file://)
	BundleSHA256     string            `json:"bundle_sha256"`           // the signed SiteBundle bytes
	SourceDigest     string            `json:"source_digest,omitempty"` // site YAML + policy + list files
	Profile          string            `json:"profile"`
	MonitorOnly      bool              `json:"monitor_only"`
	Hosts            []string          `json:"hosts"`
	AllowedListeners []string          `json:"allowed_listeners"`
	TokenKeyIDs      []string          `json:"token_key_ids"`
	Rules            int               `json:"rules"`
	Environments     []EnvSummary      `json:"environments"`
	Artifacts        []ArtifactSummary `json:"artifacts"`
	Lists            int               `json:"lists"`
}

// EnvSummary is one environment in a Summary.
type EnvSummary struct {
	Name       string   `json:"name"`
	Hosts      []string `json:"hosts"`
	Routes     int      `json:"routes"`
	Rules      int      `json:"rules"`
	RateLimits int      `json:"rate_limits"`
}

// ArtifactSummary is one artifact in a Summary.
type ArtifactSummary struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Size    uint64 `json:"size"`
	Version string `json:"version,omitempty"`
}

// Summarize describes a bundle; signed and file may be nil (unsigned build).
func Summarize(sb *morphgatev1.SiteBundle, bundleBytes []byte, signed *morphgatev1.SignedBundle, file []byte) Summary {
	sum := sha256.Sum256(bundleBytes)
	s := Summary{
		Site: sb.SiteId, Version: sb.Version,
		CreatedAt:        time.UnixMilli(sb.CreatedAtMs).UTC().Format(time.RFC3339),
		BundleSHA256:     hex.EncodeToString(sum[:]),
		SourceDigest:     sb.SourceDigest,
		Profile:          profileName(sb.GetUpstream().GetKind()),
		MonitorOnly:      sb.MonitorOnly,
		Hosts:            nonNil(sb.Hosts),
		AllowedListeners: nonNil(sb.AllowedListeners),
		TokenKeyIDs:      nonNil(sb.TokenKeyIds),
		Environments:     []EnvSummary{},
		Artifacts:        []ArtifactSummary{},
		Lists:            len(sb.Lists),
	}
	if sb.NotBeforeMs != 0 {
		s.NotBefore = time.UnixMilli(sb.NotBeforeMs).UTC().Format(time.RFC3339)
	}
	if signed != nil {
		s.KeyID = signed.KeyId
	}
	if file != nil {
		fs := sha256.Sum256(file)
		s.FileSHA256 = hex.EncodeToString(fs[:])
	}
	for _, env := range sb.Environments {
		s.Rules += len(env.Rules)
		s.Environments = append(s.Environments, EnvSummary{Name: env.Name, Hosts: nonNil(env.Hosts),
			Routes: len(env.Routes), Rules: len(env.Rules), RateLimits: len(env.RateLimits)})
	}
	for _, a := range sb.Artifacts {
		s.Artifacts = append(s.Artifacts, ArtifactSummary{Name: a.Name, SHA256: a.Sha256, Size: a.Size, Version: a.Version})
	}
	return s
}

func profileName(k morphgatev1.UpstreamProfileKind) string {
	switch k {
	case morphgatev1.UpstreamProfileKind_UPSTREAM_PROFILE_KIND_CLOUDFLARE:
		return "cloudflare"
	case morphgatev1.UpstreamProfileKind_UPSTREAM_PROFILE_KIND_DIRECT_TLS:
		return "direct_tls"
	}
	return k.String()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
