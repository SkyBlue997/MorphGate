package intelsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"morphgate/control-plane/internal/cli"
)

// Cloudflare IP artifact constants (docs/impl/phase1-spec.md §12.1, §12.2).
const (
	KindCloudflareIPs      = "mg-cloudflare-ips"
	DefaultCloudflareIPURL = "https://api.cloudflare.com/client/v4/ips"
	maxCloudflareIPsSize   = 1 << 20 // §12.1
	minV4, maxV4           = 5, 64
	minV6, maxV6           = 2, 32
	// cfIPsMaxChangePct is the §14.4 guard: a per-family entry count change
	// above this percentage needs --accept-change.
	cfIPsMaxChangePct = 30
)

// CloudflareIPs is the `cloudflare-ips` artifact (§12.2). Field order is the
// canonical key order.
type CloudflareIPs struct {
	V         int      `json:"v"`
	Kind      string   `json:"kind"`
	Source    string   `json:"source"`
	FetchedAt string   `json:"fetched_at"`
	ETag      string   `json:"etag"`
	IPv4CIDRs []string `json:"ipv4_cidrs"`
	IPv6CIDRs []string `json:"ipv6_cidrs"`
}

// ParseCloudflareIPs decodes (rejecting unknown fields) and validates an
// artifact.
func ParseCloudflareIPs(data []byte) (*CloudflareIPs, error) {
	if len(data) > maxCloudflareIPsSize {
		return nil, fmt.Errorf("cloudflare-ips: larger than %d bytes", maxCloudflareIPsSize)
	}
	var a CloudflareIPs
	if err := decodeStrict(data, &a); err != nil {
		return nil, fmt.Errorf("cloudflare-ips: %w", err)
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// Validate applies §12.2; writer and reader use the same rules.
func (a *CloudflareIPs) Validate() error {
	if a.V != 1 {
		return fmt.Errorf("cloudflare-ips: v must be 1, got %d", a.V)
	}
	if a.Kind != KindCloudflareIPs {
		return fmt.Errorf("cloudflare-ips: kind must be %q, got %q", KindCloudflareIPs, a.Kind)
	}
	if _, err := checkHTTPSURL(a.Source); err != nil {
		return fmt.Errorf("cloudflare-ips: source: %w", err)
	}
	if !isRFC3339(a.FetchedAt) {
		return fmt.Errorf("cloudflare-ips: fetched_at %q is not RFC 3339", a.FetchedAt)
	}
	if err := checkToken("etag", a.ETag, 128); err != nil {
		return fmt.Errorf("cloudflare-ips: %w", err)
	}
	if err := checkFamily("ipv4_cidrs", a.IPv4CIDRs, true, minV4, maxV4); err != nil {
		return err
	}
	return checkFamily("ipv6_cidrs", a.IPv6CIDRs, false, minV6, maxV6)
}

func checkFamily(field string, cidrs []string, v4 bool, lo, hi int) error {
	if len(cidrs) < lo || len(cidrs) > hi {
		return fmt.Errorf("cloudflare-ips: %s has %d entries, want %d-%d", field, len(cidrs), lo, hi)
	}
	for _, s := range cidrs {
		p, err := parseCIDR(s, cloudflareIPRules, true)
		if err != nil {
			return fmt.Errorf("cloudflare-ips: %s: %w", field, err)
		}
		if p.Addr().Is4() != v4 {
			return fmt.Errorf("cloudflare-ips: %s: %q is the wrong address family", field, s)
		}
	}
	return nil
}

// checkToken accepts 1..max printable ASCII characters.
func checkToken(field, s string, max int) error {
	if s == "" || len(s) > max {
		return fmt.Errorf("%s must be 1-%d characters", field, max)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return fmt.Errorf("%s contains a non-printable or space character", field)
		}
	}
	return nil
}

// Encode renders the canonical JSON form.
func (a *CloudflareIPs) Encode() ([]byte, error) { return EncodeCanonical(a) }

// cfIPsAPIResponse is the part of `GET /client/v4/ips` that mgctl reads.
type cfIPsAPIResponse struct {
	Success *bool `json:"success"`
	Result  *struct {
		IPv4CIDRs []string `json:"ipv4_cidrs"`
		IPv6CIDRs []string `json:"ipv6_cidrs"`
		ETag      string   `json:"etag"`
	} `json:"result"`
}

// ArtifactFromAPI turns a `/client/v4/ips` response into a validated
// artifact. fetchedAt is rendered as RFC 3339 in UTC, whole seconds.
func ArtifactFromAPI(body []byte, source string, fetchedAt time.Time) (*CloudflareIPs, error) {
	var r cfIPsAPIResponse
	// The API response is third-party data: unknown fields are tolerated,
	// the values are validated below.
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("Cloudflare IPs API: invalid JSON: %w", err)
	}
	if r.Success == nil || !*r.Success {
		return nil, errors.New("Cloudflare IPs API: success is not true")
	}
	if r.Result == nil {
		return nil, errors.New("Cloudflare IPs API: no result")
	}
	a := &CloudflareIPs{
		V:         1,
		Kind:      KindCloudflareIPs,
		Source:    source,
		FetchedAt: fetchedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		ETag:      r.Result.ETag,
		IPv4CIDRs: nonNil(r.Result.IPv4CIDRs),
		IPv6CIDRs: nonNil(r.Result.IPv6CIDRs),
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// sameRanges reports whether two artifacts list the same networks,
// irrespective of order.
func sameRanges(a, b *CloudflareIPs) bool {
	return slices.Equal(sortedCopy(a.IPv4CIDRs), sortedCopy(b.IPv4CIDRs)) &&
		slices.Equal(sortedCopy(a.IPv6CIDRs), sortedCopy(b.IPv6CIDRs))
}

// changeTooLarge reports whether a count moved by more than pct percent.
func changeTooLarge(oldN, newN, pct int) bool {
	d := newN - oldN
	if d < 0 {
		d = -d
	}
	return d*100 > oldN*pct
}

// CFIPsOptions are the `mgctl cf ips sync` flags (§14.4).
type CFIPsOptions struct {
	URL             string // default DefaultCloudflareIPURL; https only
	Out             string
	Previous        string // default: the existing Out file
	AcceptChange    bool
	MetricsTextfile string
}

// CFIPsResult describes a successful sync.
type CFIPsResult struct {
	Artifact *CloudflareIPs
	Previous *CloudflareIPs // nil on the first sync
	Changed  bool           // the artifact file was (re)written
	SHA256   string         // of the artifact file now at Out
}

// cfIPsDiff is the audit record's diff (§12.8): counts and etags only.
type cfIPsDiff struct {
	ETag         string `json:"etag"`
	PreviousETag string `json:"previous_etag"`
	IPv4         int    `json:"ipv4"`
	IPv6         int    `json:"ipv6"`
	PreviousIPv4 int    `json:"previous_ipv4"`
	PreviousIPv6 int    `json:"previous_ipv6"`
	SHA256       string `json:"sha256"`
	Out          string `json:"out"`
	AcceptChange bool   `json:"accept_change"`
}

// SyncCloudflareIPs implements `mgctl cf ips sync` (§14.4): fetch, validate,
// compare with the previous artifact, write it atomically when the ranges
// changed, then always record the success in `<out>.state.json` and the
// metrics textfile.
func SyncCloudflareIPs(ctx context.Context, env cli.Env, fc fetchConfig, opts CFIPsOptions) (*CFIPsResult, error) {
	src := opts.URL
	if src == "" {
		src = DefaultCloudflareIPURL
	}
	if _, err := checkHTTPSURL(src); err != nil {
		return nil, usageErr(fmt.Errorf("--url: %w", err))
	}
	now := envNow(env)

	prevPath, explicitPrev := opts.Previous, opts.Previous != ""
	if !explicitPrev {
		prevPath = opts.Out
	}
	var prev *CloudflareIPs
	if data, err := readLimited(prevPath, maxCloudflareIPsSize); err == nil {
		p, perr := ParseCloudflareIPs(data)
		if perr != nil {
			if !opts.AcceptChange {
				return nil, invalidErr(fmt.Errorf("previous artifact %s: %w (fix it, or pass --accept-change to replace it)", prevPath, perr))
			}
			fmt.Fprintf(stderr(env), "warning: ignoring invalid previous artifact %s: %v\n", prevPath, perr)
		} else {
			prev = p
		}
	} else if !errors.Is(err, fs.ErrNotExist) || explicitPrev {
		return nil, invalidErr(fmt.Errorf("previous artifact: %w", err))
	}

	body, err := fc.fetch(ctx, src, "application/json", maxCloudflareIPsSize)
	if err != nil {
		return nil, ioErr(err)
	}
	next, err := ArtifactFromAPI(body, src, now)
	if err != nil {
		return nil, invalidErr(err)
	}

	res := &CFIPsResult{Artifact: next, Previous: prev}
	current, _ := readLimited(opts.Out, maxCloudflareIPsSize)
	unchanged := prev != nil && current != nil && bytes.Equal(mustEncode(prev), current) &&
		(prev.ETag == next.ETag || sameRanges(prev, next))
	if unchanged {
		// Keep the artifact bytes (and so the bundle's artifact hash) stable.
		res.Artifact = prev
		res.SHA256 = sha256Hex(current)
	} else {
		if prev != nil && !opts.AcceptChange {
			var problems []string
			if changeTooLarge(len(prev.IPv4CIDRs), len(next.IPv4CIDRs), cfIPsMaxChangePct) {
				problems = append(problems, fmt.Sprintf("IPv4 entries %d -> %d", len(prev.IPv4CIDRs), len(next.IPv4CIDRs)))
			}
			if changeTooLarge(len(prev.IPv6CIDRs), len(next.IPv6CIDRs), cfIPsMaxChangePct) {
				problems = append(problems, fmt.Sprintf("IPv6 entries %d -> %d", len(prev.IPv6CIDRs), len(next.IPv6CIDRs)))
			}
			if len(problems) > 0 {
				return nil, invalidErr(fmt.Errorf("change protection: %v changed by more than %d%%; check the ranges and rerun with --accept-change", problems, cfIPsMaxChangePct))
			}
		}
		data, err := next.Encode()
		if err != nil {
			return nil, internalErr(err)
		}
		if err := WriteFileAtomic(opts.Out, data, 0o644); err != nil {
			return nil, ioErr(fmt.Errorf("writing %s: %w", opts.Out, err))
		}
		res.Changed = true
		res.SHA256 = sha256Hex(data)
	}

	state, err := EncodeCanonical(SyncState{V: 1, LastSuccess: now.UTC().Truncate(time.Second).Format(time.RFC3339), ETag: next.ETag})
	if err != nil {
		return nil, internalErr(err)
	}
	if err := WriteFileAtomic(StatePath(opts.Out), state, 0o644); err != nil {
		return nil, ioErr(fmt.Errorf("writing %s: %w", StatePath(opts.Out), err))
	}
	if opts.MetricsTextfile != "" {
		fams := []MetricFamily{{
			Name: "mg_cf_ips_sync_timestamp_seconds",
			Help: "Unix time of the last successful mgctl cf ips sync.",
			Type: "gauge",
			Metrics: []Metric{{
				Value: float64(now.Unix()),
			}},
		}}
		if err := WriteTextfile(opts.MetricsTextfile, fams); err != nil {
			return nil, ioErr(fmt.Errorf("writing %s: %w", opts.MetricsTextfile, err))
		}
	}
	if res.Changed {
		d := cfIPsDiff{
			ETag: next.ETag, IPv4: len(next.IPv4CIDRs), IPv6: len(next.IPv6CIDRs),
			SHA256: res.SHA256, Out: opts.Out, AcceptChange: opts.AcceptChange,
		}
		if prev != nil {
			d.PreviousETag, d.PreviousIPv4, d.PreviousIPv6 = prev.ETag, len(prev.IPv4CIDRs), len(prev.IPv6CIDRs)
		}
		if err := audit(env, cli.AuditEvent{
			Action: "cf.ips.sync", ResourceType: "artifact", ResourceID: "cloudflare-ips", Diff: d,
		}); err != nil {
			return res, internalErr(fmt.Errorf("audit log: %w", err))
		}
	}
	return res, nil
}

func mustEncode(a *CloudflareIPs) []byte {
	b, err := a.Encode()
	if err != nil {
		return nil
	}
	return b
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
