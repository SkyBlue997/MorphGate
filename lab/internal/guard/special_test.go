package guard

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// IPv6 transition prefixes embed an IPv4 address that a NAT64 gateway or relay
// forwards to. 64:ff9b::/96 passes a naive "at least /48" width check while
// standing for the whole IPv4 Internet, so none of them may be configured.
func TestConfigRejectsTranslationPrefixes(t *testing.T) {
	for _, cidr := range []string{
		"64:ff9b::/96",           // NAT64 well-known prefix: all of IPv4
		"64:ff9b::808:808",       // NAT64 form of 8.8.8.8
		"64:ff9b:1::/48",         // NAT64 local-use prefix
		"2002:c000:204::/48",     // 6to4 relay for 192.0.2.4
		"2001:0:4136:e378::/64",  // Teredo
		"64:ff9b::a9fe:a9fe/128", // NAT64 form of the metadata address
	} {
		t.Run(cidr, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AllowCIDRs = append(cfg.AllowCIDRs, cidr)
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "never allowed") {
				t.Fatalf("allow_cidrs %s: err = %v, want rejection", cidr, err)
			}
			cfg = DefaultConfig()
			cfg.OwnerTargets = []OwnerTarget{{Host: "stg.example.com", ExpectedCIDRs: []string{cidr}}}
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "never allowed") {
				t.Fatalf("expected_cidrs %s: err = %v, want rejection", cidr, err)
			}
		})
	}
}

// Cloud instance-metadata endpoints that are not link-local: AWS IMDS over
// IPv6 sits inside the ULA range (so "private"), GCP's IPv6 metadata server
// too, Alibaba Cloud's is a single CGNAT address. None may be a lab target.
func TestConfigRejectsMetadataEndpoints(t *testing.T) {
	for _, cidr := range []string{
		"fd00:ec2::254",      // AWS IMDS (IPv6)
		"fd00:ec2::/48",      // AWS link services (IMDS, DNS, NTP)
		"fd20:ce::254",       // GCP metadata server (IPv6)
		"100.100.100.200",    // Alibaba Cloud ECS metadata
		"100.100.100.200/32", // same, CIDR form
		"192.0.0.192",        // Oracle Cloud metadata (alternative address)
	} {
		t.Run(cidr, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AllowCIDRs = append(cfg.AllowCIDRs, cidr)
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "metadata") {
				t.Fatalf("allow_cidrs %s: err = %v, want rejection", cidr, err)
			}
			cfg = DefaultConfig()
			cfg.OwnerTargets = []OwnerTarget{{Host: "stg.example.com", ExpectedCIDRs: []string{cidr}}}
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "metadata") {
				t.Fatalf("expected_cidrs %s: err = %v, want rejection", cidr, err)
			}
		})
	}
}

// A broad private range that merely contains a metadata endpoint stays a valid
// config entry, but the endpoint inside it is still denied, both as an IP
// literal and as a DNS answer for an allowlisted name.
func TestMetadataDeniedInsideAllowedRanges(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowCIDRs = []string{"127.0.0.0/8", "::1/128", "fc00::/7"}
	res := &fakeResolver{answers: map[string][][]string{
		"imds.test":    {{"fd00:ec2::254"}},
		"gcp.test":     {{"fd20:ce::254"}},
		"nat64.test":   {{"64:ff9b::a9fe:a9fe"}},
		"ula.test":     {{"fd12:3456:789a::1"}},
		"mixed.test":   {{"fd12:3456:789a::1", "fd00:ec2::254"}},
		"imdsdns.test": {{"fd00:ec2::253"}},
	}}
	rec := &recordingDialer{}
	g := mustGuard(t, cfg, WithResolver(res), WithDialFunc(rec.dial))

	for _, raw := range []string{
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://[fd00:ec2::253]/",
		"http://[fd20:ce::254]/computeMetadata/v1/",
	} {
		if _, err := g.CheckURL(raw); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "metadata") {
			t.Errorf("CheckURL(%s) = %v, want a metadata denial", raw, err)
		}
	}
	if _, err := g.CheckURL("http://[fd12:3456:789a::1]:8080/"); err != nil {
		t.Errorf("ordinary ULA address inside fc00::/7 denied: %v", err)
	}

	for host, allow := range map[string]bool{
		"imds.test": false, "gcp.test": false, "nat64.test": false,
		"mixed.test": false, "imdsdns.test": false, "ula.test": true,
	} {
		conn, err := g.DialContext(context.Background(), "tcp", host+":80")
		if allow {
			if err != nil {
				t.Errorf("dial %s: %v", host, err)
				continue
			}
			conn.Close()
			continue
		}
		if err == nil {
			conn.Close()
			t.Errorf("dial %s allowed, want denied", host)
		} else if !errors.Is(err, ErrDenied) {
			t.Errorf("dial %s: %v is not ErrDenied", host, err)
		}
	}
	for _, d := range rec.dials {
		if strings.Contains(d, "ec2") || strings.Contains(d, "fd20:ce") || strings.Contains(d, "64:ff9b") {
			t.Errorf("denied destination was dialled: %s", d)
		}
	}

	// Connect-time hook: the last line of defence sees the same policy.
	for _, addr := range []string{"[fd00:ec2::254]:80", "[fd20:ce::254]:80", "[64:ff9b::7f00:1]:80"} {
		if err := controlFor(isLocal)("tcp", addr, nil); !errors.Is(err, ErrDenied) {
			t.Errorf("control(%s) = %v, want denied", addr, err)
		}
	}
}
