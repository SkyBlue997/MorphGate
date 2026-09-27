package cfaudit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Site is the part of a site YAML (docs/impl/phase1-spec.md §8.2) that the
// audit reads: site, hosts, profile and cloudflare.*, plus the route paths
// for check 14 (cf_challenge_overlap). Every other key is ignored: full
// validation belongs to `mgctl site check` (internal/sitecfg), and this
// loose reader keeps the audit independent of that package.
type Site struct {
	Site         string          `yaml:"site"`
	Profile      string          `yaml:"profile"`
	Hosts        []string        `yaml:"hosts"`
	Cloudflare   *SiteCloudflare `yaml:"cloudflare"`
	Environments []struct {
		Routes []struct {
			Name  string   `yaml:"name"`
			Paths []string `yaml:"paths"`
		} `yaml:"routes"`
	} `yaml:"environments"`
}

// SiteCloudflare is the site's `cloudflare:` block.
type SiteCloudflare struct {
	Zone                string   `yaml:"zone"`
	LocationHeaders     bool     `yaml:"location_headers"`
	Tier1               bool     `yaml:"tier1"`
	OwnerZones          []string `yaml:"owner_zones"`
	PseudoIPv4Overwrite bool     `yaml:"pseudo_ipv4_overwrite"`
	OriginMode          string   `yaml:"origin_mode"` // tunnel | aop
	AccountID           string   `yaml:"account_id"`
	TunnelID            string   `yaml:"tunnel_id"`
}

var (
	siteIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	hostPattern   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

const maxSiteFileSize = 1 << 20

// LoadSite reads and checks the keys the audit needs.
func LoadSite(path string) (*Site, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSiteFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSiteFileSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxSiteFileSize)
	}
	return ParseSite(path, data)
}

// ParseSite parses a site YAML loosely (unknown keys are ignored) and checks
// the fields the audit relies on.
func ParseSite(file string, data []byte) (*Site, error) {
	var s Site
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty file", file)
		}
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if !siteIDPattern.MatchString(s.Site) {
		return nil, fmt.Errorf("%s: site %q must match %s", file, s.Site, siteIDPattern)
	}
	if s.Profile != "cloudflare" {
		return nil, fmt.Errorf("%s: mgctl cf audit needs profile: cloudflare, got %q", file, s.Profile)
	}
	if len(s.Hosts) == 0 {
		return nil, fmt.Errorf("%s: hosts is empty", file)
	}
	for i, h := range s.Hosts {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if len(h) > 253 || !hostPattern.MatchString(h) {
			return nil, fmt.Errorf("%s: host %q is not a DNS host name", file, s.Hosts[i])
		}
		s.Hosts[i] = h
	}
	cf := s.Cloudflare
	if cf == nil {
		return nil, fmt.Errorf("%s: profile cloudflare needs a cloudflare: block", file)
	}
	cf.Zone = strings.TrimSuffix(strings.ToLower(cf.Zone), ".")
	if !hostPattern.MatchString(cf.Zone) || !strings.Contains(cf.Zone, ".") {
		return nil, fmt.Errorf("%s: cloudflare.zone %q is not a zone name", file, cf.Zone)
	}
	switch cf.OriginMode {
	case "":
		cf.OriginMode = "tunnel"
	case "tunnel", "aop":
	default:
		return nil, fmt.Errorf("%s: cloudflare.origin_mode must be tunnel or aop, got %q", file, cf.OriginMode)
	}
	if (cf.AccountID == "") != (cf.TunnelID == "") {
		return nil, fmt.Errorf("%s: cloudflare.account_id and tunnel_id go together", file)
	}
	for _, id := range []string{cf.AccountID, cf.TunnelID} {
		if id != "" && !idPattern.MatchString(id) {
			return nil, fmt.Errorf("%s: invalid cloudflare account or tunnel id %q", file, id)
		}
	}
	return &s, nil
}

// routePaths returns the site's route path patterns, in file order.
func (s *Site) routePaths() []string {
	var out []string
	for _, e := range s.Environments {
		for _, r := range e.Routes {
			out = append(out, r.Paths...)
		}
	}
	return out
}
