package cfapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Zone is an entry of `GET /zones`.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Plan   struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		LegacyID string `json:"legacy_id"` // free | pro | business | enterprise
	} `json:"plan"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}

// ErrZoneNotFound is returned by FindZone when no zone has the name.
var ErrZoneNotFound = errors.New("zone not found")

// FindZone looks a zone up by name (`GET /zones?name=`). It fails unless
// exactly one zone matches.
func (c *Client) FindZone(ctx context.Context, name string) (*Zone, error) {
	if err := checkSegment("zone name", name); err != nil {
		return nil, err
	}
	var zones []Zone
	if err := c.Get(ctx, "/zones", url.Values{"name": {name}}, &zones); err != nil {
		return nil, err
	}
	var match []Zone
	for _, z := range zones {
		if strings.EqualFold(z.Name, name) {
			match = append(match, z)
		}
	}
	switch len(match) {
	case 0:
		return nil, fmt.Errorf("%w: %q (or the token cannot read it)", ErrZoneNotFound, name)
	case 1:
		if err := checkSegment("zone id", match[0].ID); err != nil {
			return nil, err
		}
		return &match[0], nil
	}
	return nil, fmt.Errorf("zone name %q matches %d zones", name, len(match))
}

// Setting is a zone setting (`GET /zones/{zone}/settings/{name}`).
type Setting struct {
	ID       string          `json:"id"`
	Value    json.RawMessage `json:"value"`
	Editable bool            `json:"editable"`
}

// String returns the value of a string-valued setting.
func (s *Setting) String() (string, error) {
	var v string
	if err := json.Unmarshal(s.Value, &v); err != nil {
		return "", fmt.Errorf("setting %s: value is not a string", s.ID)
	}
	return v, nil
}

// Setting reads one zone setting.
func (c *Client) Setting(ctx context.Context, zoneID, name string) (*Setting, error) {
	if err := checkSegment("zone id", zoneID); err != nil {
		return nil, err
	}
	if err := checkSegment("setting", name); err != nil {
		return nil, err
	}
	var s Setting
	if err := c.Get(ctx, "/zones/"+zoneID+"/settings/"+name, nil, &s); err != nil {
		return nil, err
	}
	if s.ID == "" {
		s.ID = name
	}
	return &s, nil
}

// ManagedHeader is one Managed Transform.
type ManagedHeader struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

// ManagedHeaders is `GET /zones/{zone}/managed_headers`: only the transforms
// available on the zone's plan are listed.
type ManagedHeaders struct {
	Request  []ManagedHeader `json:"managed_request_headers"`
	Response []ManagedHeader `json:"managed_response_headers"`
}

// RequestHeader returns the request-header transform with this id.
func (m *ManagedHeaders) RequestHeader(id string) (ManagedHeader, bool) {
	for _, h := range m.Request {
		if h.ID == id {
			return h, true
		}
	}
	return ManagedHeader{}, false
}

// ManagedHeaders reads the zone's Managed Transforms.
func (c *Client) ManagedHeaders(ctx context.Context, zoneID string) (*ManagedHeaders, error) {
	if err := checkSegment("zone id", zoneID); err != nil {
		return nil, err
	}
	var m ManagedHeaders
	if err := c.Get(ctx, "/zones/"+zoneID+"/managed_headers", nil, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Ruleset is a zone phase entry point ruleset.
type Ruleset struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	Rules []Rule `json:"rules"`
	// Missing is true when the phase has no entry point ruleset (HTTP 404):
	// the zone has no rules in that phase.
	Missing bool `json:"-"`
}

// Rule is one ruleset rule. ActionParameters stays raw: its shape depends on
// the action and phase.
type Rule struct {
	ID               string          `json:"id"`
	Ref              string          `json:"ref"`
	Description      string          `json:"description"`
	Expression       string          `json:"expression"`
	Action           string          `json:"action"`
	ActionParameters json.RawMessage `json:"action_parameters"`
	Enabled          *bool           `json:"enabled"`
}

// IsEnabled treats an absent flag as enabled (the Rulesets API default).
func (r *Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Name returns the rule's ref, or its id when it has none.
func (r *Rule) Name() string {
	if r.Ref != "" {
		return r.Ref
	}
	return r.ID
}

// Params decodes the rule's action_parameters into v; absent parameters leave
// v unchanged.
func (r *Rule) Params(v any) error {
	if len(r.ActionParameters) == 0 || string(r.ActionParameters) == "null" {
		return nil
	}
	return json.Unmarshal(r.ActionParameters, v)
}

// Phases whose entry point rulesets the audit reads.
const (
	PhaseLateTransform  = "http_request_late_transform"
	PhaseFirewallCustom = "http_request_firewall_custom"
	PhaseRateLimit      = "http_ratelimit"
	PhaseCacheSettings  = "http_request_cache_settings"
)

// EntrypointRuleset reads `GET /zones/{zone}/rulesets/phases/{phase}/entrypoint`.
// A 404 means the phase has no rules and returns an empty ruleset with
// Missing set (§14.3).
func (c *Client) EntrypointRuleset(ctx context.Context, zoneID, phase string) (*Ruleset, error) {
	if err := checkSegment("zone id", zoneID); err != nil {
		return nil, err
	}
	if err := checkSegment("phase", phase); err != nil {
		return nil, err
	}
	var rs Ruleset
	err := c.Get(ctx, "/zones/"+zoneID+"/rulesets/phases/"+phase+"/entrypoint", nil, &rs)
	if IsNotFound(err) {
		return &Ruleset{Phase: phase, Missing: true}, nil
	}
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// BotManagement is `GET /zones/{zone}/bot_management`. Its fields differ by
// plan (Bot Fight Mode on Free, SBFM groups on Pro and above, AI bot
// settings), so the raw object is kept and read field by field.
type BotManagement struct {
	Fields map[string]json.RawMessage
}

// Bool returns a boolean field and whether it is present.
func (b *BotManagement) Bool(key string) (value, ok bool) {
	raw, present := b.Fields[key]
	if !present || json.Unmarshal(raw, &value) != nil {
		return false, false
	}
	return value, true
}

// String returns a string field and whether it is present.
func (b *BotManagement) String(key string) (value string, ok bool) {
	raw, present := b.Fields[key]
	if !present || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

// BotManagement reads the zone's bot settings.
func (c *Client) BotManagement(ctx context.Context, zoneID string) (*BotManagement, error) {
	if err := checkSegment("zone id", zoneID); err != nil {
		return nil, err
	}
	b := &BotManagement{}
	if err := c.Get(ctx, "/zones/"+zoneID+"/bot_management", nil, &b.Fields); err != nil {
		return nil, err
	}
	return b, nil
}

// Tunnel is `GET /accounts/{account}/cfd_tunnel/{id}`.
type Tunnel struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Status      string            `json:"status"` // inactive | degraded | healthy | down
	Connections []json.RawMessage `json:"connections"`
}

// Tunnel reads a Cloudflare Tunnel.
func (c *Client) Tunnel(ctx context.Context, accountID, tunnelID string) (*Tunnel, error) {
	if err := checkSegment("account id", accountID); err != nil {
		return nil, err
	}
	if err := checkSegment("tunnel id", tunnelID); err != nil {
		return nil, err
	}
	var t Tunnel
	if err := c.Get(ctx, "/accounts/"+accountID+"/cfd_tunnel/"+tunnelID, nil, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// AOPSettings is `GET /zones/{zone}/origin_tls_client_auth/settings`
// (zone-level Authenticated Origin Pulls).
type AOPSettings struct {
	Enabled bool `json:"enabled"`
}

// AOPSettings reads whether zone-level AOP is enabled.
func (c *Client) AOPSettings(ctx context.Context, zoneID string) (*AOPSettings, error) {
	if err := checkSegment("zone id", zoneID); err != nil {
		return nil, err
	}
	var s AOPSettings
	if err := c.Get(ctx, "/zones/"+zoneID+"/origin_tls_client_auth/settings", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// AOPCertificate is a zone-level AOP client certificate.
type AOPCertificate struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresOn string `json:"expires_on"`
	Issuer    string `json:"issuer"`
}

// AOPCertificates lists the zone-level AOP certificates
// (`GET /zones/{zone}/origin_tls_client_auth`).
func (c *Client) AOPCertificates(ctx context.Context, zoneID string) ([]AOPCertificate, error) {
	if err := checkSegment("zone id", zoneID); err != nil {
		return nil, err
	}
	var certs []AOPCertificate
	if err := c.Get(ctx, "/zones/"+zoneID+"/origin_tls_client_auth", nil, &certs); err != nil {
		return nil, err
	}
	return certs, nil
}

// AOPHostname is a per-hostname AOP association
// (`GET /zones/{zone}/origin_tls_client_auth/hostnames/{host}`).
type AOPHostname struct {
	Hostname   string `json:"hostname"`
	CertID     string `json:"cert_id"`
	Enabled    *bool  `json:"enabled"`
	Status     string `json:"status"`
	CertStatus string `json:"cert_status"`
	ExpiresOn  string `json:"expires_on"`
}

// AOPHostname reads the per-hostname AOP setting of one host; a 404 means
// the host has none and returns (nil, nil).
func (c *Client) AOPHostname(ctx context.Context, zoneID, host string) (*AOPHostname, error) {
	if err := checkSegment("zone id", zoneID); err != nil {
		return nil, err
	}
	if err := checkSegment("host name", host); err != nil {
		return nil, err
	}
	var h AOPHostname
	err := c.Get(ctx, "/zones/"+zoneID+"/origin_tls_client_auth/hostnames/"+host, nil, &h)
	if IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}
