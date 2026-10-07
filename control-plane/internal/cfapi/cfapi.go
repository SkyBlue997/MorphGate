// Package cfapi is a small read-only client for the Cloudflare API v4, used by
// `mgctl cf audit` (docs/impl/phase1-spec.md §14.3). It only issues GET
// requests: nothing in MorphGate Phase 1 changes a Cloudflare zone.
//
// The API token is sent only as a bearer token to the configured base URL
// (https, or http to a loopback test server), redirects are never followed,
// and neither the token nor response bodies appear in errors.
package cfapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the Cloudflare API v4 endpoint; MGCTL_CF_API_BASE
// overrides it (tests point it at httptest servers).
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// UserAgent is sent on every request (integrator ruling I-7).
const UserAgent = "morphgate-dev-tooling"

// maxResponseSize bounds one API response body.
const maxResponseSize = 8 << 20

// Client issues read-only Cloudflare API requests.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// New returns a client for base (DefaultBaseURL if empty). base must be https
// unless it points at a loopback address, so the token never crosses the
// network in clear text. hc may be nil.
func New(base, token string, hc *http.Client) (*Client, error) {
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("invalid Cloudflare API base URL %q", base)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("Cloudflare API base URL must not carry credentials, a query or a fragment")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("Cloudflare API base URL %s: http is only allowed for loopback test servers", u.Redacted())
	}
	if token == "" {
		return nil, errors.New("empty API token")
	}
	var c http.Client
	if hc != nil {
		c = *hc
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	// Never follow redirects: the bearer token must only go to the base URL.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: u, token: token, http: &c}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Message is one entry of the API's errors / messages arrays.
type Message struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// APIError is a failed request: a non-2xx status or success == false.
type APIError struct {
	Method string
	Path   string // request path relative to the base URL, without query
	Status int    // HTTP status
	Errors []Message
}

func (e *APIError) Error() string {
	var parts []string
	for _, m := range e.Errors {
		parts = append(parts, fmt.Sprintf("%d %s", m.Code, truncate(m.Message, 200)))
	}
	msg := fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.Status)
	if len(parts) > 0 {
		msg += " (" + strings.Join(parts, "; ") + ")"
	}
	return msg
}

// IsForbidden reports whether err is a permission problem (HTTP 401 / 403):
// the audit reports such checks as `manual` (§14.3).
func IsForbidden(err error) bool {
	var e *APIError
	return errors.As(err, &e) && (e.Status == http.StatusForbidden || e.Status == http.StatusUnauthorized)
}

// IsNotFound reports whether err is an HTTP 404.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// envelope is the common API v4 response wrapper.
type envelope struct {
	Success bool            `json:"success"`
	Errors  []Message       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// Get performs GET base+path?query and decodes the envelope's result into
// out (skipped when out is nil).
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error {
	u := *c.base
	u.Path = c.base.Path + path
	u.RawPath = ""
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return fmt.Errorf("GET %s: reading response: %w", path, err)
	}
	if len(body) > maxResponseSize {
		return fmt.Errorf("GET %s: response larger than %d bytes", path, maxResponseSize)
	}
	return decodeResponse(path, resp.StatusCode, body, out)
}

// decodeResponse checks the status and envelope and decodes the result.
func decodeResponse(path string, status int, body []byte, out any) error {
	var env envelope
	jsonErr := json.Unmarshal(body, &env)
	if status < 200 || status > 299 {
		ae := &APIError{Method: http.MethodGet, Path: path, Status: status}
		if jsonErr == nil {
			ae.Errors = env.Errors
		}
		return ae
	}
	if jsonErr != nil {
		return fmt.Errorf("GET %s: invalid JSON response: %w", path, jsonErr)
	}
	if !env.Success {
		return &APIError{Method: http.MethodGet, Path: path, Status: status, Errors: env.Errors}
	}
	if out == nil {
		return nil
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return fmt.Errorf("GET %s: response has no result", path)
	}
	if err := json.Unmarshal(env.Result, out); err != nil {
		return fmt.Errorf("GET %s: unexpected result: %w", path, err)
	}
	return nil
}

// checkSegment accepts the path segments this client builds from input
// (zone and account ids, tunnel ids, host names, setting and phase names), so
// no escaping is ever needed and no input can change the request path.
func checkSegment(what, s string) error {
	if s == "" || len(s) > 253 {
		return fmt.Errorf("invalid %s %q", what, s)
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '-' || b == '_') {
			return fmt.Errorf("invalid %s %q", what, s)
		}
	}
	if s == "." || s == ".." {
		return fmt.Errorf("invalid %s %q", what, s)
	}
	return nil
}
