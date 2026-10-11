package turnstile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"morphgate/control-plane/internal/keys"
)

// DefaultBaseURL is the Cloudflare API v4 endpoint; MGCTL_CF_API_BASE
// overrides it (tests point it at httptest servers on loopback).
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// UserAgent is sent on every request; it carries no owner identity
// (integrator rulings I-7, I-15; Phase 2 spec §16).
const UserAgent = "morphgate-dev-tooling"

const (
	// maxResponseSize bounds one API response body.
	maxResponseSize = 4 << 20
	// perPage and maxPages bound the widget listing.
	perPage  = 100
	maxPages = 100
)

var (
	// accountPattern accepts Cloudflare account ids (32 hex digits) and
	// other plain identifiers, never anything that changes the request path.
	accountPattern = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)
	// tokenPattern is the syntax of an API token: visible ASCII only.
	tokenPattern = regexp.MustCompile(`^[\x21-\x7e]{1,512}$`)
)

// Client manages the owner's Turnstile widgets through the documented
// Cloudflare API (Account → Turnstile → Edit). It lists widgets, reads one
// widget (with its secret) and rotates its secret; nothing else.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// New returns a client for base (DefaultBaseURL if empty). base must be
// https unless it points at a loopback address, so the token never crosses
// the network in clear text; redirects are never followed. hc may be nil.
func New(base, token string, hc *http.Client) (*Client, error) {
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("invalid Cloudflare API base URL %q", base)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("the Cloudflare API base URL must not carry credentials, a query or a fragment")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("Cloudflare API base URL %s: http is only allowed for loopback test servers", u.Redacted())
	}
	if !tokenPattern.MatchString(token) {
		return nil, errors.New("the API token is empty or not visible ASCII")
	}
	var c http.Client
	if hc != nil {
		c = *hc
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
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

// Widget is a Turnstile widget. Secret is set only by Widget and
// RotateSecret; String and GoString never show it.
type Widget struct {
	Sitekey    string   `json:"sitekey"`
	Name       string   `json:"name"`
	Mode       string   `json:"mode"`
	Domains    []string `json:"domains"`
	CreatedOn  string   `json:"created_on"`
	ModifiedOn string   `json:"modified_on"`
	Secret     string   `json:"secret,omitempty"`
}

// String describes the widget without its secret.
func (w Widget) String() string {
	return fmt.Sprintf("widget{sitekey: %s, name: %q, mode: %s, domains: %s}", w.Sitekey, w.Name, w.Mode, strings.Join(w.Domains, ","))
}

// GoString keeps %#v from printing the secret.
func (w Widget) GoString() string { return w.String() }

// Message is one entry of the API's errors array.
type Message struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// APIError is a failed request: a non-2xx status or success == false.
type APIError struct {
	Method, Path string
	Status       int
	Errors       []Message
}

func (e *APIError) Error() string {
	var parts []string
	for _, m := range e.Errors {
		msg := m.Message
		if len(msg) > 200 {
			msg = msg[:200] + "..."
		}
		parts = append(parts, fmt.Sprintf("%d %s", m.Code, msg))
	}
	s := fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.Status)
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, "; ") + ")"
	}
	return s
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []Message       `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
}

// do sends one request and decodes the envelope. path is relative to the
// base URL and built only from validated segments.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (*envelope, error) {
	u := *c.base
	u.Path = c.base.Path + path
	u.RawPath = ""
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s %s: reading the response: %w", method, path, err)
	}
	if len(data) > maxResponseSize {
		return nil, fmt.Errorf("%s %s: response larger than %d bytes", method, path, maxResponseSize)
	}
	var env envelope
	jsonErr := json.Unmarshal(data, &env)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Method: method, Path: path, Status: resp.StatusCode}
		if jsonErr == nil {
			ae.Errors = env.Errors
		}
		return nil, ae
	}
	if jsonErr != nil {
		return nil, fmt.Errorf("%s %s: the response is not the API's JSON envelope", method, path)
	}
	if !env.Success {
		return nil, &APIError{Method: method, Path: path, Status: resp.StatusCode, Errors: env.Errors}
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return nil, fmt.Errorf("%s %s: the response has no result", method, path)
	}
	return &env, nil
}

func widgetsPath(account string) (string, error) {
	if !accountPattern.MatchString(account) {
		return "", fmt.Errorf("invalid account id %q", account)
	}
	return "/accounts/" + account + "/challenges/widgets", nil
}

func widgetPath(account, sitekey string) (string, error) {
	p, err := widgetsPath(account)
	if err != nil {
		return "", err
	}
	if !siteKeyPattern.MatchString(sitekey) {
		return "", fmt.Errorf("invalid sitekey %q", sitekey)
	}
	return p + "/" + sitekey, nil
}

// siteKeyPattern is the sitekey syntax of the bundle (§8.2).
var siteKeyPattern = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)

// CheckIDs validates an account id and (unless empty) a sitekey before any
// request is built.
func CheckIDs(account, sitekey string) error {
	if !accountPattern.MatchString(account) {
		return fmt.Errorf("invalid account id %q", account)
	}
	if sitekey != "" && !siteKeyPattern.MatchString(sitekey) {
		return fmt.Errorf("invalid sitekey %q", sitekey)
	}
	return nil
}

// Widgets lists the account's widgets
// (GET /accounts/{id}/challenges/widgets, every page). The listing has no
// secrets; any secret in the response is dropped.
func (c *Client) Widgets(ctx context.Context, account string) ([]Widget, error) {
	path, err := widgetsPath(account)
	if err != nil {
		return nil, err
	}
	var out []Widget
	for page := 1; page <= maxPages; page++ {
		env, err := c.do(ctx, http.MethodGet, path, url.Values{"page": {strconv.Itoa(page)}, "per_page": {strconv.Itoa(perPage)}}, nil)
		if err != nil {
			return nil, err
		}
		var ws []Widget
		if err := json.Unmarshal(env.Result, &ws); err != nil {
			return nil, fmt.Errorf("GET %s: unexpected result", path)
		}
		for i := range ws {
			ws[i].Secret = ""
		}
		out = append(out, ws...)
		info := env.ResultInfo
		if len(ws) == 0 || info == nil || info.TotalCount <= len(out) || len(ws) < perPage {
			return out, nil
		}
	}
	return nil, fmt.Errorf("GET %s: more than %d pages", path, maxPages)
}

// decodeWidgetWithSecret decodes a widget whose secret must be present and
// well-formed (1-256 visible ASCII characters, spec §8.7).
func decodeWidgetWithSecret(method, path string, raw json.RawMessage, sitekey string) (*Widget, error) {
	var w Widget
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("%s %s: unexpected result", method, path)
	}
	if w.Sitekey != sitekey {
		return nil, fmt.Errorf("%s %s: the result is widget %q, not %q", method, path, w.Sitekey, sitekey)
	}
	if err := keys.ValidTurnstileSecret(w.Secret); err != nil {
		return nil, fmt.Errorf("%s %s: the widget secret is unusable: %v", method, path, err)
	}
	return &w, nil
}

// Widget reads one widget including its secret
// (GET /accounts/{id}/challenges/widgets/{sitekey}).
func (c *Client) Widget(ctx context.Context, account, sitekey string) (*Widget, error) {
	path, err := widgetPath(account, sitekey)
	if err != nil {
		return nil, err
	}
	env, err := c.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeWidgetWithSecret(http.MethodGet, path, env.Result, sitekey)
}

// rotateRequest is the rotate_secret body. invalidate_immediately has no
// omitempty: it is always sent explicitly (spec §8.7), so a change of the
// API's default can never decide what happens to the old secret.
type rotateRequest struct {
	InvalidateImmediately bool `json:"invalidate_immediately"`
}

// RotateSecret rotates the widget secret
// (POST /accounts/{id}/challenges/widgets/{sitekey}/rotate_secret) and
// returns the widget with its new secret. With invalidateImmediately false
// Cloudflare keeps the old secret valid for 2 hours (no second rotation in
// that window); true invalidates it at once (suspected leak).
func (c *Client) RotateSecret(ctx context.Context, account, sitekey string, invalidateImmediately bool) (*Widget, error) {
	path, err := widgetPath(account, sitekey)
	if err != nil {
		return nil, err
	}
	path += "/rotate_secret"
	env, err := c.do(ctx, http.MethodPost, path, nil, rotateRequest{InvalidateImmediately: invalidateImmediately})
	if err != nil {
		return nil, err
	}
	return decodeWidgetWithSecret(http.MethodPost, path, env.Result, sitekey)
}
