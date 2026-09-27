package intelsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// UserAgent is sent on every outbound request. Integrator ruling I-7
// (docs/impl/phase1-spec.md) fixes it for all work packages; it carries no
// owner identity.
const UserAgent = "morphgate-dev-tooling"

const (
	// maxRedirects is the number of https -> https redirects a range
	// download may follow (§14.5).
	maxRedirects = 3
	// defaultFetchTimeout bounds one download, including redirects (§14.5).
	defaultFetchTimeout = 30 * time.Second
)

// fetchConfig controls downloads; tests shorten the timeout.
type fetchConfig struct {
	client  *http.Client
	timeout time.Duration
}

// newFetchClient derives the download client from the one mgctl provides
// (tests inject clients that trust httptest TLS servers). Redirects must stay
// on https and are limited to maxRedirects.
func newFetchClient(base *http.Client, timeout time.Duration) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	}
	if c.Timeout == 0 || c.Timeout > timeout {
		c.Timeout = timeout
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return fmt.Errorf("more than %d redirects", maxRedirects)
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to non-https URL %s", redactURL(req.URL))
		}
		return nil
	}
	return &c
}

// checkHTTPSURL accepts only absolute https URLs without credentials.
func checkHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q", raw)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("URL %q must be absolute https", raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("URL %s must not carry credentials", redactURL(u))
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("URL %s must not have a fragment", redactURL(u))
	}
	return u, nil
}

// redactURL prints a URL without user info, for error messages.
func redactURL(u *url.URL) string {
	c := *u
	c.User = nil
	return c.String()
}

// errTooLarge marks a response body over the limit.
var errTooLarge = errors.New("response too large")

// fetch GETs raw (https only) and returns the body of a 200 response, at most
// limit bytes.
func (fc fetchConfig) fetch(ctx context.Context, raw, accept string, limit int64) ([]byte, error) {
	u, err := checkHTTPSURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, fc.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", accept)
	resp, err := newFetchClient(fc.client, fc.timeout).Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", redactURL(u), unwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain a little so the connection can be reused; ignore errors.
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil, fmt.Errorf("GET %s: HTTP %d", redactURL(u), resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("GET %s: %w (%d > %d bytes)", redactURL(u), errTooLarge, resp.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: reading body: %w", redactURL(u), unwrapURLError(err))
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: %w (over %d bytes)", redactURL(u), errTooLarge, limit)
	}
	return body, nil
}

// unwrapURLError drops the *url.Error wrapper, whose message repeats the URL.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
