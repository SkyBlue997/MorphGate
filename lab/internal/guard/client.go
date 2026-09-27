package guard

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// Client returns an HTTP client that can only reach allowed targets:
//
//   - every request URL, including each redirect hop, passes CheckURL;
//   - every connection goes through DialContext (connect-time IP check);
//   - proxies from the environment are ignored, so the guard always sees the
//     real destination;
//   - at most MaxRedirects redirects are followed;
//   - requests share the Guard's rate cap and have fixed timeouts.
func (g *Guard) Client() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           g.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   TLSHandshakeTimeout,
		ResponseHeaderTimeout: ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   1,
	}
	return &http.Client{
		Transport: &guardedTransport{guard: g, next: transport},
		Timeout:   RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return fmt.Errorf("lab guard: stopped after %d redirects", MaxRedirects)
			}
			if _, err := g.CheckURL(req.URL.String()); err != nil {
				return fmt.Errorf("redirect refused: %w", err)
			}
			return nil
		},
	}
}

// guardedTransport checks the URL and waits for the rate limiter before every
// round trip, so the cap also covers redirect hops.
type guardedTransport struct {
	guard *Guard
	next  http.RoundTripper
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if _, err := t.guard.CheckURL(req.URL.String()); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	if err := t.guard.limiter.Wait(req.Context()); err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	return t.next.RoundTrip(req)
}
