// Package replay sends recorded, benign request flows of the owner's own
// application to a guarded base URL.
//
// A scenario is a fixed list of requests (method, path, headers, body). The
// replayer sends exactly those requests, one at a time, through the guard's
// rate-capped client. It does not generate payloads, mutate requests, fuzz, or
// run anything concurrently.
package replay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"morphgate/lab/internal/guard"
)

// Limits for scenario files.
const (
	MaxRequests      = 1000
	MaxBodyBytes     = 1 << 20
	MaxResponseBytes = 1 << 20
	maxFileBytes     = 8 << 20
)

// DefaultUserAgent is sent when a request does not set User-Agent, so lab
// traffic is identifiable in the owner's logs.
const DefaultUserAgent = "mglab/0 (MorphGate Validation Lab replay)"

var (
	allowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	headerName     = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
	// Headers the HTTP client owns (framing, hop-by-hop, routing).
	forbiddenHeaders = []string{
		"Host", "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive",
		"Upgrade", "Te", "Trailer", "Proxy-Authorization", "Proxy-Connection", "Expect",
	}
)

// Scenario is a recorded flow.
type Scenario struct {
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	BaseURL     string    `yaml:"base_url"`
	Requests    []Request `yaml:"requests"`
}

// Request is one recorded request. Path is relative to the base URL and may
// carry a query string.
type Request struct {
	Name         string            `yaml:"name"`
	Method       string            `yaml:"method"`
	Path         string            `yaml:"path"`
	Headers      map[string]string `yaml:"headers"`
	Body         string            `yaml:"body"`
	ExpectStatus int               `yaml:"expect_status"`
}

// Load reads and validates a scenario file. Unknown fields are errors.
func Load(path string) (*Scenario, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s: scenario file larger than %d bytes", path, maxFileBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s: empty scenario", path)
		}
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Validate checks the scenario without sending anything.
func (s *Scenario) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("name is required")
	}
	if len(s.Requests) == 0 {
		return errors.New("requests is empty")
	}
	if len(s.Requests) > MaxRequests {
		return fmt.Errorf("%d requests exceed the limit of %d", len(s.Requests), MaxRequests)
	}
	var errs []error
	for i, r := range s.Requests {
		if err := r.validate(); err != nil {
			errs = append(errs, fmt.Errorf("requests[%d] (%s %s): %w", i, r.Method, r.Path, err))
		}
	}
	return errors.Join(errs...)
}

func (r *Request) validate() error {
	if !slices.Contains(allowedMethods, r.Method) {
		return fmt.Errorf("method %q is not one of %s", r.Method, strings.Join(allowedMethods, ", "))
	}
	if err := validatePath(r.Path); err != nil {
		return err
	}
	for k, v := range r.Headers {
		if !headerName.MatchString(k) {
			return fmt.Errorf("invalid header name %q", k)
		}
		if slices.Contains(forbiddenHeaders, http.CanonicalHeaderKey(k)) {
			return fmt.Errorf("header %q is managed by the client and may not be set", k)
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("header %q contains CR, LF or NUL", k)
		}
	}
	if len(r.Body) > MaxBodyBytes {
		return fmt.Errorf("body larger than %d bytes", MaxBodyBytes)
	}
	if r.ExpectStatus != 0 && (r.ExpectStatus < 100 || r.ExpectStatus > 599) {
		return fmt.Errorf("expect_status %d is not an HTTP status", r.ExpectStatus)
	}
	return nil
}

// validatePath accepts only origin-form paths ("/a/b?c=d") so a scenario can
// never name another host.
func validatePath(p string) error {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return fmt.Errorf("path %q must start with a single '/'", p)
	}
	if strings.ContainsAny(p, "\\#") {
		return fmt.Errorf("path %q must not contain '\\' or '#'", p)
	}
	for _, c := range p {
		if c <= ' ' || c == 0x7f {
			return fmt.Errorf("path %q contains whitespace or control characters", p)
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("path %q is not a plain origin-form path", p)
	}
	return nil
}

// Summary counts what happened during a replay.
type Summary struct {
	Sent       int // requests that received a response
	Failed     int // transport errors (connection refused, timeouts, ...)
	Mismatched int // responses whose status differed from expect_status
}

// OK reports whether every request got the expected response.
func (s Summary) OK() bool { return s.Failed == 0 && s.Mismatched == 0 }

// Run replays s against base (which overrides s.BaseURL when non-empty) using
// g's client. Requests are sent strictly one after another. A guard denial at
// any point aborts the replay with an error wrapping guard.ErrDenied.
func Run(ctx context.Context, g *guard.Guard, s *Scenario, base string, out io.Writer) (Summary, error) {
	var sum Summary
	if err := s.Validate(); err != nil {
		return sum, err
	}
	if base == "" {
		base = s.BaseURL
	}
	if base == "" {
		return sum, errors.New("no base URL: set base_url in the scenario or pass -base")
	}
	bt, err := g.CheckURL(base)
	if err != nil {
		return sum, err
	}
	bu := bt.URL
	if bu.RawQuery != "" || bu.ForceQuery {
		return sum, fmt.Errorf("base URL %q must not have a query", base)
	}
	prefix := strings.TrimSuffix(bu.EscapedPath(), "/")
	origin := bu.Scheme + "://" + bu.Host

	client := g.Client()
	// Recorded flows often log in first; keep cookies between the scenario's
	// requests like the browser that recorded them did. The jar only ever sees
	// responses from guarded targets.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return sum, err
	}
	client.Jar = jar
	fmt.Fprintf(out, "replaying %q: %d request(s) to %s at <= %.1f req/s\n", s.Name, len(s.Requests), origin+prefix, g.RateRPS())
	for i, r := range s.Requests {
		t, err := g.CheckURL(origin + prefix + r.Path)
		if err != nil {
			return sum, err
		}
		if t.URL.Host != bu.Host {
			return sum, fmt.Errorf("requests[%d]: resolved host %q differs from base host %q", i, t.URL.Host, bu.Host)
		}
		req, err := http.NewRequestWithContext(ctx, r.Method, t.URL.String(), strings.NewReader(r.Body))
		if err != nil {
			return sum, fmt.Errorf("requests[%d]: %w", i, err)
		}
		if r.Body == "" {
			req.Body, req.ContentLength = http.NoBody, 0
		}
		for k, v := range r.Headers {
			req.Header.Set(k, v)
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", DefaultUserAgent)
		}

		label := r.Name
		if label == "" {
			label = r.Method + " " + r.Path
		}
		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start).Round(time.Millisecond)
		if err != nil {
			if errors.Is(err, guard.ErrDenied) {
				fmt.Fprintf(out, "%4d  %-32s  DENIED  %v\n", i+1, label, err)
				return sum, fmt.Errorf("requests[%d]: %w", i, err)
			}
			if ctx.Err() != nil {
				return sum, ctx.Err()
			}
			sum.Failed++
			fmt.Fprintf(out, "%4d  %-32s  ERROR   %v\n", i+1, label, err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponseBytes))
		resp.Body.Close()
		sum.Sent++
		note := ""
		if r.ExpectStatus != 0 && resp.StatusCode != r.ExpectStatus {
			sum.Mismatched++
			note = fmt.Sprintf("  (expected %d)", r.ExpectStatus)
		}
		fmt.Fprintf(out, "%4d  %-32s  %d  %s%s\n", i+1, label, resp.StatusCode, elapsed, note)
	}
	fmt.Fprintf(out, "done: %d sent, %d failed, %d unexpected status\n", sum.Sent, sum.Failed, sum.Mismatched)
	return sum, nil
}
