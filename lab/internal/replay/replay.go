// Package replay sends recorded, benign request flows of the owner's own
// application to a guarded base URL.
//
// A scenario is a fixed list of requests (method, path, headers, body) with
// optional expectations on each response. The replayer sends exactly those
// requests, one at a time, through the guard's rate-capped client. It does
// not generate payloads, mutate requests, fuzz, run anything concurrently or
// compute anything from a response: the only per-run input is the scenario's
// declared variables (for example a port), substituted before the first
// request is sent.
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
	"sort"
	"strconv"
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
	MaxPathBytes     = 8 << 10
	MaxDelayMS       = 10000
	MaxVars          = 64
	MaxVarBytes      = 4096
	// MaxExpectations bounds each expectation list or map of a request.
	MaxExpectations = 32
	maxFileBytes    = 8 << 20
)

// DefaultUserAgent is sent when a request does not set User-Agent, so lab
// traffic is identifiable in the owner's logs.
const DefaultUserAgent = "mglab/0 (MorphGate Validation Lab replay)"

var (
	allowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	headerName     = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
	varName        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	// Headers the HTTP client owns (framing, hop-by-hop, routing).
	forbiddenHeaders = []string{
		"Host", "Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive",
		"Upgrade", "Te", "Trailer", "Proxy-Authorization", "Proxy-Connection", "Expect",
	}
)

// Scenario is a recorded flow.
type Scenario struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	BaseURL     string `yaml:"base_url"`
	// Vars declares the variables that path, header values and body may
	// reference as ${name} ("$${" is a literal "${"). The value is the
	// default; null means the variable must be given when replaying
	// (mglab replay -var name=value).
	Vars     map[string]*string `yaml:"vars"`
	Requests []Request          `yaml:"requests"`

	// resolved is set on the copy Resolve returns: its fields are final
	// text, no longer templates.
	resolved bool
}

// Request is one recorded request. Path is relative to the base URL and may
// carry a query string. The expect_* fields are checked against the final
// response (after redirects, which the guard also checks); the "absent"
// expectations also against every redirect before it. Any unmet expectation
// makes the request count as mismatched.
type Request struct {
	Name    string            `yaml:"name"`
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
	// DelayMS waits this long (0-10000 ms) before sending the request.
	DelayMS int `yaml:"delay_ms"`

	ExpectStatus int `yaml:"expect_status"`
	// ExpectStatusIn lists acceptable statuses (instead of ExpectStatus).
	ExpectStatusIn []int `yaml:"expect_status_in"`
	// ExpectHeader maps a response header name to a substring one of its
	// values must contain ("" = the header must be present).
	ExpectHeader map[string]string `yaml:"expect_header"`
	// ExpectHeaderAbsent lists response headers that must not be present,
	// on the response or on any redirect leading to it: "Location" thus
	// means that no redirect happened.
	ExpectHeaderAbsent []string `yaml:"expect_header_absent"`
	// ExpectCookieAbsent lists cookie names no Set-Cookie of the response,
	// or of any redirect leading to it, may set (compared without regard to
	// case, so a variant spelling counts too).
	ExpectCookieAbsent []string `yaml:"expect_cookie_absent"`
	// ExpectBodyContains must occur in the first MaxResponseBytes of the
	// response body.
	ExpectBodyContains string `yaml:"expect_body_contains"`
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
	s, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Parse decodes and validates a scenario document. Unknown fields are
// errors.
func Parse(data []byte) (*Scenario, error) {
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("scenario larger than %d bytes", maxFileBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty scenario")
		}
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks the scenario without sending anything. Variable references
// must name declared variables; the requests are checked with every variable
// set to its default, or to a placeholder when it has none. Resolve checks
// the requests again with the real values.
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
	if s.resolved {
		return s.validateRequests()
	}
	if err := s.validateVars(); err != nil {
		return err
	}
	values := make(map[string]string, len(s.Vars))
	for name, def := range s.Vars {
		if def != nil {
			values[name] = *def
		} else {
			values[name] = "x" // placeholder: only the template is checked here
		}
	}
	_, err := s.expand(values)
	return err
}

func (s *Scenario) validateVars() error {
	if len(s.Vars) > MaxVars {
		return fmt.Errorf("%d vars exceed the limit of %d", len(s.Vars), MaxVars)
	}
	for _, name := range sortedKeys(s.Vars) {
		if !varName.MatchString(name) {
			return fmt.Errorf("vars: invalid variable name %q (want [A-Za-z_][A-Za-z0-9_]*, at most 64 characters)", name)
		}
		if def := s.Vars[name]; def != nil {
			if err := checkVarValue(*def); err != nil {
				return fmt.Errorf("vars.%s: %w", name, err)
			}
		}
	}
	return nil
}

func checkVarValue(v string) error {
	if len(v) > MaxVarBytes {
		return fmt.Errorf("value longer than %d bytes", MaxVarBytes)
	}
	if strings.ContainsAny(v, "\r\n\x00") {
		return errors.New("value contains CR, LF or NUL")
	}
	return nil
}

// Resolve returns a copy of the scenario with every ${name} replaced. values
// overrides the declared defaults; naming an undeclared variable, or leaving
// a variable without a default unset, is an error. The copy is validated with
// the final text (a path that a value turns into another host's URL is
// refused here).
func (s *Scenario) Resolve(values map[string]string) (*Scenario, error) {
	if s.resolved {
		if len(values) > 0 {
			return nil, errors.New("scenario variables are already resolved")
		}
		if err := s.Validate(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := s.validateVars(); err != nil {
		return nil, err
	}
	final := make(map[string]string, len(s.Vars))
	for name, def := range s.Vars {
		if def != nil {
			final[name] = *def
		}
	}
	for _, name := range sortedKeys(values) {
		if _, ok := s.Vars[name]; !ok {
			return nil, fmt.Errorf("variable %q is not declared in the scenario's vars", name)
		}
		if err := checkVarValue(values[name]); err != nil {
			return nil, fmt.Errorf("variable %q: %w", name, err)
		}
		final[name] = values[name]
	}
	for _, name := range sortedKeys(s.Vars) {
		if _, ok := final[name]; !ok {
			return nil, fmt.Errorf("variable %q has no default and was not given (-var %s=...)", name, name)
		}
	}
	out, err := s.expand(final)
	if err != nil {
		return nil, err
	}
	if err := out.Validate(); err != nil {
		return nil, err
	}
	return out, nil
}

// expand substitutes values into a copy of every request and validates each
// resulting request.
func (s *Scenario) expand(values map[string]string) (*Scenario, error) {
	out := &Scenario{Name: s.Name, Description: s.Description, BaseURL: s.BaseURL, resolved: true}
	out.Requests = make([]Request, len(s.Requests))
	var errs []error
	for i, r := range s.Requests {
		x, err := r.expand(values)
		if err == nil {
			err = x.validate()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("requests[%d] (%s %s): %w", i, r.Method, r.Path, err))
		}
		out.Requests[i] = x
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

func (r Request) expand(values map[string]string) (Request, error) {
	var err error
	x := r
	if x.Path, err = substitute(r.Path, values); err != nil {
		return x, fmt.Errorf("path: %w", err)
	}
	if len(r.Headers) > 0 {
		x.Headers = make(map[string]string, len(r.Headers))
		for _, k := range sortedKeys(r.Headers) {
			v, err := substitute(r.Headers[k], values)
			if err != nil {
				return x, fmt.Errorf("header %q: %w", k, err)
			}
			x.Headers[k] = v
		}
	}
	if x.Body, err = substitute(r.Body, values); err != nil {
		return x, fmt.Errorf("body: %w", err)
	}
	return x, nil
}

// substitute replaces ${name} with values[name] in one pass; "$${" is a
// literal "${". Substituted text is never scanned again.
func substitute(t string, values map[string]string) (string, error) {
	if !strings.Contains(t, "${") {
		return t, nil
	}
	var b strings.Builder
	for i := 0; i < len(t); {
		switch {
		case strings.HasPrefix(t[i:], "$${"):
			b.WriteString("${")
			i += 3
		case strings.HasPrefix(t[i:], "${"):
			end := strings.IndexByte(t[i+2:], '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated ${ at byte %d", i)
			}
			name := t[i+2 : i+2+end]
			if !varName.MatchString(name) {
				return "", fmt.Errorf("invalid variable reference ${%s}", name)
			}
			v, ok := values[name]
			if !ok {
				return "", fmt.Errorf("variable %q is not declared in vars", name)
			}
			b.WriteString(v)
			i += 3 + end
		default:
			b.WriteByte(t[i])
			i++
		}
	}
	return b.String(), nil
}

func (r *Request) validate() error {
	if !slices.Contains(allowedMethods, r.Method) {
		return fmt.Errorf("method %q is not one of %s", r.Method, strings.Join(allowedMethods, ", "))
	}
	if err := validatePath(r.Path); err != nil {
		return err
	}
	seen := make(map[string]bool, len(r.Headers))
	for _, k := range sortedKeys(r.Headers) {
		v := r.Headers[k]
		if !headerName.MatchString(k) {
			return fmt.Errorf("invalid header name %q", k)
		}
		ck := http.CanonicalHeaderKey(k)
		if slices.Contains(forbiddenHeaders, ck) {
			return fmt.Errorf("header %q is managed by the client and may not be set", k)
		}
		// Two spellings of one name (e.g. a YAML merge overridden with a
		// different case) would leave the value sent to map iteration order.
		if seen[ck] {
			return fmt.Errorf("header %q is set twice (names are case-insensitive)", ck)
		}
		seen[ck] = true
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("header %q contains CR, LF or NUL", k)
		}
	}
	if len(r.Body) > MaxBodyBytes {
		return fmt.Errorf("body larger than %d bytes", MaxBodyBytes)
	}
	if r.DelayMS < 0 || r.DelayMS > MaxDelayMS {
		return fmt.Errorf("delay_ms %d is not in 0..%d", r.DelayMS, MaxDelayMS)
	}
	return r.validateExpectations()
}

func (r *Request) validateExpectations() error {
	if r.ExpectStatus != 0 && !isStatus(r.ExpectStatus) {
		return fmt.Errorf("expect_status %d is not an HTTP status", r.ExpectStatus)
	}
	if r.ExpectStatusIn != nil {
		if r.ExpectStatus != 0 {
			return errors.New("set expect_status or expect_status_in, not both")
		}
		if len(r.ExpectStatusIn) == 0 || len(r.ExpectStatusIn) > MaxExpectations {
			return fmt.Errorf("expect_status_in must list 1-%d statuses", MaxExpectations)
		}
		for _, c := range r.ExpectStatusIn {
			if !isStatus(c) {
				return fmt.Errorf("expect_status_in: %d is not an HTTP status", c)
			}
		}
	}
	if len(r.ExpectHeader) > MaxExpectations || len(r.ExpectHeaderAbsent) > MaxExpectations ||
		len(r.ExpectCookieAbsent) > MaxExpectations {
		return fmt.Errorf("at most %d entries per expectation", MaxExpectations)
	}
	for k, v := range r.ExpectHeader {
		if !headerName.MatchString(k) {
			return fmt.Errorf("expect_header: invalid header name %q", k)
		}
		if strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("expect_header %q contains CR, LF or NUL", k)
		}
	}
	for _, k := range r.ExpectHeaderAbsent {
		if !headerName.MatchString(k) {
			return fmt.Errorf("expect_header_absent: invalid header name %q", k)
		}
	}
	for _, k := range r.ExpectCookieAbsent {
		if !headerName.MatchString(k) {
			return fmt.Errorf("expect_cookie_absent: invalid cookie name %q", k)
		}
	}
	if len(r.ExpectBodyContains) > MaxVarBytes {
		return fmt.Errorf("expect_body_contains longer than %d bytes", MaxVarBytes)
	}
	return nil
}

func isStatus(c int) bool { return c >= 100 && c <= 599 }

// validatePath accepts only origin-form paths ("/a/b?c=d") so a scenario can
// never name another host.
func validatePath(p string) error {
	if len(p) > MaxPathBytes {
		return fmt.Errorf("path longer than %d bytes", MaxPathBytes)
	}
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

// validateRequests checks already resolved requests.
func (s *Scenario) validateRequests() error {
	var errs []error
	for i, r := range s.Requests {
		if err := r.validate(); err != nil {
			errs = append(errs, fmt.Errorf("requests[%d] (%s %s): %w", i, r.Method, r.Path, err))
		}
	}
	return errors.Join(errs...)
}

// hop is one response of a request's redirect chain.
type hop struct {
	status int
	header http.Header
}

// redirects describes the redirects before the final response ("" if none).
func redirects(hops []hop) string {
	if len(hops) < 2 {
		return ""
	}
	codes := make([]string, len(hops)-1)
	for i, h := range hops[:len(hops)-1] {
		codes[i] = strconv.Itoa(h.status)
	}
	return " (after " + strings.Join(codes, ", ") + ")"
}

// check compares a response with the request's expectations and returns one
// message per unmet expectation. hops holds every response of the redirect
// chain, the final one included: the "absent" expectations apply to each.
func (r *Request) check(status int, header http.Header, body []byte, hops []hop) []string {
	var out []string
	if r.ExpectStatus != 0 && status != r.ExpectStatus {
		out = append(out, fmt.Sprintf("expected %d", r.ExpectStatus))
	}
	if r.ExpectStatusIn != nil && !slices.Contains(r.ExpectStatusIn, status) {
		codes := make([]string, len(r.ExpectStatusIn))
		for i, c := range r.ExpectStatusIn {
			codes[i] = strconv.Itoa(c)
		}
		out = append(out, "expected one of "+strings.Join(codes, ", "))
	}
	for _, name := range sortedKeys(r.ExpectHeader) {
		want := r.ExpectHeader[name]
		values := header.Values(name)
		switch {
		case len(values) == 0:
			out = append(out, fmt.Sprintf("header %s missing", name))
		case !slices.ContainsFunc(values, func(v string) bool { return strings.Contains(v, want) }):
			out = append(out, fmt.Sprintf("header %s does not contain %q", name, want))
		}
	}
	if len(hops) == 0 {
		hops = []hop{{status, header}}
	}
	for _, name := range r.ExpectHeaderAbsent {
		for i, h := range hops {
			if len(h.header.Values(name)) == 0 {
				continue
			}
			if i < len(hops)-1 {
				out = append(out, fmt.Sprintf("header %s present on the %d redirect", name, h.status))
			} else {
				out = append(out, fmt.Sprintf("header %s present", name))
			}
			break
		}
	}
	for _, name := range r.ExpectCookieAbsent {
	cookie:
		for _, h := range hops {
			for _, line := range h.header.Values("Set-Cookie") {
				if strings.EqualFold(setCookieName(line), name) {
					// The value may be a credential: report the name only.
					out = append(out, fmt.Sprintf("Set-Cookie %s received", name))
					break cookie
				}
			}
		}
	}
	if r.ExpectBodyContains != "" && !bytes.Contains(body, []byte(r.ExpectBodyContains)) {
		out = append(out, fmt.Sprintf("body does not contain %q", r.ExpectBodyContains))
	}
	return out
}

// setCookieName returns the cookie name of a Set-Cookie value: the text
// before the first '=' (the whole value when there is none), trimmed. Parsing
// by hand keeps malformed lines, which net/http's parser would drop, in view.
func setCookieName(line string) string {
	name, _, _ := strings.Cut(line, ";")
	name, _, _ = strings.Cut(name, "=")
	return strings.TrimSpace(name)
}

// Summary counts what happened during a replay.
type Summary struct {
	Sent       int // requests that received a response
	Failed     int // transport errors (connection refused, timeouts, ...)
	Mismatched int // responses that did not meet the request's expectations
}

// OK reports whether every request got the expected response.
func (s Summary) OK() bool { return s.Failed == 0 && s.Mismatched == 0 }

// hopsKey carries the response recorder of one scenario request through its
// redirect chain (net/http gives redirect requests the original context).
type hopsKey struct{}

// hopRecorder records the status and headers of every response, including
// redirects the client follows, so the "absent" expectations see all of them.
type hopRecorder struct{ next http.RoundTripper }

func (h hopRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := h.next.RoundTrip(req)
	if err == nil {
		if rec, ok := req.Context().Value(hopsKey{}).(*[]hop); ok {
			*rec = append(*rec, hop{resp.StatusCode, resp.Header.Clone()})
		}
	}
	return resp, err
}

// Run replays s against base (which overrides s.BaseURL when non-empty) using
// g's client. A scenario that still has variables is resolved with their
// defaults first (use Resolve to supply values). Requests are sent strictly
// one after another. A guard denial at any point aborts the replay with an
// error wrapping guard.ErrDenied.
func Run(ctx context.Context, g *guard.Guard, s *Scenario, base string, out io.Writer) (Summary, error) {
	var sum Summary
	s, err := s.Resolve(nil)
	if err != nil {
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
	client.Transport = hopRecorder{next: client.Transport}
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
		if r.DelayMS > 0 {
			timer := time.NewTimer(time.Duration(r.DelayMS) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return sum, ctx.Err()
			case <-timer.C:
			}
		}
		var hops []hop
		rctx := context.WithValue(ctx, hopsKey{}, &hops)
		req, err := http.NewRequestWithContext(rctx, r.Method, t.URL.String(), strings.NewReader(r.Body))
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
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
		resp.Body.Close()
		elapsed := time.Since(start).Round(time.Millisecond)
		if readErr != nil {
			if ctx.Err() != nil {
				return sum, ctx.Err()
			}
			sum.Failed++
			fmt.Fprintf(out, "%4d  %-32s  ERROR   reading the body: %v\n", i+1, label, readErr)
			continue
		}
		sum.Sent++
		note := redirects(hops)
		if unmet := r.check(resp.StatusCode, resp.Header, body, hops); len(unmet) > 0 {
			sum.Mismatched++
			note += "  (" + strings.Join(unmet, "; ") + ")"
		}
		fmt.Fprintf(out, "%4d  %-32s  %d  %s%s\n", i+1, label, resp.StatusCode, elapsed, note)
	}
	fmt.Fprintf(out, "done: %d sent, %d failed, %d unexpected response(s)\n", sum.Sent, sum.Failed, sum.Mismatched)
	return sum, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
