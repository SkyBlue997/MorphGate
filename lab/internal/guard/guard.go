// Package guard keeps all Validation Lab traffic on the owner's own targets.
//
// It is the safety boundary of the lab: every URL is checked against an
// explicit allowlist (CheckURL), every connection re-validates the address it
// actually connects to after DNS resolution (DialContext, which defeats DNS
// rebinding), and the HTTP client it builds re-checks every redirect and caps
// the request rate for the whole process. Anything not explicitly allowed is
// denied.
//
// The guard is one of two layers (docs/07-roadmap.md Phase 0): the lab should
// also run on an isolated network whose egress only reaches the same targets.
package guard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// MaxURLLength bounds the URLs the guard will look at.
const MaxURLLength = 4096

// ErrDenied matches every error returned for a target outside the allowlist.
var ErrDenied = errors.New("lab guard: target denied")

// DeniedError explains why a target was refused.
type DeniedError struct {
	Target string
	Reason string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("lab guard: denied %q: %s", e.Target, e.Reason)
}

// Is makes errors.Is(err, ErrDenied) true for every DeniedError.
func (e *DeniedError) Is(target error) bool { return target == ErrDenied }

func deny(target, format string, args ...any) *DeniedError {
	return &DeniedError{Target: target, Reason: fmt.Sprintf(format, args...)}
}

// MatchKind says which allowlist entry admitted a host.
type MatchKind int

const (
	MatchNone   MatchKind = iota
	MatchHost             // exact entry in allow_hosts
	MatchSuffix           // label-aligned entry in allow_suffixes
	MatchOwner            // owner_targets entry
	MatchIP               // IP literal inside allow_cidrs
)

func (k MatchKind) String() string {
	switch k {
	case MatchHost:
		return "allow_hosts"
	case MatchSuffix:
		return "allow_suffixes"
	case MatchOwner:
		return "owner_targets"
	case MatchIP:
		return "allow_cidrs"
	}
	return "none"
}

// Target is an allowed URL in canonical form.
type Target struct {
	// URL is the canonical URL to use for the request: lower-case ASCII host,
	// canonical IP spelling, no fragment.
	URL    *url.URL
	Host   string // canonical host without brackets or port
	Port   int
	Kind   MatchKind
	Reason string
}

// Resolver is the subset of *net.Resolver the guard needs.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc connects to an already validated "ip:port".
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Option customises a Guard.
type Option func(*Guard)

// WithResolver replaces the DNS resolver (tests, or a lab-specific resolver).
func WithResolver(r Resolver) Option { return func(g *Guard) { g.resolver = r } }

// WithDialFunc replaces the final connect step (tests). The function only
// ever receives IP literals that already passed validation.
func WithDialFunc(d DialFunc) Option { return func(g *Guard) { g.dial = d } }

// Guard enforces the lab target allowlist.
type Guard struct {
	cfg      *compiled
	resolver Resolver
	dial     DialFunc
	limiter  *limiter
}

// Timeouts used by the guard's dialer and client.
const (
	DialTimeout           = 5 * time.Second
	TLSHandshakeTimeout   = 10 * time.Second
	ResponseHeaderTimeout = 15 * time.Second
	RequestTimeout        = 30 * time.Second
	MaxRedirects          = 5
)

// New validates cfg and returns a Guard.
func New(cfg Config, opts ...Option) (*Guard, error) {
	c, err := cfg.compile()
	if err != nil {
		return nil, err
	}
	g := &Guard{cfg: c, resolver: net.DefaultResolver}
	for _, o := range opts {
		o(g)
	}
	g.limiter = newLimiter(c.rps)
	return g, nil
}

// RateRPS returns the effective request rate cap.
func (g *Guard) RateRPS() float64 { return g.cfg.rps }

// CheckURL decides whether raw may be requested. On success it returns the
// canonical target; on failure the error is a *DeniedError.
func (g *Guard) CheckURL(raw string) (*Target, error) {
	if len(raw) > MaxURLLength {
		return nil, deny(raw[:64]+"...", "URL longer than %d bytes", MaxURLLength)
	}
	for _, r := range raw {
		switch {
		case r <= ' ' || r == 0x7f:
			return nil, deny(raw, "whitespace or control character in URL")
		case r == '\\':
			// Browsers treat '\' as '/' in http(s) URLs while Go treats it as
			// data; refuse rather than guess which parser the target uses.
			return nil, deny(raw, "backslash in URL")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, deny(raw, "unparsable URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, deny(raw, "scheme %q is not allowed (only http and https)", u.Scheme)
	}
	if u.Opaque != "" {
		return nil, deny(raw, "opaque URL (expected scheme://host/...)")
	}
	if u.User != nil {
		return nil, deny(raw, "userinfo (user@ or user:pass@) is not allowed in lab URLs")
	}
	if u.Host == "" {
		return nil, deny(raw, "missing host")
	}
	if strings.Contains(authority(raw), "%") {
		return nil, deny(raw, "percent-encoding in the host is not allowed")
	}

	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, deny(raw, "empty port")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, deny(raw, "invalid port %q", p)
		}
		port = n
	}

	h, kind, reason, err := g.matchHost(u.Hostname(), strings.HasPrefix(u.Host, "["))
	if err != nil {
		return nil, deny(raw, "%s", err)
	}

	canon := *u
	canon.Host = h.canonical()
	if u.Port() != "" {
		canon.Host += ":" + strconv.Itoa(port)
	}
	canon.Fragment, canon.RawFragment = "", ""
	return &Target{URL: &canon, Host: h.String(), Port: port, Kind: kind, Reason: reason}, nil
}

// authority returns the raw authority component of an absolute URL.
func authority(raw string) string {
	_, rest, ok := strings.Cut(raw, "//")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// matchHost normalises host and finds the allowlist entry that admits it.
func (g *Guard) matchHost(host string, bracketed bool) (hostInfo, MatchKind, string, error) {
	h, err := normalizeHost(host, bracketed)
	if err != nil {
		return h, MatchNone, "", err
	}
	if h.addr.IsValid() {
		if n, never := neverTargetFor(h.addr); never {
			return h, MatchNone, "", fmt.Errorf("%s is never a lab target: %s", describeIP(h), n.what)
		}
		switch {
		case !g.cfg.inCIDRs(h.addr):
			return h, MatchNone, "", fmt.Errorf("%s is not inside allow_cidrs", describeIP(h))
		}
		return h, MatchIP, fmt.Sprintf("%s is inside allow_cidrs", describeIP(h)), nil
	}
	if _, ok := g.cfg.owners[h.name]; ok {
		return h, MatchOwner, fmt.Sprintf("host %q is a registered owner target", h.name), nil
	}
	if g.cfg.hosts[h.name] {
		return h, MatchHost, fmt.Sprintf("host %q is in allow_hosts", h.name), nil
	}
	if s, ok := g.cfg.suffixMatch(h.name); ok {
		return h, MatchSuffix, fmt.Sprintf("host %q matches allow_suffixes %q", h.name, s), nil
	}
	return h, MatchNone, "", fmt.Errorf("host %q is not in the lab allowlist", h.name)
}

func describeIP(h hostInfo) string {
	if h.trick != "" {
		return h.trick
	}
	return "IP " + h.addr.String()
}

// addrPolicy returns the predicate a connect-time address must satisfy for a
// host admitted by kind, with a description for error messages.
func (g *Guard) addrPolicy(h hostInfo, kind MatchKind) (func(netip.Addr) bool, string) {
	switch kind {
	case MatchIP:
		want := h.addr
		return func(a netip.Addr) bool {
			a = a.Unmap()
			return a == want && !isForbidden(a) && g.cfg.inCIDRs(a)
		}, "the literal address inside allow_cidrs"
	case MatchOwner:
		prefixes := g.cfg.owners[h.name]
		return func(a netip.Addr) bool {
			a = a.Unmap()
			if isForbidden(a) {
				return false
			}
			for _, p := range prefixes {
				if p.Contains(a) {
					return true
				}
			}
			return false
		}, "the owner target's expected_cidrs"
	case MatchHost, MatchSuffix:
		return isLocal, "loopback or private (RFC 1918 / ULA) addresses"
	}
	return func(netip.Addr) bool { return false }, "nothing"
}

// Resolve resolves host (as it appears in a dial address) and validates every
// resolved address. It is used by DialContext and by `mglab check -resolve`.
func (g *Guard) Resolve(ctx context.Context, network, host string) ([]netip.Addr, error) {
	h, kind, _, err := g.matchHost(host, strings.Contains(host, ":"))
	if err != nil {
		return nil, deny(host, "%s", err)
	}
	allowed, desc := g.addrPolicy(h, kind)
	if h.addr.IsValid() {
		if !allowed(h.addr) {
			return nil, deny(host, "%s is not allowed", h.addr)
		}
		return []netip.Addr{h.addr}, nil
	}

	ipNetwork := "ip"
	switch network {
	case "tcp4":
		ipNetwork = "ip4"
	case "tcp6":
		ipNetwork = "ip6"
	}
	addrs, err := g.resolver.LookupNetIP(ctx, ipNetwork, h.name)
	if err != nil {
		return nil, fmt.Errorf("lab guard: resolving %q: %w", h.name, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("lab guard: %q did not resolve to any address", h.name)
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		// One bad answer taints the whole response: a mix of local and public
		// addresses is either a misconfiguration or a rebinding attempt.
		if !allowed(a) {
			return nil, deny(host, "resolved to %s, but %s (%s) may only use %s", a, h.name, kind, desc)
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// DialContext resolves and validates the destination, then connects to the
// validated IP directly so no second, unchecked resolution can happen. The
// socket-level Control hook checks the address once more immediately before
// connect(2).
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, deny(address, "network %q is not allowed", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, deny(address, "invalid address: %v", err)
	}
	h, kind, _, err := g.matchHost(host, strings.Contains(host, ":"))
	if err != nil {
		return nil, deny(address, "%s", err)
	}
	allowed, _ := g.addrPolicy(h, kind)
	addrs, err := g.Resolve(ctx, network, host)
	if err != nil {
		return nil, err
	}

	dial := g.dial
	if dial == nil {
		d := &net.Dialer{Timeout: DialTimeout, Control: controlFor(allowed)}
		dial = d.DialContext
	}
	var errs []error
	for _, a := range addrs {
		conn, err := dial(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		if errors.Is(err, ErrDenied) {
			return nil, err
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// controlFor returns a net.Dialer Control hook that refuses to connect to any
// address outside allowed. It runs after resolution, right before connect(2).
func controlFor(allowed func(netip.Addr) bool) func(network, address string, _ syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return deny(address, "unparsable connect address")
		}
		if !allowed(ap.Addr()) {
			return deny(address, "connect-time address %s is not allowed", ap.Addr())
		}
		return nil
	}
}
