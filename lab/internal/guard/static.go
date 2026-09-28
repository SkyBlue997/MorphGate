package guard

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// WithStaticHosts answers the lookup of the listed host names with fixed
// addresses, like an /etc/hosts entry or curl's --resolve: for lab targets
// that have no DNS record, such as a *.test site name served by an Edge on
// loopback. Other names go to the resolver set so far (options apply in
// order), so combine it after WithResolver.
//
// It replaces the lookup only. The name must still be admitted by the
// allowlist before anything is resolved, and every mapped address is
// validated exactly like a DNS answer (Resolve, then the connect-time check),
// so a mapping can never reach a target the allowlist would refuse.
func WithStaticHosts(hosts map[string][]netip.Addr) Option {
	m := make(map[string][]netip.Addr, len(hosts))
	for name, addrs := range hosts {
		key := strings.TrimSuffix(strings.ToLower(name), ".")
		for _, a := range addrs {
			m[key] = append(m[key], a.Unmap())
		}
	}
	return func(g *Guard) { g.resolver = &staticHosts{hosts: m, next: g.resolver} }
}

type staticHosts struct {
	hosts map[string][]netip.Addr
	next  Resolver
}

func (s *staticHosts) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addrs, ok := s.hosts[strings.TrimSuffix(strings.ToLower(host), ".")]
	if !ok {
		if s.next == nil {
			return nil, fmt.Errorf("no address for %q", host)
		}
		return s.next.LookupNetIP(ctx, network, host)
	}
	var out []netip.Addr
	for _, a := range addrs {
		switch {
		case network == "ip4" && !a.Is4(), network == "ip6" && !a.Is6():
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s address mapped for %q", network, host)
	}
	return out, nil
}

// ParseHostMapping parses one "name=address" host mapping for
// WithStaticHosts. The name must be a host name (not an IP literal) and is
// returned lower-case without a trailing dot; the address must be a plain IP
// literal that is not on the never-target list. Whether the name is
// allowlisted and the address acceptable for it is decided by the Guard when
// the name is used, as for any DNS answer.
func ParseHostMapping(s string) (string, netip.Addr, error) {
	name, addr, ok := strings.Cut(s, "=")
	if !ok || name == "" || addr == "" {
		return "", netip.Addr{}, fmt.Errorf("host mapping %q: want name=address", s)
	}
	h, err := normalizeHost(name, false)
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("host mapping %q: %v", s, err)
	}
	if h.addr.IsValid() {
		return "", netip.Addr{}, fmt.Errorf("host mapping %q: %q is an IP address, not a host name", s, name)
	}
	a, err := netip.ParseAddr(addr)
	if err != nil || a.Zone() != "" {
		return "", netip.Addr{}, fmt.Errorf("host mapping %q: %q is not an IP address", s, addr)
	}
	a = a.Unmap()
	if n, never := neverTargetFor(a); never {
		return "", netip.Addr{}, fmt.Errorf("host mapping %q: %s is never a lab target: %s", s, a, n.what)
	}
	return h.name, a, nil
}
