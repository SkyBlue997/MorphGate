package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Reference semantics of the policy extension functions (spec §5.3). The Rust
// IR evaluator must match these exactly; keep them small and free of
// Go-specific behaviour.

// ipIn reports whether ip is contained in any entry of list. Entries are CIDR
// prefixes or single addresses. IPv4-mapped IPv6 addresses and IPv4-mapped
// CIDRs (::ffff:a.b.c.d/n, n >= 96) are compared as IPv4. An ip that is not a
// valid address (including one with an IPv6 zone) is not contained in
// anything. Every entry is validated, even after a match: an unparsable entry
// (or one with a zone) is an error so that a broken named list is never
// silently ignored.
func ipIn(ip string, list []string) (bool, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return false, nil
	}
	addr = addr.Unmap()
	found := false
	for _, entry := range list {
		p, err := parseIPOrPrefix(entry)
		if err != nil {
			return false, err
		}
		if !found && p.Contains(addr) {
			found = true
		}
	}
	return found, nil
}

// parseIPOrPrefix parses "a.b.c.d", "a.b.c.d/n", "::1" or "fc00::/7" into a
// masked prefix. Zones are rejected.
func parseIPOrPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("ip_in: invalid CIDR %q", s)
		}
		if p.Addr().Is4In6() {
			bits := p.Bits() - 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("ip_in: invalid CIDR %q", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), bits)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("ip_in: invalid IP address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// errBadGlob is returned for patterns the matcher refuses.
var errBadGlob = errors.New("glob: empty pattern")

// glob matches s against pattern. Pattern syntax:
//
//   - "*" matches any run of characters except '/'
//   - "**" matches any run of characters including '/'
//   - "?" matches exactly one character except '/'
//
// Every other character matches itself; there are no character classes or
// escapes. Matching is case-sensitive and linear in len(s)*len(pattern).
func glob(s, pattern string) (bool, error) {
	if pattern == "" {
		return false, errBadGlob
	}
	return globMatch([]rune(s), compileGlob(pattern)), nil
}

type globToken struct {
	kind byte // 'c' literal, '?' one, '*' segment star, 'S' double star
	r    rune
}

func compileGlob(pattern string) []globToken {
	var toks []globToken
	rs := []rune(pattern)
	for i := 0; i < len(rs); i++ {
		switch {
		case rs[i] == '*' && i+1 < len(rs) && rs[i+1] == '*':
			// Collapse any run of stars of length >= 2 into one '**'.
			for i+1 < len(rs) && rs[i+1] == '*' {
				i++
			}
			toks = append(toks, globToken{kind: 'S'})
		case rs[i] == '*':
			toks = append(toks, globToken{kind: '*'})
		case rs[i] == '?':
			toks = append(toks, globToken{kind: '?'})
		default:
			toks = append(toks, globToken{kind: 'c', r: rs[i]})
		}
	}
	return toks
}

// globMatch is a dynamic-programming matcher: reach[j] is true when the first
// i characters of s can be matched by the first j tokens.
func globMatch(s []rune, toks []globToken) bool {
	reach := make([]bool, len(toks)+1)
	reach[0] = true
	closeStars := func() {
		for j, t := range toks {
			if reach[j] && (t.kind == '*' || t.kind == 'S') {
				reach[j+1] = true
			}
		}
	}
	closeStars()
	for _, c := range s {
		next := make([]bool, len(toks)+1)
		for j, t := range toks {
			if !reach[j] {
				continue
			}
			switch t.kind {
			case 'c':
				if c == t.r {
					next[j+1] = true
				}
			case '?':
				if c != '/' {
					next[j+1] = true
				}
			case '*':
				if c != '/' {
					next[j] = true
				}
			case 'S':
				next[j] = true
			}
		}
		reach = next
		closeStars()
	}
	return reach[len(toks)]
}
