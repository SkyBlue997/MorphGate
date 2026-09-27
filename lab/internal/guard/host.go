package guard

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// hostInfo is a normalised URL host.
type hostInfo struct {
	// name is the lower-case ASCII host name; empty when the host is an IP.
	name string
	// addr is set when the host is an IP address (IPv4-mapped IPv6 unmapped).
	addr netip.Addr
	// trick describes a non-canonical spelling of an IP address, e.g.
	// "decimal IPv4 form of 127.0.0.1"; empty for canonical hosts.
	trick string
}

// canonical returns the host as it should appear in a URL.
func (h hostInfo) canonical() string {
	if !h.addr.IsValid() {
		return h.name
	}
	if h.addr.Is6() {
		return "[" + h.addr.String() + "]"
	}
	return h.addr.String()
}

// String returns the host without brackets, for messages.
func (h hostInfo) String() string {
	if h.addr.IsValid() {
		return h.addr.String()
	}
	return h.name
}

// normalizeHost canonicalises a URL host (without port). bracketed is true
// when the URL spelled the host as an IPv6 literal in [brackets].
//
// Steps: IPv6 literals are parsed strictly (no zones) and unmapped; names are
// lower-cased and converted to ASCII with UTS #46 (IDNA lookup profile, STD3
// rules), then one trailing dot is removed. A name that the WHATWG URL
// parser would treat as IPv4 (its last label is numeric, e.g. "2130706433",
// "0x7f.1", "017700000001", "127.1") is decoded the same way browsers do, so
// the guard judges the address the name really denotes.
func normalizeHost(host string, bracketed bool) (hostInfo, error) {
	if host == "" {
		return hostInfo{}, errors.New("empty host")
	}
	if bracketed {
		if strings.Contains(host, "%") {
			return hostInfo{}, errors.New("IPv6 zone identifiers are not allowed")
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() {
			return hostInfo{}, fmt.Errorf("invalid IPv6 literal %q", host)
		}
		if a.Is4In6() {
			u := a.Unmap()
			return hostInfo{addr: u, trick: fmt.Sprintf("IPv4-mapped IPv6 form of %s", u)}, nil
		}
		return hostInfo{addr: a}, nil
	}

	for i := 0; i < len(host); i++ {
		if c := host[i]; c <= ' ' || c == 0x7f || c == '%' || c == '\\' || c == '@' || c == '[' || c == ']' || c == ':' {
			return hostInfo{}, fmt.Errorf("invalid character %q in host", c)
		}
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(host))
	if err != nil {
		return hostInfo{}, fmt.Errorf("invalid host name %q: %v", host, err)
	}
	name := strings.TrimSuffix(ascii, ".")
	if name == "" {
		return hostInfo{}, errors.New("empty host")
	}
	if len(name) > 253 {
		return hostInfo{}, errors.New("host name longer than 253 characters")
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" {
			return hostInfo{}, fmt.Errorf("empty label in host %q", host)
		}
		if len(l) > 63 {
			return hostInfo{}, fmt.Errorf("label longer than 63 characters in host %q", host)
		}
	}

	if endsInNumber(labels) {
		a, err := parseWHATWGIPv4(labels)
		if err != nil {
			return hostInfo{}, fmt.Errorf("host %q looks like an IPv4 address but is not valid: %v", host, err)
		}
		h := hostInfo{addr: a}
		if name != a.String() {
			h.trick = fmt.Sprintf("non-canonical IPv4 form %q of %s", name, a)
		}
		return h, nil
	}
	return hostInfo{name: name}, nil
}

// endsInNumber implements the WHATWG URL "ends in a number" check: the host is
// parsed as IPv4 when its last label is all digits or a valid IPv4 number.
func endsInNumber(labels []string) bool {
	last := labels[len(labels)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, err := parseIPv4Number(last)
	return err == nil
}

// parseIPv4Number parses one part of a WHATWG IPv4 host: decimal, octal with a
// leading 0, or hex with a 0x prefix.
func parseIPv4Number(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty part")
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		s, base = s[2:], 16
		if s == "" {
			return 0, nil
		}
	case len(s) >= 2 && s[0] == '0':
		s, base = s[1:], 8
	}
	for _, c := range s {
		if !isDigitInBase(c, base) {
			return 0, fmt.Errorf("invalid digit %q", c)
		}
	}
	n, err := strconv.ParseUint(s, base, 64)
	if err != nil || n > 0xFFFFFFFF {
		return 0, errors.New("number out of range")
	}
	return n, nil
}

func isDigitInBase(c rune, base int) bool {
	switch base {
	case 8:
		return c >= '0' && c <= '7'
	case 10:
		return c >= '0' && c <= '9'
	default:
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	}
}

// parseWHATWGIPv4 decodes 1-4 dot-separated numbers; the last one fills the
// remaining bytes ("127.1" is 127.0.0.1, "2130706433" is 127.0.0.1).
func parseWHATWGIPv4(labels []string) (netip.Addr, error) {
	if len(labels) > 4 {
		return netip.Addr{}, errors.New("more than four parts")
	}
	nums := make([]uint64, len(labels))
	for i, l := range labels {
		n, err := parseIPv4Number(l)
		if err != nil {
			return netip.Addr{}, err
		}
		nums[i] = n
	}
	last := nums[len(nums)-1]
	if last >= 1<<(8*(5-len(nums))) {
		return netip.Addr{}, errors.New("last part out of range")
	}
	v := uint32(last)
	for i, n := range nums[:len(nums)-1] {
		if n > 255 {
			return netip.Addr{}, errors.New("part out of range")
		}
		v |= uint32(n) << (8 * (3 - i))
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), nil
}
