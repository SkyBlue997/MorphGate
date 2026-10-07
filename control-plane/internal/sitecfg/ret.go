package sitecfg

import (
	"errors"
	"fmt"
	"strings"
)

// EdgePrefix is the reserved path prefix of the Edge's own endpoints.
const EdgePrefix = "/__mg"

// MaxRetLen bounds a challenge return path (spec §6.4).
const MaxRetLen = 512

// ValidateRet checks a challenge return path (spec §6.4, the Go twin of
// mg-challenge's validate_ret): it starts with "/" but not "//" or "/\", has
// no "\", control characters or "#", is at most 512 bytes, and its path (the
// part before "?") is not in the Edge's /__mg namespace.
func ValidateRet(ret string) error {
	switch {
	case ret == "" || ret[0] != '/':
		return errors.New("must start with /")
	case strings.HasPrefix(ret, "//") || strings.HasPrefix(ret, `/\`):
		return errors.New(`must not start with // or /\ (it would leave the site)`)
	case len(ret) > MaxRetLen:
		return fmt.Errorf("longer than %d bytes", MaxRetLen)
	case strings.ContainsAny(ret, `\#`):
		return errors.New(`must not contain \ or #`)
	case strings.ContainsFunc(ret, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return errors.New("must not contain control characters")
	}
	path, _, _ := strings.Cut(ret, "?")
	if IsReserved(path) {
		return fmt.Errorf("is in the Edge's reserved %s/ namespace", EdgePrefix)
	}
	return nil
}

// IsReserved reports whether path (without query) is in the Edge's /__mg
// namespace as mg_core::paths::is_reserved decides it: the raw path, its RFC
// 3986 view or its Cloudflare view is /__mg or starts with /__mg/.
func IsReserved(path string) bool {
	in := func(p string) bool {
		rest, ok := strings.CutPrefix(p, EdgePrefix)
		return ok && (rest == "" || rest[0] == '/')
	}
	return in(path) || in(rfc3986View(path)) || in(cloudflareView(path))
}

// rfc3986View: percent-encoded unreserved characters decoded, then dot
// segments removed (Cloudflare's "RFC 3986" normalization).
func rfc3986View(path string) string {
	if !strings.ContainsAny(path, "%.") {
		return path
	}
	return removeDotSegments(decodeUnreserved(path))
}

// cloudflareView: unreserved characters decoded, "\" turned into "/", runs of
// "/" merged, dot segments removed (Cloudflare's default normalization).
func cloudflareView(path string) string {
	if !strings.ContainsAny(path, `%.\`) && !strings.Contains(path, "//") {
		return path
	}
	decoded := strings.ReplaceAll(decodeUnreserved(path), `\`, "/")
	return removeDotSegments(mergeSlashes(decoded))
}

func mergeSlashes(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '/' && i > 0 && p[i-1] == '/' {
			continue
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodeUnreserved decodes %XX escapes of RFC 3986 unreserved characters and
// upper-cases the hex digits of every other valid escape.
func decodeUnreserved(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) {
			hi, ok1 := unhex(p[i+1])
			lo, ok2 := unhex(p[i+2])
			if ok1 && ok2 {
				c := hi<<4 | lo
				if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || strings.IndexByte("-._~", c) >= 0 {
					b.WriteByte(c)
				} else {
					b.WriteByte('%')
					b.WriteString(strings.ToUpper(p[i+1 : i+3]))
				}
				i += 2
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

// removeDotSegments is RFC 3986 §5.2.4 for absolute paths; other inputs are
// returned unchanged.
func removeDotSegments(p string) string {
	rest, ok := strings.CutPrefix(p, "/")
	if !ok {
		return p
	}
	var out []string
	trailing := false
	for _, seg := range strings.Split(rest, "/") {
		trailing = seg == "." || seg == ".."
		switch seg {
		case ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	res := "/" + strings.Join(out, "/")
	if trailing && !strings.HasSuffix(res, "/") {
		res += "/"
	}
	return res
}
