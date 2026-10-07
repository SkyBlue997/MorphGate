package cfaudit

import (
	"regexp"
	"slices"
	"strings"
)

// The expected contents of the MorphGate rules. They mirror the templates in
// adapters/cloudflare/, which live outside the Go module and cannot be
// embedded; TestExpectationsMatchAdapterTemplates compares the two.

// Tier0Headers maps each Tier 0 header of the `mg_signals_v*` Request Header
// Transform Rule to its `set` expression (docs/08 §2.3).
var Tier0Headers = map[string]string{
	"x-mg-cf-tls-version":      "cf.tls_version",
	"x-mg-cf-tls-cipher":       "cf.tls_cipher",
	"x-mg-cf-tls-ciphers-sha1": "cf.tls_ciphers_sha1",
	"x-mg-cf-tls-ext-sha1":     "cf.tls_client_extensions_sha1",
	"x-mg-cf-tls-hello-len":    "to_string(cf.tls_client_hello_length)",
	"x-mg-cf-tls-random":       "cf.tls_client_random",
	"x-mg-cf-http-version":     "http.request.version",
	"x-mg-cf-rtt":              "to_string(cf.timings.client_tcp_rtt_msec)",
	"x-mg-cf-quic-rtt":         "to_string(cf.timings.client_quic_rtt_msec)",
	"x-mg-cf-asn":              "to_string(ip.src.asnum)",
	"x-mg-cf-vbot":             "to_string(cf.client.bot)",
	"x-mg-cf-vbot-cat":         "cf.verified_bot_category",
	"x-mg-cf-hdr-names":        `join(http.request.headers.names, ",")`,
}

// tier0Alternatives are the other accepted spellings (spec §19: which of the
// two cipher-list field names Cloudflare accepts is still to be measured).
var tier0Alternatives = map[string][]string{
	"x-mg-cf-tls-ciphers-sha1": {"cf.tls_client_ciphers_sha1"},
}

// Tier1Headers are removed by the same rule, so only a Snippet or Worker can
// set them (docs/08 §2.3).
var Tier1Headers = []string{"x-mg-cf-priority", "x-mg-cf-accept-encoding", "x-mg-cf-as-org", "x-mg-cf-t1"}

// UpstreamKeyHeader is the optional static secret header (spec §9.2, §17).
const UpstreamKeyHeader = "x-mg-upstream-key"

// UpstreamKeyPlaceholderPrefix starts the placeholder value of the
// adapters/cloudflare/transform-rule.upstream-key.json template.
const UpstreamKeyPlaceholderPrefix = "REPLACE-ME"

// Rule refs and expressions of the MorphGate templates.
const (
	RefBypassMG    = "mg_bypass_mg_paths"
	RefSkipMG      = "mg_skip_mg_paths"
	RefSkipCleared = "mg_skip_cleared"

	BypassMGExpression = `starts_with(http.request.uri.path, "/__mg/") and not starts_with(http.request.uri.path, "/__mg/s/")`
	SkipMGExpression   = `starts_with(http.request.uri.path, "/__mg/")`
	notMGPrefix        = `not starts_with(http.request.uri.path, "/__mg/")`
)

var signalsRefPattern = regexp.MustCompile(`^mg_signals_v\d+$`)

// challengeActions are the Cloudflare actions that show a challenge page.
var challengeActions = []string{"challenge", "js_challenge", "managed_challenge"}

// blockingActions may stop a /__mg/ request before MorphGate sees it.
var blockingActions = []string{"block", "challenge", "js_challenge", "managed_challenge"}

// normalizeExpr collapses whitespace outside string literals to one space
// and drops it after an opening bracket or comma and before a closing
// bracket or comma, so expressions that differ only in spacing compare equal
// (§14.3 check 12). Spaces between words and around operators are kept, so
// "a) or (b" stays splittable at " or ".
func normalizeExpr(s string) string {
	var b strings.Builder
	inString, escaped, pendingSpace := false, false, false
	var last byte // last byte written, 0 before the first
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			b.WriteByte(c)
			last = c
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			pendingSpace = true
			continue
		}
		if pendingSpace {
			if last != 0 && strings.IndexByte("([{,", last) < 0 && strings.IndexByte(")]},", c) < 0 {
				b.WriteByte(' ')
			}
			pendingSpace = false
		}
		if c == '"' {
			inString = true
		}
		b.WriteByte(c)
		last = c
	}
	return b.String()
}

// stripParens removes redundant outer parentheses.
func stripParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' && balancedInside(s[1:len(s)-1]) {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// balancedInside reports whether s has balanced parentheses outside strings
// (so "(a) or (b)" is not treated as one parenthesised term).
func balancedInside(s string) bool {
	depth, inString, escaped := 0, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0 && !inString
}

// splitTopLevel splits s at top-level occurrences of any separator (outside
// parentheses, braces and strings).
func splitTopLevel(s string, seps ...string) []string {
	var parts []string
	depth, inString, escaped, start := 0, false, false, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
			continue
		case '(', '{', '[':
			depth++
			continue
		case ')', '}', ']':
			depth--
			continue
		}
		if depth != 0 {
			continue
		}
		for _, sep := range seps {
			if strings.HasPrefix(s[i:], sep) {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + len(sep)
				i += len(sep) - 1
				break
			}
		}
	}
	return append(parts, strings.TrimSpace(s[start:]))
}

// tokKind classifies the tokens of a Rules language expression.
type tokKind int

const (
	tokWord   tokKind = iota // field or function name, keyword, number, IP literal
	tokString                // "quoted" or r#"raw"# string literal
	tokPunct                 // operator or bracket
)

// token is one lexical unit of an expression; start and end index into it.
type token struct {
	kind       tokKind
	text       string
	start, end int
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '.' || c == '$' || c == ':' || c == '/' || c == '-'
}

// tokenize splits a Rules language expression into words, string literals
// and punctuation, so keywords are recognised in any spacing ("a||b",
// ")or(") and never inside strings. ok is false for an unterminated string
// or unbalanced brackets: callers then treat the expression as unreadable.
func tokenize(s string) (toks []token, ok bool) {
	var open []byte
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '"':
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' {
					j++
				}
			}
			if j >= len(s) {
				return nil, false
			}
			toks = append(toks, token{tokString, s[i : j+1], i, j + 1})
			i = j + 1
		case c == 'r' && (i == 0 || !isWordByte(s[i-1])) && rawStringStart(s[i+1:]):
			hashes := 0
			for s[i+1+hashes] == '#' {
				hashes++
			}
			body := i + 2 + hashes
			closing := `"` + strings.Repeat("#", hashes)
			k := strings.Index(s[body:], closing)
			if k < 0 {
				return nil, false
			}
			end := body + k + len(closing)
			toks = append(toks, token{tokString, s[i:end], i, end})
			i = end
		case isWordByte(c):
			j := i
			for j < len(s) && isWordByte(s[j]) {
				j++
			}
			toks = append(toks, token{tokWord, s[i:j], i, j})
			i = j
		default:
			n := 1
			if i+1 < len(s) {
				switch s[i : i+2] {
				case "&&", "||", "^^", "==", "!=", "<=", ">=":
					n = 2
				}
			}
			switch c {
			case '(', '{', '[':
				open = append(open, c)
			case ')', '}', ']':
				want := map[byte]byte{')': '(', '}': '{', ']': '['}[c]
				if len(open) == 0 || open[len(open)-1] != want {
					return nil, false
				}
				open = open[:len(open)-1]
			}
			toks = append(toks, token{tokPunct, s[i : i+n], i, i + n})
			i += n
		}
	}
	return toks, len(open) == 0
}

// rawStringStart reports whether s (after an `r`) opens a raw string:
// zero or more '#' followed by '"'.
func rawStringStart(s string) bool {
	i := 0
	for i < len(s) && s[i] == '#' {
		i++
	}
	return i < len(s) && s[i] == '"'
}

func keyword(t token, words ...string) bool {
	return t.kind == tokWord && slices.Contains(words, strings.ToLower(t.text))
}

// isDisjunction: "or", "||", "xor", "^^" let a term match without the others.
func isDisjunction(t token) bool {
	return keyword(t, "or", "xor") || t.kind == tokPunct && (t.text == "||" || t.text == "^^")
}

func isConjunction(t token) bool {
	return keyword(t, "and") || t.kind == tokPunct && t.text == "&&"
}

// isNegation: "not" and "!" (but not "!=").
func isNegation(t token) bool {
	return keyword(t, "not") || t.kind == tokPunct && t.text == "!"
}

// operandEnd returns the end (exclusive token index) of the operand of a
// negation whose operand starts at toks[j]: "not" binds tighter than "and",
// "xor" and "or", so the operand ends at the next of those outside brackets,
// or at the bracket that closes the enclosing group.
func operandEnd(toks []token, j int) int {
	depth := 0
	for k := j; k < len(toks); k++ {
		t := toks[k]
		if t.kind == tokPunct {
			switch t.text {
			case "(", "{", "[":
				depth++
			case ")", "}", "]":
				if depth == 0 {
					return k
				}
				depth--
			}
		}
		if depth == 0 && (isConjunction(t) || isDisjunction(t)) {
			return k
		}
	}
	return len(toks)
}

var (
	hostInPattern = regexp.MustCompile(`^http\.host in \{((?:\s*"[^"\\]*"\s*,?)*)\}$`)
	hostEqPattern = regexp.MustCompile(`^http\.host (?:eq|==) "([^"\\]*)"$`)
	quotedPattern = regexp.MustCompile(`"([^"\\]*)"`)
)

// coveredHosts evaluates which hosts a rule expression matches. It
// understands `true`, `http.host in {"a" "b"}`, `http.host eq "a"` and
// disjunctions of those; anything else is reported as not recognised, since
// the audit cannot then prove that every site host is covered. Host literals
// are compared as written: string comparisons in rule expressions are
// case-sensitive and http.host carries the lower-case host name, so
// "Example.com" never matches it.
func coveredHosts(expr string) (all bool, hosts []string, recognised bool) {
	e := stripParens(strings.TrimSpace(expr))
	if e == "true" {
		return true, nil, true
	}
	for _, term := range splitTopLevel(e, " or ", " || ") {
		term = normalizeSpaces(stripParens(term))
		if m := hostInPattern.FindStringSubmatch(term); m != nil {
			for _, q := range quotedPattern.FindAllStringSubmatch(m[1], -1) {
				hosts = append(hosts, q[1])
			}
			continue
		}
		if m := hostEqPattern.FindStringSubmatch(term); m != nil {
			hosts = append(hosts, m[1])
			continue
		}
		return false, nil, false
	}
	return false, hosts, true
}

func normalizeSpaces(s string) string { return strings.Join(strings.Fields(s), " ") }

// missingHosts returns the site hosts an expression does not cover, or
// ok=false when the expression is not in a recognised form.
func missingHosts(expr string, siteHosts []string) (missing []string, ok bool) {
	all, hosts, recognised := coveredHosts(expr)
	if !recognised {
		return nil, false
	}
	if all {
		return nil, true
	}
	for _, h := range siteHosts {
		if !slices.Contains(hosts, h) {
			missing = append(missing, h)
		}
	}
	return missing, true
}

// staticExtensions are file types that never carry a MorphGate challenge or
// per-user HTML.
var staticExtensions = []string{
	"7z", "avif", "bmp", "br", "css", "csv", "eot", "flac", "gif", "gz", "ico", "jpeg", "jpg", "js", "json5",
	"m4a", "map", "mjs", "mp3", "mp4", "ogg", "otf", "pdf", "png", "svg", "svgz", "tar", "tif", "tiff", "ttf",
	"wasm", "wav", "webm", "webp", "woff", "woff2", "xz", "zip", "zst",
}

var (
	extInPattern     = regexp.MustCompile(`http\.request\.uri\.path\.extension\s+in\s*\{([^}]*)\}`)
	extEqPattern     = regexp.MustCompile(`http\.request\.uri\.path\.extension\s*(?:eq|==)\s*"([^"\\]*)"`)
	endsWithPattern  = regexp.MustCompile(`ends_with\(\s*http\.request\.uri\.path\s*,\s*"\.([^"\\]*)"\s*\)`)
	sdkPrefixPattern = regexp.MustCompile(`^starts_with\(\s*http\.request\.uri\.path\s*,\s*"/__mg/s/"\s*\)$`)
)

// restrictedToStatic reports whether a cache rule expression only matches
// static files by extension (§14.3 check 13): it must be a pure conjunction
// (no "or", "||", "xor" or "^^" at any depth, in any spacing), must name at
// least one extension, every extension it names must be a static type, and
// no negation may cover an extension test. Other terms of the conjunction,
// negated or not, only narrow it. The content-hashed SDK path /__mg/s/ also
// counts as static. This is a deliberately conservative reading: an
// unreadable expression is never static, and
// `--ack ttl_override_trap:<ref>=<note>` records reviewed exceptions.
func restrictedToStatic(expr string) bool {
	e := normalizeSpaces(stripParens(strings.TrimSpace(expr)))
	toks, ok := tokenize(e)
	if !ok {
		return false
	}
	if sdkPrefixPattern.MatchString(e) {
		return true
	}
	for i, t := range toks {
		if isDisjunction(t) {
			return false
		}
		if isNegation(t) {
			for _, u := range toks[i+1 : operandEnd(toks, i+1)] {
				if u.kind == tokWord && (u.text == "http.request.uri.path.extension" || u.text == "ends_with") {
					return false
				}
			}
		}
	}
	var exts []string
	for _, m := range extInPattern.FindAllStringSubmatch(e, -1) {
		for _, q := range quotedPattern.FindAllStringSubmatch(m[1], -1) {
			exts = append(exts, q[1])
		}
	}
	for _, m := range extEqPattern.FindAllStringSubmatch(e, -1) {
		exts = append(exts, m[1])
	}
	for _, m := range endsWithPattern.FindAllStringSubmatch(e, -1) {
		exts = append(exts, m[1])
	}
	if len(exts) == 0 {
		return false
	}
	for _, x := range exts {
		if !slices.Contains(staticExtensions, strings.ToLower(x)) {
			return false
		}
	}
	return true
}

// withoutExclusions returns expr with its simple negated terms removed:
// `not starts_with(http.request.uri.path, "/__mg/")` or `!(a eq "b")` only
// exclude what they mention, so a rule that says "everything except /__mg/"
// does not cover /__mg/ (§14.3 check 14). A negation over a compound term
// (`not (a and b)` = `not a or not b`) can still match what it mentions and
// is kept, as is everything when negations nest or the expression is
// unreadable.
func withoutExclusions(expr string) string {
	toks, ok := tokenize(expr)
	if !ok {
		return expr
	}
	type span struct{ from, to int } // byte offsets
	var cut []span
	for i, t := range toks {
		if !isNegation(t) {
			continue
		}
		end := operandEnd(toks, i+1)
		if end == i+1 {
			return expr
		}
		operand := toks[i+1 : end]
		if slices.ContainsFunc(operand, isNegation) {
			return expr // nested negations: keep the literal reading
		}
		if !slices.ContainsFunc(operand, func(u token) bool { return isConjunction(u) || isDisjunction(u) }) {
			cut = append(cut, span{t.start, toks[end-1].end})
		}
	}
	var b strings.Builder
	last := 0
	for _, c := range cut {
		b.WriteString(expr[last:c.from])
		last = c.to
	}
	b.WriteString(expr[last:])
	return b.String()
}

// literalPrefix returns the part of a route pattern before its first
// wildcard, without a trailing slash; "" when that is just "/".
func literalPrefix(pattern string) string {
	if i := strings.IndexAny(pattern, "*?"); i >= 0 {
		pattern = pattern[:i]
	}
	pattern = strings.TrimRight(pattern, "/")
	if pattern == "" {
		return ""
	}
	return pattern
}
