package intelsync

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"morphgate/control-plane/internal/cli"
)

// crawlerMaxChangePct is the D-36 guard: an operator whose CIDR count moves
// by more than this percentage needs --accept-change.
const crawlerMaxChangePct = 50

// parsePrefixesJSON reads the `prefixes_json` format:
// {"creationTime": "...", "prefixes": [{"ipv4Prefix": "..."} | {"ipv6Prefix": "..."}]}.
// Unknown keys (e.g. Google's syncToken) are ignored: this is third-party data
// whose values are validated entry by entry.
func parsePrefixesJSON(body []byte) (entries []string, creationTime string, err error) {
	var doc struct {
		CreationTime *string `json:"creationTime"`
		Prefixes     []struct {
			IPv4 *string `json:"ipv4Prefix"`
			IPv6 *string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("invalid prefixes_json: %w", err)
	}
	if doc.CreationTime != nil {
		creationTime = *doc.CreationTime
		if creationTime != "" {
			if err := checkPrintable("creationTime", creationTime, maxCreationTimeLen); err != nil {
				return nil, "", err
			}
		}
	}
	for i, p := range doc.Prefixes {
		switch {
		case p.IPv4 != nil && p.IPv6 == nil:
			a, err := netip.ParsePrefix(*p.IPv4)
			if err != nil || !a.Addr().Is4() {
				return nil, "", fmt.Errorf("prefixes[%d]: ipv4Prefix %q is not an IPv4 CIDR", i, *p.IPv4)
			}
			entries = append(entries, *p.IPv4)
		case p.IPv6 != nil && p.IPv4 == nil:
			a, err := netip.ParsePrefix(*p.IPv6)
			if err != nil || !a.Addr().Is6() {
				return nil, "", fmt.Errorf("prefixes[%d]: ipv6Prefix %q is not an IPv6 CIDR", i, *p.IPv6)
			}
			entries = append(entries, *p.IPv6)
		default:
			return nil, "", fmt.Errorf("prefixes[%d]: needs exactly one of ipv4Prefix, ipv6Prefix", i)
		}
	}
	return entries, creationTime, nil
}

// parseCIDRText reads the `cidr_text` format: one CIDR (or address) per line;
// blank lines and '#' comments are ignored.
func parseCIDRText(body []byte) ([]string, error) {
	var entries []string
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 4096), 4096)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if i := strings.IndexByte(s, '#'); i >= 0 {
			s = s[:i]
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if strings.ContainsAny(s, " \t") {
			return nil, fmt.Errorf("line %d: more than one entry", line)
		}
		entries = append(entries, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	return entries, nil
}

// normalizeEntries validates fetched entries under the §12.3 rules and
// returns their canonical CIDR text. Any invalid entry fails the whole list.
func normalizeEntries(entries []string, test bool) ([]string, error) {
	rules := crawlerRules
	rules.allowDocumentation = test
	var out []string
	var problems []string
	for _, e := range entries {
		p, err := parseCIDR(e, rules, false)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		out = append(out, p.String())
	}
	if len(problems) > 0 {
		more := ""
		if len(problems) > 5 {
			more = fmt.Sprintf(" (and %d more)", len(problems)-5)
			problems = problems[:5]
		}
		return nil, fmt.Errorf("invalid entries: %s%s", strings.Join(problems, "; "), more)
	}
	return out, nil
}

// fetchOperator downloads, parses and validates every range list of one
// operator and merges them (first occurrence wins the order).
func fetchOperator(ctx context.Context, fc fetchConfig, op SourceOperator, fetchedAt string, test bool) ([]string, []CrawlerSource, error) {
	cidrs := []string{}
	sources := []CrawlerSource{}
	seen := map[string]bool{}
	for _, r := range op.Verify.IPRanges {
		body, err := fc.fetch(ctx, r.URL, "application/json, text/plain;q=0.9, */*;q=0.1", maxCrawlerRegistrySize)
		if err != nil {
			return nil, nil, err
		}
		var entries []string
		var creation string
		switch r.Format {
		case FormatPrefixesJSON:
			entries, creation, err = parsePrefixesJSON(body)
		case FormatCIDRText:
			entries, err = parseCIDRText(body)
		default:
			err = fmt.Errorf("unknown format %q", r.Format)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.URL, err)
		}
		if len(entries) == 0 {
			// An empty list is treated as a failed download: it would
			// silently drop every official range of the operator.
			return nil, nil, fmt.Errorf("%s: no ranges in the response", r.URL)
		}
		norm, err := normalizeEntries(entries, test)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.URL, err)
		}
		for _, c := range norm {
			if !seen[c] {
				seen[c] = true
				cidrs = append(cidrs, c)
			}
		}
		sources = append(sources, CrawlerSource{
			URL: r.URL, Format: r.Format, FetchedAt: fetchedAt, CreationTime: creation,
			SHA256: sha256Hex(body), Stale: false,
		})
	}
	if len(cidrs) > maxCIDRsPerOperator {
		return nil, nil, fmt.Errorf("%d CIDRs, at most %d", len(cidrs), maxCIDRsPerOperator)
	}
	return cidrs, sources, nil
}

// CrawlerOptions are the `mgctl crawler sync` flags (§14.5).
type CrawlerOptions struct {
	Registry     string // source YAML
	Out          string
	Previous     string // default: the existing Out file
	AcceptChange bool
}

// CrawlerResult describes a successful sync.
type CrawlerResult struct {
	Registry *CrawlerRegistry
	Previous *CrawlerRegistry
	Stale    []string // operators whose previous ranges were kept
	Changed  bool
	SHA256   string
	Diff     []OperatorChange
}

// OperatorChange compares one operator with the previous artifact.
type OperatorChange struct {
	ID             string
	New, Removed   bool
	OldCount       int
	NewCount       int
	Added, Dropped []string // CIDR text, sorted
	NewlyCoveredV4 *big.Int // addresses covered now but not before
	NewlyCoveredV6 *big.Int
	PreviousV4     *big.Int // addresses covered before
	PreviousV6     *big.Int
	Violations     []string // D-36 change protection hits
}

// crawlerDiff is the audit record's diff: counts and hashes only.
type crawlerDiff struct {
	SHA256       string             `json:"sha256"`
	Out          string             `json:"out"`
	Test         bool               `json:"test"`
	AcceptChange bool               `json:"accept_change"`
	Operators    []crawlerDiffEntry `json:"operators"`
}

type crawlerDiffEntry struct {
	ID            string `json:"id"`
	CIDRs         int    `json:"cidrs"`
	PreviousCIDRs int    `json:"previous_cidrs"`
	Stale         bool   `json:"stale"`
}

// SyncCrawlers implements `mgctl crawler sync` (§14.5): fetch every
// operator's official ranges, validate each entry (§12.3), fall back to the
// previous ranges of an operator whose download failed (marked stale), apply
// the D-36 change protection and write the artifact atomically.
func SyncCrawlers(ctx context.Context, env cli.Env, fc fetchConfig, opts CrawlerOptions) (*CrawlerResult, error) {
	srcData, err := readLimited(opts.Registry, maxSourceFileSize)
	if err != nil {
		return nil, invalidErr(fmt.Errorf("--registry: %w", err))
	}
	src, err := ParseRegistrySource(opts.Registry, srcData)
	if err != nil {
		return nil, invalidErr(err)
	}

	prevPath, explicitPrev := opts.Previous, opts.Previous != ""
	if !explicitPrev {
		prevPath = opts.Out
	}
	var prev *CrawlerRegistry
	if data, err := readLimited(prevPath, maxCrawlerRegistrySize); err == nil {
		p, perr := ParseCrawlerRegistry(data)
		if perr != nil {
			if !opts.AcceptChange {
				return nil, invalidErr(fmt.Errorf("previous registry %s: %w (fix it, or pass --accept-change to replace it)", prevPath, perr))
			}
			fmt.Fprintf(stderr(env), "warning: ignoring invalid previous registry %s: %v\n", prevPath, perr)
		} else {
			prev = p
		}
	} else if !errors.Is(err, fs.ErrNotExist) || explicitPrev {
		return nil, invalidErr(fmt.Errorf("previous registry: %w", err))
	}
	if prev != nil && prev.Test != src.Test {
		return nil, invalidErr(fmt.Errorf("previous registry %s has test=%v but the source has test=%v", prevPath, prev.Test, src.Test))
	}

	now := envNow(env).UTC().Truncate(time.Second).Format(time.RFC3339)
	next := &CrawlerRegistry{V: 1, Kind: KindCrawlerRegistry, GeneratedAt: now, Test: src.Test}
	res := &CrawlerResult{Registry: next, Previous: prev}
	var failed []string
	for _, sop := range src.Operators {
		op := CrawlerOperator{
			ID: sop.ID, Name: sop.Name, Purpose: sop.Purpose, UATokens: sop.UATokens,
			Verify:  CrawlerVerify{Mode: sop.Verify.Mode, RDNSSuffixes: nonNil(sop.Verify.RDNSSuffixes)},
			CIDRs:   []string{},
			Sources: []CrawlerSource{},
		}
		cidrs, sources, err := fetchOperator(ctx, fc, sop, now, src.Test)
		if err == nil {
			op.CIDRs, op.Sources = cidrs, sources
		} else if old := prev.find(sop.ID); old != nil {
			fmt.Fprintf(stderr(env), "warning: %s: %v; keeping the previous %d CIDR(s), marked stale\n", sop.ID, err, len(old.CIDRs))
			op.CIDRs = append([]string{}, old.CIDRs...)
			for _, s := range old.Sources {
				s.Stale = true
				op.Sources = append(op.Sources, s)
			}
			res.Stale = append(res.Stale, sop.ID)
		} else {
			fmt.Fprintf(stderr(env), "error: %s: %v (no previous ranges to fall back on)\n", sop.ID, err)
			failed = append(failed, sop.ID)
			continue
		}
		next.Operators = append(next.Operators, op)
	}
	if len(failed) > 0 {
		return nil, invalidErr(fmt.Errorf("fetching failed for %s and no previous registry has their ranges", strings.Join(failed, ", ")))
	}
	if err := next.Validate(); err != nil {
		return nil, invalidErr(err)
	}

	if prev != nil {
		res.Diff = compareRegistries(prev, next)
		var violations []string
		for _, d := range res.Diff {
			for _, v := range d.Violations {
				violations = append(violations, d.ID+": "+v)
			}
		}
		if len(violations) > 0 && !opts.AcceptChange {
			printDiff(stderr(env), res.Diff)
			return nil, invalidErr(fmt.Errorf("change protection (D-36): %s; check the ranges and rerun with --accept-change", strings.Join(violations, "; ")))
		}
	}

	// Keep the existing file (and so the bundle's artifact hash) only when
	// nothing changed and it is already the canonical encoding (§12.0), as
	// `cf ips sync` does; a file another tool rewrote is replaced.
	if current, err := readLimited(opts.Out, maxCrawlerRegistrySize); err == nil {
		if cur, perr := ParseCrawlerRegistry(current); perr == nil && sameContent(cur, next) {
			if enc, eerr := cur.Encode(); eerr == nil && bytes.Equal(enc, current) {
				res.Registry = cur
				res.SHA256 = sha256Hex(current)
				return res, nil
			}
		}
	}
	data, err := next.Encode()
	if err != nil {
		return nil, internalErr(err)
	}
	if err := WriteFileAtomic(opts.Out, data, 0o644); err != nil {
		return nil, ioErr(fmt.Errorf("writing %s: %w", opts.Out, err))
	}
	res.Changed = true
	res.SHA256 = sha256Hex(data)

	d := crawlerDiff{SHA256: res.SHA256, Out: opts.Out, Test: next.Test, AcceptChange: opts.AcceptChange, Operators: []crawlerDiffEntry{}}
	for _, op := range next.Operators {
		e := crawlerDiffEntry{ID: op.ID, CIDRs: len(op.CIDRs), Stale: slices.Contains(res.Stale, op.ID)}
		if old := prev.find(op.ID); old != nil {
			e.PreviousCIDRs = len(old.CIDRs)
		}
		d.Operators = append(d.Operators, e)
	}
	if err := audit(env, cli.AuditEvent{
		Action: "crawler.sync", ResourceType: "artifact", ResourceID: "crawler-registry", Diff: d,
	}); err != nil {
		return res, internalErr(fmt.Errorf("audit log: %w", err))
	}
	return res, nil
}

// compareRegistries applies the D-36 change protection per operator: the
// CIDR count may not move by more than 50%, and the addresses newly covered
// in either family may not exceed the addresses the operator covered before.
func compareRegistries(prev, next *CrawlerRegistry) []OperatorChange {
	var out []OperatorChange
	for _, op := range next.Operators {
		c := OperatorChange{ID: op.ID, NewCount: len(op.CIDRs)}
		old := prev.find(op.ID)
		if old == nil {
			c.New = true
			c.Added = sortedCopy(op.CIDRs)
			out = append(out, c)
			continue
		}
		c.OldCount = len(old.CIDRs)
		c.Added, c.Dropped = setDiff(op.CIDRs, old.CIDRs), setDiff(old.CIDRs, op.CIDRs)
		oldV4, oldV6 := intervalsOf(old.CIDRs)
		newV4, newV6 := intervalsOf(op.CIDRs)
		c.PreviousV4, c.PreviousV6 = size(oldV4), size(oldV6)
		c.NewlyCoveredV4 = new(big.Int).Sub(size(newV4), size(intersect(newV4, oldV4)))
		c.NewlyCoveredV6 = new(big.Int).Sub(size(newV6), size(intersect(newV6, oldV6)))
		if c.OldCount > 0 && changeTooLarge(c.OldCount, c.NewCount, crawlerMaxChangePct) {
			c.Violations = append(c.Violations, fmt.Sprintf("CIDR count %d -> %d (more than %d%%)", c.OldCount, c.NewCount, crawlerMaxChangePct))
		}
		if c.NewlyCoveredV4.Cmp(c.PreviousV4) > 0 {
			c.Violations = append(c.Violations, fmt.Sprintf("newly covered IPv4 addresses %s exceed the previous total %s", c.NewlyCoveredV4, c.PreviousV4))
		}
		if c.NewlyCoveredV6.Cmp(c.PreviousV6) > 0 {
			c.Violations = append(c.Violations, fmt.Sprintf("newly covered IPv6 addresses %s exceed the previous total %s", c.NewlyCoveredV6, c.PreviousV6))
		}
		out = append(out, c)
	}
	for _, op := range prev.Operators {
		if next.find(op.ID) == nil {
			out = append(out, OperatorChange{ID: op.ID, Removed: true, OldCount: len(op.CIDRs), Dropped: sortedCopy(op.CIDRs)})
		}
	}
	return out
}

// printDiff lists what changed, at most 20 CIDRs per side and operator.
func printDiff(w io.Writer, diff []OperatorChange) {
	const maxList = 20
	list := func(sign string, s []string) {
		for i, c := range s {
			if i == maxList {
				fmt.Fprintf(w, "    %s ... %d more\n", sign, len(s)-maxList)
				return
			}
			fmt.Fprintf(w, "    %s %s\n", sign, c)
		}
	}
	for _, d := range diff {
		switch {
		case d.New:
			fmt.Fprintf(w, "  %s: new operator, %d CIDR(s)\n", d.ID, d.NewCount)
		case d.Removed:
			fmt.Fprintf(w, "  %s: removed from the source, %d CIDR(s) dropped\n", d.ID, d.OldCount)
		case len(d.Added) == 0 && len(d.Dropped) == 0:
			continue
		default:
			fmt.Fprintf(w, "  %s: %d -> %d CIDR(s)\n", d.ID, d.OldCount, d.NewCount)
			for _, v := range d.Violations {
				fmt.Fprintf(w, "    ! %s\n", v)
			}
		}
		list("+", d.Added)
		list("-", d.Dropped)
	}
}

// setDiff returns the sorted entries of a that are not in b.
func setDiff(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, s := range b {
		in[s] = true
	}
	var out []string
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// interval is an inclusive address range.
type interval struct{ lo, hi *big.Int }

// intervalsOf converts valid CIDRs into merged, sorted IPv4 and IPv6 ranges.
func intervalsOf(cidrs []string) (v4, v6 []interval) {
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				continue // validated before; unreachable
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		lo := new(big.Int).SetBytes(p.Masked().Addr().AsSlice())
		span := new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
		hi := new(big.Int).Add(lo, span)
		hi.Sub(hi, big.NewInt(1))
		if p.Addr().Is4() {
			v4 = append(v4, interval{lo, hi})
		} else {
			v6 = append(v6, interval{lo, hi})
		}
	}
	return merge(v4), merge(v6)
}

func merge(iv []interval) []interval {
	sort.Slice(iv, func(i, j int) bool { return iv[i].lo.Cmp(iv[j].lo) < 0 })
	var out []interval
	for _, x := range iv {
		if n := len(out); n > 0 {
			next := new(big.Int).Add(out[n-1].hi, big.NewInt(1))
			if x.lo.Cmp(next) <= 0 {
				if x.hi.Cmp(out[n-1].hi) > 0 {
					out[n-1].hi = x.hi
				}
				continue
			}
		}
		out = append(out, interval{new(big.Int).Set(x.lo), new(big.Int).Set(x.hi)})
	}
	return out
}

// intersect returns the overlap of two merged interval lists.
func intersect(a, b []interval) []interval {
	var out []interval
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		lo := a[i].lo
		if b[j].lo.Cmp(lo) > 0 {
			lo = b[j].lo
		}
		hi := a[i].hi
		if b[j].hi.Cmp(hi) < 0 {
			hi = b[j].hi
		}
		if lo.Cmp(hi) <= 0 {
			out = append(out, interval{lo, hi})
		}
		if a[i].hi.Cmp(b[j].hi) < 0 {
			i++
		} else {
			j++
		}
	}
	return out
}

// size counts the addresses in a merged interval list.
func size(iv []interval) *big.Int {
	n := new(big.Int)
	for _, x := range iv {
		n.Add(n, new(big.Int).Sub(x.hi, x.lo))
		n.Add(n, big.NewInt(1))
	}
	return n
}
