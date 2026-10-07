package keys

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PseudoKey is the owner-level pseudonymisation key K_pseudo (D-06). Its fmt
// output never includes the key.
type PseudoKey struct {
	ID        string
	Key       []byte
	CreatedAt time.Time
}

// Format implements fmt.Formatter (on the value, so pointers and copies are
// both covered) so that no verb prints the key.
func (k PseudoKey) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "PseudoKey{ID: %q, CreatedAt: %s, Key: <redacted>}", k.ID, formatTime(k.CreatedAt))
}

type pseudoKeyFile struct {
	V         int    `json:"v"`
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Key       string `json:"key"`
	CreatedAt string `json:"created_at"`
}

type upstreamKeysFile struct {
	V         int      `json:"v"`
	Kind      string   `json:"kind"`
	Values    []string `json:"values"`
	CreatedAt string   `json:"created_at"`
}

// GeneratePseudoKey creates pseudo.key.json with id pseudo-<YYYYMMDD>.
func GeneratePseudoKey(date time.Time, rnd io.Reader) ([]byte, error) {
	key, err := readSecret(rnd)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(pseudoKeyFile{V: 1, Kind: KindPseudoKey, ID: "pseudo-" + dateStamp(date),
		Key: encodeKey(key), CreatedAt: formatTime(date)})
}

// ParsePseudoKey parses pseudo.key.json.
func ParsePseudoKey(data []byte) (*PseudoKey, error) {
	var f pseudoKeyFile
	if err := strictDecode(data, &f); err != nil {
		return nil, err
	}
	if err := checkHeader(f.V, f.Kind, KindPseudoKey); err != nil {
		return nil, err
	}
	if !KIDPattern.MatchString(f.ID) {
		return nil, fmt.Errorf("id: %q does not match %s", f.ID, KIDPattern)
	}
	key, err := decodeKey("key", f.Key, SecretSize)
	if err != nil {
		return nil, err
	}
	created, err := parseTime("created_at", f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &PseudoKey{ID: f.ID, Key: key, CreatedAt: created}, nil
}

// GenerateUpstreamKeys creates upstream-keys.json with one new random value.
// With a previous file (rotation) the new value goes first and the previous
// values[0] is kept as the second accepted value.
func GenerateUpstreamKeys(previous []byte, now time.Time, rnd io.Reader) ([]byte, error) {
	var keep []string
	if previous != nil {
		prev, err := parseUpstreamKeys(previous)
		if err != nil {
			return nil, err
		}
		keep = prev.Values[:1]
	}
	v, err := readSecret(rnd)
	if err != nil {
		return nil, err
	}
	value := encodeKey(v)
	if len(keep) > 0 && keep[0] == value {
		return nil, fmt.Errorf("the new upstream value equals the current one")
	}
	return canonicalJSON(upstreamKeysFile{V: 1, Kind: KindUpstreamKeys,
		Values: append([]string{value}, keep...), CreatedAt: formatTime(now)})
}

// UpstreamPrimaryValue returns values[0] of upstream-keys.json: the static
// value of the Cloudflare Tier 0 rule that sets x-mg-upstream-key.
func UpstreamPrimaryValue(data []byte) (string, error) {
	f, err := parseUpstreamKeys(data)
	if err != nil {
		return "", err
	}
	return f.Values[0], nil
}

func parseUpstreamKeys(data []byte) (*upstreamKeysFile, error) {
	var f upstreamKeysFile
	if err := strictDecode(data, &f); err != nil {
		return nil, err
	}
	if err := checkHeader(f.V, f.Kind, KindUpstreamKeys); err != nil {
		return nil, err
	}
	if len(f.Values) < 1 || len(f.Values) > MaxUpstreamValues {
		return nil, fmt.Errorf("values: %d entries, want 1-%d", len(f.Values), MaxUpstreamValues)
	}
	for i, v := range f.Values {
		if _, err := decodeKey(fmt.Sprintf("values[%d]", i), v, SecretSize); err != nil {
			return nil, err
		}
	}
	if len(f.Values) == 2 && f.Values[0] == f.Values[1] {
		return nil, fmt.Errorf("values: duplicate value")
	}
	if _, err := parseTime("created_at", f.CreatedAt); err != nil {
		return nil, err
	}
	return &f, nil
}

// KH is the keyed hash used in Valkey keys (§9.7):
// lower_hex(HMAC-SHA256(key, domain || 0x00 || typ || 0x00 || value))[0..32].
func KH(key []byte, domain, typ, value string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	m.Write([]byte(typ))
	m.Write([]byte{0})
	m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// EntityOf is the "ip" entity of an address (D-24): the IPv4 address itself
// (IPv4-mapped IPv6 counts as IPv4), or the IPv6 /64 network.
func EntityOf(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String()
	}
	return netip.PrefixFrom(ip, 64).Masked().String()
}

// PrefixOf is the aggregation prefix of an address: /24 for IPv4, /48 for IPv6.
func PrefixOf(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is4() {
		return netip.PrefixFrom(ip, 24).Masked().String()
	}
	return netip.PrefixFrom(ip, 48).Masked().String()
}

// Verdict entity types accepted by VerdictKey.
var VerdictTypes = []string{"ip", "prefix", "asn", "session"}

// VerdictKey returns the full Valkey key "mg:v:{site}:{type}:{key}" (§9.7)
// under which the owner stores an EntityVerdict by hand (D-10). site is a
// site id or "all" (shared IP / prefix / ASN verdicts). value is:
//
//   - ip: an IP address; the key uses its ip entity (IPv6: the /64);
//   - prefix: an IP address (its /24 or /48 is used) or that prefix itself;
//   - asn: a decimal ASN, optionally prefixed by "AS"; never 0;
//   - session: a clearance token sub (base64url of 16 bytes).
func VerdictKey(pseudoJSON []byte, site, typ, value string) (string, error) {
	pk, err := ParsePseudoKey(pseudoJSON)
	if err != nil {
		return "", fmt.Errorf("pseudonymisation key: %w", err)
	}
	if site != "all" && !SitePattern.MatchString(site) {
		return "", fmt.Errorf("site %q is neither \"all\" nor a site id", site)
	}
	var key string
	switch typ {
	case "ip":
		ip, err := parseAddr(value)
		if err != nil {
			return "", err
		}
		key = KH(pk.Key, "mg-ent-v1", "ip", EntityOf(ip))
	case "prefix":
		p, err := verdictPrefix(value)
		if err != nil {
			return "", err
		}
		key = KH(pk.Key, "mg-ent-v1", "prefix", p)
	case "asn":
		s := value
		if len(s) > 2 && strings.EqualFold(s[:2], "as") {
			s = s[2:]
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
			return "", fmt.Errorf("asn %q is not a decimal ASN between 1 and 4294967295", value)
		}
		key = s
	case "session":
		if site == "all" {
			return "", fmt.Errorf("session verdicts are per site; --site all is only for ip, prefix and asn")
		}
		if _, err := decodeKey("session", value, 16); err != nil {
			return "", fmt.Errorf("session %q is not a clearance token sub (base64url of 16 bytes)", value)
		}
		key = value
	default:
		return "", fmt.Errorf("type %q is not one of %s", typ, strings.Join(VerdictTypes, ", "))
	}
	return "mg:v:" + site + ":" + typ + ":" + key, nil
}

func parseAddr(s string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q is not an IP address", s)
	}
	return ip, nil
}

// verdictPrefix accepts an address or its canonical /24 (IPv4) or /48 (IPv6).
func verdictPrefix(s string) (string, error) {
	if !strings.Contains(s, "/") {
		ip, err := parseAddr(s)
		if err != nil {
			return "", err
		}
		return PrefixOf(ip), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP prefix", s)
	}
	want := 48
	if p.Addr().Is4() {
		want = 24
	}
	if p.Addr().Is4In6() || p.Bits() != want || p.Masked() != p {
		return "", fmt.Errorf("prefix %q: prefix verdicts are keyed by the canonical /24 (IPv4) or /48 (IPv6) network", s)
	}
	return p.String(), nil
}
