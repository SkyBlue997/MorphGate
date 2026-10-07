package bundle

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	morphgatev1 "morphgate/control-plane/gen/morphgate/v1"
	"morphgate/control-plane/internal/keys"
	"morphgate/control-plane/internal/policy"
	"morphgate/control-plane/internal/sitecfg"
)

const (
	sitesDir     = "../../testdata/sites"
	phase1       = "../../../testdata/phase1"
	fullYAML     = sitesDir + "/valid/full.yaml"
	minimalYAML  = sitesDir + "/valid/minimal.yaml"
	artifactsDir = phase1 + "/artifacts"
)

var buildTime = time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)

func loadSite(t *testing.T, path string) *sitecfg.Site {
	t.Helper()
	s, diags, err := sitecfg.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if sitecfg.HasErrors(diags) {
		t.Fatalf("%s: %v", path, diags)
	}
	return s
}

// writeSite writes a site YAML and its extra files into a temp dir.
func writeSite(t *testing.T, yaml string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(dir, "site.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func ownerTestKey(t *testing.T) (*keys.OwnerKey, *keys.OwnerPublicKey) {
	t.Helper()
	data, err := os.ReadFile(phase1 + "/keys/owner-test.key.json")
	if err != nil {
		t.Fatal(err)
	}
	k, err := keys.ParseOwnerKey(data)
	if err != nil {
		t.Fatal(err)
	}
	pubData, err := os.ReadFile(phase1 + "/keys/owner-test.pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := keys.ParseOwnerPublicKey(pubData)
	if err != nil {
		t.Fatal(err)
	}
	return k, pub
}

// Stand-in IR constructors (the real lowering is WP-G1's compiler).
func lit(b bool) *morphgatev1.Expr {
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Literal{Literal: &morphgatev1.Literal{Value: &morphgatev1.Literal_BoolValue{BoolValue: b}}}}
}

func field(p string) *morphgatev1.Expr {
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Field{Field: p}}
}

func namedList(n string) *morphgatev1.Expr {
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_NamedList{NamedList: n}}
}

func inList(l, r *morphgatev1.Expr) *morphgatev1.Expr {
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_InList{InList: &morphgatev1.Binary{Lhs: l, Rhs: r}}}
}

func ipIn(l, r *morphgatev1.Expr) *morphgatev1.Expr {
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_IpIn{IpIn: &morphgatev1.Binary{Lhs: l, Rhs: r}}}
}

func or(args ...*morphgatev1.Expr) *morphgatev1.Expr {
	return &morphgatev1.Expr{Kind: &morphgatev1.Expr_Or{Or: &morphgatev1.Nary{Args: args}}}
}

// defaultLowering stands in for the compiler: each list the rule uses
// becomes an ip_in() (when the source passes it to ip_in) or an in_list test,
// ORed together; max_steps is a small constant.
func defaultLowering(cr *policy.CheckedRule) *morphgatev1.PolicyExpr {
	args := []*morphgatev1.Expr{lit(false), lit(true)}
	for _, l := range cr.Lists {
		if strings.Contains(cr.Expr, `ip_in(net.ip, list("`+l+`"))`) {
			args = append(args, ipIn(field("net.ip"), namedList(l)))
		} else {
			args = append(args, inList(field("req.path"), namedList(l)))
		}
	}
	return &morphgatev1.PolicyExpr{IrVersion: 1, Root: or(args...), MaxSteps: 42}
}

// withLowering replaces the IR lowering for one test; nil means defaultLowering.
func withLowering(t *testing.T, lower func(*policy.CheckedRule) *morphgatev1.PolicyExpr) {
	t.Helper()
	if lower == nil {
		lower = defaultLowering
	}
	old := ruleProto
	ruleProto = func(cr *policy.CheckedRule) *morphgatev1.CompiledRule {
		pb := cr.Proto()
		pb.IrVersion = 1
		ir, err := proto.MarshalOptions{Deterministic: true}.Marshal(lower(cr))
		if err != nil {
			t.Fatal(err)
		}
		pb.ExprIr = ir
		return pb
	}
	t.Cleanup(func() { ruleProto = old })
}

// testMMDB encodes a minimal, fully valid MaxMind DB (IPv4, one search-tree
// node, no data records) with the given metadata.
func testMMDB(dbType string, buildEpoch uint64) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 0, 1, 0, 0, 1}) // node 0: both 24-bit records = node_count (no data)
	b.Write(make([]byte, 16))         // data section separator
	b.WriteString("\xab\xcd\xefMaxMind.com")
	mmdbMap(&b, []any{
		"binary_format_major_version", uint16(2),
		"binary_format_minor_version", uint16(0),
		"build_epoch", buildEpoch,
		"database_type", dbType,
		"description", []any{"en", "MorphGate test database"},
		"ip_version", uint16(4),
		"languages", []string{"en"},
		"node_count", uint32(1),
		"record_size", uint16(24),
	})
	return b.Bytes()
}

// mmdbCtrl writes a MaxMind DB control byte (types > 7 use the extended form).
func mmdbCtrl(b *bytes.Buffer, typ, size int) {
	if size >= 29 {
		panic("test helper: size too large")
	}
	if typ <= 7 {
		b.WriteByte(byte(typ<<5 | size))
		return
	}
	b.WriteByte(byte(size))
	b.WriteByte(byte(typ - 7))
}

func mmdbValue(b *bytes.Buffer, v any) {
	uintBytes := func(n uint64) []byte {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], n)
		return bytes.TrimLeft(raw[:], "\x00")
	}
	switch v := v.(type) {
	case string:
		mmdbCtrl(b, 2, len(v))
		b.WriteString(v)
	case uint16:
		ub := uintBytes(uint64(v))
		mmdbCtrl(b, 5, len(ub))
		b.Write(ub)
	case uint32:
		ub := uintBytes(uint64(v))
		mmdbCtrl(b, 6, len(ub))
		b.Write(ub)
	case uint64:
		ub := uintBytes(v)
		mmdbCtrl(b, 9, len(ub))
		b.Write(ub)
	case []string:
		mmdbCtrl(b, 11, len(v))
		for _, s := range v {
			mmdbValue(b, s)
		}
	case []any: // map as key/value pairs
		mmdbMap(b, v)
	}
}

func mmdbMap(b *bytes.Buffer, kv []any) {
	mmdbCtrl(b, 7, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		mmdbValue(b, kv[i])
		mmdbValue(b, kv[i+1])
	}
}

type xorshift uint64

func (x *xorshift) next() uint64 {
	*x ^= *x << 13
	*x ^= *x >> 7
	*x ^= *x << 17
	return uint64(*x)
}

func (x *xorshift) mutate(seed []byte) []byte {
	b := bytes.Clone(seed)
	switch x.next() % 4 {
	case 0:
		b = make([]byte, x.next()%512)
		for i := range b {
			b[i] = byte(x.next())
		}
	case 1:
		if len(b) > 0 {
			for range 1 + x.next()%4 {
				b[x.next()%uint64(len(b))] ^= byte(1 << (x.next() % 8))
			}
		}
	case 2:
		if len(b) > 0 {
			b = b[:x.next()%uint64(len(b))]
		}
	default:
		if len(b) > 0 {
			i := x.next() % uint64(len(b))
			b = append(b[:i:i], append([]byte{0x0a, 0xff, 0xff, 0x7f, '[', '"'}, b[i:]...)...)
		}
	}
	return b
}
