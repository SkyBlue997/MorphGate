package nearline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

// Valkey for the tests (spec §17 WP-N1): MG_TEST_VALKEY_URL, else a
// throwaway valkey-server (or redis-server) from PATH on a unix socket in a
// temporary directory, else the Valkey tests skip. MG_REQUIRE_VALKEY=1 (set
// in CI) turns the skip into a failure.
//
// The tests run in database testDB, so a development instance's database 0
// is never touched; they delete only the keys they use (mg:ev and the
// verdict keys of random t<hex> sites). They do not run in parallel.

const testDB = 9

var vk struct {
	addr     ValkeyAddr // the server, without a database
	user     string     // admin credentials from MG_TEST_VALKEY_URL, if any
	password string
	skip     string
	spawned  bool // a throwaway server this process started
}

func TestMain(m *testing.M) {
	cleanup := startValkey()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func startValkey() func() {
	if raw := strings.TrimSpace(os.Getenv("MG_TEST_VALKEY_URL")); raw != "" {
		u, err := url.Parse(raw)
		if err != nil {
			vk.skip = "MG_TEST_VALKEY_URL is not a URL"
			return func() {}
		}
		switch u.Scheme {
		case "unix":
			vk.addr = ValkeyAddr{Network: "unix", Address: u.Path}
		default:
			port := u.Port()
			if port == "" {
				port = "6379"
			}
			vk.addr = ValkeyAddr{Network: "tcp", Address: net.JoinHostPort(u.Hostname(), port)}
		}
		if u.User != nil {
			vk.user = u.User.Username()
			vk.password, _ = u.User.Password()
		}
		return func() {}
	}
	bin := ""
	for _, b := range []string{"valkey-server", "redis-server"} {
		if p, err := exec.LookPath(b); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		vk.skip = "no valkey-server (set MG_TEST_VALKEY_URL or install valkey)"
		return func() {}
	}
	dir, err := os.MkdirTemp("", "mgnl")
	if err != nil {
		vk.skip = "cannot create a temporary directory: " + err.Error()
		return func() {}
	}
	sock := filepath.Join(dir, "v.sock")
	cmd := exec.Command(bin, "--port", "0", "--unixsocket", sock, "--unixsocketperm", "700",
		"--save", "", "--appendonly", "no", "--dir", dir)
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		vk.skip = "cannot start " + bin + ": " + err.Error()
		return func() {}
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		os.RemoveAll(dir)
	}
	for range 200 {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			vk.addr = ValkeyAddr{Network: "unix", Address: sock}
			vk.spawned = true
			return stop
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop()
	vk.skip = "valkey-server did not become ready within 5 s"
	return func() {}
}

// fixture is one test's view of the Valkey server.
type fixture struct {
	t     *testing.T
	admin valkey.Client
	site  string
	key   string // stream key
	ctx   context.Context
}

func needValkey(t *testing.T) *fixture {
	t.Helper()
	if vk.skip != "" {
		if os.Getenv("MG_REQUIRE_VALKEY") == "1" {
			t.Fatalf("MG_REQUIRE_VALKEY=1 but %s", vk.skip)
		}
		t.Skip(vk.skip)
	}
	o := ConnOptions{Addr: vk.addr, User: vk.user, Password: vk.password}
	o.Addr.DB = testDB
	c, err := valkey.NewClient(o.clientOption())
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	fx := &fixture{t: t, admin: c, site: "t" + randHex(8), key: "mg:ev", ctx: context.Background()}
	fx.del(fx.key)
	t.Cleanup(func() {
		fx.del(fx.key)
		keys, _ := c.Do(fx.ctx, c.B().Keys().Pattern("mg:v:"+fx.site+":*").Build()).AsStrSlice()
		fx.del(keys...)
		c.Close()
	})
	return fx
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (fx *fixture) do(args ...string) valkey.ValkeyResult {
	return fx.admin.Do(fx.ctx, fx.admin.B().Arbitrary(args[0]).Args(args[1:]...).Build())
}

func (fx *fixture) del(keys ...string) {
	if len(keys) == 0 {
		return
	}
	if err := fx.admin.Do(fx.ctx, fx.admin.B().Del().Key(keys...).Build()).Error(); err != nil {
		fx.t.Fatalf("DEL: %v", err)
	}
}

// xadd appends one entry (field/value pairs) and returns its ID.
func (fx *fixture) xadd(fv ...string) string {
	fx.t.Helper()
	id, err := fx.do(append([]string{"XADD", fx.key, "*"}, fv...)...).ToString()
	if err != nil {
		fx.t.Fatalf("XADD: %v", err)
	}
	return id
}

// connOptions returns options for a worker connection as user (admin when "").
func (fx *fixture) connOptions(user, password string) ConnOptions {
	o := ConnOptions{Addr: vk.addr, User: vk.user, Password: vk.password, ClientName: ClientName}
	if user != "" {
		o.User, o.Password = user, password
	}
	o.Addr.DB = testDB
	return o
}

func (fx *fixture) store(o ConnOptions, consumer string) *Store {
	fx.t.Helper()
	s, err := Dial(fx.ctx, o, fx.key, "nl", consumer)
	if err != nil {
		fx.t.Fatalf("Dial: %v", err)
	}
	fx.t.Cleanup(s.Close)
	return s
}

// config returns a valid configuration for the fixture's site.
func (fx *fixture) config() *Config {
	cfg := DefaultConfig()
	cfg.Version = 1
	cfg.Valkey.URL = "redis://127.0.0.1:6379/"
	cfg.Sites = []string{fx.site}
	cfg.Stream.BlockMs = 100 // keep empty reads short in tests
	if err := cfg.Validate(); err != nil {
		fx.t.Fatalf("config: %v", err)
	}
	return &cfg
}

// fv renders an Entry-like map in the XADD field order of spec §13.1.
func decisionFV(site string, ts int64, over map[string]string) []string {
	base := [][2]string{
		{"v", "2"}, {"kind", "decision"}, {"site", site}, {"ts", strconv.FormatInt(ts, 10)},
		{"rid", randHex(16)}, {"sess", ""}, {"route", "default"}, {"action", "allow"}, {"dry", "0"},
		{"class", "unknown"}, {"score", "30"}, {"ipk", testIPK(1)}, {"pfk", testIPK(1001)}, {"asn", "64500"},
		{"status", "200"}, {"m", "GET"}, {"ph", fmt.Sprintf("%016x", 1)}, {"ct", "h"}, {"bt", "0"},
		{"xs", "0"}, {"tk", "0"}, {"pf", "-"}, {"uf", "chrome"}, {"fam", "4"}, {"ctype", ""},
	}
	out := make([]string, 0, 2*len(base))
	for _, kv := range base {
		v := kv[1]
		if o, ok := over[kv[0]]; ok {
			v = o
		}
		out = append(out, kv[0], v)
	}
	return out
}

// testIPK returns a deterministic 32-hex key.
func testIPK(n int) string { return fmt.Sprintf("%032x", n) }
