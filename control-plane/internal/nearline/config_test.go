package nearline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const exampleConfig = "../../cmd/mg-nearline/mg-nearline.yaml.example"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

var credEnv = env(map[string]string{CredentialsVar: "/run/credentials/mg-nearline.service"})

const minimal = "version: 1\nvalkey: {url: \"redis://127.0.0.1:6379/\"}\nsites: [blog]\n"

func TestSpecExampleParsesToTheDefaults(t *testing.T) {
	cfg, err := LoadConfig(exampleConfig, credEnv)
	if err != nil {
		t.Fatal(err)
	}
	want := DefaultConfig()
	want.Version = 1
	want.Valkey = Valkey{URL: "unix:///run/valkey/valkey.sock", User: "mg-nearline", PasswordFile: "/run/credentials/mg-nearline.service/mg-nearline-valkey"}
	want.Sites = []string{"blog"}
	if cfg.Valkey != want.Valkey || cfg.Stream != want.Stream || cfg.Windows != want.Windows ||
		cfg.Detectors != want.Detectors || cfg.Acceptance != want.Acceptance || cfg.MetricsListen != want.MetricsListen ||
		len(cfg.Sites) != 1 || cfg.Sites[0] != "blog" || cfg.VerdictEvents.VLMain != "" {
		t.Fatalf("example config:\n got %+v\nwant %+v", *cfg, want)
	}
	// The spec's §13.5 block, with vl_main, is accepted as well.
	spec := strings.Replace(readExample(t), "# verdict_events:", "verdict_events:", 1)
	cfg, err = ParseConfig([]byte(spec), credEnv)
	if err != nil || cfg.VerdictEvents.VLMain != "http://127.0.0.1:9428" {
		t.Fatalf("with vl_main: %v %+v", err, cfg)
	}
}

func readExample(t *testing.T) string {
	data, err := os.ReadFile(exampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMinimalConfigUsesDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte(minimal), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	d := DefaultConfig()
	if cfg.Detectors != d.Detectors || cfg.Stream != d.Stream || cfg.Detectors.Scanner.Mode != ModeShadow ||
		time.Duration(cfg.Detectors.SharedToken.TTL) != time.Hour {
		t.Fatalf("defaults: %+v", cfg)
	}
	// A partial detector block keeps the other defaults.
	cfg, err = ParseConfig([]byte(minimal+"detectors:\n  scanner: {mode: enforce}\n"), env(nil))
	if err != nil || cfg.Detectors.Scanner.Mode != ModeEnforce || cfg.Detectors.Scanner.BaitDistinct != 2 || cfg.Detectors.HighRate.Mode != ModeShadow {
		t.Fatalf("partial override: %v %+v", err, cfg)
	}
}

func TestCredentialsDirectoryRule(t *testing.T) {
	base := strings.Replace(minimal, "valkey: {url: \"redis://127.0.0.1:6379/\"}\n", "", 1)
	doc := func(v string) []byte {
		return []byte(base + "valkey: {url: \"redis://127.0.0.1:6379/\", password_file: \"" + v + "\"}\n")
	}
	cfg, err := ParseConfig(doc("${CREDENTIALS_DIRECTORY}/mg-nearline-valkey"), credEnv)
	if err != nil || cfg.Valkey.PasswordFile != "/run/credentials/mg-nearline.service/mg-nearline-valkey" {
		t.Fatalf("expansion: %v %+v", err, cfg)
	}
	for name, c := range map[string]struct {
		val string
		env func(string) string
	}{
		"other variable":     {"${HOME}/x", credEnv},
		"unset":              {"${CREDENTIALS_DIRECTORY}/x", env(nil)},
		"empty":              {"${CREDENTIALS_DIRECTORY}/x", env(map[string]string{CredentialsVar: ""})},
		"mixed":              {"${CREDENTIALS_DIRECTORY}/${USER}", credEnv},
		"lower case":         {"${credentials_directory}/x", credEnv},
		"unterminated":       {"${CREDENTIALS_DIRECTORY/x", credEnv},
		"relative after all": {"x/${CREDENTIALS_DIRECTORY}", credEnv},
	} {
		if _, err := ParseConfig(doc(c.val), c.env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Expansion applies to values only and never re-parses the result.
	odd := env(map[string]string{CredentialsVar: "/run/x\": [1"})
	cfg, err = ParseConfig(doc("${CREDENTIALS_DIRECTORY}/p"), odd)
	if err != nil || cfg.Valkey.PasswordFile != "/run/x\": [1/p" {
		t.Fatalf("YAML-like variable value: %v %+v", err, cfg)
	}
}

func TestConfigRejects(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"version":         strings.Replace(minimal, "version: 1", "version: 2", 1),
		"no version":      strings.Replace(minimal, "version: 1\n", "", 1),
		"unknown key":     minimal + "extra: 1\n",
		"unknown nested":  minimal + "stream: {key: \"mg:ev\", grop: nl}\n",
		"unknown det":     minimal + "detectors: {asn: {mode: shadow}}\n",
		"no sites":        "version: 1\nvalkey: {url: \"redis://127.0.0.1:6379/\"}\n",
		"site all":        "version: 1\nvalkey: {url: \"redis://127.0.0.1:6379/\"}\nsites: [all]\n",
		"site dup":        "version: 1\nvalkey: {url: \"redis://127.0.0.1:6379/\"}\nsites: [a, a]\n",
		"site upper":      "version: 1\nvalkey: {url: \"redis://127.0.0.1:6379/\"}\nsites: [Blog]\n",
		"no url":          "version: 1\nsites: [blog]\n",
		"remote valkey":   "version: 1\nvalkey: {url: \"redis://10.0.0.5:6379/\"}\nsites: [blog]\n",
		"valkey name":     "version: 1\nvalkey: {url: \"redis://localhost:6379/\"}\nsites: [blog]\n",
		"valkey creds":    "version: 1\nvalkey: {url: \"redis://u:p@127.0.0.1:6379/\"}\nsites: [blog]\n",
		"valkey tls":      "version: 1\nvalkey: {url: \"rediss://127.0.0.1:6379/\"}\nsites: [blog]\n",
		"unix relative":   "version: 1\nvalkey: {url: \"unix://run/v.sock\"}\nsites: [blog]\n",
		"password rel":    "version: 1\nvalkey: {url: \"redis://127.0.0.1:6379/\", password_file: x}\nsites: [blog]\n",
		"mode":            minimal + "detectors: {scanner: {mode: block}}\n",
		"risk 0":          minimal + "detectors: {scanner: {risk: 0}}\n",
		"risk 101":        minimal + "detectors: {high_rate: {risk: 101}}\n",
		"ttl text":        minimal + "detectors: {scanner: {ttl: soon}}\n",
		"ttl number":      minimal + "detectors: {scanner: {ttl: 15}}\n",
		"ttl short":       minimal + "detectors: {scanner: {ttl: 500ms}}\n",
		"share":           minimal + "detectors: {scanner: {share_404: 1.5}}\n",
		"ratio 0":         minimal + "detectors: {challenge_abuse: {max_pass_ratio: 0}}\n",
		"minutes":         minimal + "detectors: {high_rate: {minutes: 0}}\n",
		"max keys":        minimal + "windows: {max_keys: 0}\n",
		"metrics public":  minimal + "metrics_listen: \"0.0.0.0:9902\"\n",
		"metrics name":    minimal + "metrics_listen: \"localhost:9902\"\n",
		"vl http public":  minimal + "verdict_events: {vl_main: \"http://203.0.113.9:9428\"}\n",
		"vl http name":    minimal + "verdict_events: {vl_main: \"http://vl.example.com:9428\"}\n",
		"vl query":        minimal + "verdict_events: {vl_main: \"http://127.0.0.1:9428/?x=1\"}\n",
		"vl creds":        minimal + "verdict_events: {vl_main: \"https://u:p@vl.example.com/\"}\n",
		"anchor":          minimal + "a: &x 1\n",
		"two docs":        minimal + "---\nversion: 1\n",
		"batch":           minimal + "stream: {batch: 0}\n",
		"wrong type":      minimal + "windows: {max_keys: lots}\n",
		"stream key ws":   minimal + "stream: {key: \"mg ev\"}\n",
		"acceptance days": minimal + "acceptance: {window_days: 0}\n",
	}
	for name, doc := range cases {
		if _, err := ParseConfig([]byte(doc), credEnv); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, doc := range map[string]string{
		"vl https name":  minimal + "verdict_events: {vl_main: \"https://vl.example.com/base/\"}\n",
		"vl private":     minimal + "verdict_events: {vl_main: \"http://10.0.0.5:9428\"}\n",
		"metrics ula":    minimal + "metrics_listen: \"[fd00::1]:9902\"\n",
		"unix":           "version: 1\nvalkey: {url: \"unix:///run/valkey/valkey.sock\"}\nsites: [blog, shop]\n",
		"v6 loopback db": "version: 1\nvalkey: {url: \"redis://[::1]:6380/3\"}\nsites: [blog]\n",
		"no port":        "version: 1\nvalkey: {url: \"redis://127.0.0.1\"}\nsites: [blog]\n",
	} {
		if _, err := ParseConfig([]byte(doc), credEnv); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValkeyURLAndVLURL(t *testing.T) {
	a, err := ParseValkeyURL("redis://[::1]:6380/3")
	if err != nil || a.Network != "tcp" || a.Address != "[::1]:6380" || a.DB != 3 {
		t.Fatalf("%+v %v", a, err)
	}
	a, err = ParseValkeyURL("unix:///run/valkey/valkey.sock")
	if err != nil || a.Network != "unix" || a.Address != "/run/valkey/valkey.sock" {
		t.Fatalf("%+v %v", a, err)
	}
	u, err := VLInsertURL("http://127.0.0.1:9428")
	if err != nil || u != "http://127.0.0.1:9428/insert/jsonline?_stream_fields=kind,site&_time_field=ts&_msg_field=msg" {
		t.Fatalf("%q %v", u, err)
	}
	u, err = VLInsertURL("https://vl.example.com/base/")
	if err != nil || !strings.HasPrefix(u, "https://vl.example.com/base/insert/jsonline?") {
		t.Fatalf("%q %v", u, err)
	}
}

func TestReadPassword(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for content, want := range map[string]string{"s3cret\n": "s3cret", "s3cret": "s3cret", "s3cret\r\n": "s3cret"} {
		if got, err := ReadPassword(write("p", content)); err != nil || got != want {
			t.Errorf("%q: %q %v", content, got, err)
		}
	}
	for _, content := range []string{"", "\n", "a\nb\n", strings.Repeat("x", 5000)} {
		if _, err := ReadPassword(write("p", content)); err == nil {
			t.Errorf("%q: accepted", content)
		}
	}
	if _, err := ReadPassword(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
	// The error never contains the content.
	_, err := ReadPassword(write("p", "abc\ndef"))
	if err == nil || strings.Contains(err.Error(), "abc") {
		t.Errorf("error: %v", err)
	}
}
