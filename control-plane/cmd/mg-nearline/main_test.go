package main

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"morphgate/control-plane/internal/nearline"
)

const (
	unitPath    = "../../../deploy/systemd/mg-nearline.service"
	examplePath = "mg-nearline.yaml.example"
	specPath    = "../../../docs/impl/phase2-spec.md"
)

func runCmd(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, func(k string) string { return env[k] })
	return code, out.String(), errb.String()
}

func TestVersionAndUsage(t *testing.T) {
	if code, out, _ := runCmd(t, nil, "--version"); code != 0 || !strings.HasPrefix(out, "mg-nearline ") {
		t.Errorf("--version: %d %q", code, out)
	}
	if code, _, _ := runCmd(t, nil, "--bogus"); code != 2 {
		t.Errorf("unknown flag: exit %d, want 2", code)
	}
	if code, _, _ := runCmd(t, nil, "extra"); code != 2 {
		t.Errorf("extra argument: exit %d, want 2", code)
	}
	if code, _, errs := runCmd(t, nil, "--config", filepath.Join(t.TempDir(), "missing.yaml")); code != 2 || !strings.Contains(errs, "missing.yaml") {
		t.Errorf("missing config: %d %q", code, errs)
	}
}

func TestCheckConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mg-nearline-valkey"), []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	example, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	// The shipped example with a socket that does not exist: the file and
	// the credential are fine, Valkey is not (exit 1).
	sock := filepath.Join(dir, "none.sock")
	cfgText := strings.Replace(string(example), "unix:///run/valkey/valkey.sock", "unix://"+sock, 1)
	cfgPath := filepath.Join(dir, "mg-nearline.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{nearline.CredentialsVar: dir}
	if code, _, errs := runCmd(t, env, "--check-config", "--config", cfgPath); code != 1 || errs == "" {
		t.Errorf("unreachable Valkey: exit %d %q, want 1", code, errs)
	}
	// Without $CREDENTIALS_DIRECTORY the configuration is invalid (exit 2).
	if code, _, errs := runCmd(t, nil, "--check-config", "--config", cfgPath); code != 2 || !strings.Contains(errs, "CREDENTIALS_DIRECTORY") {
		t.Errorf("no credentials directory: exit %d %q", code, errs)
	}
	// A missing credential file is reported without its content.
	if code, _, errs := runCmd(t, map[string]string{nearline.CredentialsVar: t.TempDir()}, "--check-config", "--config", cfgPath); code != 2 || !strings.Contains(errs, "password_file") {
		t.Errorf("missing credential: exit %d %q", code, errs)
	}
}

// unitDirectives returns key -> values of the unit's non-comment lines.
func unitDirectives(t *testing.T) (map[string][]string, string) {
	data, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	d := map[string][]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unit line %q", line)
		}
		d[k] = append(d[k], v)
	}
	return d, string(data)
}

// TestUnitMatchesBinaryAndExample keeps deploy/systemd/mg-nearline.service,
// the example configuration and the binary in step (spec §13.6).
func TestUnitMatchesBinaryAndExample(t *testing.T) {
	d, text := unitDirectives(t)
	for k, want := range map[string]string{
		"DynamicUser":         "yes",
		"SupplementaryGroups": "valkey",
		"IPAddressAllow":      "localhost",
		"IPAddressDeny":       "any",
		"MemoryMax":           "512M",
		"Restart":             "on-failure",
		"LogNamespace":        "morphgate",
		"NoNewPrivileges":     "yes",
		"WantedBy":            "multi-user.target",
	} {
		if len(d[k]) != 1 || d[k][0] != want {
			t.Errorf("%s=%v, want %s", k, d[k], want)
		}
	}
	// ExecStart: the binary's own flags and the default configuration path.
	exec := strings.Fields(d["ExecStart"][0])
	if exec[0] != "/usr/local/bin/mg-nearline" || len(exec) != 3 || exec[1] != "--config" || exec[2] != DefaultConfigPath {
		t.Errorf("ExecStart %q", exec)
	}
	// The credential the unit loads is the file the example reads.
	creds := d["LoadCredentialEncrypted"]
	if len(creds) != 1 {
		t.Fatalf("LoadCredentialEncrypted %v", creds)
	}
	name, src, _ := strings.Cut(creds[0], ":")
	if name != "mg-nearline-valkey" || src != "/etc/credstore.encrypted/mg-nearline-valkey" {
		t.Errorf("credential %q", creds[0])
	}
	cfg, err := nearline.LoadConfig(examplePath, func(k string) string {
		if k == nearline.CredentialsVar {
			return "/run/credentials/mg-nearline.service"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if path.Base(cfg.Valkey.PasswordFile) != name || !strings.HasPrefix(cfg.Valkey.PasswordFile, "/run/credentials/") {
		t.Errorf("password_file %q does not name the credential %q", cfg.Valkey.PasswordFile, name)
	}
	// IPAddressAllow=localhost: the example only talks to loopback.
	if !strings.HasPrefix(cfg.Valkey.URL, "unix://") || !strings.HasPrefix(cfg.MetricsListen, "127.0.0.1:") {
		t.Errorf("example url %q / metrics_listen %q need more than localhost", cfg.Valkey.URL, cfg.MetricsListen)
	}
	if cfg.Valkey.User != "mg-nearline" {
		t.Errorf("example user %q", cfg.Valkey.User)
	}
	for _, det := range nearline.Detectors {
		if cfg.Detectors.Mode(det) != nearline.ModeShadow {
			t.Errorf("example %s mode %q: every detector ships in shadow", det, cfg.Detectors.Mode(det))
		}
	}

	// The ACL line in the unit's header is the spec's §13.6 line.
	spec, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for line := range strings.SplitSeq(string(spec), "\n") {
		if l := strings.TrimSpace(line); strings.HasPrefix(l, "ACL SETUSER mg-nearline ") {
			want = strings.Fields(l)
		}
	}
	var got []string
	in := false
	for line := range strings.SplitSeq(text, "\n") {
		l := strings.TrimSpace(strings.TrimPrefix(line, "#"))
		if strings.HasPrefix(l, "ACL SETUSER mg-nearline ") {
			in = true
		}
		if in {
			if l == "" || strings.HasPrefix(l, "(") {
				break
			}
			got = append(got, strings.Fields(l)...)
		}
	}
	if strings.Join(got, " ") != strings.Join(want, " ") || len(want) == 0 {
		t.Errorf("unit ACL\n %q\nspec\n %q", got, want)
	}
}
