package mgctl

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"morphgate/control-plane/internal/policy"
)

const (
	validDir     = "../../testdata/policies/valid"
	docsExamples = validDir + "/docs06-examples.yaml"
	invalidDir   = "../../testdata/policies/invalid"
)

func run(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCommands(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		code      int
		stdoutHas string
		stderrHas string
	}{
		{"no args", nil, ExitUsage, "", "Usage:"},
		{"help", []string{"help"}, ExitOK, "Usage:", ""},
		{"version", []string{"version"}, ExitOK, "mgctl ", ""},
		{"unknown command", []string{"deploy"}, ExitUsage, "", `unknown command "deploy"`},
		{"policy without subcommand", []string{"policy"}, ExitUsage, "", "expected a subcommand"},
		{"policy unknown subcommand", []string{"policy", "lint"}, ExitUsage, "", `unknown subcommand "lint"`},
		{"check without files", []string{"policy", "check"}, ExitUsage, "", "no policy files"},
		{"check missing file", []string{"policy", "check", "does-not-exist.yaml"}, ExitUsage, "", "does-not-exist.yaml"},
		{"check bad flag", []string{"policy", "check", "-nope", docsExamples}, ExitUsage, "", "flag provided but not defined"},
		{"check bad profile", []string{"policy", "check", "-profile", "akamai", docsExamples}, ExitUsage, "", `unknown upstream profile "akamai"`},
		{"check unchecked profile", []string{"policy", "check", "-profile", "cloudfront", docsExamples}, ExitUsage, "", `upstream profile "cloudfront" has no field-availability table`},
		// Warning counts are not pinned here: the policy package (WP-G1) owns
		// which reads warn; its own tests pin the exact diagnostics.
		{"check valid dir", []string{"policy", "check", validDir}, ExitOK, "ok: ", ""},
		{"check valid with profile", []string{"policy", "check", "-profile", "cloudflare", validDir}, ExitOK, "warning(s)", "is always MISSING under the cloudflare profile"},
		{"check profile conflict", []string{"policy", "check", "-profile", "direct_tls", validDir}, ExitInvalid, "", `cloudflare-site.yaml:4:1: error: profile: file declares profile "cloudflare" but the check was requested for "direct_tls"`},
		{"check invalid file", []string{"policy", "check", invalidDir + "/non-bool-expr.yaml"}, ExitInvalid, "", `rule "returns-int": expr: expression must evaluate to bool, got int`},
		{"check mixed files", []string{"policy", "check", docsExamples, invalidDir + "/unknown-field.yaml"}, ExitInvalid, "", `unknown field "mdoe"`},
		{"check tight cost budget", []string{"policy", "check", "-max-cost", "100", docsExamples}, ExitInvalid, "", "exceeds the limit 100"},
		{"compile invalid", []string{"policy", "compile", invalidDir}, ExitInvalid, "", "error(s)"},
		// Only the dispatch is tested here; the cf / crawler packages (WP-G3)
		// test their own commands.
		{"cf without subcommand", []string{"cf"}, ExitUsage, "", "expected a subcommand: audit | ips"},
		{"cf unknown subcommand", []string{"cf", "purge"}, ExitUsage, "", `unknown subcommand "purge"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := run(tc.args...)
			if code != tc.code {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tc.code, stdout, stderr)
			}
			if !strings.Contains(stdout, tc.stdoutHas) {
				t.Errorf("stdout does not contain %q:\n%s", tc.stdoutHas, stdout)
			}
			if !strings.Contains(stderr, tc.stderrHas) {
				t.Errorf("stderr does not contain %q:\n%s", tc.stderrHas, stderr)
			}
		})
	}
}

func TestCompileJSON(t *testing.T) {
	code, stdout, stderr := run("policy", "compile", docsExamples)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	// ir_version 0 (Phase 0) omits expr_ir and says so; from ir_version 1
	// (WP-G1) every rule carries base64 expr_ir. Either state is valid here.
	irVersion := float64(policy.IRVersion)
	if irVersion == 0 && !strings.Contains(stderr, "expr_ir is omitted") {
		t.Errorf("missing Phase 1 IR note on stderr: %q", stderr)
	}
	var raw []map[string]any
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%s", err, stdout)
	}
	// docs06-examples.yaml belongs to WP-G1 and may grow; look rules up by id.
	byID := make(map[string]map[string]any, len(raw))
	for _, r := range raw {
		id, _ := r["id"].(string)
		byID[id] = r
	}
	if len(raw) == 0 {
		t.Fatalf("got no rules")
	}
	for _, r := range raw {
		ir, hasIR := r["expr_ir"].(string)
		switch {
		case irVersion == 0 && hasIR:
			t.Errorf("rule %v has expr_ir at ir_version 0", r["id"])
		case irVersion > 0 && (!hasIR || ir == ""):
			t.Errorf("rule %v lacks expr_ir at ir_version %v", r["id"], irVersion)
		}
		if r["ir_version"] != irVersion {
			t.Errorf("rule %v ir_version = %v, want %v", r["id"], r["ir_version"], irVersion)
		}
		cost, ok := r["cost"].(map[string]any)
		if !ok || cost["max"].(float64) < cost["min"].(float64) || cost["max"].(float64) == 0 {
			t.Errorf("rule %v has a bad cost estimate: %v", r["id"], r["cost"])
		}
	}
	deny := byID["test-env-default-deny"]
	if deny == nil || deny["locked"] != true || deny["mode"] != "enforce" ||
		deny["rollout_percent"] != float64(100) || !strings.Contains(deny["expr_source"].(string), `list("owner_cidrs")`) {
		t.Errorf("unexpected rule test-env-default-deny: %v", deny)
	}
	high := byID["login-high-risk"]
	if high == nil || high["mode"] != "dry_run" || high["params"].(map[string]any)["type"] != "interactive" {
		t.Errorf("unexpected rule login-high-risk: %v", high)
	}
}

func TestCompileToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "rules.json")
	code, stdout, stderr := run("policy", "compile", "-o", out, validDir)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty with -o, got %q", stdout)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// The rule count belongs to the policy testdata (WP-G1); only require a non-empty array.
	var rules []json.RawMessage
	if err := json.Unmarshal(data, &rules); err != nil || len(rules) == 0 {
		t.Fatalf("bad output file (%d rules): %v", len(rules), err)
	}

	// A failing compile must not touch an existing output file.
	code, _, _ = run("policy", "compile", "-o", out, invalidDir+"/bad-phase.yaml")
	if code != ExitInvalid {
		t.Fatalf("exit %d, want %d", code, ExitInvalid)
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(after, data) {
		t.Error("output file changed after a failed compile")
	}
}
