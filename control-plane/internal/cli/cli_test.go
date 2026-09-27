package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestNotImplemented(t *testing.T) {
	var errb bytes.Buffer
	code := NotImplemented(Env{Stderr: &errb}, "cf ips", "WP-G3")
	if code != ExitUsage {
		t.Fatalf("exit %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errb.String(), "mgctl cf ips: not implemented yet (Phase 1 WP-G3") {
		t.Errorf("unexpected message %q", errb.String())
	}
}
