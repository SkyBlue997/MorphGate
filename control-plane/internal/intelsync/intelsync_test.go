package intelsync

import (
	"bytes"
	"testing"

	"morphgate/control-plane/internal/cli"
)

func TestStubsReportNotImplemented(t *testing.T) {
	for name, run := range map[string]cli.Handler{"cf ips": RunCFIPs, "crawler": RunCrawler} {
		var errb bytes.Buffer
		if code := run([]string{"sync"}, cli.Env{Stderr: &errb}); code != cli.ExitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, cli.ExitUsage)
		}
		if errb.Len() == 0 {
			t.Errorf("%s: no message", name)
		}
	}
}
