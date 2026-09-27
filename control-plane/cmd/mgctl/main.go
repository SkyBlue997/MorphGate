// Command mgctl is the MorphGate operations CLI: policy validation and
// compilation today, Cloudflare zone audit and bundle signing in Phase 1.
package main

import (
	"os"

	"morphgate/control-plane/internal/mgctl"
)

func main() {
	os.Exit(mgctl.Run(os.Args[1:], os.Stdout, os.Stderr))
}
