// Command mg-nearline is the MorphGate near-line worker: it consumes the mg:ev
// stream (consumer group nl), runs the v1 detectors and writes risk-raising
// verdicts through the mg_verdict_put script (docs/impl/phase2-spec.md §13).
//
// Phase 2, WP-N1. This stub only reserves the command; it exits non-zero so a
// unit that starts it by mistake fails loudly instead of doing nothing.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "mg-nearline: not implemented yet (Phase 2, WP-N1)")
	os.Exit(1)
}
