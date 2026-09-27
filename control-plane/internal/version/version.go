// Package version reports the build version of control-plane binaries.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Version is set at build time with
//
//	-ldflags "-X morphgate/control-plane/internal/version.Version=v0.1.0"
var Version = "0.0.0-dev"

// String returns "<name> <version> (<vcs revision>, <go version>)".
func String(name string) string {
	rev := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				rev = s.Value
				if len(rev) > 12 {
					rev = rev[:12]
				}
			}
		}
	}
	return fmt.Sprintf("%s %s (%s, %s)", name, Version, rev, runtime.Version())
}
