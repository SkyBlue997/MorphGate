// Command mglab is the MorphGate Validation Lab CLI. All traffic it sends goes
// through lab/internal/guard, which only admits the owner's own targets.
package main

import (
	"os"

	"morphgate/lab/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
