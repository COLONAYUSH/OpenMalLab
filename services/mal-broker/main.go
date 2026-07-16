// mal-broker is the guard on the worker-to-control boundary. it reads a worker's
// result from stdin (hostile-derived bytes), decodes it under hard caps in a
// process that itself runs jailed (no network, non-root, read-only), and writes
// a validated, typed result to stdout. the orchestrator reads only the broker's
// output and never decodes raw worker bytes. fail-closed: any violation exits
// nonzero, and the node floors to SUSPICIOUS upstream. see DESIGN-AUDIT RC-2.
//
// deliberately dependency-free and self-contained: the trust boundary imports
// nothing it does not absolutely need, not even our own packages.
package main

import (
	"fmt"
	"os"
)

func main() {
	out, err := validate(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mal-broker reject: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintf(os.Stderr, "mal-broker reject: emit: %v\n", err)
		os.Exit(1)
	}
}
