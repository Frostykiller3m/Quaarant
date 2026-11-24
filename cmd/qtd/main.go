// Command qtd is the quarantine daemon. It owns all sandboxes and serves the qt API.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Frostykiller3m/Quaarant/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Get().String("qtd"))
		return
	}
	fmt.Fprintln(os.Stderr, "qtd: not implemented yet (see docs/BUILD_PLAN.md M1-T1)")
	os.Exit(1)
}
