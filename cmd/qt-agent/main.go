// Command qt-agent is the quarantine guest agent. It runs inside Firecracker microVMs and talks
// to qtd over vsock.
//
// It is always built static (CGO_ENABLED=0) and may only depend on the standard library and
// internal packages: everything it links ends up inside untrusted guests.
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
		fmt.Println(version.Get().String("qt-agent"))
		return
	}
	fmt.Fprintln(os.Stderr, "qt-agent: not implemented yet (see docs/BUILD_PLAN.md M2-T1)")
	os.Exit(1)
}
