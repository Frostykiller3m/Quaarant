// Command qt-agent is the quarantine guest agent. In gvisor sandboxes it is the init process
// ("qt-agent pause"); in Firecracker microVMs (M2) it talks to qtd over vsock.
//
// It is always built static (CGO_ENABLED=0) and may only depend on the standard library and
// internal packages: everything it links ends up inside untrusted guests.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Frostykiller3m/Quaarant/internal/agent"
	"github.com/Frostykiller3m/Quaarant/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Get().String("qt-agent"))
		return
	}
	switch flag.Arg(0) {
	case "pause":
		os.Exit(agent.Pause())
	default:
		fmt.Fprintln(os.Stderr, "usage: qt-agent pause | --version")
		os.Exit(2)
	}
}
