// Command qt-agent is the quarantine guest agent. In gvisor sandboxes it is the init process
// ("qt-agent pause"). In Firecracker microVMs it is PID 1 (stage 1 from qtd's initramfs as
// /init, then "init2" in the sandbox's root), and its child "serve" talks to qtd over vsock;
// "spawn" drops privileges before running a command.
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
	// The kernel runs the initramfs /init as PID 1 with no arguments.
	if os.Getpid() == 1 && len(os.Args) == 1 {
		os.Exit(agent.InitStage1())
	}
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Get().String("qt-agent"))
		return
	}
	switch flag.Arg(0) {
	case "pause":
		os.Exit(agent.Pause())
	case "init2":
		os.Exit(agent.InitStage2())
	case "serve":
		os.Exit(agent.Serve())
	case "spawn":
		os.Exit(agent.Spawn())
	default:
		fmt.Fprintln(os.Stderr, "usage: qt-agent pause | init2 | serve | spawn | --version")
		os.Exit(2)
	}
}
