// Command qtd is the quarantine daemon. It owns all sandboxes and serves the qt API.
package main

import (
	"os"

	"github.com/Frostykiller3m/Quaarant/internal/daemon"
)

func main() {
	os.Exit(daemon.Main(os.Args[1:], os.Stdout, os.Stderr))
}
