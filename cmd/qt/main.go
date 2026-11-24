// Command qt is the quarantine CLI.
package main

import (
	"os"

	"github.com/Frostykiller3m/Quaarant/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
