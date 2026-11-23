// Command qt is the quarantine CLI.
package main

import (
	"os"

	"github.com/qt-dev/quarantine/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
