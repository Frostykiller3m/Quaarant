// Package cli implements the qt command-line interface.
package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// NewRootCommand builds the qt command tree writing to the given streams.
func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:   "qt",
		Short: "quarantine: run untrusted code in a disposable, observed sandbox",
		Long: "qt runs untrusted code inside a gVisor sandbox or Firecracker microVM,\n" +
			"records everything it does on the host, and reports what it found.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(newVersionCommand())
	return root
}

// Execute runs qt with os.Args and returns the process exit code.
func Execute() int {
	root := NewRootCommand(os.Stdout, os.Stderr)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "qt:", err)
		return 1
	}
	return 0
}
