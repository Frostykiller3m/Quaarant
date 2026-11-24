// Package cli implements the qt command-line interface.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// NewRootCommand builds the qt command tree writing to the given streams.
func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	return newRoot(stdout, stderr, &globals{dial: dialSocket})
}

func newRoot(stdout, stderr io.Writer, g *globals) *cobra.Command {
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
	root.PersistentFlags().StringVar(&g.socket, "socket", defaultSocket(), "qtd socket (env QT_SOCKET)")
	root.AddCommand(
		newVersionCommand(), newDoctorCommand(),
		newRunCommand(g), newExecCommand(g), newShellCommand(g), newLsCommand(g), newRmCommand(g),
		newCpCommand(g), newDiffCommand(g), newEventsCommand(g),
	)
	return root
}

// Execute runs qt with os.Args and returns the process exit code.
func Execute() int {
	root := NewRootCommand(os.Stdout, os.Stderr)
	return exitCode(root.Execute(), os.Stderr)
}

// exitCode maps a command error to qt's exit status: a sandboxed command's own status passes
// through silently; anything else is printed and exits 1.
func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var ec exitCodeError
	if errors.As(err, &ec) {
		return ec.code
	}
	fmt.Fprintln(stderr, "qt:", err)
	return 1
}
