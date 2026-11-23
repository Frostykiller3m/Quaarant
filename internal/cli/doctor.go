package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/qt-dev/quarantine/internal/doctor"
)

// DefaultDataDir is where qtd keeps images and sandboxes.
const DefaultDataDir = "/var/lib/quarantine"

// newDoctorEnv is replaced in tests.
var newDoctorEnv = doctor.SystemEnv

// errNoIsolation makes `qt doctor` exit non-zero when nothing can run.
var errNoIsolation = errors.New("no usable isolation level on this host")

func newDoctorCommand() *cobra.Command {
	var (
		asJSON  bool
		dataDir string
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check this host for KVM, gVisor, cgroup v2, nftables and reflink support",
		Long: "doctor checks what this host can run and recommends an --isolation level.\n" +
			"It exits non-zero when no isolation level is usable.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep := doctor.Run(cmd.Context(), newDoctorEnv(), dataDir)
			var err error
			if asJSON {
				err = rep.WriteJSON(cmd.OutOrStdout())
			} else {
				err = rep.WriteTable(cmd.OutOrStdout())
			}
			if err != nil {
				return err
			}
			if !rep.Usable() {
				return errNoIsolation
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	cmd.Flags().StringVar(&dataDir, "data-dir", DefaultDataDir, "data directory to test for reflink support")
	return cmd
}
