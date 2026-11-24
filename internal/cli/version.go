package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Frostykiller3m/Quaarant/internal/version"
)

func newVersionCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print qt build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			if asJSON {
				raw, err := info.JSON()
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), string(raw))
				return err
			}
			_, err := fmt.Fprint(cmd.OutOrStdout(), info.Text("qt"))
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print as JSON")
	return cmd
}
