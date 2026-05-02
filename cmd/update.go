package cmd

import (
	"fmt"
	"strconv"

	"github.com/Nicholas-Kloster/visorlog/store"
	"github.com/spf13/cobra"
)

var (
	flagUpdateStatus string
	flagUpdateNote   string
)

var updateCmd = &cobra.Command{
	Use:   "update <id>",
	Short: "Update the lifecycle status of a finding",
	Long: `Move a finding through its lifecycle stages.

Stages: open → disclosed → acknowledged → remediated → verified → archived

Example:
  visorlog update 42 --status disclosed --note "emailed kominfo@jatengprov.go.id"
  visorlog update 42 --status remediated`,
	Args: cobra.ExactArgs(1),
	RunE: runUpdate,
}

func init() {
	updateCmd.Flags().StringVar(&flagUpdateStatus, "status", "", "new lifecycle status (required)")
	updateCmd.Flags().StringVar(&flagUpdateNote, "note", "", "optional note to append")
	updateCmd.MarkFlagRequired("status")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid id %q", args[0])
	}

	validStatuses := map[string]bool{
		store.StatusOpen:         true,
		store.StatusDisclosed:    true,
		store.StatusAcknowledged: true,
		store.StatusRemediated:   true,
		store.StatusVerified:     true,
		store.StatusArchived:     true,
	}
	if !validStatuses[flagUpdateStatus] {
		return fmt.Errorf("invalid status %q — valid: open, disclosed, acknowledged, remediated, verified, archived", flagUpdateStatus)
	}

	db, err := store.Open(flagDB)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.UpdateStatus(id, flagUpdateStatus, flagUpdateNote); err != nil {
		return err
	}

	fmt.Printf("updated #%d → %s\n", id, flagUpdateStatus)
	return nil
}
