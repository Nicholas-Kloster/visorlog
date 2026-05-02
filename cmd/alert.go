package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/visorlog/alert"
	"github.com/Nicholas-Kloster/visorlog/store"
	"github.com/spf13/cobra"
)

var alertCmd = &cobra.Command{
	Use:   "alert",
	Short: "Check built-in alert rules against current findings",
	Long: `Evaluates all alert rules and prints fired alerts.

Built-in rules:
  new-takeover   — any open TAKEOVER finding
  new-critical   — any open CRITICAL finding
  stale-critical — CRITICAL open >7 days
  stale-high     — HIGH open >14 days`,
	RunE: runAlert,
}

func runAlert(cmd *cobra.Command, args []string) error {
	db, err := store.Open(flagDB)
	if err != nil {
		return err
	}
	defer db.Close()

	alerts, err := alert.Check(db, alert.DefaultRules)
	if err != nil {
		return err
	}

	if len(alerts) == 0 {
		fmt.Println("no alerts")
		return nil
	}

	for _, a := range alerts {
		fmt.Printf("[%s] %s  (id:%d)\n", a.Rule, a.Message, a.Event.ID)
	}
	fmt.Printf("\n%d alert(s) fired\n", len(alerts))
	return nil
}
