package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var flagDB string

var rootCmd = &cobra.Command{
	Use:   "visorlog",
	Short: "NuClide findings ledger — ECS-normalized, lifecycle-tracked, append-only",
	Long: `VisorLog is the centralized findings store for the NuClide OSINT ecosystem.
All tools (VisorGoose, aimap, ollama-recon) write events here.
Every finding has a lifecycle: open → disclosed → acknowledged → remediated → verified.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagDB, "db", "visorlog.db", "SQLite database path")

	rootCmd.AddCommand(ingestCmd)
	rootCmd.AddCommand(queryCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(alertCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(addCmd)
}

func exitErr(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
