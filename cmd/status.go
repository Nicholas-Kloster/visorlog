package cmd

import (
	"fmt"
	"strings"

	"github.com/Nicholas-Kloster/visorlog/store"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Overview of open findings by sector and severity",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	db, err := store.Open(flagDB)
	if err != nil {
		return err
	}
	defer db.Close()

	counts, err := db.OpenCount()
	if err != nil {
		return err
	}

	stats, err := db.Stats()
	if err != nil {
		return err
	}

	// open summary
	fmt.Println("=== OPEN FINDINGS ===")
	total := 0
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n, ok := counts[sev]; ok && n > 0 {
			bar := strings.Repeat("█", clamp(n, 40))
			fmt.Printf("  %-10s %s %d\n", sev, bar, n)
			total += n
		}
	}
	if total == 0 {
		fmt.Println("  (none)")
	}
	fmt.Println()

	// by sector
	fmt.Println("=== BY SECTOR / SEVERITY / STATUS ===")
	fmt.Printf("%-15s  %-10s  %-12s  %s\n", "SECTOR", "SEVERITY", "STATUS", "COUNT")
	fmt.Println(strings.Repeat("─", 55))
	for _, s := range stats {
		fmt.Printf("%-15s  %-10s  %-12s  %d\n", s.Sector, s.Severity, s.Status, s.Count)
	}

	// stale check
	stale, err := db.StaleCritical(7)
	if err != nil {
		return err
	}
	if len(stale) > 0 {
		fmt.Printf("\n⚠  %d critical/high finding(s) open >7 days — run 'visorlog alert'\n", len(stale))
	}

	return nil
}

func clamp(n, max int) int {
	if n > max {
		return max
	}
	return n
}
