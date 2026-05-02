package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Nicholas-Kloster/visorlog/store"
	"github.com/spf13/cobra"
)

var (
	flagReportOut    string
	flagReportStatus string
	flagReportSector string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate Markdown report from the findings store",
	RunE:  runReport,
}

func init() {
	reportCmd.Flags().StringVar(&flagReportOut, "out", "visorlog-report.md", "output file")
	reportCmd.Flags().StringVar(&flagReportStatus, "status", "open", "filter by lifecycle status (empty = all)")
	reportCmd.Flags().StringVar(&flagReportSector, "sector", "", "filter by sector")
}

func runReport(cmd *cobra.Command, args []string) error {
	db, err := store.Open(flagDB)
	if err != nil {
		return err
	}
	defer db.Close()

	events, err := db.Query(store.QueryFilter{
		Status: flagReportStatus,
		Sector: flagReportSector,
		Limit:  10000,
	})
	if err != nil {
		return err
	}

	var sb strings.Builder
	sb.WriteString("# VisorLog Findings Report\n\n")
	sb.WriteString(fmt.Sprintf("_Generated: %s_\n\n", time.Now().UTC().Format("2006-01-02 15:04 UTC")))
	if flagReportStatus != "" {
		sb.WriteString(fmt.Sprintf("**Status filter:** `%s`", flagReportStatus))
	}
	if flagReportSector != "" {
		sb.WriteString(fmt.Sprintf("  **Sector:** `%s`", flagReportSector))
	}
	sb.WriteString("\n\n---\n\n")

	sb.WriteString(fmt.Sprintf("**Total findings:** %d\n\n", len(events)))

	sb.WriteString("| ID | Severity | Status | IP | Hostname | Country | Sector | Tags |\n")
	sb.WriteString("|-----|----------|--------|-----|----------|---------|--------|------|\n")

	for _, e := range events {
		hn := e.HostHostname
		if hn == "" {
			hn = "—"
		}
		tags := strings.Join(e.Tags, ", ")
		sb.WriteString(fmt.Sprintf("| %d | %s | %s | `%s` | %s | %s | %s | %s |\n",
			e.ID, e.EventSeverity, e.LifecycleStatus,
			e.HostIP, hn, e.OrgCountry, e.Sector, tags))
	}

	if err := os.WriteFile(flagReportOut, []byte(sb.String()), 0644); err != nil {
		return err
	}
	fmt.Printf("[report] %d findings → %s\n", len(events), flagReportOut)
	return nil
}
