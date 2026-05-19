package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Nicholas-Kloster/visorlog/store"
	"github.com/spf13/cobra"
)

var (
	flagQuerySector   string
	flagQuerySeverity string
	flagQueryStatus   string
	flagQueryTag      string
	flagQueryTags     []string
	flagQueryCountry  string
	flagQuerySource   string
	flagQueryTLD      string
	flagQuerySince    string
	flagQueryUntil    string
	flagQueryLimit    int
	flagQueryJSON     bool
	flagQueryFormat   string
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Filter and search findings",
	Example: `  visorlog query --tag TAKEOVER --status open
  visorlog query --sector government --severity critical
  visorlog query --country ID --json`,
	RunE: runQuery,
}

func init() {
	queryCmd.Flags().StringVar(&flagQuerySector, "sector", "", "filter by sector (government, university, healthcare, commercial)")
	queryCmd.Flags().StringVar(&flagQuerySeverity, "severity", "", "filter by severity (critical, high, medium, low)")
	queryCmd.Flags().StringVar(&flagQueryStatus, "status", "", "filter by lifecycle status (open, disclosed, acknowledged, remediated, verified)")
	queryCmd.Flags().StringVar(&flagQueryTag, "tag", "", "filter by tag (TAKEOVER, CVE-2025-63389, CLOUD, RAG)")
	queryCmd.Flags().StringSliceVar(&flagQueryTags, "tags", nil, "filter by multiple tags (any-match), e.g. --tags SETUP-OPEN,DEV-MODE")
	queryCmd.Flags().StringVar(&flagQueryCountry, "country", "", "filter by ISO2 country code")
	queryCmd.Flags().StringVar(&flagQuerySource, "source", "", "filter by source tool (visorgoose, aimap, ollama-recon, etc.)")
	queryCmd.Flags().StringVar(&flagQueryTLD, "tld", "", "filter by TLD (e.g. .go.id)")
	queryCmd.Flags().StringVar(&flagQuerySince, "since", "", "events with timestamp >= this (YYYY-MM-DD or RFC3339)")
	queryCmd.Flags().StringVar(&flagQueryUntil, "until", "", "events with timestamp <= this (YYYY-MM-DD or RFC3339)")
	queryCmd.Flags().IntVar(&flagQueryLimit, "limit", 100, "max results")
	queryCmd.Flags().BoolVar(&flagQueryJSON, "json", false, "output as JSON (shortcut for --format json)")
	queryCmd.Flags().StringVar(&flagQueryFormat, "format", "table", "output format: table, json, csv, md")
}

func runQuery(cmd *cobra.Command, args []string) error {
	db, err := store.Open(flagDB)
	if err != nil {
		return err
	}
	defer db.Close()

	events, err := db.Query(store.QueryFilter{
		Sector:   flagQuerySector,
		Severity: flagQuerySeverity,
		Status:   flagQueryStatus,
		Tag:      flagQueryTag,
		Tags:     flagQueryTags,
		Country:  flagQueryCountry,
		Source:   flagQuerySource,
		TLD:      flagQueryTLD,
		Since:    flagQuerySince,
		Until:    flagQueryUntil,
		Limit:    flagQueryLimit,
	})
	if err != nil {
		return err
	}

	// --json is a shortcut for --format json (kept for backwards compat).
	format := flagQueryFormat
	if flagQueryJSON {
		format = "json"
	}

	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(events)
	case "csv":
		return writeCSV(events)
	case "md":
		return writeMarkdown(events)
	case "table", "":
		return writeTable(events)
	default:
		return fmt.Errorf("unknown format %q (expected: table, json, csv, md)", format)
	}
}

func writeTable(events []*store.Event) error {
	if len(events) == 0 {
		fmt.Println("no results")
		return nil
	}
	fmt.Printf("%-6s  %-8s  %-8s  %-20s  %-35s  %-12s  %s\n",
		"ID", "SEVERITY", "STATUS", "IP", "HOSTNAME", "COUNTRY", "TAGS")
	fmt.Println(strings.Repeat("─", 110))
	for _, e := range events {
		hn := e.HostHostname
		if len(hn) > 34 {
			hn = hn[:31] + "..."
		}
		tags := strings.Join(e.Tags, ",")
		fmt.Printf("%-6d  %-8s  %-8s  %-20s  %-35s  %-12s  %s\n",
			e.ID, e.EventSeverity, e.LifecycleStatus, e.HostIP, hn, e.OrgCountry, tags)
	}
	fmt.Printf("\n%d result(s)\n", len(events))
	return nil
}

func writeCSV(events []*store.Event) error {
	w := csv.NewWriter(os.Stdout)
	defer w.Flush()
	w.Write([]string{
		"id", "timestamp", "severity", "status", "ip", "hostname",
		"org", "country", "sector", "tld", "tags", "source", "vuln_ids", "notes",
	})
	for _, e := range events {
		w.Write([]string{
			fmt.Sprintf("%d", e.ID), e.Timestamp, e.EventSeverity, e.LifecycleStatus,
			e.HostIP, e.HostHostname, e.OrgName, e.OrgCountry, e.Sector, e.TLD,
			strings.Join(e.Tags, "|"), e.Source, strings.Join(e.VulnIDs, "|"), e.Notes,
		})
	}
	return w.Error()
}

func writeMarkdown(events []*store.Event) error {
	fmt.Println("| ID | Severity | Status | IP | Hostname | Country | Tags |")
	fmt.Println("|---:|---|---|---|---|---|---|")
	for _, e := range events {
		tags := strings.Join(e.Tags, ", ")
		fmt.Printf("| %d | %s | %s | %s | %s | %s | %s |\n",
			e.ID, e.EventSeverity, e.LifecycleStatus, e.HostIP, e.HostHostname, e.OrgCountry, tags)
	}
	fmt.Printf("\n_%d result(s)_\n", len(events))
	return nil
}
