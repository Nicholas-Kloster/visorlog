package cmd

import (
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
	flagQueryCountry  string
	flagQuerySource   string
	flagQueryTLD      string
	flagQueryLimit    int
	flagQueryJSON     bool
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
	queryCmd.Flags().StringVar(&flagQueryCountry, "country", "", "filter by ISO2 country code")
	queryCmd.Flags().StringVar(&flagQuerySource, "source", "", "filter by source tool (visorgoose, aimap, ollama-recon)")
	queryCmd.Flags().StringVar(&flagQueryTLD, "tld", "", "filter by TLD (e.g. .go.id)")
	queryCmd.Flags().IntVar(&flagQueryLimit, "limit", 100, "max results")
	queryCmd.Flags().BoolVar(&flagQueryJSON, "json", false, "output as JSON")
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
		Country:  flagQueryCountry,
		Source:   flagQuerySource,
		TLD:      flagQueryTLD,
		Limit:    flagQueryLimit,
	})
	if err != nil {
		return err
	}

	if flagQueryJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(events)
	}

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
