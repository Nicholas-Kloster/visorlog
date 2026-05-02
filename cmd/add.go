package cmd

import (
	"fmt"
	"strings"

	"github.com/Nicholas-Kloster/visorlog/store"
	"github.com/spf13/cobra"
)

var (
	flagAddIP       string
	flagAddHostname string
	flagAddOrg      string
	flagAddCountry  string
	flagAddSector   string
	flagAddTLD      string
	flagAddSeverity string
	flagAddTags     string
	flagAddVulns    string
	flagAddNote     string
	flagAddSource   string
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Manually add a finding",
	Example: `  visorlog add --ip 103.107.245.11 --hostname sijoli-11-245-107.jatengprov.go.id \
    --org "Dinas Kominfo Jawa Tengah" --country ID --sector government \
    --tld .go.id --severity critical --tags TAKEOVER,CLOUD --source manual`,
	RunE: runAdd,
}

func init() {
	addCmd.Flags().StringVar(&flagAddIP, "ip", "", "host IP (required)")
	addCmd.Flags().StringVar(&flagAddHostname, "hostname", "", "hostname")
	addCmd.Flags().StringVar(&flagAddOrg, "org", "", "organization name")
	addCmd.Flags().StringVar(&flagAddCountry, "country", "", "ISO2 country code")
	addCmd.Flags().StringVar(&flagAddSector, "sector", "", "sector: government, university, healthcare, commercial")
	addCmd.Flags().StringVar(&flagAddTLD, "tld", "", "TLD pattern (e.g. .go.id)")
	addCmd.Flags().StringVar(&flagAddSeverity, "severity", store.SeverityMedium, "severity: critical, high, medium, low, info")
	addCmd.Flags().StringVar(&flagAddTags, "tags", "", "comma-separated tags (e.g. TAKEOVER,CLOUD)")
	addCmd.Flags().StringVar(&flagAddVulns, "vulns", "", "comma-separated CVE IDs")
	addCmd.Flags().StringVar(&flagAddNote, "note", "", "initial notes")
	addCmd.Flags().StringVar(&flagAddSource, "source", "manual", "source tool")
	addCmd.MarkFlagRequired("ip")
}

func runAdd(cmd *cobra.Command, args []string) error {
	db, err := store.Open(flagDB)
	if err != nil {
		return err
	}
	defer db.Close()

	var tags []string
	if flagAddTags != "" {
		for _, t := range strings.Split(flagAddTags, ",") {
			tags = append(tags, strings.TrimSpace(t))
		}
	}

	var vulns []string
	if flagAddVulns != "" {
		for _, v := range strings.Split(flagAddVulns, ",") {
			vulns = append(vulns, strings.TrimSpace(v))
		}
	}

	e := store.NewDiscovery(
		flagAddIP, flagAddHostname, flagAddOrg, flagAddCountry,
		flagAddSector, flagAddTLD, flagAddSource, flagAddSeverity,
		tags, vulns,
	)
	e.Notes = flagAddNote

	id, err := db.Insert(e)
	if err != nil {
		return err
	}

	fmt.Printf("added #%d — %s (%s)\n", id, flagAddIP, flagAddSeverity)
	return nil
}
