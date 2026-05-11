package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Nicholas-Kloster/visorlog/store"
	"github.com/spf13/cobra"
)

var (
	flagIngestFile   string
	flagIngestFormat string
	flagIngestSector string
	flagIngestDedup  bool
)

var ingestCmd = &cobra.Command{
	Use:   "ingest",
	Short: "Ingest events from NDJSON or a VisorGoose state file",
	Long: `Reads events from stdin (NDJSON) or a file and writes them to the database.

Formats:
  ndjson        One JSON event per line (default)
  visorgoose    VisorGoose state JSON (visorgoose-state.json)
  ollama-recon  ollama-recon.py state JSON (ollama-gov-state.json etc.)

Examples:
  visorgoose scan | visorlog ingest
  visorlog ingest --from visorgoose-state.json --format visorgoose
  visorlog ingest --from ollama-gov-state.json --format ollama-recon`,
	RunE: runIngest,
}

func init() {
	ingestCmd.Flags().StringVar(&flagIngestFile, "from", "", "read from file instead of stdin")
	ingestCmd.Flags().StringVar(&flagIngestFormat, "format", "ndjson", "input format: ndjson, visorgoose, ollama-recon")
	ingestCmd.Flags().StringVar(&flagIngestSector, "sector", "", "override sector for all ingested events")
	ingestCmd.Flags().BoolVar(&flagIngestDedup, "dedup", true, "skip IPs already in the database")
}

func runIngest(cmd *cobra.Command, args []string) error {
	db, err := store.Open(flagDB)
	if err != nil {
		return err
	}
	defer db.Close()

	var reader *os.File
	if flagIngestFile != "" {
		reader, err = os.Open(flagIngestFile)
		if err != nil {
			return err
		}
		defer reader.Close()
	} else {
		reader = os.Stdin
	}

	switch flagIngestFormat {
	case "visorgoose":
		return ingestVisorGoose(db, reader)
	case "ollama-recon":
		return ingestOllamaRecon(db, reader)
	default:
		return ingestNDJSON(db, reader)
	}
}

func ingestNDJSON(db *store.DB, r *os.File) error {
	scanner := bufio.NewScanner(r)
	// Bump the per-line buffer cap so we can ingest events with rich
	// raw payloads (the default 64KB chokes on the larger VisorBishop
	// LiteLLM rows with 50+ model_ids).
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 4*1024*1024)

	var inserted, skipped, duped int

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e store.Event
		if err := json.Unmarshal(line, &e); err != nil {
			fmt.Fprintf(os.Stderr, "skip malformed line: %v\n", err)
			skipped++
			continue
		}

		// Dedup by (source, notes) when the dedup flag is set. The
		// notes field carries the unique target URL for VisorBishop
		// events; combining with source prevents collisions with
		// other ingesters that happen to share a target string.
		if flagIngestDedup && e.Source != "" && e.Notes != "" {
			exists, _ := db.NoteExists(e.Source, e.Notes)
			if exists {
				duped++
				continue
			}
		}

		if _, err := db.Insert(&e); err != nil {
			return err
		}
		inserted++
	}

	fmt.Printf("ingested %d events (%d skipped, %d deduped)\n", inserted, skipped, duped)
	return scanner.Err()
}

// visorGooseState mirrors the VisorGoose state.json structure
type visorGooseState struct {
	Nodes map[string]*visorGooseNode `json:"nodes"`
}

type visorGooseNode struct {
	IP       string              `json:"ip"`
	Hostname string              `json:"hostname"`
	Source   string              `json:"source"`
	TLD      string              `json:"tld"`
	Country  string              `json:"country"`
	Org      string              `json:"org"`
	Tags     []string            `json:"tags"`
	Services []visorGooseService `json:"services"`
}

type visorGooseService struct {
	Version    string `json:"version"`
	Vulnerable bool   `json:"vulnerable"`
	CloudProxy bool   `json:"cloud_proxy"`
	Takeover   bool   `json:"takeover"`
	Models     []struct {
		Name string `json:"name"`
	} `json:"models"`
}

func ingestVisorGoose(db *store.DB, r *os.File) error {
	var state visorGooseState
	if err := json.NewDecoder(r).Decode(&state); err != nil {
		return fmt.Errorf("decode visorgoose state: %w", err)
	}

	var inserted int
	for _, n := range state.Nodes {
		severity := store.SeverityLow
		var vulns []string

		for _, svc := range n.Services {
			if svc.Takeover {
				severity = store.SeverityCritical
			} else if svc.Vulnerable && severity != store.SeverityCritical {
				severity = store.SeverityHigh
			} else if svc.CloudProxy && severity == store.SeverityLow {
				severity = store.SeverityMedium
			}
			if svc.Vulnerable {
				vulns = append(vulns, "CVE-2025-63389")
			}
		}

		// derive sector from TLD
		sector := tldToSector(n.TLD)

		e := store.NewDiscovery(
			n.IP, n.Hostname, n.Org, n.Country,
			sector, n.TLD, "visorgoose", severity,
			n.Tags, vulns,
		)

		if _, err := db.Insert(e); err != nil {
			return err
		}
		inserted++
	}

	fmt.Printf("ingested %d nodes from VisorGoose state\n", inserted)
	return nil
}

// ollamaReconNode mirrors the ollama-recon.py state format
type ollamaReconNode struct {
	IP              string   `json:"ip"`
	Org             string   `json:"org"`
	Hostnames       []string `json:"hostnames"`
	Status          string   `json:"status"` // "live", "dead", "timeout"
	Version         string   `json:"version"`
	Models          []string `json:"models"`
	CloudProxy      bool     `json:"cloud_proxy"`
	AccountTakeover bool     `json:"account_takeover"`
	SigninURL       string   `json:"signin_url"`
	Country         string   `json:"country"`
}

func ingestOllamaRecon(db *store.DB, r *os.File) error {
	var raw map[string]ollamaReconNode
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return fmt.Errorf("decode ollama-recon state: %w", err)
	}

	var inserted, skipped, duped int
	for _, n := range raw {
		if n.Status != "live" {
			skipped++
			continue
		}

		if flagIngestDedup {
			exists, _ := db.IPExists(n.IP)
			if exists {
				duped++
				continue
			}
		}

		hostname := ""
		if len(n.Hostnames) > 0 {
			hostname = n.Hostnames[0]
		}

		severity := store.SeverityLow
		var tags, vulns []string

		if n.AccountTakeover {
			severity = store.SeverityCritical
			tags = append(tags, "TAKEOVER")
		}
		if n.CloudProxy {
			if severity != store.SeverityCritical {
				severity = store.SeverityMedium
			}
			tags = append(tags, "CLOUD")
		}
		for _, m := range n.Models {
			ml := strings.ToLower(m)
			if strings.Contains(ml, "bge") || strings.Contains(ml, "embed") || strings.Contains(ml, "nomic") {
				tags = append(tags, "RAG")
				break
			}
		}
		for _, m := range n.Models {
			if strings.Contains(strings.ToLower(m), "distill") {
				tags = append(tags, "DISTILLED")
				break
			}
		}

		tld := extractTLD(hostname)
		sector := flagIngestSector
		if sector == "" {
			sector = tldToSector(tld)
		}

		e := store.NewDiscovery(
			n.IP, hostname, n.Org, n.Country,
			sector, tld, "ollama-recon", severity,
			tags, vulns,
		)
		if n.SigninURL != "" {
			e.Notes = "signin_url: " + n.SigninURL
		}

		if _, err := db.Insert(e); err != nil {
			return err
		}
		inserted++
	}

	fmt.Printf("ingested %d live nodes (%d dead/skipped, %d deduped) from ollama-recon state\n", inserted, skipped, duped)
	return nil
}

func extractTLD(hostname string) string {
	govTLDs := []string{".go.id", ".gov.br", ".gov.tw", ".gouv.fr", ".gob.mx",
		".go.jp", ".gov.in", ".gov.au", ".gov.uk", ".gc.ca", ".gob.es",
		".gov.cn", ".gov.za", ".go.kr", ".gov.sg", ".go.th", ".gob.ar",
		".gov.my", ".gov.ph", ".gov.pk", ".gov.vn", ".gov.ng", ".gov.eg",
		".gov", ".mil"}
	for _, tld := range govTLDs {
		if strings.HasSuffix(hostname, tld) {
			return tld
		}
	}
	// university patterns
	univSuffixes := []string{".edu", ".ac.uk", ".edu.au", ".ac.id", ".edu.br", ".ac.in"}
	for _, sfx := range univSuffixes {
		if strings.HasSuffix(hostname, sfx) {
			return sfx
		}
	}
	return ""
}

func tldToSector(tld string) string {
	govTLDs := []string{".gov", ".go.id", ".gov.br", ".gov.tw",
		".gouv.fr", ".gob.mx", ".go.jp", ".gov.in", ".gov.au",
		".gov.uk", ".gc.ca", ".gob.es", ".gov.cn", ".gov.za",
		".go.kr", ".gov.sg", ".go.th", ".gob.ar", ".gov.my",
		".gov.ph", ".gov.pk", ".gov.vn", ".gov.ng", ".gov.eg"}
	for _, g := range govTLDs {
		if tld == g {
			return store.SectorGovernment
		}
	}
	if tld == ".mil" {
		return store.SectorMilitary
	}
	univTLDs := []string{".edu", ".ac.uk", ".edu.au", ".ac.id", ".edu.br",
		".ac.in", ".edu.cn", ".ac.kr", ".ac.jp", ".edu.tw",
		".ac.za", ".edu.sg", ".ac.nz", ".edu.mx", ".edu.ph"}
	for _, u := range univTLDs {
		if tld == u {
			return store.SectorUniversity
		}
	}
	return store.SectorCommercial
}
