package store

import (
	"encoding/json"
	"time"
)

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// EventCategory values
const (
	CategoryDiscovery    = "discovery"
	CategoryDisclosure   = "disclosure"
	CategoryRemediation  = "remediation"
	CategoryRegression   = "regression"
	CategoryAcknowledged = "acknowledged"
)

// Lifecycle statuses
const (
	StatusOpen         = "open"
	StatusDisclosed    = "disclosed"
	StatusAcknowledged = "acknowledged"
	StatusRemediated   = "remediated"
	StatusVerified     = "verified"
	StatusArchived     = "archived"
)

// Sectors
const (
	SectorGovernment  = "government"
	SectorUniversity  = "university"
	SectorHealthcare  = "healthcare"
	SectorCommercial  = "commercial"
	SectorISP         = "isp"
	SectorMilitary    = "military"
)

// Event is the core normalized record — ECS-inspired.
type Event struct {
	ID              int64                  `json:"id,omitempty"`
	Timestamp       string                 `json:"timestamp"`
	EventCategory   string                 `json:"event.category"`
	EventType       string                 `json:"event.type"`       // created, updated, closed
	EventSeverity   string                 `json:"event.severity"`
	HostIP          string                 `json:"host.ip,omitempty"`
	HostHostname    string                 `json:"host.hostname,omitempty"`
	OrgName         string                 `json:"org.name,omitempty"`
	OrgCountry      string                 `json:"org.country,omitempty"`
	Sector          string                 `json:"nuclide.sector,omitempty"`
	TLD             string                 `json:"nuclide.tld,omitempty"`
	Tags            []string               `json:"nuclide.tags,omitempty"`
	Source          string                 `json:"nuclide.source,omitempty"` // visorgoose, aimap, ollama-recon, manual
	VulnIDs         []string               `json:"vuln.ids,omitempty"`
	LifecycleStatus string                 `json:"lifecycle.status"`
	Notes           string                 `json:"notes,omitempty"`
	Raw             map[string]interface{} `json:"raw,omitempty"`
}

func NewDiscovery(ip, hostname, org, country, sector, tld, source, severity string, tags, vulns []string) *Event {
	return &Event{
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		EventCategory:   CategoryDiscovery,
		EventType:       "created",
		EventSeverity:   severity,
		HostIP:          ip,
		HostHostname:    hostname,
		OrgName:         org,
		OrgCountry:      country,
		Sector:          sector,
		TLD:             tld,
		Tags:            tags,
		Source:          source,
		VulnIDs:         vulns,
		LifecycleStatus: StatusOpen,
	}
}

// tagsJSON marshals a string slice to a JSON array string for SQLite storage.
func tagsJSON(tags []string) string {
	if len(tags) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(tags)
	return string(b)
}

// parseTags unmarshals a JSON array string back to []string.
func parseTags(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var tags []string
	json.Unmarshal([]byte(s), &tags)
	return tags
}
