package alert

import (
	"fmt"
	"strings"

	"github.com/Nicholas-Kloster/visorlog/store"
)

// Rule defines a condition that fires an alert.
type Rule struct {
	Name       string
	Severity   string // if set, only match this severity
	Tag        string // if set, only match events with this tag
	Status     string // if set, only match this lifecycle status
	StaleDays  int    // if >0, alert on findings open longer than N days
	Message    string // template: {host_ip}, {host_hostname}, {severity}, {age}
}

// DefaultRules are the built-in alert rules.
var DefaultRules = []Rule{
	{
		Name:     "new-takeover",
		Tag:      "TAKEOVER",
		Status:   store.StatusOpen,
		Message:  "TAKEOVER open: {host_ip} ({host_hostname}) [{sector}]",
	},
	{
		Name:     "new-critical",
		Severity: store.SeverityCritical,
		Status:   store.StatusOpen,
		Message:  "CRITICAL open: {host_ip} ({host_hostname}) — {org_name}",
	},
	{
		Name:      "stale-critical",
		Severity:  store.SeverityCritical,
		Status:    store.StatusOpen,
		StaleDays: 7,
		Message:   "STALE {severity}: {host_ip} open for >{stale_days} days — disclose?",
	},
	{
		Name:      "stale-high",
		Severity:  store.SeverityHigh,
		Status:    store.StatusOpen,
		StaleDays: 14,
		Message:   "STALE HIGH: {host_ip} open for >{stale_days} days",
	},
}

// Alert is a fired rule instance.
type Alert struct {
	Rule    string
	Message string
	Event   *store.Event
}

// Check evaluates all rules against the database and returns fired alerts.
func Check(db *store.DB, rules []Rule) ([]Alert, error) {
	var alerts []Alert

	for _, rule := range rules {
		f := store.QueryFilter{
			Severity: rule.Severity,
			Status:   rule.Status,
			Tag:      rule.Tag,
			Limit:    1000,
		}

		var events []*store.Event
		var err error

		if rule.StaleDays > 0 {
			events, err = db.StaleCritical(rule.StaleDays)
		} else {
			events, err = db.Query(f)
		}
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}

		for _, e := range events {
			// tag filter applied in-process for stale queries
			if rule.Tag != "" {
				found := false
				for _, t := range e.Tags {
					if t == rule.Tag {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			msg := render(rule.Message, rule, e)
			alerts = append(alerts, Alert{
				Rule:    rule.Name,
				Message: msg,
				Event:   e,
			})
		}
	}

	return alerts, nil
}

func render(tmpl string, rule Rule, e *store.Event) string {
	r := strings.NewReplacer(
		"{host_ip}", e.HostIP,
		"{host_hostname}", e.HostHostname,
		"{org_name}", e.OrgName,
		"{severity}", e.EventSeverity,
		"{sector}", e.Sector,
		"{status}", e.LifecycleStatus,
		"{stale_days}", fmt.Sprintf("%d", rule.StaleDays),
	)
	return r.Replace(tmpl)
}
