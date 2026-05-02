package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection.
type DB struct {
	conn *sql.DB
	Path string
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp        TEXT    NOT NULL,
	event_category   TEXT    NOT NULL,
	event_type       TEXT    NOT NULL DEFAULT 'created',
	event_severity   TEXT    NOT NULL DEFAULT 'info',
	host_ip          TEXT,
	host_hostname    TEXT,
	org_name         TEXT,
	org_country      TEXT,
	sector           TEXT,
	tld              TEXT,
	tags             TEXT    DEFAULT '[]',
	source           TEXT,
	vuln_ids         TEXT    DEFAULT '[]',
	lifecycle_status TEXT    NOT NULL DEFAULT 'open',
	notes            TEXT,
	raw              TEXT
);

CREATE INDEX IF NOT EXISTS idx_host_ip          ON events(host_ip);
CREATE INDEX IF NOT EXISTS idx_lifecycle_status ON events(lifecycle_status);
CREATE INDEX IF NOT EXISTS idx_event_severity   ON events(event_severity);
CREATE INDEX IF NOT EXISTS idx_sector           ON events(sector);
CREATE INDEX IF NOT EXISTS idx_timestamp        ON events(timestamp);
`

// Open opens or creates the VisorLog SQLite database.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &DB{conn: conn, Path: path}, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// IPExists returns true if any event already exists for the given IP.
func (db *DB) IPExists(ip string) (bool, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM events WHERE host_ip = ?`, ip).Scan(&count)
	return count > 0, err
}

// Insert writes a new event record.
func (db *DB) Insert(e *Event) (int64, error) {
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if e.LifecycleStatus == "" {
		e.LifecycleStatus = StatusOpen
	}

	rawJSON := ""
	if e.Raw != nil {
		b, _ := json.Marshal(e.Raw)
		rawJSON = string(b)
	}

	res, err := db.conn.Exec(`
		INSERT INTO events
		(timestamp, event_category, event_type, event_severity,
		 host_ip, host_hostname, org_name, org_country, sector, tld,
		 tags, source, vuln_ids, lifecycle_status, notes, raw)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Timestamp, e.EventCategory, e.EventType, e.EventSeverity,
		e.HostIP, e.HostHostname, e.OrgName, e.OrgCountry, e.Sector, e.TLD,
		tagsJSON(e.Tags), e.Source, tagsJSON(e.VulnIDs),
		e.LifecycleStatus, e.Notes, rawJSON,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// QueryFilter holds optional filters for Query.
type QueryFilter struct {
	Sector   string
	Severity string
	Status   string
	Tag      string
	Country  string
	Source   string
	TLD      string
	Limit    int
}

// Query returns events matching the filter.
func (db *DB) Query(f QueryFilter) ([]*Event, error) {
	where := []string{"1=1"}
	args := []interface{}{}

	if f.Sector != "" {
		where = append(where, "sector = ?")
		args = append(args, f.Sector)
	}
	if f.Severity != "" {
		where = append(where, "event_severity = ?")
		args = append(args, f.Severity)
	}
	if f.Status != "" {
		where = append(where, "lifecycle_status = ?")
		args = append(args, f.Status)
	}
	if f.Tag != "" {
		where = append(where, "tags LIKE ?")
		args = append(args, "%"+f.Tag+"%")
	}
	if f.Country != "" {
		where = append(where, "org_country = ?")
		args = append(args, f.Country)
	}
	if f.Source != "" {
		where = append(where, "source = ?")
		args = append(args, f.Source)
	}
	if f.TLD != "" {
		where = append(where, "tld = ?")
		args = append(args, f.TLD)
	}

	limit := 100
	if f.Limit > 0 {
		limit = f.Limit
	}

	q := fmt.Sprintf(`
		SELECT id, timestamp, event_category, event_type, event_severity,
		       host_ip, host_hostname, org_name, org_country, sector, tld,
		       tags, source, vuln_ids, lifecycle_status, notes
		FROM events
		WHERE %s
		ORDER BY timestamp DESC
		LIMIT %d`, strings.Join(where, " AND "), limit)

	rows, err := db.conn.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e := &Event{}
		var tagsStr, vulnStr string
		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.EventCategory, &e.EventType, &e.EventSeverity,
			&e.HostIP, &e.HostHostname, &e.OrgName, &e.OrgCountry, &e.Sector, &e.TLD,
			&tagsStr, &e.Source, &vulnStr, &e.LifecycleStatus, &e.Notes,
		); err != nil {
			return nil, err
		}
		e.Tags = parseTags(tagsStr)
		e.VulnIDs = parseTags(vulnStr)
		events = append(events, e)
	}
	return events, rows.Err()
}

// UpdateStatus sets the lifecycle status for an event by ID and appends a note.
func (db *DB) UpdateStatus(id int64, status, note string) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	_, err := db.conn.Exec(`
		UPDATE events
		SET lifecycle_status = ?,
		    notes = CASE WHEN notes = '' OR notes IS NULL
		                 THEN ? || ' [' || ? || ']'
		                 ELSE notes || ' | ' || ? || ' [' || ? || ']'
		            END
		WHERE id = ?`,
		status,
		note, ts,
		note, ts,
		id,
	)
	return err
}

// Stats returns a summary count grouped by sector + severity + status.
type StatRow struct {
	Sector   string
	Severity string
	Status   string
	Count    int
}

func (db *DB) Stats() ([]StatRow, error) {
	rows, err := db.conn.Query(`
		SELECT COALESCE(sector,'—'), event_severity, lifecycle_status, COUNT(*)
		FROM events
		GROUP BY sector, event_severity, lifecycle_status
		ORDER BY sector, event_severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []StatRow
	for rows.Next() {
		var s StatRow
		rows.Scan(&s.Sector, &s.Severity, &s.Status, &s.Count)
		stats = append(stats, s)
	}
	return stats, rows.Err()
}

// OpenCount returns the count of open findings by severity.
func (db *DB) OpenCount() (map[string]int, error) {
	rows, err := db.conn.Query(`
		SELECT event_severity, COUNT(*)
		FROM events
		WHERE lifecycle_status = 'open'
		GROUP BY event_severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var sev string
		var count int
		rows.Scan(&sev, &count)
		counts[sev] = count
	}
	return counts, rows.Err()
}

// StaleCritical returns open critical/high findings older than maxAgeDays.
func (db *DB) StaleCritical(maxAgeDays int) ([]*Event, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -maxAgeDays).Format(time.RFC3339)
	rows, err := db.conn.Query(`
		SELECT id, timestamp, event_category, event_type, event_severity,
		       host_ip, host_hostname, org_name, org_country, sector, tld,
		       tags, source, vuln_ids, lifecycle_status, notes
		FROM events
		WHERE lifecycle_status = 'open'
		  AND event_severity IN ('critical','high')
		  AND timestamp < ?
		ORDER BY timestamp ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e := &Event{}
		var tagsStr, vulnStr string
		rows.Scan(
			&e.ID, &e.Timestamp, &e.EventCategory, &e.EventType, &e.EventSeverity,
			&e.HostIP, &e.HostHostname, &e.OrgName, &e.OrgCountry, &e.Sector, &e.TLD,
			&tagsStr, &e.Source, &vulnStr, &e.LifecycleStatus, &e.Notes,
		)
		e.Tags = parseTags(tagsStr)
		e.VulnIDs = parseTags(vulnStr)
		events = append(events, e)
	}
	return events, rows.Err()
}
