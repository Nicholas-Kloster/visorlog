package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/Nicholas-Kloster/visorlog/alert"
	"github.com/Nicholas-Kloster/visorlog/store"
)

//go:embed static
var staticFiles embed.FS

// Server wraps the HTTP server and database.
type Server struct {
	db   *store.DB
	addr string
}

func New(db *store.DB, addr string) *Server {
	return &Server{db: db, addr: addr}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// API
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/findings/", s.handleFindingUpdate) // /api/findings/:id/status

	fmt.Printf("[visorlog] dashboard → http://%s\n", s.addr)
	return http.ListenAndServe(s.addr, mux)
}

// StatsResponse is the JSON payload for /api/stats
type StatsResponse struct {
	Total           int            `json:"total"`
	OpenBySeverity  map[string]int `json:"open_by_severity"`
	StatusCounts    map[string]int `json:"status_counts"`
	SeverityCounts  map[string]int `json:"severity_counts"`
	SectorCounts    map[string]int `json:"sector_counts"`
	TakeoverCount   int            `json:"takeover_count"`
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	// open by severity
	openBySev, _ := s.db.OpenCount()

	// all stats grouped
	rows, _ := s.db.Stats()

	statusCounts := map[string]int{}
	severityCounts := map[string]int{}
	sectorCounts := map[string]int{}
	total := 0

	for _, row := range rows {
		statusCounts[row.Status] += row.Count
		severityCounts[row.Severity] += row.Count
		sectorCounts[row.Sector] += row.Count
		total += row.Count
	}

	// takeover count
	takeovers, _ := s.db.Query(store.QueryFilter{Tag: "TAKEOVER", Limit: 10000})

	resp := StatsResponse{
		Total:          total,
		OpenBySeverity: openBySev,
		StatusCounts:   statusCounts,
		SeverityCounts: severityCounts,
		SectorCounts:   sectorCounts,
		TakeoverCount:  len(takeovers),
	}

	jsonResponse(w, resp)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.QueryFilter{
		Status:   q.Get("status"),
		Severity: q.Get("severity"),
		Sector:   q.Get("sector"),
		Tag:      q.Get("tag"),
		Country:  q.Get("country"),
		Source:   q.Get("source"),
		TLD:      q.Get("tld"),
		Limit:    500,
	}
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			f.Limit = n
		}
	}

	events, err := s.db.Query(f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	jsonResponse(w, events)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := alert.Check(s.db, alert.DefaultRules)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	jsonResponse(w, alerts)
}

func (s *Server) handleFindingUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	// extract ID from /api/findings/:id/status
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/findings/"), "/")
	if len(parts) < 2 || parts[1] != "status" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "invalid id", 400)
		return
	}

	var body struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	if err := s.db.UpdateStatus(id, body.Status, body.Note); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func jsonResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
