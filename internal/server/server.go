// Package server exposes the JSON API. Phase 1 is intentionally minimal and
// unauthenticated (localhost/self-hosted); Phase 2 adds token + session auth.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/bfalcher/certguard/internal/config"
	"github.com/bfalcher/certguard/internal/scanner"
	"github.com/bfalcher/certguard/internal/store"
)

type Server struct {
	cfg   config.Config
	store *store.Store
	mux   *http.ServeMux
}

func New(cfg config.Config, st *store.Store) *Server {
	s := &Server{cfg: cfg, store: st, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/certs", s.handleListCerts)
	s.mux.HandleFunc("POST /api/v1/scan", s.handleScan)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now().UTC()
	type item struct {
		Cert          any `json:"cert"`
		DaysRemaining int `json:"days_remaining"`
	}
	out := make([]item, 0, len(certs))
	for _, c := range certs {
		out = append(out, item{Cert: c, DaysRemaining: c.DaysRemaining(now)})
	}
	writeJSON(w, http.StatusOK, out)
}

type scanRequest struct {
	Target string `json:"target"` // "host", "host:port", or URL
	Name   string `json:"name"`
	DryRun bool   `json:"dry_run"` // scan but do not persist
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	host, port, err := scanner.ParseTarget(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ScanTimeout+2*time.Second)
	defer cancel()

	res, err := scanner.Scan(ctx, host, port, scanner.Options{Timeout: s.cfg.ScanTimeout})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	if req.DryRun {
		writeJSON(w, http.StatusOK, map[string]any{"scan": res})
		return
	}
	stored, err := s.store.UpsertScan(req.Name, res)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scan": res, "saved": stored})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
