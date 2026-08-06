package server

import (
	"embed"
	"io/fs"
	"net/http"
)

// webFS holds the embedded web UI (templates + static assets), compiled into
// the binary so certguard ships as a single self-contained file.
//
//go:embed all:web
var webFS embed.FS

// registerUI wires the browser-facing routes: static assets and the HTML
// pages. Data is fetched by the pages themselves from the JSON API, so these
// handlers only gate access and serve files.
func (s *Server) registerUI() {
	static, err := fs.Sub(webFS, "web/static")
	if err != nil {
		panic(err) // embedded path is a compile-time constant; can't fail at runtime
	}
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))

	s.mux.HandleFunc("GET /login", s.handleLoginPage)
	s.mux.HandleFunc("GET /settings", s.handleSettingsPage)
	s.mux.HandleFunc("GET /inventory", s.handleInventoryPage)
	s.mux.HandleFunc("GET /{$}", s.handleDashboardPage)
}

// handleInventoryPage serves the full tracked-entry table to authenticated
// users. Like the other pages it carries no data — the table is filled from
// GET /api/v1/certs, the same endpoint the dashboard reads.
func (s *Server) handleInventoryPage(w http.ResponseWriter, r *http.Request) {
	if s.resolveUser(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.serveEmbedded(w, "web/inventory.html")
}

// handleSettingsPage serves the settings page to authenticated users.
func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	if s.resolveUser(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.serveEmbedded(w, "web/settings.html")
}

// handleDashboardPage serves the dashboard to authenticated users and redirects
// everyone else to the login page (no flash of protected content).
func (s *Server) handleDashboardPage(w http.ResponseWriter, r *http.Request) {
	if s.resolveUser(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.serveEmbedded(w, "web/dashboard.html")
}

// handleLoginPage serves the login form, bouncing already-authenticated users
// to the dashboard.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s.resolveUser(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.serveEmbedded(w, "web/login.html")
}

func (s *Server) serveEmbedded(w http.ResponseWriter, name string) {
	b, err := webFS.ReadFile(name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
