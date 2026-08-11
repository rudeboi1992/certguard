package server

import (
	"net/http"
	"runtime"
	"runtime/debug"
)

// Build metadata. main stamps these at startup from its own link-time
// variables, so `certguard version` on the CLI and GET /api/v1/version in the
// API can never disagree about what is running.
//
// Nothing is stamped by a plain `go build`, so Commit and BuildDate fall back
// to the VCS information the Go toolchain embeds on its own.
var (
	Version   = "0.1.0-dev"
	Commit    = ""
	BuildDate = ""
)

// SetBuildInfo records what this binary was built from. Empty arguments are
// ignored, so an unstamped build keeps the defaults and the VCS fallback.
func SetBuildInfo(version, commit, buildDate string) {
	if version != "" {
		Version = version
	}
	if commit != "" {
		Commit = commit
	}
	if buildDate != "" {
		BuildDate = buildDate
	}
}

// VersionInfo is what /api/v1/version returns: enough to reproduce a build and
// to tell whether an instance is behind, without any deployment detail.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Dirty     bool   `json:"dirty,omitempty"` // built from a modified checkout
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// BuildInfo reports what this binary was built from, preferring the values
// stamped at link time and filling gaps from the embedded VCS stamp.
func BuildInfo() VersionInfo {
	v := VersionInfo{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}
	for _, st := range bi.Settings {
		switch st.Key {
		case "vcs.revision":
			if v.Commit == "" {
				v.Commit = st.Value
			}
		case "vcs.time":
			if v.BuildDate == "" {
				v.BuildDate = st.Value
			}
		case "vcs.modified":
			v.Dirty = st.Value == "true"
		}
	}
	return v
}

// handleVersion reports the running build. It requires a session because the
// version of a service is a hint worth withholding from anonymous callers —
// the same reason the public status page reports counts and nothing else.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, BuildInfo())
}
