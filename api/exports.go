package api

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *V1Server) RegisterExports(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/exports/", s.handleClientExport)
}

func (s *V1Server) handleClientExport(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/exports/")
	parts := strings.Split(tail, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeError(w, http.StatusBadRequest, "expected /api/v1/exports/{username}/{format}")
		return
	}

	artifact, err := s.mgr.ExportClient(r.Context(), parts[0], parts[1])
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", artifact.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, artifact.Filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact.Data)
}
