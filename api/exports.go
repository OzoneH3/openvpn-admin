package api

import (
	"encoding/json"
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

	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/exports/")
	parts := strings.Split(tail, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeError(w, http.StatusBadRequest, "expected /api/v1/exports/{username}/{format}")
		return
	}

	password := ""
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		var body struct {
			Password string `json:"password"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		password = body.Password
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	artifact, err := s.mgr.ExportClientProtected(r.Context(), parts[0], parts[1], password)
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
