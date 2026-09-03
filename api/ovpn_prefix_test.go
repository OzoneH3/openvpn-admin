package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOVPNAPIPrefixStripsToCanonicalAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.URL.Path))
	})
	mux.Handle("/ovpn/api/", http.StripPrefix("/ovpn", mux))

	req := httptest.NewRequest(http.MethodGet, "/ovpn/api/v1/ping", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != "/api/v1/ping" {
		t.Fatalf("rewritten path = %q, want /api/v1/ping", got)
	}
}

func TestDashboardUsesOVPNAPIPrefix(t *testing.T) {
	dir := t.TempDir()
	index := `<!doctype html><script>fetch("/api/v1/users"); fetch("/api/v1/login")</script>`
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ovpn/", nil)
	rr := httptest.NewRecorder()
	staticHandler(dir).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if strings.Contains(body, `"/api/v1/`) {
		t.Fatalf("dashboard still contains root API path: %s", body)
	}
	for _, want := range []string{"/ovpn/api/v1/users", "/ovpn/api/v1/login"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q: %s", want, body)
		}
	}
}
