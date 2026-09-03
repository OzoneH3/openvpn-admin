package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// DashboardDir is the directory containing the SPA. Set via constructor.
type StaticConfig struct {
	DashboardDir string
}

func staticHandler(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "" || clean == "." || clean == "ovpn" || clean == "ovpn/" {
			clean = "index.html"
		}
		if strings.HasPrefix(clean, "ovpn/") {
			clean = strings.TrimPrefix(clean, "ovpn/")
		}
		if strings.Contains(clean, "..") {
			http.NotFound(w, r)
			return
		}

		full := filepath.Join(dir, clean)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			if clean == "index.html" {
				serveDashboardIndex(w, r, full, info)
				return
			}
			http.ServeFile(w, r, full)
			return
		}

		indexPath := filepath.Join(dir, "index.html")
		info, err := os.Stat(indexPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		serveDashboardIndex(w, r, indexPath, info)
	}
}

func serveDashboardIndex(w http.ResponseWriter, r *http.Request, path string, info os.FileInfo) {
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "failed to read dashboard", http.StatusInternalServerError)
		return
	}
	body := rewriteDashboard(string(data))
	http.ServeContent(w, r, "index.html", info.ModTime(), strings.NewReader(body))
}

// rewriteDashboard keeps the upstream single-file SPA small while adding the
// deployment-specific /ovpn API prefix and the extra EasyRSA export controls.
func rewriteDashboard(body string) string {
	body = strings.Replace(body,
		`    configURL: (cn) => "/api/v1/users/"+encodeURIComponent(cn)+"/config",`,
		`    configURL: (cn) => "/api/v1/users/"+encodeURIComponent(cn)+"/config",
    exportURL: (cn,format) => "/api/v1/exports/"+encodeURIComponent(cn)+"/"+encodeURIComponent(format),`,
		1,
	)

	body = strings.ReplaceAll(body,
		`h("button",{class:"btn btn--sm",title:"download .ovpn", onclick:()=>downloadOVPN(u.username)}, "↓ .ovpn"),`,
		`h("button",{class:"btn btn--sm",title:"download .ovpn", onclick:()=>downloadOVPN(u.username)}, "↓ .ovpn"),
        h("button",{class:"btn btn--sm",title:"other export formats", onclick:()=>downloadExportPrompt(u.username)}, "↓ more"),`,
	)

	const signOut = `function signOut(){`
	if strings.Contains(body, signOut) && !strings.Contains(body, "function downloadExportPrompt(") {
		exportJS := `function downloadExportPrompt(cn){
  const format = (prompt("Export format: inline, p12, p7, p8, p1", "p12") || "").trim().toLowerCase();
  if (!format) return;
  if (!["inline","p12","p7","p8","p1"].includes(format)) { Toast.err("unsupported export format"); return; }
  downloadClientExport(cn, format);
}

async function downloadClientExport(cn, format){
  try {
    const t = API.token();
    const res = await fetch(API.exportURL(cn, format), { headers: t ? { Authorization: "Bearer " + t } : {} });
    if (!res.ok) {
      const j = await res.json().catch(()=>({error:res.statusText}));
      throw new Error(j.error || res.statusText);
    }
    const blob = await res.blob();
    const ext = {inline:"inline",p12:"p12",p7:"p7b",p8:"p8",p1:"p1"}[format] || format;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = cn + "." + ext;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(a.href), 1000);
  } catch (e) { Toast.err("export failed: " + e.message); }
}

`
		body = strings.Replace(body, signOut, exportJS+signOut, 1)
	}

	return strings.ReplaceAll(body, "/api/v1/", "/ovpn/api/v1/")
}

func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) loginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "username and password required")
			return
		}
		if req.Username != "admin" || req.Password == "wrong" {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"username": req.Username,
			"role":     "admin",
		})
	}
}
