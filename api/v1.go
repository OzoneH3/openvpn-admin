package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/shutcode/openvpn-admin/internal/ovpn"
)

// V1Server adapts the on-host OpenVPN/easyrsa state to the SPA's REST shape.
// Unlike the existing /api/users path, v1 is the source of truth for
// dashboard rendering — the SPA never falls back to seed data.
type V1Server struct {
	mgr           *ovpn.Manager
	adminUser     string
	adminPassword string
	jwtSigner     JWTSigner
	startedAt     time.Time
	loginLimiter  *loginLimiter
}

// JWTSigner is a tiny seam so we can reuse the existing auth.JWTManager
// without taking its full type into this file.
type JWTSigner interface {
	IssueAdminToken(username string) (string, error)
}

// NewV1Server constructs the v1 API.
func NewV1Server(mgr *ovpn.Manager, adminUser, adminPassword string, signer JWTSigner) *V1Server {
	if adminUser == "" {
		adminUser = "admin"
	}
	return &V1Server{
		mgr:           mgr,
		adminUser:     adminUser,
		adminPassword: adminPassword,
		jwtSigner:     signer,
		startedAt:     time.Now(),
		loginLimiter:  newLoginLimiter(),
	}
}

// Register attaches v1 routes to mux.
func (s *V1Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/login", s.handleLogin)
	mux.HandleFunc("/api/v1/me", s.handleMe)
	mux.HandleFunc("/api/v1/dashboard", s.handleDashboard)
	mux.HandleFunc("/api/v1/users", s.handleUsers)
	mux.HandleFunc("/api/v1/users/", s.handleUserItem)
	mux.HandleFunc("/api/v1/sessions", s.handleSessions)
	mux.HandleFunc("/api/v1/logs", s.handleLogs)
}

// ----- shapes consumed by the SPA -----

type apiUser struct {
	Username    string     `json:"username"`
	Status      string     `json:"status"`
	Group       string     `json:"group"`
	StaticIP    string     `json:"static_ip,omitempty"`
	Cert        string     `json:"cert"`
	Serial      string     `json:"serial"`
	CertExpires time.Time  `json:"cert_expires"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	Online      bool       `json:"online"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	LastIP      string     `json:"last_ip,omitempty"`
	BytesIn     int64      `json:"bytes_in"`
	BytesOut    int64      `json:"bytes_out"`
}

type apiSession struct {
	User        string    `json:"user"`
	RealIP      string    `json:"real_ip"`
	VirtualIP   string    `json:"virtual_ip"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	ConnectedAt time.Time `json:"connected_at"`
	Cipher      string    `json:"cipher,omitempty"`
}

type apiDashboard struct {
	Server struct {
		Online      bool   `json:"online"`
		Unit        string `json:"unit"`
		Uptime      string `json:"uptime"`
		Endpoint    string `json:"endpoint,omitempty"`
		Cipher      string `json:"cipher,omitempty"`
		Subnet      string `json:"subnet,omitempty"`
		ServiceVer  string `json:"version,omitempty"`
	} `json:"server"`
	Counts struct {
		Total    int `json:"total"`
		Online   int `json:"online"`
		Revoked  int `json:"revoked"`
		Expiring int `json:"expiring"` // certs that expire within 30 days
	} `json:"counts"`
	Sessions []apiSession `json:"sessions"`
}

// ----- handlers -----

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResp struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func (s *V1Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.adminPassword == "" {
		writeError(w, http.StatusServiceUnavailable, "admin authentication is not configured")
		return
	}

	clientKey := loginClientKey(r)
	if !s.loginLimiter.allowed(clientKey) {
		w.Header().Set("Retry-After", "900")
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts")
		return
	}

	var req loginReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	if req.Username == "" || req.Password == "" || !constantTimeCredentialsEqual(req.Username, req.Password, s.adminUser, s.adminPassword) {
		s.loginLimiter.failure(clientKey)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	s.loginLimiter.success(clientKey)
	tok, err := s.jwtSigner.IssueAdminToken(req.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue token: "+err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, loginResp{Token: tok, Username: req.Username, Role: "admin"})
}

func (s *V1Server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	user, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": user, "role": "admin"})
}

func (s *V1Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		users, err := s.collectUsers()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users, "total": len(users)})
	case http.MethodPost:
		var body struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if _, err := s.mgr.AddClient(r.Context(), body.Username); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"username": body.Username})
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *V1Server) handleUserItem(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	tail := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if tail == "" {
		writeError(w, http.StatusBadRequest, "missing username")
		return
	}
	parts := strings.SplitN(tail, "/", 2)
	cn := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch {
	case action == "config" && r.Method == http.MethodGet:
		bundle, err := s.mgr.BuildOVPN(cn)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-openvpn-profile")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.ovpn"`, cn))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bundle)
	case action == "" && r.Method == http.MethodDelete:
		if err := s.mgr.RevokeClient(r.Context(), cn); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *V1Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	sessions, err := ovpn.ReadSessions(s.mgr.StatusPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]apiSession, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, apiSession{
			User:        s.CommonName,
			RealIP:      s.RealIP,
			VirtualIP:   s.VirtualIP,
			BytesIn:     s.BytesIn,
			BytesOut:    s.BytesOut,
			ConnectedAt: s.ConnectedAt,
			Cipher:      s.Cipher,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out, "total": len(out)})
}

func (s *V1Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	entries, err := s.mgr.TailJournal(r.Context(), 300)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": entries, "total": len(entries)})
}

func (s *V1Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	users, _ := s.collectUsers()
	sessions, _ := ovpn.ReadSessions(s.mgr.StatusPath)

	var d apiDashboard
	d.Server.Online = s.mgr.IsServiceActive(r.Context())
	d.Server.Unit = s.mgr.ServiceUnit
	d.Server.Uptime = s.mgr.ServiceUptime(r.Context())
	d.Server.Cipher = "AES-128-GCM"
	d.Server.Subnet = "10.8.0.0/24"

	for _, u := range users {
		d.Counts.Total++
		if u.Status == "revoked" {
			d.Counts.Revoked++
			continue
		}
		if !u.CertExpires.IsZero() && time.Until(u.CertExpires) < 30*24*time.Hour {
			d.Counts.Expiring++
		}
	}
	d.Counts.Online = len(sessions)
	for _, sess := range sessions {
		d.Sessions = append(d.Sessions, apiSession{
			User:        sess.CommonName,
			RealIP:      sess.RealIP,
			VirtualIP:   sess.VirtualIP,
			BytesIn:     sess.BytesIn,
			BytesOut:    sess.BytesOut,
			ConnectedAt: sess.ConnectedAt,
			Cipher:      sess.Cipher,
		})
	}
	writeJSON(w, http.StatusOK, d)
}

// collectUsers merges PKI rows with static-IP and live-session data so the
// SPA can render a single uniform list.
func (s *V1Server) collectUsers() ([]apiUser, error) {
	certs, err := ovpn.ReadIndex(s.mgr.EasyRSADir)
	if err != nil {
		return nil, err
	}
	statics := ovpn.ReadStaticIPs(s.mgr.OpenVPNDir)
	sessions, _ := ovpn.ReadSessions(s.mgr.StatusPath)

	online := map[string]ovpn.Session{}
	for _, sess := range sessions {
		online[sess.CommonName] = sess
	}

	// Hide the server's own cert (CN starts with "server_") and dedupe by CN
	// keeping the most-recent valid row over expired/revoked ones.
	byCN := map[string]apiUser{}
	for _, c := range certs {
		if strings.HasPrefix(c.CommonName, "server_") {
			continue
		}
		u := apiUser{
			Username:    c.CommonName,
			Status:      c.Status,
			Group:       "vpn",
			Cert:        "CN=" + c.CommonName,
			Serial:      c.Serial,
			CertExpires: c.NotAfter,
			StaticIP:    statics[c.CommonName],
		}
		if !c.RevokedAt.IsZero() {
			r := c.RevokedAt
			u.RevokedAt = &r
		}
		if sess, ok := online[c.CommonName]; ok {
			u.Online = true
			u.LastIP = sess.RealIP
			lastSeen := sess.ConnectedAt
			u.LastSeenAt = &lastSeen
			u.BytesIn = sess.BytesIn
			u.BytesOut = sess.BytesOut
		}
		// Prefer valid > revoked when CN appears multiple times in index.
		if existing, ok := byCN[c.CommonName]; ok {
			if existing.Status == "valid" && u.Status != "valid" {
				continue
			}
		}
		byCN[c.CommonName] = u
	}

	out := make([]apiUser, 0, len(byCN))
	for _, u := range byCN {
		out = append(out, u)
	}
	return out, nil
}

// ----- auth helper -----

func (s *V1Server) requireAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	hdr := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(hdr, p) {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return "", false
	}
	tok := strings.TrimPrefix(hdr, p)
	user, ok := s.jwtSigner.(adminVerifier).VerifyAdminToken(tok)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return "", false
	}
	return user, true
}

type adminVerifier interface {
	VerifyAdminToken(string) (string, bool)
}
