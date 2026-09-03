package api

import (
	"net/http"
	"strings"

	"github.com/shutcode/openvpn-admin/internal/auth"
	"github.com/shutcode/openvpn-admin/internal/ovpn"
	"github.com/shutcode/openvpn-admin/internal/service"
	"github.com/google/uuid"
)

// Server holds all dependencies for the API server
type Server struct {
	userService *service.UserService
	jwtManager  *auth.JWTManager
	certWorker  *service.CertificateWorker
	config      ServerConfig
}

// ServerConfig holds configuration for the API server
type ServerConfig struct {
	JWTSecret      string
	AllowedOrigins []string
	RequireAuth    bool
	DashboardDir   string

	// Manager wraps on-host OpenVPN/easy-rsa state for the v1 API.
	// When nil the v1 routes are not registered.
	Manager       *ovpn.Manager
	AdminUser     string
	AdminPassword string
}

func (s *Server) extractUserIDFromPath(r *http.Request) (uuid.UUID, error) {
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api/users/")
	path = strings.TrimSuffix(path, "/config")
	return uuid.Parse(path)
}

// NewServer creates a new API server
func NewServer(userService *service.UserService, certWorker *service.CertificateWorker, config ServerConfig) *Server {
	jwtConfig := auth.DefaultJWTConfig(config.JWTSecret)
	jwtManager := auth.NewJWTManager(jwtConfig)
	return &Server{userService: userService, jwtManager: jwtManager, certWorker: certWorker, config: config}
}

// Handler returns the HTTP handler with all routes registered
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	chain := Chain(RecoveryMiddleware, LoggingMiddleware, CORSMiddleware(s.config.AllowedOrigins))
	return chain(mux)
}

// registerRoutes registers all API routes
func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", s.handleGetServerStatus())
	mux.HandleFunc("/api/login", s.loginHandler())
	mux.HandleFunc("/health", healthHandler())

	if s.config.Manager != nil {
		v1 := NewV1Server(s.config.Manager, s.config.AdminUser, s.config.AdminPassword, s.jwtManager)
		v1.Register(mux)
		v1.RegisterExports(mux)
	}

	if s.config.RequireAuth {
		authChain := Chain(AuthMiddleware(s.jwtManager))
		mux.Handle("/api/users", authChain(s.handleUsers()))
		mux.Handle("/api/users/", authChain(s.handleUserByID()))
		mux.Handle("/api/jobs", authChain(s.handleJobs()))
	} else {
		mux.HandleFunc("/api/users", s.handleUsers())
		mux.HandleFunc("/api/users/", s.handleUserByID())
		mux.HandleFunc("/api/jobs", s.handleJobs())
	}

	if s.config.DashboardDir != "" {
		mux.HandleFunc("/", staticHandler(s.config.DashboardDir))
	}
}

func (s *Server) handleUsers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.ListUsersHandler(w, r)
		case http.MethodPost:
			s.CreateUserHandler(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func (s *Server) handleUserByID() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/config") {
			if r.Method == http.MethodGet {
				s.GetUserConfigHandler(w, r)
			} else if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
			} else {
				writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			}
			return
		}
		switch r.Method {
		case http.MethodGet:
			s.GetUserHandler(w, r)
		case http.MethodDelete:
			s.DeleteUserHandler(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func (s *Server) handleJobs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.ListJobsHandler(w, r)
		case http.MethodOptions:
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}
