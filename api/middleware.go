package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/shutcode/openvpn-admin/internal/auth"
)

// contextKey is the type for context keys
type contextKey int

const (
	// ClaimsContextKey is the context key for JWT claims
	ClaimsContextKey contextKey = iota
)

// Response envelope for consistent API responses
type responseEnvelope struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *string     `json:"error,omitempty"`
}

// Middleware is a chainable HTTP middleware function type
type Middleware func(http.Handler) http.Handler

// Chain chains multiple middleware functions together
func Chain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// LoggingMiddleware logs HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start)
		log.Printf("[%s] %s %s - %d - %v", r.Method, r.URL.Path, r.RemoteAddr, wrapped.statusCode, duration)
	})
}

// RecoveryMiddleware recovers from panics and returns a 500 error
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovered: %v\n%s", err, debug.Stack())
				writeError(w, http.StatusInternalServerError, "Internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware handles CORS headers. Same-origin requests do not need CORS
// headers, so an empty allow-list safely disables cross-origin API access.
func CORSMiddleware(allowedOrigins []string) Middleware {
	allowedSet := make(map[string]struct{}, len(allowedOrigins))
	wildcard := false
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		if origin == "*" {
			wildcard = true
			continue
		}
		allowedSet[origin] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			_, explicitlyAllowed := allowedSet[origin]
			allowed := wildcard || explicitlyAllowed
			if !allowed {
				if r.Method == http.MethodOptions {
					http.Error(w, "CORS origin denied", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// Wildcard mode is intentionally non-credentialed. We reflect the
			// request origin for backwards compatibility with existing clients,
			// but never emit Allow-Credentials unless the origin is explicitly listed.
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			if explicitlyAllowed && !wildcard {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
			w.Header().Set("Access-Control-Max-Age", "86400")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AuthMiddleware validates JWT tokens and adds claims to context
func AuthMiddleware(jwtManager *auth.JWTManager) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeError(w, http.StatusUnauthorized, "Authorization header required")
				return
			}
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				writeError(w, http.StatusUnauthorized, "Invalid authorization header format")
				return
			}
			claims, err := jwtManager.ValidateAccessToken(parts[1])
			if err != nil {
				writeError(w, http.StatusUnauthorized, fmt.Sprintf("Invalid token: %v", err))
				return
			}
			ctx := auth.ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole middleware ensures the user has the specified role
func RequireRole(role string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := auth.ClaimsFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "Authentication required")
				return
			}
			if claims.Role != role && claims.Role != "admin" {
				writeError(w, http.StatusForbidden, "Insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.ResponseWriter.WriteHeader(code)
		rw.written = true
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(responseEnvelope{Success: true, Data: data})
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(responseEnvelope{Success: false, Error: &message})
}
