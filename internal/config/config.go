package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds application configuration
type Config struct {
	// Database
	DBPath string

	// HTTP Server
	Port string

	// EasyRSA paths
	EasyRSAPath string
	OpenVPNPath string
	ClientsDir  string

	// Security
	JWTSecret string

	// Worker
	WorkerCount int
	QueueSize   int

	// SPA dashboard directory served at /
	DashboardDir string

	// Admin auth
	AdminUser     string
	AdminPassword string

	// OpenVPN service status. When OpenVPNListenPort is set (>0), the
	// dashboard checks the local TCP/UDP listener first; otherwise it uses
	// ServiceUnit. StatusFile remains the source for connected-session data.
	StatusFile        string
	ServiceUnit       string
	OpenVPNListenPort int
	OpenVPNListenProto string
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		DBPath:             getEnv("DB_PATH", "./data/openvpn.db"),
		Port:               getEnv("PORT", "8080"),
		EasyRSAPath:        getEnv("EASYRSA_PATH", "/etc/openvpn/easy-rsa"),
		OpenVPNPath:        getEnv("OPENVPN_PATH", "/etc/openvpn"),
		ClientsDir:         getEnv("CLIENTS_DIR", "/etc/openvpn/clients"),
		WorkerCount:        getEnvInt("WORKER_COUNT", 2),
		QueueSize:          getEnvInt("QUEUE_SIZE", 100),
		DashboardDir:       getEnv("DASHBOARD_DIR", "./dashboard"),
		AdminUser:          getEnv("ADMIN_USER", "admin"),
		StatusFile:         getEnv("STATUS_FILE", "/var/log/openvpn/status.log"),
		ServiceUnit:        getEnv("SERVICE_UNIT", "openvpn-server@server.service"),
		OpenVPNListenPort:  getEnvInt("OPENVPN_LISTEN_PORT", 0),
		OpenVPNListenProto: strings.ToLower(getEnv("OPENVPN_LISTEN_PROTO", "udp")),
	}

	if cfg.OpenVPNListenPort < 0 || cfg.OpenVPNListenPort > 65535 {
		return nil, fmt.Errorf("OPENVPN_LISTEN_PORT must be between 0 and 65535")
	}
	if cfg.OpenVPNListenProto != "udp" && cfg.OpenVPNListenProto != "tcp" {
		return nil, fmt.Errorf("OPENVPN_LISTEN_PROTO must be udp or tcp")
	}

	jwtSecret, err := readRequiredSecret("JWT_SECRET", "JWT_SECRET_FILE")
	if err != nil {
		return nil, fmt.Errorf("JWT secret: %w", err)
	}
	cfg.JWTSecret = jwtSecret

	adminPassword, err := readRequiredSecret("ADMIN_PASSWORD", "ADMIN_PASSWORD_FILE")
	if err != nil {
		return nil, fmt.Errorf("admin password: %w", err)
	}
	cfg.AdminPassword = adminPassword

	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}
	_ = os.MkdirAll(cfg.ClientsDir, 0o755)

	return cfg, nil
}

func readRequiredSecret(envName, fileEnvName string) (string, error) {
	if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
		return value, nil
	}
	if path := strings.TrimSpace(os.Getenv(fileEnvName)); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("%s is not set and %s could not be read: %w", envName, fileEnvName, err)
		}
		if value := strings.TrimSpace(string(data)); value != "" {
			return value, nil
		}
		return "", fmt.Errorf("%s points to an empty secret file", fileEnvName)
	}
	return "", fmt.Errorf("%s (or %s) is required", envName, fileEnvName)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}
