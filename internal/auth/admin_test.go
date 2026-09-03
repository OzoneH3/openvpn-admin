package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyAdminToken(t *testing.T) {
	cfg := DefaultJWTConfig("test-secret")
	mgr := NewJWTManager(cfg)

	t.Run("valid token", func(t *testing.T) {
		token, err := mgr.IssueAdminToken("admin")
		require.NoError(t, err)
		user, ok := mgr.VerifyAdminToken(token)
		assert.True(t, ok)
		assert.Equal(t, "admin", user)
	})

	t.Run("wrong algorithm rejected", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":  "admin",
			"role": "admin",
			"iss":  cfg.Issuer,
			"exp":  time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
		signed, err := token.SignedString(cfg.AccessSecret)
		require.NoError(t, err)
		_, ok := mgr.VerifyAdminToken(signed)
		assert.False(t, ok)
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":  "admin",
			"role": "admin",
			"iss":  "someone-else",
			"exp":  time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(cfg.AccessSecret)
		require.NoError(t, err)
		_, ok := mgr.VerifyAdminToken(signed)
		assert.False(t, ok)
	})

	t.Run("missing expiry rejected", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":  "admin",
			"role": "admin",
			"iss":  cfg.Issuer,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(cfg.AccessSecret)
		require.NoError(t, err)
		_, ok := mgr.VerifyAdminToken(signed)
		assert.False(t, ok)
	})

	t.Run("non-admin role rejected", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub":  "user",
			"role": "user",
			"iss":  cfg.Issuer,
			"exp":  time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(cfg.AccessSecret)
		require.NoError(t, err)
		_, ok := mgr.VerifyAdminToken(signed)
		assert.False(t, ok)
	})
}
