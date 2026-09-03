package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConstantTimeCredentialsEqual(t *testing.T) {
	assert.True(t, constantTimeCredentialsEqual("admin", "secret", "admin", "secret"))
	assert.False(t, constantTimeCredentialsEqual("root", "secret", "admin", "secret"))
	assert.False(t, constantTimeCredentialsEqual("admin", "wrong", "admin", "secret"))
}

func TestLoginLimiter(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Unix(1_700_000_000, 0)
	limiter.now = func() time.Time { return now }

	for i := 0; i < loginMaxFailures-1; i++ {
		assert.True(t, limiter.allowed("127.0.0.1"))
		limiter.failure("127.0.0.1")
	}
	assert.True(t, limiter.allowed("127.0.0.1"))
	limiter.failure("127.0.0.1")
	assert.False(t, limiter.allowed("127.0.0.1"))

	now = now.Add(loginLockout + time.Second)
	assert.True(t, limiter.allowed("127.0.0.1"))
}

func TestLoginLimiterSuccessClearsFailures(t *testing.T) {
	limiter := newLoginLimiter()
	limiter.failure("127.0.0.1")
	limiter.failure("127.0.0.1")
	limiter.success("127.0.0.1")

	assert.True(t, limiter.allowed("127.0.0.1"))
	assert.Empty(t, limiter.attempts)
}

func TestLoginClientKeyIgnoresForwardedHeaders(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/login", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")

	assert.Equal(t, "10.0.0.5", loginClientKey(req))
}
