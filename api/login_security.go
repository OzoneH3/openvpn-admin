package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	loginFailureWindow = 5 * time.Minute
	loginLockout       = 15 * time.Minute
	loginMaxFailures   = 5
)

type loginAttempt struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
	now      func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		attempts: make(map[string]loginAttempt),
		now:      time.Now,
	}
}

func (l *loginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	a, ok := l.attempts[key]
	if !ok {
		return true
	}
	if !a.lockedUntil.IsZero() && now.Before(a.lockedUntil) {
		return false
	}
	if now.Sub(a.windowStart) >= loginFailureWindow {
		delete(l.attempts, key)
	}
	return true
}

func (l *loginLimiter) failure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	a := l.attempts[key]
	if a.windowStart.IsZero() || now.Sub(a.windowStart) >= loginFailureWindow {
		a = loginAttempt{windowStart: now}
	}
	a.failures++
	if a.failures >= loginMaxFailures {
		a.lockedUntil = now.Add(loginLockout)
	}
	l.attempts[key] = a
}

func (l *loginLimiter) success(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

func loginClientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func constantTimeCredentialsEqual(gotUser, gotPassword, wantUser, wantPassword string) bool {
	// Compare fixed-length SHA-256 digests so timing does not reveal whether
	// the username or password length/content matched first.
	gotUserDigest := sha256.Sum256([]byte(gotUser))
	wantUserDigest := sha256.Sum256([]byte(wantUser))
	gotPasswordDigest := sha256.Sum256([]byte(gotPassword))
	wantPasswordDigest := sha256.Sum256([]byte(wantPassword))

	userOK := subtle.ConstantTimeCompare(gotUserDigest[:], wantUserDigest[:])
	passwordOK := subtle.ConstantTimeCompare(gotPasswordDigest[:], wantPasswordDigest[:])
	return userOK&passwordOK == 1
}
