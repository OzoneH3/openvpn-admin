package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueAdminToken returns a signed JWT identifying the WebUI admin. The
// SPA stores this in localStorage and presents it via Authorization headers.
func (m *JWTManager) IssueAdminToken(username string) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub":  username,
		"role": "admin",
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  now.Add(m.config.AccessTTL).Unix(),
		"iss":  m.config.Issuer,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(m.config.AccessSecret)
}

// VerifyAdminToken validates a token issued via IssueAdminToken and returns
// the embedded subject. It accepts either bare admin tokens or full Claims
// access tokens issued by the original GenerateTokenPair flow.
func (m *JWTManager) VerifyAdminToken(tokenString string) (string, bool) {
	parsed, err := jwt.Parse(
		tokenString,
		func(t *jwt.Token) (any, error) { return m.config.AccessSecret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(m.config.Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !parsed.Valid {
		return "", false
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", false
	}
	if role, _ := claims["role"].(string); role != "admin" {
		return "", false
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		if user, _ := claims["username"].(string); user != "" {
			sub = user
		}
	}
	return sub, sub != ""
}
