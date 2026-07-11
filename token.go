package auth

import (
	"time"

	"github.com/goloop/jwt"
)

// defaultAccessTTL is the default lifetime of an access token.
const defaultAccessTTL = 15 * time.Minute

// TokenManager issues and verifies access tokens for subjects. It is a thin,
// opinionated layer over goloop/jwt: HS256, mandatory expiry, sensible
// defaults.
type TokenManager struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
	leeway   time.Duration
	now      func() time.Time
}

// TokenOption configures a TokenManager.
type TokenOption func(*TokenManager)

// WithIssuer sets the token issuer (iss) and requires it on verification.
func WithIssuer(issuer string) TokenOption {
	return func(m *TokenManager) { m.issuer = issuer }
}

// WithAudience sets the token audience (aud) and requires it on verification.
func WithAudience(audience string) TokenOption {
	return func(m *TokenManager) { m.audience = audience }
}

// WithTTL sets the access-token lifetime.
func WithTTL(d time.Duration) TokenOption {
	return func(m *TokenManager) {
		if d > 0 {
			m.ttl = d
		}
	}
}

// WithLeeway sets the clock-skew tolerance used on verification.
func WithLeeway(d time.Duration) TokenOption {
	return func(m *TokenManager) { m.leeway = d }
}

// WithClock overrides the time source (for testing). A nil function is ignored.
func WithClock(now func() time.Time) TokenOption {
	return func(m *TokenManager) {
		if now != nil {
			m.now = now
		}
	}
}

// NewTokenManager creates a TokenManager with the given HMAC secret. The secret
// must be at least 32 bytes (the HS256 minimum); a shorter one makes Issue and
// Verify fail with jwt.ErrWeakKey. The secret is copied, so the caller may reuse
// or zero its slice afterwards.
func NewTokenManager(secret []byte, opts ...TokenOption) *TokenManager {
	m := &TokenManager{
		secret: append([]byte(nil), secret...),
		ttl:    defaultAccessTTL,
		now:    time.Now,
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Issue signs an access token for the subject. The subject id must be set.
func (m *TokenManager) Issue(sub Subject) (string, error) {
	if sub.ID == "" {
		return "", ErrEmptySubject
	}
	now := m.now()
	claims := jwt.Claims{
		Subject:   sub.ID,
		Issuer:    m.issuer,
		ExpiresAt: now.Add(m.ttl).Unix(),
		IssuedAt:  now.Unix(),
		Extra:     map[string]any{},
	}
	if m.audience != "" {
		claims.Audience = jwt.Audience{m.audience}
	}
	if sub.Email != "" {
		claims.Extra["email"] = sub.Email
	}
	if len(sub.Roles) > 0 {
		claims.Extra["roles"] = sub.Roles
	}
	if len(sub.Scopes) > 0 {
		claims.Extra["scopes"] = sub.Scopes
	}
	return jwt.Sign(claims, m.secret)
}

// Verify checks an access token and reconstructs the subject.
func (m *TokenManager) Verify(token string) (Subject, error) {
	opts := []jwt.Option{jwt.WithClock(m.now)}
	if m.leeway > 0 {
		opts = append(opts, jwt.WithLeeway(m.leeway))
	}
	if m.issuer != "" {
		opts = append(opts, jwt.WithIssuer(m.issuer))
	}
	if m.audience != "" {
		opts = append(opts, jwt.WithAudience(m.audience))
	}

	claims, err := jwt.Verify(token, m.secret, opts...)
	if err != nil {
		return Subject{}, err
	}
	// A token with no subject must not authenticate anyone.
	if claims.Subject == "" {
		return Subject{}, ErrInvalidToken
	}

	return Subject{
		ID:     claims.Subject,
		Email:  stringClaim(claims.Extra, "email"),
		Roles:  stringSliceClaim(claims.Extra, "roles"),
		Scopes: stringSliceClaim(claims.Extra, "scopes"),
	}, nil
}

func stringClaim(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func stringSliceClaim(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}
