package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"
)

// RefreshToken is the server-side record of a refresh token. Only the Hash is
// stored; the client holds the secret. Persist these in a RefreshStore.
type RefreshToken struct {
	ID        string
	Subject   string
	Hash      string // hex SHA-256 of the secret; safe to store
	ExpiresAt time.Time
}

// NewRefreshToken creates a refresh token for the subject. It returns the
// server-side record (to store) and the opaque token string (to give the
// client, in the form "id.secret"). The raw secret is never stored.
func NewRefreshToken(subject string, ttl time.Duration) (RefreshToken, string, error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return RefreshToken{}, "", err
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return RefreshToken{}, "", err
	}
	id := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)

	rt := RefreshToken{
		ID:        id,
		Subject:   subject,
		Hash:      hashSecret(secret),
		ExpiresAt: time.Now().Add(ttl),
	}
	return rt, id + "." + secret, nil
}

// ParseRefreshToken splits an opaque token string into its id and secret. The
// token must be exactly "id.secret" with both parts non-empty.
func ParseRefreshToken(token string) (id, secret string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", ErrMalformedRefresh
	}
	return parts[0], parts[1], nil
}

// Verify checks the secret against the stored hash (constant time) and the
// expiry. Look the record up by id first, then call Verify with the secret.
func (rt RefreshToken) Verify(secret string) error {
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(rt.Hash)) != 1 {
		return ErrRefreshMismatch
	}
	if !rt.ExpiresAt.IsZero() && time.Now().After(rt.ExpiresAt) {
		return ErrRefreshExpired
	}
	return nil
}

// hashSecret returns the hex SHA-256 of a high-entropy secret. PBKDF2 is
// unnecessary here because the secret is random, not a low-entropy password.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// RefreshStore persists refresh tokens. Implementations live in the application
// (for example over a database); auth defines only the contract.
type RefreshStore interface {
	// Save stores a new refresh token.
	Save(ctx context.Context, rt RefreshToken) error
	// Rotate atomically revokes oldID and stores next. When oldID was
	// already rotated or revoked, implementations return ErrRefreshUsed so
	// the caller can respond to token reuse.
	Rotate(ctx context.Context, oldID string, next RefreshToken) error
	// Revoke removes a refresh token by id.
	Revoke(ctx context.Context, id string) error
}
