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
	ID      string
	Subject string
	Hash    string // hex SHA-256 of the secret; safe to store

	// IssuedAt is when the token was minted. It answers the one question a
	// session list and a "sign out everywhere" both need: was this token
	// handed out before the event that should have ended it - a password
	// change, a suspected theft - or after.
	//
	// Deriving it from ExpiresAt is not the same thing. That would subtract a
	// TTL that lives in configuration and changes between issues, so a token
	// minted yesterday under a different setting would report a time it never
	// had, and a revocation cut-off would miss or over-reach.
	//
	// A record read back from a store written before this field existed has
	// the zero time here.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// NewRefreshToken creates a refresh token for the subject. It returns the
// server-side record (to store) and the opaque token string (to give the
// client, in the form "id.secret"). The raw secret is never stored. The subject
// must be non-empty (ErrEmptySubject) and the ttl positive (ErrInvalidTTL), so
// a token cannot be minted without an owner or already expired.
func NewRefreshToken(subject string, ttl time.Duration) (RefreshToken, string, error) {
	if subject == "" {
		return RefreshToken{}, "", ErrEmptySubject
	}
	if ttl <= 0 {
		return RefreshToken{}, "", ErrInvalidTTL
	}
	idBytes := make([]byte, refreshIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return RefreshToken{}, "", err
	}
	secretBytes := make([]byte, refreshSecretBytes)
	if _, err := rand.Read(secretBytes); err != nil {
		return RefreshToken{}, "", err
	}
	id := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)

	// Both stamps come from one reading of the clock, so that
	// ExpiresAt.Sub(IssuedAt) is exactly the ttl asked for. Two readings
	// would differ by the time in between, and the next person to notice
	// would go looking for a bug that is not there.
	issued := time.Now().UTC()
	rt := RefreshToken{
		ID:        id,
		Subject:   subject,
		Hash:      hashSecret(secret),
		IssuedAt:  issued,
		ExpiresAt: issued.Add(ttl),
	}
	return rt, id + "." + secret, nil
}

// Token part sizes. NewRefreshToken emits a hex-encoded id and secret of fixed
// length; ParseRefreshToken enforces exactly these so a malformed or oversized
// token is rejected before any hashing or store lookup.
const (
	refreshIDBytes     = 16
	refreshSecretBytes = 32
	refreshIDLen       = 2 * refreshIDBytes     // hex characters
	refreshSecretLen   = 2 * refreshSecretBytes // hex characters
)

// ParseRefreshToken splits an opaque token string into its id and secret. The
// token must be exactly "id.secret", each a lowercase-hex string of the length
// NewRefreshToken produces; anything else is ErrMalformedRefresh.
func ParseRefreshToken(token string) (id, secret string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 ||
		len(parts[0]) != refreshIDLen || len(parts[1]) != refreshSecretLen ||
		!isHexString(parts[0]) || !isHexString(parts[1]) {
		return "", "", ErrMalformedRefresh
	}
	return parts[0], parts[1], nil
}

// isHexString reports whether s is non-empty and all lowercase hex digits,
// matching what hex.EncodeToString produces.
func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Verify checks the secret against the stored hash (constant time) and the
// expiry. Look the record up by id first, then call Verify with the secret. It
// returns ErrRefreshMismatch before ErrRefreshExpired; if you surface these to
// clients, collapse them into one opaque error so an expired token cannot be
// used to test whether a guessed secret was correct.
func (rt RefreshToken) Verify(secret string) error {
	return VerifyRefreshSecret(rt.Hash, rt.ExpiresAt, secret)
}

// VerifyRefreshSecret checks a presented refresh-token secret against a stored
// hash and expiry, without rebuilding a RefreshToken. It is the
// storage-friendly form of RefreshToken.Verify: after ParseRefreshToken yields
// the id and secret and you load the record by id, pass the record's stored
// hash and expiry straight in. It returns ErrRefreshMismatch before
// ErrRefreshExpired, matching RefreshToken.Verify. A zero expiresAt means no
// expiry check.
func VerifyRefreshSecret(storedHash string, expiresAt time.Time, secret string) error {
	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(storedHash)) != 1 {
		return ErrRefreshMismatch
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
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
