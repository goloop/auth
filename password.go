package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// PasswordHasher hashes and verifies passwords. The encoded string returned by
// Hash is self-describing (algorithm, parameters, salt and digest), so Verify
// needs no external state. Implement this interface to plug in Argon2id or
// another algorithm without changing callers.
type PasswordHasher interface {
	Hash(password []byte) (encoded string, err error)
	Verify(encoded string, password []byte) error
}

// Default PBKDF2 parameters. The iteration count follows current guidance for
// PBKDF2-HMAC-SHA256.
const (
	defaultIterations = 600000
	defaultKeyLength  = 32
	defaultSaltLength = 16
)

// pbkdf2Hasher is a PasswordHasher backed by PBKDF2-HMAC-SHA256 (standard
// library only).
type pbkdf2Hasher struct {
	iterations int
	keyLength  int
	saltLength int
}

// HashOption configures NewPBKDF2.
type HashOption func(*pbkdf2Hasher)

// WithIterations sets the PBKDF2 iteration count.
func WithIterations(n int) HashOption {
	return func(h *pbkdf2Hasher) {
		if n > 0 {
			h.iterations = n
		}
	}
}

// NewPBKDF2 returns a PBKDF2-HMAC-SHA256 PasswordHasher.
func NewPBKDF2(opts ...HashOption) PasswordHasher {
	h := &pbkdf2Hasher{
		iterations: defaultIterations,
		keyLength:  defaultKeyLength,
		saltLength: defaultSaltLength,
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Hash returns an encoded PBKDF2 hash: pbkdf2-sha256$iter$salt$digest.
func (h *pbkdf2Hasher) Hash(password []byte) (string, error) {
	salt := make([]byte, h.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, string(password), salt, h.iterations, h.keyLength)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		h.iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

// Verify checks password against an encoded hash in constant time.
func (h *pbkdf2Hasher) Verify(encoded string, password []byte) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return ErrInvalidHash
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		// A zero-length digest would make the constant-time compare below
		// succeed for any password.
		return ErrInvalidHash
	}

	got, err := pbkdf2.Key(sha256.New, string(password), salt, iter, len(want))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}
