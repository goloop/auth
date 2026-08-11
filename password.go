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

// Rehasher reports whether a stored hash is weaker than the hasher's current
// settings and should be replaced. A PasswordHasher may also implement it so a
// successful login can transparently upgrade an old hash:
//
//	if err := h.Verify(stored, pw); err == nil {
//	    if rh, ok := h.(auth.Rehasher); ok && rh.NeedsRehash(stored) {
//	        newHash, _ := h.Hash(pw) // persist newHash
//	    }
//	}
type Rehasher interface {
	NeedsRehash(encoded string) bool
}

// Default PBKDF2 parameters. The iteration count follows current guidance for
// PBKDF2-HMAC-SHA256.
const (
	defaultIterations = 600000
	defaultKeyLength  = 32
	defaultSaltLength = 16
)

// Verification bounds. A stored hash outside these is rejected: the floors keep
// a weak or malformed hash from ever verifying, and the ceiling on iterations
// bounds the CPU a single login can be made to spend on a hostile hash.
const (
	minVerifySaltLen    = 8
	minVerifyKeyLen     = 16
	maxVerifyKeyLen     = 128
	maxVerifyIterations = 10_000_000
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

// WithIterations sets the PBKDF2 iteration count. A non-positive value is
// ignored. The count is capped at the verification ceiling so a hasher can
// never produce a hash its own Verify would reject as out of bounds; a very low
// value is accepted but weakens the hash, so keep it high in production.
func WithIterations(n int) HashOption {
	return func(h *pbkdf2Hasher) {
		if n <= 0 {
			return
		}
		if n > maxVerifyIterations {
			n = maxVerifyIterations
		}
		h.iterations = n
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

// parsePBKDF2 decodes an encoded hash and validates its parameters against the
// verification bounds. Enforcing the bounds here means a malformed or
// deliberately hostile hash (a one-byte digest, a billion iterations) is
// rejected before any key derivation runs.
func parsePBKDF2(encoded string) (iter int, salt, digest []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return 0, nil, nil, ErrInvalidHash
	}
	iter, err = strconv.Atoi(parts[1])
	if err != nil || iter <= 0 || iter > maxVerifyIterations {
		return 0, nil, nil, ErrInvalidHash
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < minVerifySaltLen {
		return 0, nil, nil, ErrInvalidHash
	}
	digest, err = base64.RawStdEncoding.DecodeString(parts[3])
	// A digest that is too short weakens the constant-time compare; too long
	// only wastes work. Both are rejected.
	if err != nil || len(digest) < minVerifyKeyLen || len(digest) > maxVerifyKeyLen {
		return 0, nil, nil, ErrInvalidHash
	}
	return iter, salt, digest, nil
}

// Verify checks password against an encoded hash in constant time. A hash whose
// parameters fall outside the verification bounds is rejected as invalid.
func (h *pbkdf2Hasher) Verify(encoded string, password []byte) error {
	iter, salt, want, err := parsePBKDF2(encoded)
	if err != nil {
		return err
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

// NeedsRehash reports whether encoded should be replaced with a fresh hash: it
// returns true for a malformed hash, or one whose iteration count, salt or key
// length is below this hasher's current settings. Call it after a successful
// Verify to upgrade stored hashes as defaults strengthen over time.
func (h *pbkdf2Hasher) NeedsRehash(encoded string) bool {
	iter, salt, digest, err := parsePBKDF2(encoded)
	if err != nil {
		return true
	}
	return iter < h.iterations ||
		len(salt) < h.saltLength ||
		len(digest) < h.keyLength
}

// BurnVerify spends the cost of a password check without having a user to
// check against. Call it on the branch where the account does not exist:
//
//	u, err := repo.ByEmail(ctx, email)
//	if errors.Is(err, sql.ErrNoRows) {
//	    auth.BurnVerify(hasher, decoy, []byte(password))
//	    return ErrInvalidCredentials
//	}
//
// Without it, a login endpoint answers "no such account" in a millisecond and
// "wrong password" in a hundred, because only the second one hashes anything.
// The messages can be identical and the difference is still there, on a
// stopwatch, and it turns the endpoint into a list of which addresses are
// registered.
//
// The decoy is an encoded hash of anything, produced once at startup by the
// same hasher with the same settings:
//
//	decoy, _ := hasher.Hash([]byte(randomString()))
//
// It has to come from the same settings as the real hashes, or the two
// branches cost different amounts again and the oracle comes back through the
// side door. [Rehasher.NeedsRehash] reports when a stored hash has fallen
// behind the current settings, which is the way to keep a long-lived decoy
// honest.
//
// THIS IS NOT ENOUGH ON ITS OWN. It levels the coarse difference between "no
// such user" and "wrong password", and it does nothing about rate limiting,
// about replies that differ in wording or status, or about timing that varies
// with the work done after a successful check. Treating it as the whole answer
// to enumeration is worse than not having it, because it feels like the
// problem is closed.
//
// The result is deliberately discarded: there is nothing to learn from
// verifying a password against a hash of something else.
func BurnVerify(h PasswordHasher, decoyHash string, password []byte) {
	if h == nil || decoyHash == "" {
		return
	}
	_ = h.Verify(decoyHash, password)
}
