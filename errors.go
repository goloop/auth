package auth

import "errors"

var (
	// ErrInvalidToken is returned when a token fails verification.
	ErrInvalidToken = errors.New("auth: invalid token")

	// ErrEmptySubject is returned when issuing a token whose subject id is
	// empty.
	ErrEmptySubject = errors.New("auth: empty subject id")

	// ErrInvalidTTL is returned when a token is requested with a non-positive
	// lifetime.
	ErrInvalidTTL = errors.New("auth: ttl must be positive")

	// ErrPasswordMismatch is returned when a password does not match its hash.
	ErrPasswordMismatch = errors.New("auth: password mismatch")

	// ErrInvalidHash is returned when an encoded password hash is malformed.
	ErrInvalidHash = errors.New("auth: invalid password hash")

	// ErrRefreshExpired is returned when a refresh token is past its expiry.
	ErrRefreshExpired = errors.New("auth: refresh token expired")

	// ErrRefreshMismatch is returned when a refresh secret does not match.
	ErrRefreshMismatch = errors.New("auth: refresh token mismatch")

	// ErrMalformedRefresh is returned when a refresh token string is malformed.
	ErrMalformedRefresh = errors.New("auth: malformed refresh token")

	// ErrRefreshUsed is returned by RefreshStore.Rotate implementations
	// when the old token was already rotated or revoked. Callers treat it
	// as token reuse: revoke the subject's other sessions and require a
	// fresh login.
	ErrRefreshUsed = errors.New("auth: refresh token already used")
)
