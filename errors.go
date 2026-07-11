package auth

import "errors"

var (
	// ErrNoToken is returned when a request carries no credentials.
	ErrNoToken = errors.New("auth: no token")

	// ErrInvalidToken is returned when a token fails verification.
	ErrInvalidToken = errors.New("auth: invalid token")

	// ErrNoSubject is returned when the context has no authenticated subject.
	ErrNoSubject = errors.New("auth: no subject in context")

	// ErrEmptySubject is returned when issuing or verifying a token whose
	// subject id is empty.
	ErrEmptySubject = errors.New("auth: empty subject id")

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
)
