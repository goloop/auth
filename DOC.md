# auth - reference

`auth` is a set of authentication primitives. Full English reference; Ukrainian
in [DOC.UK.md](DOC.UK.md).

## Contents

- [Subjects and context](#subjects-and-context)
- [Passwords](#passwords)
- [Access tokens](#access-tokens)
- [Middleware](#middleware)
- [Refresh tokens](#refresh-tokens)
- [Dependencies](#dependencies)
- [Scope](#scope)

## Subjects and context

```go
type Subject struct {
	ID     string
	Email  string
	Roles  []string
	Scopes []string
}
```

`WithSubject(ctx, s)` stores a subject; `SubjectFrom(ctx)` retrieves it.
`HasRole`/`HasScope` are convenience checks. Middleware populates the subject;
handlers read it.

## Passwords

```go
type PasswordHasher interface {
	Hash(password []byte) (encoded string, err error)
	Verify(encoded string, password []byte) error
}
```

`NewPBKDF2(opts...)` returns a PBKDF2-HMAC-SHA256 hasher (standard library
`crypto/pbkdf2`). Defaults: 600000 iterations, 32-byte key, 16-byte random
salt. `WithIterations(n)` tunes the cost. The encoded form is
`pbkdf2-sha256$iterations$salt$digest` (base64), and `Verify` compares in
constant time. `Verify` also enforces parameter bounds, so a malformed or
hostile hash (a one-byte digest, a billion iterations) is rejected before any
key derivation runs rather than weakening the check or burning CPU.

The hasher also implements `Rehasher`:

```go
type Rehasher interface {
	NeedsRehash(encoded string) bool
}
```

Call `NeedsRehash` after a successful `Verify` to upgrade a stored hash when the
defaults strengthen:

```go
if err := h.Verify(stored, pw); err == nil {
	if rh, ok := h.(auth.Rehasher); ok && rh.NeedsRehash(stored) {
		newHash, _ := h.Hash(pw) // persist newHash
	}
}
```

To use Argon2id, implement `PasswordHasher` in your application (accepting the
`golang.org/x/crypto` dependency there); `auth` stays dependency-clean.

## Access tokens

```go
tm := auth.NewTokenManager(secret, opts...)
token, err := tm.Issue(subject)
sub, err := tm.Verify(token)
```

| Option | Effect | Default |
|--------|--------|---------|
| `WithIssuer(s)` | set and require iss | "" |
| `WithAudience(s)` | set and require aud | "" |
| `WithTTL(d)` | access-token lifetime | 15m |
| `WithLeeway(d)` | clock-skew tolerance on verify | 0 |
| `WithClock(fn)` | time source (testing) | time.Now |

The secret must be at least 32 bytes (the HS256 minimum); it is copied on
construction, so the caller may reuse or zero its slice. `Issue` encodes the
subject's ID as `sub` and its email/roles/scopes as custom claims. `Verify` (via
`goloop/jwt`) enforces HS256, a present `exp`, the issuer and audience, and
reconstructs the subject.

## Middleware

```go
func (m *TokenManager) Bearer(next http.Handler) http.Handler
func (m *TokenManager) Cookie(name string, next http.Handler) http.Handler
func (m *TokenManager) Protect(next http.Handler) http.Handler
func (m *TokenManager) ProtectScope(scope string, next http.Handler) http.Handler
func Require(next http.Handler) http.Handler
func RequireScope(scope string, next http.Handler) http.Handler
```

`Bearer` reads `Authorization: Bearer <token>`; `Cookie` reads a named cookie.
Both: a valid token sets the subject; a present but invalid token returns 401;
an absent token passes through, leaving enforcement to `Require`/`RequireScope`.
`Require` returns 401 without a subject; `RequireScope` returns 401 without a
subject or 403 without the scope.

`Protect` is `Bearer` + `Require` in one call, and `ProtectScope` is `Bearer` +
`RequireScope`. Prefer them for a route that must never be reached
unauthenticated: wrapping a handler with `Bearer` alone lets an anonymous
request through, which is an easy mistake to make.

## Refresh tokens

```go
rt, token, err := auth.NewRefreshToken(subject, ttl)
id, secret, err := auth.ParseRefreshToken(token)
err = rt.Verify(secret) // constant-time; checks expiry
```

`NewRefreshToken` returns a record to store (which holds only a SHA-256 hash of
the secret) and an opaque `id.secret` token for the client. The subject must be
non-empty (`ErrEmptySubject`) and the ttl positive (`ErrInvalidTTL`), so a token
is never minted without an owner or already expired. Verification looks the
record up by `id`, then checks the secret in constant time. The secret is
high-entropy random, so a plain hash is sufficient (unlike a password). `Verify`
reports a secret mismatch before expiry; collapse both into one opaque error if
you surface them, so an expired token cannot test a guessed secret.

```go
type RefreshStore interface {
	Save(ctx, RefreshToken) error
	Rotate(ctx, oldID string, next RefreshToken) error
	Revoke(ctx, id string) error
}
```

`Rotate` atomically revokes the old token and stores the new one. Implement the
store over your database.

## Dependencies

`auth` depends only on the standard library and `github.com/goloop/jwt` (a
sibling module) for HS256 token signing. It has no third-party dependencies.

## Scope

`auth` does not include: a user repository, RBAC schema, OAuth/OIDC, UI, email
sending or migrations. It provides crypto, tokens and middleware; you own the
user and refresh-token tables.
