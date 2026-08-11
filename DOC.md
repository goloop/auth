# auth - reference

`auth` is a set of authentication primitives. Full English reference; Ukrainian
in [DOC.UK.md](DOC.UK.md).

## Contents

- [Subjects and context](#subjects-and-context)
- [Passwords](#passwords)
- [Access tokens](#access-tokens)
- [Middleware](#middleware)
- [Refresh tokens](#refresh-tokens)
- [Writing a shared store](#writing-a-shared-store)
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

### Not saying who exists

A login that hashes only when the account exists answers "no such account" two
orders of magnitude faster than "wrong password", and identical error messages
do not hide it: the endpoint becomes a list of registered addresses, readable
with a stopwatch. `BurnVerify` spends the same work on the missing-account
branch:

```go
var decoy string // built once at startup: hasher.Hash(randomBytes)

u, err := repo.ByEmail(ctx, email)
if errors.Is(err, sql.ErrNoRows) {
    auth.BurnVerify(hasher, decoy, []byte(password))
    return ErrInvalidCredentials
}
```

The decoy must come from the same hasher with the same settings, or the two
branches cost different amounts again; `NeedsRehash` keeps a long-lived decoy
in step. With an empty decoy the helper hashes the password instead of silently
returning, so the misconfigured deployment is not the one where the oracle
reopens. It levels this one difference and nothing else - rate limiting and
uniform replies are still yours.

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

When you verify from storage you usually have the stored hash and expiry as
plain columns, not a `RefreshToken`. `VerifyRefreshSecret` checks against those
directly, so there is no need to rebuild the struct:

```go
id, secret, _ := auth.ParseRefreshToken(token)
rec, _ := store.RefreshByID(ctx, id) // your storage: hash + expiry
err := auth.VerifyRefreshSecret(rec.SecretHash, rec.ExpiresAt, secret)
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
store over your database. Every record carries `IssuedAt` alongside
`ExpiresAt`, both from one clock reading - which is what a session list and a
"revoke everything issued before the password change" both need.

### The optional halves

Three things a full refresh cycle needs are optional interfaces beside the
required contract, each with a package function that works either way and
returns `ErrUnsupported` when the store does not offer it:

```go
rec, err := auth.Get(ctx, store, id)          // RefreshStoreGetter
err = auth.RevokeAll(ctx, store, subject)     // RefreshStoreAllRevoker
res, err := auth.RotateWithStatus(ctx, store, oldID, next) // GraceRotator
```

`RotateWithStatus` reports what the attempt was:

| Status | Meaning | Respond with |
|---|---|---|
| `Rotated` | the token was current; a successor was issued | the new pair |
| `PreviousWithinGrace` | the immediately previous token, again, within the window | 401; do not punish |
| `ReusedStale` | an older or revoked token | revoke the family |
| `RotateUnknown` | no judgement; the error is the whole story | handle the error |

The zero value is `RotateUnknown`, deliberately: a result travels next to an
error, and a zero that read as success would reward exactly the caller who
checked the status first. `RotateResult.Subject` names the owner when the store
still knows it, so the response to `ReusedStale` has something to revoke by.

`PreviousWithinGrace` is not authentication. By the time it is reported the
previous record - its secret hash included - is gone, so nothing has verified
that the presented secret belongs to that id. It means "a client whose
connection dropped is repeating itself; answer 401 without revoking the
family", never "the bearer is who they claim".

On a store without `GraceRotator`, `RotateWithStatus` never invents a grace:
success maps to `Rotated` and `ErrRefreshUsed` to `ReusedStale`. A store that
cannot prove the difference is not made to assert it.

### The in-memory reference

`NewMemoryRefreshStore` implements the whole contract, optional halves
included, and enforces expiry: an expired token cannot be rotated
(`ErrRefreshExpired` - deliberately not the reuse signal, since an idle client
is not a thief), `Get` treats an expired record as absent, and dead records
are reaped. It is for tests and single-process programs; `WithGrace(d)` opens
the grace window, which is otherwise off.

## Writing a shared store

`MemoryRefreshStore` is for tests and single-process programs. A service with
more than one instance needs a store the instances share, and that is
application code - `auth` takes no dependency on a database or a cache.

What the contract asks for is not obvious from the interface alone, so here is
the whole of it, with the mistakes that keep being made.

**Rotation must be one atomic step.** Read, check and swap cannot be separate
round trips: two clients presenting the same token at once must produce exactly
one successor. In Redis that means a script rather than a sequence of commands:

```lua
-- KEYS[1] the token being rotated, KEYS[2] the successor,
-- KEYS[3] the subject index.
-- ARGV[1] the successor record, ARGV[2] old id, ARGV[3] new id, ARGV[4] ttl.
if redis.call('del', KEYS[1]) == 1 then
  redis.call('set', KEYS[2], ARGV[1], 'EX', ARGV[4])
  redis.call('srem', KEYS[3], ARGV[2])
  redis.call('sadd', KEYS[3], ARGV[3])
  redis.call('expire', KEYS[3], ARGV[4])
  return 1
end
return 0
```

The `del` returning 1 is both the check and the claim: whoever deletes the key
is the one rotation that wins, and everyone else gets 0 and `ErrRefreshUsed`.
Two commands - a `get` then a `del` - leave a window where both clients pass
the check.

**The subject index is maintained in three places.** `Save`, `Rotate` and
`Revoke` all change which tokens a subject has. Update it in two of the three
and `RevokeAll` reports success while a session keeps running - the worst
possible outcome for a button labelled "sign out everywhere". Give the index at
least the ttl of the longest token it holds, or it expires first and the
tokens outlive their own index.

**A store that could not be reached has decided nothing.** Return the
infrastructure error as itself. `ErrRefreshUsed` is a statement about the
token, and a caller that treats it as one will end every session the subject
has - over a network blip.

**An epoch instead of an index** is a reasonable alternative: one timestamp per
subject, and a token is dead if it was issued before it. It avoids the
three-place index entirely, and it has one trap. The epoch check has to happen
*inside* the same atomic operation as the swap. Checked separately, a revoked
token passes the check, swaps itself for a successor stamped after the epoch,
and the whole family comes back. Keep the epoch at nanosecond precision too: at
one-second resolution a token issued 200ms before a password reset compares as
newer and survives, and that is exactly the token that was in the attacker's
hands.

**Then prove it.** `auth/authtest` runs the contract against an
implementation, including the concurrency:

```go
func TestRedisStore(t *testing.T) {
    authtest.RefreshStore(t, func(t *testing.T) auth.RefreshStore {
        s := newRedisStore(t, redisURL)
        t.Cleanup(func() { s.flush() })
        return s
    })
}
```

It checks the optional interfaces the store implements and skips the ones it
does not. Every one of the mistakes above has a check, including the ones that
pass a single sequential run: a store whose rotation is not atomic fails on the
concurrency check, and one whose index misses `Rotate` fails on `RevokeAll`.

## Dependencies

`auth` depends only on the standard library and `github.com/goloop/jwt` (a
sibling module) for HS256 token signing. It has no third-party dependencies.

## Scope

`auth` does not include: a user repository, RBAC schema, OAuth/OIDC, UI, email
sending or migrations. It provides crypto, tokens and middleware; you own the
user and refresh-token tables.
