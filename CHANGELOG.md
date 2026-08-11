# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-08-11

Minor release: a security review of the v0.5.0-v0.6.0 refresh work, with the
four things it found fixed. One of them renumbers `RotateStatus` - read that
item before upgrading code that stores the numeric values (in-memory use is
unaffected).

### Fixed
- `MemoryRefreshStore` now enforces `ExpiresAt`. Until now an expired record
  stayed in the map forever, `Get` returned it, and `Rotate` happily issued a
  successor for it - so a caller that skipped the Verify step could extend a
  session the clock had ended a month earlier. Rotating an expired token now
  fails with `ErrRefreshExpired`, deliberately not `ErrRefreshUsed`: expiring
  is what every honest token eventually does, and answering with the reuse
  signal would revoke an idle user's other sessions as if they were a thief.
  `Get` treats an expired record as absent.
- The store also reaps: expired tokens and grace records past their window are
  dropped by a throttled sweep on mutations, and with grace disabled no
  rotation records are kept at all. Until now every expired token and every
  abandoned chain stayed in memory for the life of the process - and a long
  life is this store's stated use case.
- `BurnVerify` with an empty decoy now spends the cost by hashing the password
  instead of silently returning. The empty decoy is the misconfiguration the
  helper is most likely to meet - the decoy never built at startup - and a
  guard that quietly does nothing in exactly that case reopens the timing
  oracle only on the deployments that got the setup wrong, where nobody is
  measuring.

### Changed
- **`RotateUnknown` is the new zero value of `RotateStatus`**; `Rotated`,
  `PreviousWithinGrace` and `ReusedStale` shift up by one. The zero value used
  to be `Rotated`, so a `RotateResult{}` returned alongside an infrastructure
  error read as a successful rotation to any caller that checked the status
  before the error. Code comparing against the named constants is unaffected;
  only stored numeric values would notice, and the constants are days old.
  `String` on an unknown value now says "unknown" rather than "rotated".
- `PreviousWithinGrace` is documented for what it is and is not: the id
  matched the immediately previous token, and nothing verified the presented
  secret - the record it would be checked against is already gone. It means
  "answer 401 without punishing the family", never "the bearer is
  authenticated". An id is not a secret.

### Added
- `RotateResult.Subject` names whose token was involved, when the store can
  still say. It exists for the response to `ReusedStale`: revoking the
  subject's other sessions needs a subject, and at detection time the caller
  may have nothing left to look one up with. Empty when the store no longer
  knows; the fallback path never fills it.
- The conformance suite gained "an expired token cannot rotate". The exact
  error is the store's to choose - expired and reused are both refusals - but
  success is not among the options, and a store that extends dead sessions now
  fails its conformance run.

## [0.6.0] - 2026-08-11

Minor release: a way to prove a refresh store is correct.

### Added
- `auth/authtest` runs the refresh-store contract against an implementation:
  `authtest.RefreshStore(t, newStore)`. It checks what the interfaces promise,
  concurrency included, and adapts to the optional halves a store implements.
  The mistakes in this area are subtle, silent and repeated - an index updated
  in two of the three places that change it, a store outage reported as token
  reuse, a read and a swap that are not one step - and none of them fails an
  ordinary sequential test. It is a separate package so importing `auth` never
  pulls `testing` into a production binary.
- `DOC.md` and `DOC.UK.md` carry the recipe for a shared store: the atomic Lua
  rotation, why `del` returning 1 is both the check and the claim, the
  three-place index rule, the epoch alternative and the trap that comes with
  it, and the nanosecond precision that trap needs.

### Fixed
- `MemoryRefreshStore` kept a token inside its grace window after later
  rotations had moved past it, so a token two or more rotations old was
  reported as `PreviousWithinGrace` - a client repeating itself - when it could
  only have been a replay. Only the immediately previous token is in the window
  now, and revoking the current token ends its predecessor's grace as well.
  The conformance suite above found this in the reference implementation on its
  first run, which is a fair summary of why it exists.

### Changed
- The interface documentation now states what the conformance suite checks and
  the reference store already did: `Rotate` must be atomic and must not report
  an unreachable store as token reuse, `Revoke` is idempotent, `Get` returns
  `ErrInvalidToken` for an unknown id, and a revoked token is never
  `PreviousWithinGrace`.

## [0.5.0] - 2026-08-11

Minor release: the parts of a refresh cycle every application was writing for
itself. All additive - `RefreshStore` is unchanged, so existing stores keep
working untouched.

### Added
- `RefreshToken.IssuedAt`. The library already read the clock to compute
  `ExpiresAt` and threw the reading away, leaving every application that wants
  "sign out everywhere" or a session list to keep the same value alongside.
  Deriving it from `ExpiresAt` is not equivalent: the TTL lives in
  configuration and changes between issues. Both stamps now come from one
  reading, so `ExpiresAt.Sub(IssuedAt)` is exactly the ttl asked for.
- `RefreshStoreGetter` + `Get`, `RefreshStoreAllRevoker` + `RevokeAll`,
  `GraceRotator` + `RotateWithStatus`: the three things a full refresh cycle
  needs beyond the required contract, as optional interfaces so that no
  existing store has to change. Each helper returns `ErrUnsupported` rather
  than pretending to have done the work.
- `RotateStatus` distinguishes a client repeating a rotation whose response it
  never received from an attacker replaying an older token. Both present a
  token that is no longer current, so a plain `Rotate` cannot tell them apart.
  A store that cannot prove the difference is never made to assert it:
  `RotateWithStatus` falls back to `ReusedStale` and never invents a grace.
- `NewMemoryRefreshStore` implements the whole contract, optional halves
  included, with rotation as one locked read-check-swap. It is for tests and
  single-process programs, and it is where the grace window's rules are
  readable rather than described.
- `BurnVerify` spends a password check on the "no such account" branch. Without
  it that branch answers two orders of magnitude faster than a wrong password,
  and identical error messages do not hide it: the endpoint tells anyone with a
  stopwatch which addresses are registered. Its documentation is explicit that
  this is not the whole answer to enumeration.

### Documentation
- The package documentation states the invariants that cost people bugs: the
  subject index must be maintained in `Save`, `Rotate` and `Revoke` together,
  and an epoch-based store must check the epoch inside the same atomic
  operation as the swap - otherwise a revoked token rotates itself a successor
  stamped after the epoch and the family comes back.

## [0.3.0] - 2026-07-12

### Added
- `VerifyRefreshSecret(storedHash, expiresAt, secret)` verifies a refresh-token
  secret against a stored hash and expiry without rebuilding a `RefreshToken`.
  When verifying from a database you have the hash and expiry as plain columns,
  so this avoids constructing a throwaway struct just to call
  `RefreshToken.Verify`, which now delegates to it.

## [0.2.0] - 2026-07-11

### Added
- `TokenManager.Protect` and `ProtectScope` wrap a handler with the bearer
  middleware and the require/require-scope gate in one call.

### Fixed
- `WithIterations` caps the hash iteration count at the verify ceiling, so a
  hash can no longer be produced that the package's own `Verify` would reject.
- Refresh-token ids and secrets are validated for exact length and hex form on
  parse.

## [0.1.0]

First release: PBKDF2 password hashing, HMAC access tokens with a bearer
middleware, and refresh tokens.
