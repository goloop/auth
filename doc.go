// Package auth provides authentication primitives: password hashing, access
// tokens, HTTP middleware and refresh-token rotation. Standard library only,
// except for goloop/jwt (a sibling module) for token signing.
//
// It gives safe building blocks without becoming an identity platform: there is
// no user repository, no RBAC schema and no OAuth. Persistence and user
// management stay in your application.
//
// # Passwords
//
//	hasher := auth.NewPBKDF2()
//	encoded, err := hasher.Hash([]byte(password)) // store encoded
//	err = hasher.Verify(encoded, []byte(attempt)) // nil on match
//
// The encoded string is self-describing (algorithm, iterations, salt, digest).
// PasswordHasher is an interface, so Argon2id can be plugged in without
// changing callers.
//
// # Access tokens
//
//	tm := auth.NewTokenManager(secret,
//	    auth.WithIssuer("api"),
//	    auth.WithTTL(15*time.Minute),
//	)
//	token, err := tm.Issue(auth.Subject{ID: "user-1", Scopes: []string{"read"}})
//	sub, err := tm.Verify(token)
//
// Tokens are HS256 JWTs (see goloop/jwt): mandatory expiry, constant-time
// verification, strict algorithm. The secret must be at least 32 bytes;
// TokenManager.Check reports a missing or weak one up front, so a service can
// refuse to start instead of failing every login after a healthy-looking boot.
//
// # Middleware
//
//	h := tm.Bearer(auth.Require(handler))         // 401 without a valid token
//	h = tm.Cookie("session", auth.RequireScope("admin", handler))
//	sub, ok := auth.SubjectFrom(r.Context())
//
// Bearer/Cookie authenticate when a token is present (401 if invalid, pass
// through if absent); Require and RequireScope enforce presence and scope.
//
// # Refresh tokens
//
//	rt, token, err := auth.NewRefreshToken(userID, 30*24*time.Hour)
//	// store rt (only its hash), give token to the client
//	id, secret, err := auth.ParseRefreshToken(token)
//	// look rt up by id, then:
//	err = rt.Verify(secret)
//
// RefreshStore is the persistence contract (Save/Rotate/Revoke); the
// implementation lives in your application.
//
// # Refresh tokens and the optional half of the store contract
//
// RefreshStore is what a store must implement. Three things a full refresh
// cycle turns out to need are optional interfaces beside it, each with a
// package function that works either way:
//
//   - RefreshStoreGetter and Get, because verifying a presented token means
//     loading the record its id names;
//   - RefreshStoreAllRevoker and RevokeAll, the only answer to a stolen token
//     and to "sign me out everywhere". It needs an index from subject to token
//     ids, maintained in Save, Rotate AND Revoke - miss one of the three and
//     the button exists while the session survives it;
//   - GraceRotator and RotateWithStatus, which tell a client repeating a
//     rotation it never saw the answer to from an attacker replaying an older
//     token. Both present a token that is no longer current; only a store that
//     keeps enough history can tell them apart, and one that cannot is never
//     asked to guess - RotateWithStatus reports ReusedStale, never
//     PreviousWithinGrace.
//
// NewMemoryRefreshStore implements all of them. It is for tests and
// single-process programs, and it doubles as an executable statement of what
// the grace window means.
//
// A store that keeps a revocation epoch per subject rather than an index is a
// reasonable alternative, and it has one trap worth naming: the epoch check
// must happen inside the same atomic operation as the token swap. Checked
// separately, a revoked token can pass the check, swap itself for a successor
// stamped after the epoch, and bring the whole family back. Keep the epoch at
// nanosecond precision too, or a token issued a fraction of a second before a
// password reset compares as newer and survives - which is exactly the token
// that was in the attacker's hands.
//
// # Logging in without saying who exists
//
// BurnVerify spends a password check on the branch where the account does not
// exist, so that branch costs what a wrong password costs. Without it the two
// differ by two orders of magnitude, identical error messages notwithstanding,
// and the endpoint becomes a list of registered addresses. It is not the whole
// answer - rate limiting and uniform replies are still yours - and its
// documentation says so plainly.
//
// See DOC.md (English) and DOC.UK.md (Ukrainian) for the full reference.
package auth
