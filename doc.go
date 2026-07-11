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
// verification, strict algorithm.
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
// See DOC.md (English) and DOC.UK.md (Ukrainian) for the full reference.
package auth
