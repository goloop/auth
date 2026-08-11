[![Go Reference](https://img.shields.io/badge/godoc-reference-blue)](https://pkg.go.dev/github.com/goloop/auth) [![License](https://img.shields.io/badge/license-MIT-brightgreen)](https://github.com/goloop/auth/blob/master/LICENSE) [![Stay with Ukraine](https://img.shields.io/static/v1?label=Stay%20with&message=Ukraine%20♥&color=ffD700&labelColor=0057B8&style=flat)](https://u24.gov.ua/)

# auth

`auth` provides authentication primitives - password hashing, access tokens,
HTTP middleware and refresh-token rotation - without becoming an identity
platform. No user repository, no RBAC schema, no OAuth. Persistence and user
management stay in your application.

Standard library only, plus [`goloop/jwt`](https://github.com/goloop/jwt) for
token signing.

## Install

```bash
go get github.com/goloop/auth
```

## Passwords

```go
hasher := auth.NewPBKDF2() // PBKDF2-HMAC-SHA256, stdlib only

encoded, err := hasher.Hash([]byte(password)) // store encoded
err = hasher.Verify(encoded, []byte(attempt)) // nil on match
```

The encoded string is self-describing (`pbkdf2-sha256$iter$salt$digest`).
`PasswordHasher` is an interface, so you can plug in Argon2id without changing
callers.

## Access tokens

```go
tm := auth.NewTokenManager(secret,
	auth.WithIssuer("api"),
	auth.WithTTL(15*time.Minute),
)

token, err := tm.Issue(auth.Subject{ID: "user-1", Scopes: []string{"read"}})
sub, err := tm.Verify(token)
```

Tokens are HS256 JWTs: mandatory expiry, constant-time verification, strict
algorithm. The secret must be at least 32 bytes; `tm.Check()` reports a missing
or weak one up front, so a service can refuse to start instead of failing every
login after a healthy-looking boot.

## Middleware

```go
h := tm.Bearer(auth.Require(handler))                    // 401 without a valid token
h = tm.Cookie("session", auth.RequireScope("admin", handler))

sub, ok := auth.SubjectFrom(r.Context())
```

`Bearer`/`Cookie` authenticate when a token is present (401 if invalid, pass
through if absent); `Require` and `RequireScope` enforce presence and scope.

## Refresh tokens

```go
rt, token, err := auth.NewRefreshToken(userID, 30*24*time.Hour)
// store rt (only its hash), give token to the client

id, secret, err := auth.ParseRefreshToken(token)
// look rt up by id, then:
err = rt.Verify(secret)
```

`RefreshStore` is the persistence contract (`Save`/`Rotate`/`Revoke`); implement
it over your database.

## Scope

`auth` does not include a user repository, RBAC schema, OAuth/OIDC, email
sending or migrations. It gives you crypto and middleware; you keep control of
your user and token tables.

## Documentation

- English reference: [DOC.md](DOC.md)
- Ukrainian reference: [DOC.UK.md](DOC.UK.md)

## License

MIT - see [LICENSE](LICENSE).
