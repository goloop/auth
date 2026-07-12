# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
