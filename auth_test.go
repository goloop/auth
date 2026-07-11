package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goloop/jwt"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

func TestPasswordHashVerify(t *testing.T) {
	h := NewPBKDF2(WithIterations(10000)) // low for test speed
	enc, err := h.Hash([]byte("s3cret"))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := h.Verify(enc, []byte("s3cret")); err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	if err := h.Verify(enc, []byte("wrong")); err != ErrPasswordMismatch {
		t.Fatalf("expected mismatch, got %v", err)
	}
	if err := h.Verify("bogus$hash", []byte("s3cret")); err != ErrInvalidHash {
		t.Fatalf("expected invalid hash, got %v", err)
	}
}

func TestPasswordEmptyDigestRejected(t *testing.T) {
	// Regression: an empty salt/digest must never verify any password.
	h := NewPBKDF2(WithIterations(10000))
	for _, enc := range []string{"pbkdf2-sha256$1$$", "pbkdf2-sha256$1$c2FsdA$"} {
		if err := h.Verify(enc, []byte("anything")); err != ErrInvalidHash {
			t.Fatalf("enc %q: expected ErrInvalidHash, got %v", enc, err)
		}
	}
}

func TestEmptySubjectRejected(t *testing.T) {
	tm := NewTokenManager(secret, WithTTL(time.Hour))
	if _, err := tm.Issue(Subject{}); err != ErrEmptySubject {
		t.Fatalf("expected ErrEmptySubject on Issue, got %v", err)
	}
	// Forge a valid-signature token with no subject and confirm Verify rejects it.
	tok, _ := jwt.Sign(jwt.Claims{ExpiresAt: time.Now().Add(time.Hour).Unix()}, secret)
	if _, err := tm.Verify(tok); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for empty sub, got %v", err)
	}
}

func TestBearerEmptyCredentialRejected(t *testing.T) {
	tm := NewTokenManager(secret, WithTTL(time.Hour))
	handler := tm.Bearer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := SubjectFrom(r.Context()); ok {
			t.Fatal("empty bearer must not authenticate")
		}
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty Bearer: expected 401, got %d", rec.Code)
	}
}

func TestPasswordSaltsDiffer(t *testing.T) {
	h := NewPBKDF2(WithIterations(10000))
	a, _ := h.Hash([]byte("same"))
	b, _ := h.Hash([]byte("same"))
	if a == b {
		t.Fatal("identical hashes: salt not random")
	}
}

func TestTokenIssueVerify(t *testing.T) {
	tm := NewTokenManager(secret, WithIssuer("api"), WithTTL(time.Hour))
	sub := Subject{ID: "user-1", Email: "u@example.com", Roles: []string{"admin"}, Scopes: []string{"read", "write"}}
	tok, err := tm.Issue(sub)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := tm.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.ID != "user-1" || got.Email != "u@example.com" {
		t.Fatalf("subject: %+v", got)
	}
	if !got.HasRole("admin") || !got.HasScope("write") {
		t.Fatalf("roles/scopes lost: %+v", got)
	}
}

func TestTokenExpiry(t *testing.T) {
	past := func() time.Time { return time.Now().Add(-2 * time.Hour) }
	tm := NewTokenManager(secret, WithTTL(time.Hour), WithClock(past))
	tok, _ := tm.Issue(Subject{ID: "x"})

	// Verify with the real clock: the token is long expired.
	tm2 := NewTokenManager(secret, WithTTL(time.Hour))
	if _, err := tm2.Verify(tok); err == nil {
		t.Fatal("expected expired token to fail")
	}
}

func TestTokenWrongSecret(t *testing.T) {
	tm := NewTokenManager(secret, WithTTL(time.Hour))
	tok, _ := tm.Issue(Subject{ID: "x"})
	other := NewTokenManager([]byte("another-secret-another-secret-00"), WithTTL(time.Hour))
	if _, err := other.Verify(tok); err == nil {
		t.Fatal("expected signature failure with wrong secret")
	}
}

func TestBearerMiddleware(t *testing.T) {
	tm := NewTokenManager(secret, WithTTL(time.Hour))
	tok, _ := tm.Issue(Subject{ID: "user-1", Scopes: []string{"read"}})

	var gotID string
	protected := tm.Bearer(Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := SubjectFrom(r.Context())
		gotID = s.ID
		w.WriteHeader(http.StatusOK)
	})))

	// Valid token.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotID != "user-1" {
		t.Fatalf("valid: code=%d id=%q", rec.Code, gotID)
	}

	// Missing token -> Require yields 401.
	rec = httptest.NewRecorder()
	protected.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing: code=%d", rec.Code)
	}

	// Invalid token -> Bearer yields 401.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not.a.token")
	protected.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid: code=%d", rec.Code)
	}
}

func TestRequireScope(t *testing.T) {
	tm := NewTokenManager(secret, WithTTL(time.Hour))
	tok, _ := tm.Issue(Subject{ID: "user-1", Scopes: []string{"read"}})

	handler := tm.Bearer(RequireScope("admin", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing scope, got %d", rec.Code)
	}
}

func TestCookieMiddleware(t *testing.T) {
	tm := NewTokenManager(secret, WithTTL(time.Hour))
	tok, _ := tm.Issue(Subject{ID: "user-1"})
	handler := tm.Cookie("session", Require(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie auth failed: %d", rec.Code)
	}
}

func TestRefreshToken(t *testing.T) {
	rt, token, err := NewRefreshToken("user-1", time.Hour)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	id, secret, err := ParseRefreshToken(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id != rt.ID {
		t.Fatalf("id mismatch: %q vs %q", id, rt.ID)
	}
	if err := rt.Verify(secret); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := rt.Verify("wrong-secret"); err != ErrRefreshMismatch {
		t.Fatalf("expected mismatch, got %v", err)
	}
	// The raw secret must not be stored.
	if rt.Hash == secret {
		t.Fatal("secret stored in clear")
	}
}

func TestRefreshExpiry(t *testing.T) {
	rt, token, err := NewRefreshToken("user-1", time.Hour)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, secret, _ := ParseRefreshToken(token)
	// Push the stored record into the past to simulate an expired token.
	rt.ExpiresAt = time.Now().Add(-time.Second)
	if err := rt.Verify(secret); err != ErrRefreshExpired {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestNewRefreshTokenValidation(t *testing.T) {
	if _, _, err := NewRefreshToken("", time.Hour); err != ErrEmptySubject {
		t.Fatalf("empty subject = %v, want ErrEmptySubject", err)
	}
	if _, _, err := NewRefreshToken("user-1", 0); err != ErrInvalidTTL {
		t.Fatalf("zero ttl = %v, want ErrInvalidTTL", err)
	}
	if _, _, err := NewRefreshToken("user-1", -time.Second); err != ErrInvalidTTL {
		t.Fatalf("negative ttl = %v, want ErrInvalidTTL", err)
	}
}

func TestParseRefreshMalformed(t *testing.T) {
	for _, s := range []string{"", "noseparator", ".secret", "id.", "id.secret.extra"} {
		if _, _, err := ParseRefreshToken(s); err != ErrMalformedRefresh {
			t.Fatalf("token %q: expected malformed, got %v", s, err)
		}
	}
}

var _ RefreshStore = (*memStore)(nil)

// memStore is a trivial in-memory RefreshStore for the interface test.
type memStore struct{ m map[string]RefreshToken }

func (s *memStore) Save(_ context.Context, rt RefreshToken) error {
	s.m[rt.ID] = rt
	return nil
}
func (s *memStore) Rotate(_ context.Context, oldID string, next RefreshToken) error {
	delete(s.m, oldID)
	s.m[next.ID] = next
	return nil
}
func (s *memStore) Revoke(_ context.Context, id string) error {
	delete(s.m, id)
	return nil
}

func TestPasswordVerifyBounds(t *testing.T) {
	h := NewPBKDF2(WithIterations(10000))
	// salt "salt" (4 bytes) is below the 8-byte floor; digest below 16 bytes;
	// an absurd iteration count is above the cap. All are rejected.
	bad := []string{
		"pbkdf2-sha256$10000$c2FsdA$" + b64("0123456789abcdef0123456789abcdef"),                                // salt too short
		"pbkdf2-sha256$10000$" + b64("0123456789abcdef") + "$" + b64("short"),                                  // digest too short
		"pbkdf2-sha256$99999999999$" + b64("0123456789abcdef") + "$" + b64("0123456789abcdef0123456789abcdef"), // iter over cap
	}
	for _, enc := range bad {
		if err := h.Verify(enc, []byte("pw")); err != ErrInvalidHash {
			t.Fatalf("enc %q: expected ErrInvalidHash, got %v", enc, err)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	strong := NewPBKDF2(WithIterations(600000))
	rh, ok := strong.(Rehasher)
	if !ok {
		t.Fatal("pbkdf2 hasher should implement Rehasher")
	}
	// A hash made with fewer iterations than the current setting needs a rehash.
	weakHash, _ := NewPBKDF2(WithIterations(10000)).Hash([]byte("pw"))
	if !rh.NeedsRehash(weakHash) {
		t.Fatal("weaker hash should need rehash")
	}
	// A hash made at the current setting does not.
	freshHash, _ := strong.Hash([]byte("pw"))
	if rh.NeedsRehash(freshHash) {
		t.Fatal("current-strength hash should not need rehash")
	}
	// A malformed hash needs a rehash.
	if !rh.NeedsRehash("garbage") {
		t.Fatal("malformed hash should need rehash")
	}
}

func TestWithIterationsCappedToVerifyCeiling(t *testing.T) {
	// Requesting more iterations than the verification ceiling must not produce
	// a hash the same hasher then rejects as out of bounds.
	h := NewPBKDF2(WithIterations(maxVerifyIterations + 5_000_000))
	enc, err := h.Hash([]byte("pw"))
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := h.Verify(enc, []byte("pw")); err != nil {
		t.Fatalf("verify capped-iteration hash: %v", err)
	}
}

func TestParseRefreshTokenBounds(t *testing.T) {
	_, tok, err := NewRefreshToken("user-1", time.Hour)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, _, err := ParseRefreshToken(tok); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	bad := []string{
		"",
		"onlyid",
		"a.b",          // too short, non-hex length
		tok + ".extra", // three parts
		strings.Repeat("a", 32) + "." + strings.Repeat("z", 64),   // right length, non-hex
		strings.Repeat("a", 31) + "." + strings.Repeat("a", 64),   // id one short
		strings.Repeat("a", 4000) + "." + strings.Repeat("a", 64), // oversized id
	}
	for _, b := range bad {
		if _, _, err := ParseRefreshToken(b); err != ErrMalformedRefresh {
			t.Errorf("ParseRefreshToken(%.16q...) = %v, want ErrMalformedRefresh", b, err)
		}
	}
}

func TestProtectRequiresToken(t *testing.T) {
	tm := NewTokenManager(secret, WithTTL(time.Hour))
	tok, _ := tm.Issue(Subject{ID: "user-1"})
	h := tm.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No token: 401 (the footgun Protect closes).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rec.Code)
	}
	// Valid token: pass.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token: got %d, want 200", rec.Code)
	}
}

// b64 raw-std-base64-encodes s, matching the encoding Hash uses.
func b64(s string) string {
	return base64.RawStdEncoding.EncodeToString([]byte(s))
}
