package auth

import (
	"net/http"
	"strings"
)

// Bearer authenticates requests carrying an "Authorization: Bearer <token>"
// header. A valid token places the subject in the context; a present but
// invalid token is rejected with 401; an absent header passes through
// unauthenticated, leaving enforcement to Require/RequireScope.
func (m *TokenManager) Bearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, hasBearer := bearerToken(r)
		if !hasBearer {
			// No bearer credential presented: continue unauthenticated.
			next.ServeHTTP(w, r)
			return
		}
		// A present but empty or invalid bearer credential is rejected rather
		// than silently treated as anonymous.
		sub, err := m.Verify(token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithSubject(r.Context(), sub)))
	})
}

// Cookie authenticates requests carrying the token in the named cookie. Its
// semantics match Bearer: valid sets the subject, invalid is 401, absent
// passes through.
func (m *TokenManager) Cookie(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(name)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		sub, err := m.Verify(c.Value)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithSubject(r.Context(), sub)))
	})
}

// Require rejects requests without an authenticated subject (401). Chain it
// after Bearer or Cookie.
func Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := SubjectFrom(r.Context()); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireScope rejects requests whose subject lacks the scope: 401 when there
// is no subject, 403 when the subject lacks the scope.
func RequireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, ok := SubjectFrom(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !sub.HasScope(scope) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken extracts the token from an Authorization: Bearer header. The
// second result reports whether a Bearer credential was presented at all
// (even an empty one), so the caller can reject a malformed Bearer header
// instead of treating it as anonymous. A different scheme or absent header
// returns ("", false).
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	const scheme = "Bearer"
	if strings.EqualFold(h, scheme) {
		return "", true // present but empty -> malformed
	}
	if len(h) > len(scheme) && strings.EqualFold(h[:len(scheme)], scheme) &&
		(h[len(scheme)] == ' ' || h[len(scheme)] == '\t') {
		return strings.TrimSpace(h[len(scheme)+1:]), true
	}
	return "", false // a different auth scheme: not a bearer credential
}
