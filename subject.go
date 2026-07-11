package auth

import "context"

// Subject is the authenticated principal carried in a request context.
type Subject struct {
	ID     string
	Email  string
	Roles  []string
	Scopes []string
}

// HasRole reports whether the subject has the named role.
func (s Subject) HasRole(role string) bool { return contains(s.Roles, role) }

// HasScope reports whether the subject has the named scope.
func (s Subject) HasScope(scope string) bool { return contains(s.Scopes, scope) }

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// subjectKey is the private context key for the authenticated subject.
type subjectKey struct{}

// WithSubject returns a context carrying the subject.
func WithSubject(ctx context.Context, s Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, s)
}

// SubjectFrom returns the subject stored in the context, if any.
func SubjectFrom(ctx context.Context) (Subject, bool) {
	s, ok := ctx.Value(subjectKey{}).(Subject)
	return s, ok
}
