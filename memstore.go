package auth

import (
	"context"
	"sync"
	"time"
)

// MemoryRefreshStore is a refresh store held in memory. It implements
// [RefreshStore] and all three optional halves, so it doubles as an executable
// statement of what those mean - particularly the grace window, whose rules
// are easier to read here than to describe.
//
// It is for tests and for single-process programs. Nothing is shared between
// processes and nothing survives a restart, so a service running more than one
// instance needs a store backed by something both instances can see.
//
// Every method is safe for concurrent use. Rotation takes the lock for the
// whole read-check-swap, which is the property that matters: a rotation split
// into separate reads and writes is where the interesting bugs live, because a
// revoked token can slip a successor in between the two.
type MemoryRefreshStore struct {
	mu sync.Mutex

	// tokens holds the live records by id, and bySubject indexes them so
	// RevokeAll has something to enumerate. The index is maintained in
	// Save, Rotate and Revoke together; missing any one of the three is
	// what leaves a store where signing out everywhere silently does not.
	tokens    map[string]RefreshToken
	bySubject map[string]map[string]bool

	// previous maps the id of a token that was just rotated to the record
	// that replaced it, so a client repeating a rotation it never saw the
	// answer to can be told apart from a replay of something older.
	previous map[string]rotatedRecord

	grace func() time.Duration
	now   func() time.Time
}

// rotatedRecord remembers one rotation for as long as the grace window lasts.
type rotatedRecord struct {
	subject string
	at      time.Time
}

// MemoryOption configures a MemoryRefreshStore.
type MemoryOption func(*MemoryRefreshStore)

// WithGrace sets how long after a rotation the token that was rotated is still
// accepted as a repeat rather than treated as reuse. Zero, the default,
// disables the window: every repeat is [ReusedStale].
//
// The window exists for a lost response, so it should be about as long as a
// client might take to retry - seconds, not minutes. Every second of it is a
// second in which a stolen token would also be accepted once.
func WithGrace(d time.Duration) MemoryOption {
	return func(s *MemoryRefreshStore) {
		s.grace = func() time.Duration { return d }
	}
}

// WithMemoryClock overrides the time source, for tests. A nil function is
// ignored.
func WithMemoryClock(now func() time.Time) MemoryOption {
	return func(s *MemoryRefreshStore) {
		if now != nil {
			s.now = now
		}
	}
}

// NewMemoryRefreshStore returns an empty in-memory store.
func NewMemoryRefreshStore(opts ...MemoryOption) *MemoryRefreshStore {
	s := &MemoryRefreshStore{
		tokens:    map[string]RefreshToken{},
		bySubject: map[string]map[string]bool{},
		previous:  map[string]rotatedRecord{},
		grace:     func() time.Duration { return 0 },
		now:       time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Compile-time proof that the reference store answers the whole contract.
var (
	_ RefreshStore           = (*MemoryRefreshStore)(nil)
	_ RefreshStoreGetter     = (*MemoryRefreshStore)(nil)
	_ RefreshStoreAllRevoker = (*MemoryRefreshStore)(nil)
	_ GraceRotator           = (*MemoryRefreshStore)(nil)
)

// Save stores a new refresh token.
func (s *MemoryRefreshStore) Save(_ context.Context, rt RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.save(rt)
	return nil
}

// save records a token and indexes it. The caller holds the lock.
func (s *MemoryRefreshStore) save(rt RefreshToken) {
	s.tokens[rt.ID] = rt
	if s.bySubject[rt.Subject] == nil {
		s.bySubject[rt.Subject] = map[string]bool{}
	}
	s.bySubject[rt.Subject][rt.ID] = true
}

// Get returns the record for an id, or ErrInvalidToken when there is none.
func (s *MemoryRefreshStore) Get(_ context.Context, id string) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rt, ok := s.tokens[id]
	if !ok {
		return RefreshToken{}, ErrInvalidToken
	}
	return rt, nil
}

// Rotate atomically revokes oldID and stores next, reporting ErrRefreshUsed
// when oldID was already rotated or revoked.
func (s *MemoryRefreshStore) Rotate(ctx context.Context, oldID string, next RefreshToken) error {
	_, err := s.RotateChecked(ctx, oldID, next)
	return err
}

// RotateChecked rotates and says what the attempt was. See [GraceRotator].
func (s *MemoryRefreshStore) RotateChecked(
	_ context.Context,
	oldID string,
	next RefreshToken,
) (RotateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, ok := s.tokens[oldID]
	if !ok {
		// The token is not current. It may still be the one rotated a
		// moment ago, which is a client repeating itself rather than an
		// attacker - but only within the window, and only if the rotation
		// is remembered.
		if rec, seen := s.previous[oldID]; seen {
			if window := s.grace(); window > 0 &&
				s.now().Sub(rec.at) <= window {
				return RotateResult{Status: PreviousWithinGrace}, ErrRefreshUsed
			}
		}
		return RotateResult{Status: ReusedStale}, ErrRefreshUsed
	}

	delete(s.tokens, oldID)
	if ids := s.bySubject[old.Subject]; ids != nil {
		delete(ids, oldID)
		if len(ids) == 0 {
			delete(s.bySubject, old.Subject)
		}
	}
	s.previous[oldID] = rotatedRecord{subject: old.Subject, at: s.now()}
	s.save(next)

	return RotateResult{Status: Rotated}, nil
}

// Revoke removes a refresh token by id. Revoking an id that is not there is
// not an error: the goal is that the token cannot be used, and it cannot.
func (s *MemoryRefreshStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A revoked token is never a repeat: whatever the client thinks, the
	// answer to presenting it again is reuse. This comes first because the
	// id has usually already been rotated away, and that is precisely the
	// case where a leftover grace record would let a revoked token back in.
	delete(s.previous, id)

	rt, ok := s.tokens[id]
	if !ok {
		return nil
	}
	delete(s.tokens, id)
	if ids := s.bySubject[rt.Subject]; ids != nil {
		delete(ids, id)
		if len(ids) == 0 {
			delete(s.bySubject, rt.Subject)
		}
	}
	return nil
}

// RevokeAll ends every session the subject has.
func (s *MemoryRefreshStore) RevokeAll(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id := range s.bySubject[subject] {
		delete(s.tokens, id)
	}
	delete(s.bySubject, subject)

	// Rotations remembered for this subject go too, or a token rotated just
	// before the revocation would still be inside its grace window.
	for id, rec := range s.previous {
		if rec.subject == subject {
			delete(s.previous, id)
		}
	}
	return nil
}
