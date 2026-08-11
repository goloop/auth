package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// plainStore implements only the required half of the contract, which is what
// every store written before the optional interfaces existed looks like.
type plainStore struct {
	rotateErr error
}

func (plainStore) Save(context.Context, RefreshToken) error { return nil }
func (s plainStore) Rotate(context.Context, string, RefreshToken) error {
	return s.rotateErr
}
func (plainStore) Revoke(context.Context, string) error { return nil }

func newToken(t *testing.T, subject string) RefreshToken {
	t.Helper()
	rt, _, err := NewRefreshToken(subject, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// Both stamps must come from one reading of the clock, or the difference
// between them is not the TTL that was asked for.
func TestRefreshTokenIssuedAt(t *testing.T) {
	before := time.Now().UTC()
	rt, _, err := NewRefreshToken("u1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()

	if rt.IssuedAt.Before(before) || rt.IssuedAt.After(after) {
		t.Errorf("IssuedAt = %v, want a time during the call", rt.IssuedAt)
	}
	if got := rt.ExpiresAt.Sub(rt.IssuedAt); got != time.Hour {
		t.Errorf("ExpiresAt - IssuedAt = %v, want exactly the ttl", got)
	}
}

// A store that implements none of the optional halves must keep working, and
// each helper must say so rather than pretend to have done the work.
func TestHelpersOnAPlainStore(t *testing.T) {
	s := plainStore{}
	ctx := context.Background()

	if _, err := Get(ctx, s, "id"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Get() = %v, want ErrUnsupported", err)
	}
	if err := RevokeAll(ctx, s, "u1"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("RevokeAll() = %v, want ErrUnsupported", err)
	}
}

// The conservative fallback is the whole safety argument: a store that cannot
// prove a repeat is benign must never be made to claim it is.
func TestRotateWithStatusFallback(t *testing.T) {
	ctx := context.Background()
	next := newToken(t, "u1")

	tests := []struct {
		name       string
		rotateErr  error
		wantStatus RotateStatus
		wantErr    error
	}{
		{"a normal rotation", nil, Rotated, nil},
		{"reuse", ErrRefreshUsed, ReusedStale, ErrRefreshUsed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RotateWithStatus(ctx, plainStore{rotateErr: tt.rotateErr}, "old", next)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("Status = %v, want %v", got.Status, tt.wantStatus)
			}
			if got.Status == PreviousWithinGrace {
				t.Error("a store that cannot prove a grace was credited with one")
			}
		})
	}
}

// A store that could not be reached has decided nothing, and ending sessions
// over a network blip would be the wrong reading of that silence.
func TestRotateWithStatusPassesInfrastructureErrors(t *testing.T) {
	boom := errors.New("dial tcp: connection refused")
	got, err := RotateWithStatus(context.Background(),
		plainStore{rotateErr: boom}, "old", newToken(t, "u1"))

	if !errors.Is(err, boom) {
		t.Fatalf("error = %v, want the store's own error", err)
	}
	if errors.Is(err, ErrRefreshUsed) || got.Status == ReusedStale {
		t.Error("an unreachable store was read as token reuse")
	}
	if got.Status != RotateUnknown {
		t.Errorf("Status = %v, want RotateUnknown - the zero value must not "+
			"read as success next to an error", got.Status)
	}
}

// The zero value of a security status must not spell success: a caller that
// forgets to check the error first should read "unknown", not "rotated".
func TestRotateStatusZeroValueIsNotSuccess(t *testing.T) {
	var zero RotateResult
	if zero.Status == Rotated {
		t.Fatal("the zero RotateStatus reads as a successful rotation")
	}
	if got := zero.Status.String(); got != "unknown" {
		t.Errorf("zero status renders as %q, want unknown", got)
	}
	if got := RotateStatus(99).String(); got != "unknown" {
		t.Errorf("an out-of-range status renders as %q, want unknown", got)
	}
}

// An expired token is dead, and a dead token neither rotates nor shows up in
// a session list - even for a caller that skipped the Verify step and went
// straight to the store.
func TestMemoryStoreEnforcesExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := NewMemoryRefreshStore(WithMemoryClock(func() time.Time { return now }))

	rt, _, err := NewRefreshToken("u1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, rt); err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Minute)

	res, err := RotateWithStatus(ctx, s, rt.ID, newToken(t, "u1"))
	if !errors.Is(err, ErrRefreshExpired) {
		t.Fatalf("rotating an expired token = %v, want ErrRefreshExpired - "+
			"expiry is the one revocation that happens without a call", err)
	}
	if errors.Is(err, ErrRefreshUsed) || res.Status == ReusedStale {
		t.Error("expiry was reported as reuse - an idle client is not a thief")
	}
	if res.Subject != "u1" {
		t.Errorf("Subject = %q, want the owner while the store still knows it",
			res.Subject)
	}

	if _, err := Get(ctx, s, rt.ID); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Get of an expired token = %v, want ErrInvalidToken", err)
	}
}

// Dead records must not accumulate for the life of the process: expired
// tokens and grace records past their window get reaped.
func TestMemoryStoreReapsDeadRecords(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := NewMemoryRefreshStore(
		WithGrace(10*time.Second),
		WithMemoryClock(func() time.Time { return now }),
	)

	// Fifty chains whose clients walk away: rotate once, never return.
	for range 50 {
		first := newToken(t, "u1")
		if err := s.Save(ctx, first); err != nil {
			t.Fatal(err)
		}
		if _, err := RotateWithStatus(ctx, s, first.ID, newToken(t, "u1")); err != nil {
			t.Fatal(err)
		}
	}

	// Well past every expiry and every grace window, one mutation triggers
	// the sweep.
	now = now.Add(2 * time.Hour)
	if err := s.Save(ctx, newToken(t, "sweeper")); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	tokens, previous, grace := len(s.tokens), len(s.previous), len(s.graceOf)
	s.mu.Unlock()

	if tokens > 1 {
		t.Errorf("tokens = %d after the sweep, want only the fresh one", tokens)
	}
	if previous != 0 || grace != 0 {
		t.Errorf("previous = %d, graceOf = %d after the sweep, want both empty",
			previous, grace)
	}
}

// With grace disabled there is no window to remember rotations for, so
// nothing may be kept about them at all.
func TestMemoryStoreKeepsNoGraceRecordsWhenDisabled(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRefreshStore()

	first := newToken(t, "u1")
	if err := s.Save(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateWithStatus(ctx, s, first.ID, newToken(t, "u1")); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	previous, grace := len(s.previous), len(s.graceOf)
	s.mu.Unlock()
	if previous != 0 || grace != 0 {
		t.Errorf("previous = %d, graceOf = %d with grace disabled, want both "+
			"empty - records nobody will read are records that only leak",
			previous, grace)
	}
}

// The subject travels with the result where the store still knows it, so the
// response to reuse has something to revoke by.
func TestRotateResultCarriesTheSubject(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRefreshStore(WithGrace(time.Minute))

	first := newToken(t, "u7")
	if err := s.Save(ctx, first); err != nil {
		t.Fatal(err)
	}

	res, err := RotateWithStatus(ctx, s, first.ID, newToken(t, "u7"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject != "u7" {
		t.Errorf("Subject on a rotation = %q, want u7", res.Subject)
	}

	res, _ = RotateWithStatus(ctx, s, first.ID, newToken(t, "u7"))
	if res.Status != PreviousWithinGrace || res.Subject != "u7" {
		t.Errorf("grace result = %+v, want the subject alongside", res)
	}
}

func TestMemoryStoreRotation(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRefreshStore()

	first := newToken(t, "u1")
	if err := s.Save(ctx, first); err != nil {
		t.Fatal(err)
	}

	got, err := Get(ctx, s, first.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.ID != first.ID || got.Subject != "u1" {
		t.Errorf("Get() = %+v, want the saved record", got)
	}

	second := newToken(t, "u1")
	res, err := RotateWithStatus(ctx, s, first.ID, second)
	if err != nil {
		t.Fatalf("RotateWithStatus() error = %v", err)
	}
	if res.Status != Rotated {
		t.Errorf("Status = %v, want Rotated", res.Status)
	}

	// The rotated token is gone and its successor is current.
	if _, err := Get(ctx, s, first.ID); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the rotated token is still current: %v", err)
	}
	if _, err := Get(ctx, s, second.ID); err != nil {
		t.Errorf("the successor is missing: %v", err)
	}
}

// Without a grace window every repeat is reuse, which is the safe default.
func TestMemoryStoreWithoutGrace(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRefreshStore()

	first := newToken(t, "u1")
	_ = s.Save(ctx, first)
	_, _ = RotateWithStatus(ctx, s, first.ID, newToken(t, "u1"))

	res, err := RotateWithStatus(ctx, s, first.ID, newToken(t, "u1"))
	if !errors.Is(err, ErrRefreshUsed) {
		t.Fatalf("error = %v, want ErrRefreshUsed", err)
	}
	if res.Status != ReusedStale {
		t.Errorf("Status = %v, want ReusedStale without a grace window", res.Status)
	}
}

// With one, the token rotated a moment ago is a client repeating itself; an
// older one is not, and neither is one presented after the window closes.
func TestMemoryStoreGraceWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	clock := func() time.Time { return now }
	s := NewMemoryRefreshStore(WithGrace(10*time.Second), WithMemoryClock(clock))

	first := newToken(t, "u1")
	_ = s.Save(ctx, first)
	second := newToken(t, "u1")
	_, _ = RotateWithStatus(ctx, s, first.ID, second)

	res, err := RotateWithStatus(ctx, s, first.ID, newToken(t, "u1"))
	if !errors.Is(err, ErrRefreshUsed) {
		t.Fatalf("error = %v, want ErrRefreshUsed even inside the window", err)
	}
	if res.Status != PreviousWithinGrace {
		t.Errorf("Status = %v, want PreviousWithinGrace", res.Status)
	}

	// The same token once the window has closed is reuse again.
	now = now.Add(time.Minute)
	res, _ = RotateWithStatus(ctx, s, first.ID, newToken(t, "u1"))
	if res.Status != ReusedStale {
		t.Errorf("Status = %v after the window, want ReusedStale", res.Status)
	}
}

// A revoked token is never a repeat, whatever the client believes: revocation
// is a decision, and the grace window must not undo it.
func TestMemoryStoreRevokeEndsGrace(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRefreshStore(WithGrace(time.Minute))

	first := newToken(t, "u1")
	_ = s.Save(ctx, first)
	_, _ = RotateWithStatus(ctx, s, first.ID, newToken(t, "u1"))
	_ = s.Revoke(ctx, first.ID)

	res, _ := RotateWithStatus(ctx, s, first.ID, newToken(t, "u1"))
	if res.Status == PreviousWithinGrace {
		t.Error("a revoked token was still inside its grace window")
	}
}

func TestMemoryStoreRevokeAll(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRefreshStore(WithGrace(time.Minute))

	var mine []RefreshToken
	for range 3 {
		rt := newToken(t, "u1")
		mine = append(mine, rt)
		_ = s.Save(ctx, rt)
	}
	other := newToken(t, "u2")
	_ = s.Save(ctx, other)

	// Rotate one so the index has to be right on both sides of a rotation.
	rotated := newToken(t, "u1")
	if _, err := RotateWithStatus(ctx, s, mine[0].ID, rotated); err != nil {
		t.Fatal(err)
	}

	if err := RevokeAll(ctx, s, "u1"); err != nil {
		t.Fatalf("RevokeAll() error = %v", err)
	}

	for _, rt := range append(mine[1:], rotated) {
		if _, err := Get(ctx, s, rt.ID); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("token %s survived RevokeAll", rt.ID)
		}
	}
	if _, err := Get(ctx, s, other.ID); err != nil {
		t.Errorf("another subject's session was revoked too: %v", err)
	}

	// The token rotated just before the revocation must not come back
	// through the grace window.
	res, _ := RotateWithStatus(ctx, s, mine[0].ID, newToken(t, "u1"))
	if res.Status == PreviousWithinGrace {
		t.Error("RevokeAll left a token inside its grace window")
	}
}

// Rotation is a read, a check and a swap, and it has to be one step: two
// clients racing the same token must not both get a successor.
func TestMemoryStoreRotationIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryRefreshStore()

	first := newToken(t, "u1")
	_ = s.Save(ctx, first)

	const racers = 16
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		wins     int
		statuses []RotateStatus
	)

	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			res, err := RotateWithStatus(ctx, s, first.ID, newToken(t, "u1"))
			mu.Lock()
			defer mu.Unlock()
			statuses = append(statuses, res.Status)
			if err == nil {
				wins++
			}
		}()
	}
	wg.Wait()

	if wins != 1 {
		t.Errorf("%d racers rotated the same token, want exactly 1", wins)
	}
	for _, st := range statuses {
		if st == PreviousWithinGrace {
			t.Error("a racer was credited with a grace on a store that has none")
		}
	}
}
