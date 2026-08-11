// Package authtest checks an implementation of the goloop/auth store
// interfaces against the contract those interfaces describe.
//
// It exists because refresh-token rotation is a place where the mistakes are
// subtle, silent and repeated. The same handful of them show up in
// independently written stores: an index that is updated in two of the three
// places that change it, a store outage reported as token reuse, a read and a
// swap that are not one step, a revoked token that a grace window quietly
// brings back. None of them fails a normal test run. All of them are worth an
// incident.
//
//	func TestMyStore(t *testing.T) {
//	    authtest.RefreshStore(t, func(t *testing.T) auth.RefreshStore {
//	        return newMyStore(t) // fresh, empty, cleaned up by t
//	    })
//	}
//
// The suite discovers which optional interfaces the store implements and
// checks each of them too, so a store that offers only the required half is
// tested for the required half and not penalised for the rest.
//
// It is a separate package so that importing goloop/auth never drags testing
// into a production binary.
package authtest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/goloop/auth"
)

// ttl is the lifetime given to tokens minted by the suite. It only has to
// outlast the test.
const ttl = time.Hour

// NewStore builds a store for one subtest: empty, and cleaned up through t.
// A fresh store per subtest keeps one check's tokens out of another's
// assertions.
type NewStore func(t *testing.T) auth.RefreshStore

// RefreshStore runs the conformance suite against the store newStore builds.
//
// Every failure names the invariant that broke and why it matters, so the
// output is a description of the bug rather than a diff of two values.
func RefreshStore(t *testing.T, newStore NewStore) {
	t.Helper()

	t.Run("rotate issues a successor", func(t *testing.T) {
		checkRotate(t, newStore(t))
	})
	t.Run("a token rotates only once", func(t *testing.T) {
		checkRotateOnce(t, newStore(t))
	})
	t.Run("an unknown token cannot rotate", func(t *testing.T) {
		checkUnknown(t, newStore(t))
	})
	t.Run("a revoked token cannot rotate", func(t *testing.T) {
		checkRevoked(t, newStore(t))
	})
	t.Run("revoking twice is not an error", func(t *testing.T) {
		checkRevokeIsIdempotent(t, newStore(t))
	})
	t.Run("rotation is atomic", func(t *testing.T) {
		checkAtomic(t, newStore(t))
	})
	t.Run("an expired token cannot rotate", func(t *testing.T) {
		checkExpired(t, newStore(t))
	})

	// The optional halves, each checked only where it is offered.
	store := newStore(t)
	if _, ok := store.(auth.RefreshStoreGetter); ok {
		t.Run("get", func(t *testing.T) { checkGetter(t, newStore(t)) })
	}
	if _, ok := store.(auth.RefreshStoreAllRevoker); ok {
		t.Run("revoke all", func(t *testing.T) { checkRevokeAll(t, newStore(t)) })
	}
	if _, ok := store.(auth.GraceRotator); ok {
		t.Run("grace", func(t *testing.T) { checkGrace(t, newStore(t)) })
	}
}

// token mints a refresh token for a subject, failing the test if it cannot.
func token(t *testing.T, subject string) auth.RefreshToken {
	t.Helper()
	rt, _, err := auth.NewRefreshToken(subject, ttl)
	if err != nil {
		t.Fatalf("auth.NewRefreshToken: %v", err)
	}
	return rt
}

// save stores a token, failing the test if the store refuses.
func save(t *testing.T, s auth.RefreshStore, rt auth.RefreshToken) {
	t.Helper()
	if err := s.Save(context.Background(), rt); err != nil {
		t.Fatalf("Save of a fresh token failed: %v", err)
	}
}

func checkRotate(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()
	first := token(t, "u1")
	save(t, s, first)

	second := token(t, "u1")
	if err := s.Rotate(ctx, first.ID, second); err != nil {
		t.Fatalf("Rotate of a current token failed: %v", err)
	}

	// The successor has to be current in its turn, or the chain stops after
	// one link and every second refresh logs the user out.
	third := token(t, "u1")
	if err := s.Rotate(ctx, second.ID, third); err != nil {
		t.Errorf("Rotate of the successor failed: %v - a rotation must leave "+
			"the new token usable, or the chain breaks after one step", err)
	}
}

func checkRotateOnce(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()
	first := token(t, "u1")
	save(t, s, first)

	if err := s.Rotate(ctx, first.ID, token(t, "u1")); err != nil {
		t.Fatalf("the first Rotate failed: %v", err)
	}

	err := s.Rotate(ctx, first.ID, token(t, "u1"))
	if !errors.Is(err, auth.ErrRefreshUsed) {
		t.Errorf("rotating an already rotated token = %v, want "+
			"auth.ErrRefreshUsed - this is the signal a replayed token "+
			"produces, and without it token theft is indistinguishable "+
			"from ordinary use", err)
	}
}

func checkUnknown(t *testing.T, s auth.RefreshStore) {
	err := s.Rotate(context.Background(), "no-such-id", token(t, "u1"))
	if !errors.Is(err, auth.ErrRefreshUsed) {
		t.Errorf("rotating an unknown id = %v, want auth.ErrRefreshUsed - an "+
			"id the store never had is not a token it can honour", err)
	}
}

func checkRevoked(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()
	rt := token(t, "u1")
	save(t, s, rt)

	if err := s.Revoke(ctx, rt.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	err := s.Rotate(ctx, rt.ID, token(t, "u1"))
	if !errors.Is(err, auth.ErrRefreshUsed) {
		t.Errorf("rotating a revoked token = %v, want auth.ErrRefreshUsed - "+
			"revocation that a rotation can undo is not revocation", err)
	}
}

func checkRevokeIsIdempotent(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()
	rt := token(t, "u1")
	save(t, s, rt)

	if err := s.Revoke(ctx, rt.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	if err := s.Revoke(ctx, rt.ID); err != nil {
		t.Errorf("revoking twice = %v, want nil - the goal is that the token "+
			"cannot be used, and after the first call it cannot; signing out "+
			"is not a place for a race to surface", err)
	}
	if err := s.Revoke(ctx, "no-such-id"); err != nil {
		t.Errorf("revoking an unknown id = %v, want nil", err)
	}
}

// checkAtomic is the check the others exist to support. Read, check and swap
// have to be one step; a store that splits them lets two clients presenting
// the same token both receive a successor, which is precisely the race a
// stolen token needs to survive undetected.
func checkAtomic(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()
	first := token(t, "u1")
	save(t, s, first)

	const racers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
		other   []error
	)

	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			err := s.Rotate(ctx, first.ID, token(t, "u1"))

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
			case errors.Is(err, auth.ErrRefreshUsed):
			default:
				other = append(other, err)
			}
		}()
	}
	wg.Wait()

	if winners != 1 {
		t.Errorf("%d of %d concurrent rotations of one token succeeded, want "+
			"exactly 1 - read, check and swap have to be a single atomic "+
			"step, or a stolen token races a legitimate one and both win",
			winners, racers)
	}
	for _, err := range other {
		t.Errorf("a losing rotation returned %v, want auth.ErrRefreshUsed", err)
	}
}

// checkExpired proves the store will not extend a session the clock already
// ended. Expiry is the one revocation that happens without anyone calling
// Revoke, and the caller most likely to skip the Verify step is the one whose
// store must catch it. The exact error is the store's to choose - expired and
// reused are both refusals - but success is not among the options.
func checkExpired(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()

	rt, _, err := auth.NewRefreshToken("u1", time.Nanosecond)
	if err != nil {
		t.Fatalf("auth.NewRefreshToken: %v", err)
	}
	save(t, s, rt)

	// The nanosecond has passed by now on any clock, but leave no room for
	// a coarse one.
	time.Sleep(10 * time.Millisecond)

	if err := s.Rotate(ctx, rt.ID, token(t, "u1")); err == nil {
		t.Error("an expired token was rotated into a fresh session - the " +
			"store extended a session the clock had already ended")
	}
}

func checkGetter(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()
	rt := token(t, "u1")
	save(t, s, rt)

	got, err := auth.Get(ctx, s, rt.ID)
	if err != nil {
		t.Fatalf("Get of a saved token failed: %v", err)
	}
	if got.ID != rt.ID || got.Subject != rt.Subject || got.Hash != rt.Hash {
		t.Errorf("Get returned %+v, want the record that was saved - the hash "+
			"is what a presented secret is checked against, so a store that "+
			"loses it cannot verify anything", got)
	}

	if _, err := auth.Get(ctx, s, "no-such-id"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Get of an unknown id = %v, want auth.ErrInvalidToken - a "+
			"caller has to tell 'no such token' from 'the store could not "+
			"answer', which are the same to a user and opposite to an "+
			"operator", err)
	}

	// After a rotation the old record is gone and the new one is there.
	next := token(t, "u1")
	if err := s.Rotate(ctx, rt.ID, next); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}
	if _, err := auth.Get(ctx, s, rt.ID); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Get of a rotated token = %v, want auth.ErrInvalidToken", err)
	}
	if _, err := auth.Get(ctx, s, next.ID); err != nil {
		t.Errorf("Get of the successor failed: %v", err)
	}

	if err := s.Revoke(ctx, next.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	if _, err := auth.Get(ctx, s, next.ID); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("Get of a revoked token = %v, want auth.ErrInvalidToken", err)
	}
}

func checkRevokeAll(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()

	saved := token(t, "u1")
	save(t, s, saved)

	// A second token that arrives through Rotate rather than Save. This is
	// the one that catches the usual bug: an index maintained in Save and
	// Revoke but not in Rotate leaves rotated tokens invisible to RevokeAll,
	// so the button reports success and the session lives on.
	seed := token(t, "u1")
	save(t, s, seed)
	rotated := token(t, "u1")
	if err := s.Rotate(ctx, seed.ID, rotated); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	stranger := token(t, "u2")
	save(t, s, stranger)

	if err := auth.RevokeAll(ctx, s, "u1"); err != nil {
		t.Fatalf("RevokeAll failed: %v", err)
	}

	for name, rt := range map[string]auth.RefreshToken{
		"a saved token":   saved,
		"a rotated token": rotated,
	} {
		err := s.Rotate(ctx, rt.ID, token(t, "u1"))
		if !errors.Is(err, auth.ErrRefreshUsed) {
			t.Errorf("%s survived RevokeAll (Rotate = %v) - the subject index "+
				"has to be maintained in Save, Rotate and Revoke alike, or "+
				"signing out everywhere leaves sessions running", name, err)
		}
	}

	// Another subject is untouched: RevokeAll ends one person's sessions,
	// not everyone's.
	if err := s.Rotate(ctx, stranger.ID, token(t, "u2")); err != nil {
		t.Errorf("another subject's token was revoked too (Rotate = %v)", err)
	}
}

func checkGrace(t *testing.T, s auth.RefreshStore) {
	ctx := context.Background()

	first := token(t, "u1")
	save(t, s, first)
	second := token(t, "u1")

	res, err := auth.RotateWithStatus(ctx, s, first.ID, second)
	if err != nil {
		t.Fatalf("RotateWithStatus of a current token failed: %v", err)
	}
	if res.Status != auth.Rotated {
		t.Errorf("a normal rotation reported %v, want Rotated", res.Status)
	}

	// Repeating the rotation just performed is either benign or reuse,
	// depending on whether this store keeps a window; both are legal. What
	// is not legal is reporting it without ErrRefreshUsed, because no
	// successor was issued and a caller that reads only the error would
	// carry on as if one had been.
	res, err = auth.RotateWithStatus(ctx, s, first.ID, token(t, "u1"))
	if !errors.Is(err, auth.ErrRefreshUsed) {
		t.Errorf("repeating a rotation = %v, want auth.ErrRefreshUsed "+
			"whatever the status", err)
	}
	if res.Status == auth.Rotated {
		t.Errorf("repeating a rotation reported Rotated - no successor was " +
			"issued, so it was not a rotation")
	}

	// A token two rotations back is not the one a lost response would
	// return, so it can only be reuse.
	third := token(t, "u1")
	if _, err := auth.RotateWithStatus(ctx, s, second.ID, third); err != nil {
		t.Fatalf("rotating the successor failed: %v", err)
	}
	res, _ = auth.RotateWithStatus(ctx, s, first.ID, token(t, "u1"))
	if res.Status == auth.PreviousWithinGrace {
		t.Errorf("a token two rotations old reported PreviousWithinGrace - " +
			"only the immediately previous token can be a client repeating " +
			"itself; anything older is a replay")
	}

	// And a revoked token is never within grace, whatever the window says.
	// Revocation is a decision, and a window that outlives it hands a
	// revoked token one more use - the use an attacker needs.
	fresh := token(t, "u1")
	save(t, s, fresh)
	successor := token(t, "u1")
	if _, err := auth.RotateWithStatus(ctx, s, fresh.ID, successor); err != nil {
		t.Fatalf("rotation before revocation failed: %v", err)
	}
	if err := s.Revoke(ctx, fresh.ID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	res, _ = auth.RotateWithStatus(ctx, s, fresh.ID, token(t, "u1"))
	if res.Status == auth.PreviousWithinGrace {
		t.Error("a revoked token reported PreviousWithinGrace - a grace " +
			"window that outlives revocation gives a revoked token one more " +
			"use, which is the one that matters")
	}
}
