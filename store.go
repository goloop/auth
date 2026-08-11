package auth

import (
	"context"
	"errors"
)

// The optional halves of the refresh-store contract.
//
// [RefreshStore] stays what it was, because every application that already
// implements it would otherwise have to change on the day it upgraded. What a
// full refresh cycle turned out to need beyond it is expressed as interfaces a
// store may also implement, each with a package function that works either
// way: [Get], [RevokeAll], [RotateWithStatus].
//
// A store that implements none of them keeps working exactly as before, and
// each helper degrades to the most conservative answer it can defend rather
// than the most convenient one.

// RefreshStoreGetter is implemented by stores that can load a token record by
// id.
//
// Verifying a presented token needs it: [ParseRefreshToken] splits the token
// into an id and a secret, and checking the secret means fetching the record
// that id names. Applications reached that conclusion independently often
// enough that the lookup belongs in the contract, even if it cannot be added
// to the required half without breaking the stores that exist.
type RefreshStoreGetter interface {
	// Get returns the record for an id. When there is no such record it
	// returns ErrInvalidToken, so a caller can tell "no such token" from
	// "the store could not answer" - which are the same thing to a user and
	// opposite things to an operator.
	Get(ctx context.Context, id string) (RefreshToken, error)
}

// RefreshStoreAllRevoker is implemented by stores that can end every session a
// subject has.
//
// Doing so requires an index from subject to token ids, and that index has to
// be maintained in Save, Rotate AND Revoke. Missing any one of the three
// leaves a store where the button exists and the session survives it, which is
// worse than not offering the button.
type RefreshStoreAllRevoker interface {
	RevokeAll(ctx context.Context, subject string) error
}

// GraceRotator is implemented by stores that can tell a client repeating a
// rotation from an attacker replaying an old token.
//
// The two look identical to a plain [RefreshStore.Rotate]: both present a
// token that is no longer current, and both get [ErrRefreshUsed]. But a client
// whose connection dropped before it read the response holds the token that
// was rotated a moment ago, while a stolen token is an older one. A store that
// keeps enough history to see the difference implements this; one that does
// not simply is not asked.
type GraceRotator interface {
	// RotateChecked rotates and reports what the attempt was. It returns
	// ErrRefreshUsed alongside both PreviousWithinGrace and ReusedStale:
	// neither issued a successor, and the status says how to react rather
	// than whether the call worked.
	//
	// A revoked token is never PreviousWithinGrace. Revocation is a
	// decision, and a grace window that outlives it hands a revoked token
	// one more use - which is the use an attacker needs.
	RotateChecked(ctx context.Context, oldID string, next RefreshToken) (RotateResult, error)
}

// RotateStatus says what a rotation attempt actually was.
type RotateStatus int

// The outcomes of a rotation.
//
// The zero value is deliberately RotateUnknown, not Rotated. A RotateResult
// travels next to an error, and the zero value is what a caller sees when the
// error is the whole story - an unreachable store, an expired token. A zero
// value that read as success would reward exactly the caller who forgot to
// check the error first.
const (
	// RotateUnknown means no rotation happened and the store made no
	// judgement about the token: the error alongside says why.
	RotateUnknown RotateStatus = iota

	// Rotated is a normal rotation: the presented token was current and a
	// successor was issued.
	Rotated

	// PreviousWithinGrace is the token that was rotated immediately before
	// the current one, presented again within the store's grace window. It
	// is the signature of a lost response, not of theft: the client never
	// saw the successor it was given. Only a store that can prove this
	// reports it.
	//
	// IT IS NOT AUTHENTICATION. By the time this is reported, the previous
	// record - its secret hash included - is gone, so nothing has checked
	// that the presented secret belongs to that id. All this status says is
	// "the id matches the immediately previous token": answer 401 without
	// punishing the family, and never treat the bearer as identified. An id
	// is not a secret, and a status that suppresses the theft response must
	// not also confer trust.
	PreviousWithinGrace

	// ReusedStale is a token that was rotated or revoked earlier than that,
	// or one the store cannot vouch for. It is the signal a stolen token
	// produces, and the reason to end every session the subject has.
	ReusedStale
)

// String renders the status for diagnostics.
func (s RotateStatus) String() string {
	switch s {
	case Rotated:
		return "rotated"
	case PreviousWithinGrace:
		return "previous_within_grace"
	case ReusedStale:
		return "reused_stale"
	case RotateUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// RotateResult is what a rotation attempt produced.
type RotateResult struct {
	Status RotateStatus

	// Subject names whose token this was, when the store can still say.
	// It exists for the response to ReusedStale: revoking the subject's
	// other sessions needs a subject, and by the time reuse is detected the
	// caller may have nothing to look one up with. Empty when the store no
	// longer knows - a plain RefreshStore never fills it.
	Subject string
}

// ErrUnsupported is returned by a helper whose store does not implement the
// optional interface the call needs. It is not a failure of the request: it
// says the capability was never there, so a caller can offer the feature only
// where it exists rather than discovering the gap at run time.
var ErrUnsupported = errors.New("auth: store does not support this operation")

// Get loads a token record by id, using the store's own lookup when it has
// one and returning [ErrUnsupported] when it does not.
func Get(ctx context.Context, s RefreshStore, id string) (RefreshToken, error) {
	g, ok := s.(RefreshStoreGetter)
	if !ok {
		return RefreshToken{}, ErrUnsupported
	}
	return g.Get(ctx, id)
}

// RevokeAll ends every session a subject has, using the store's own index when
// it has one and returning [ErrUnsupported] when it does not.
//
// There is no fallback: without an index there is no way to enumerate a
// subject's tokens, and quietly revoking nothing while returning nil would be
// the worst possible answer to "sign me out everywhere".
func RevokeAll(ctx context.Context, s RefreshStore, subject string) error {
	r, ok := s.(RefreshStoreAllRevoker)
	if !ok {
		return ErrUnsupported
	}
	return r.RevokeAll(ctx, subject)
}

// RotateWithStatus rotates a refresh token and says what the attempt was.
//
// A store that implements [GraceRotator] answers for itself. Any other store
// is rotated the ordinary way and its answer is read conservatively: success
// is [Rotated], and [ErrRefreshUsed] is [ReusedStale] - never
// [PreviousWithinGrace], because a store that cannot prove the difference must
// not be made to assert it. Handing out a grace nobody verified is a gift to
// whoever holds a stolen token; withholding one that was deserved costs a user
// a second login.
//
// Errors other than ErrRefreshUsed are returned as they are: a store that
// could not be reached has not decided anything, and treating infrastructure
// trouble as token reuse would end sessions over a network blip.
func RotateWithStatus(
	ctx context.Context,
	s RefreshStore,
	oldID string,
	next RefreshToken,
) (RotateResult, error) {
	if g, ok := s.(GraceRotator); ok {
		return g.RotateChecked(ctx, oldID, next)
	}

	err := s.Rotate(ctx, oldID, next)
	switch {
	case err == nil:
		// A plain store cannot say whose token it was; Subject stays empty
		// rather than guessed.
		return RotateResult{Status: Rotated}, nil
	case errors.Is(err, ErrRefreshUsed):
		return RotateResult{Status: ReusedStale}, err
	default:
		// The zero result: no rotation, no judgement, the error is the
		// whole story.
		return RotateResult{}, err
	}
}
