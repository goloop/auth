package auth_test

import (
	"testing"
	"time"

	"github.com/goloop/auth"
	"github.com/goloop/auth/authtest"
)

// The reference store has to pass the suite that describes the contract, or
// one of the two is wrong. Running it here also keeps the suite itself honest:
// a check that nothing can satisfy is not a check.
func TestMemoryRefreshStoreConformance(t *testing.T) {
	authtest.RefreshStore(t, func(t *testing.T) auth.RefreshStore {
		return auth.NewMemoryRefreshStore()
	})
}

// The same store with a grace window open, so the grace checks exercise the
// branch that reports PreviousWithinGrace rather than the one that declines to.
func TestMemoryRefreshStoreConformanceWithGrace(t *testing.T) {
	authtest.RefreshStore(t, func(t *testing.T) auth.RefreshStore {
		return auth.NewMemoryRefreshStore(auth.WithGrace(time.Minute))
	})
}
