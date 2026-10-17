package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestParseRefreshTokenRejectsOversizedInput(t *testing.T) {
	for _, token := range []string{"", strings.Repeat(".", 1<<16), strings.Repeat("a", 32) + ":" + strings.Repeat("b", 64)} {
		if _, _, err := ParseRefreshToken(token); !errors.Is(err, ErrMalformedRefresh) {
			t.Fatalf("got %v", err)
		}
	}
}
