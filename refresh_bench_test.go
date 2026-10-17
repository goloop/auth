package auth

import (
	"strings"
	"testing"
)

func BenchmarkParseRefreshToken(b *testing.B) {
	for _, tt := range []struct{ name, token string }{
		{"valid", strings.Repeat("a", 32) + "." + strings.Repeat("b", 64)},
		{"oversized", strings.Repeat(".", 1<<16)},
	} {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _, _ = ParseRefreshToken(tt.token)
			}
		})
	}
}
