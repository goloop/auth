package auth_test

import (
	"fmt"
	"time"

	"github.com/goloop/auth"
)

func ExampleTokenManager() {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tm := auth.NewTokenManager(secret,
		auth.WithIssuer("api"),
		auth.WithTTL(15*time.Minute),
	)

	token, err := tm.Issue(auth.Subject{
		ID:     "user-123",
		Email:  "user@example.com",
		Scopes: []string{"read", "write"},
	})
	if err != nil {
		panic(err)
	}

	sub, err := tm.Verify(token)
	if err != nil {
		panic(err)
	}
	fmt.Println(sub.ID, sub.HasScope("write"))
	// Output: user-123 true
}

func ExampleNewPBKDF2() {
	hasher := auth.NewPBKDF2()

	encoded, err := hasher.Hash([]byte("correct horse battery staple"))
	if err != nil {
		panic(err)
	}

	err = hasher.Verify(encoded, []byte("correct horse battery staple"))
	fmt.Println(err == nil)
	// Output: true
}
