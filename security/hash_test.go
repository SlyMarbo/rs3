package security

import (
	"testing"
)

func BenchmarkSalt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewSalt()
	}
}

func BenchmarkHash(b *testing.B) {
	var salt *Salt
	var err error
	for i := 0; i < b.N; i++ {
		salt = NewSalt()
		_, err = Hash("password", salt)
		if err != nil {
			panic(err)
		}
	}
}
