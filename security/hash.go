package security

import (
	"crypto/sha256"
	"math/rand"
	"time"
)

type Salt [32]byte

func (s *Salt) Bytes() []byte {
	return s[:]
}

func NewSalt() *Salt {
	out := new(Salt)
	for i := 0; i < 16; i++ {
		r := rand.Int63()
		out[i] = byte(r)
		out[16+i] = byte(r >> 8)
	}
	return out
}

func Hash(input string, s *Salt) ([]byte, error) {
	length := len(input) + 32
	salt := s.Bytes()

	first := make([]byte, 0, length)
	first = append(first, []byte(input)...)
	first = append(first, salt...)

	hash := sha256.New()

	_, err := hash.Write(first)
	if err != nil {
		return nil, err
	}

	previous := make([]byte, 0, length+32)
	previous = append(previous, []byte(input)...)
	previous = append(previous, salt...)
	previous = hash.Sum(previous)

	for i := 0; i < 2048; i++ {
		hash.Reset()
		_, err = hash.Write(previous)
		if err != nil {
			return nil, err
		}

		previous = previous[:length]
		previous = hash.Sum(previous)
	}

	hash.Reset()
	_, err = hash.Write(previous)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
