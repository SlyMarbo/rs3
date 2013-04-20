package security

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"log"
)

type Salt [32]byte

func (s *Salt) Bytes() []byte {
	return s[:]
}

func NewSalt() *Salt {
	out := new(Salt)
	_, err := io.ReadFull(rand.Reader, out[:])
	if err != nil {
		log.Panic("Error: failed to create random data for salt.")
	}
	return out
}

func Hash(input string, s *Salt) ([]byte, error) {
	if s == nil {
		return nil, errors.New("Error: nil Salt provided.")
	}
	
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
