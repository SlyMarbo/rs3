package server

import (
	"testing"
)

func TestServer(t *testing.T) {
	err := ListenAndServe(":2000", "gibberish.pem", "gibberish.key")
	if err == nil {
		t.Error("Failed to detect non-existant certificate.")
		t.Fail()
	}
}
