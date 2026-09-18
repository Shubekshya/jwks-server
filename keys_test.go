package main

import (
	"errors"
	"testing"
	"time"
)

// failingReader is used to test error handling.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated randomness failure")
}

func withFailingRandReader(t *testing.T) {
	t.Helper()
	orig := randReader
	randReader = failingReader{}
	t.Cleanup(func() { randReader = orig })
}

func TestGenerateKey_PropagatesRSAError(t *testing.T) {
	withFailingRandReader(t)

	if _, err := generateKey(time.Now()); err == nil {
		t.Error("expected an error when the RSA key generator can't read randomness")
	}
}

func TestNewKID_PropagatesReadError(t *testing.T) {
	withFailingRandReader(t)

	if _, err := newKID(); err == nil {
		t.Error("expected an error when randReader fails")
	}
}

func TestNewKeyStore_PropagatesValidKeyError(t *testing.T) {
	withFailingRandReader(t)

	if _, err := NewKeyStore(); err == nil {
		t.Error("expected NewKeyStore to propagate a key-generation error")
	}
}
