package main

import (
	"errors"
	"testing"
	"time"
)

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

func TestNewKeyStore_PropagatesValidKeyError(t *testing.T) {
	withFailingRandReader(t)

	if _, err := OpenKeyStore(":memory:"); err == nil {
		t.Error("expected NewKeyStore to propagate a key-generation error")
	}
}

func testKeyStore(t *testing.T) (*KeyStore, error) {
	t.Helper()
	ks, err := OpenKeyStore(":memory:")
	if err == nil {
		t.Cleanup(func() { _ = ks.Close() })
	}
	return ks, err
}

func mustSigningKey(t *testing.T, ks *KeyStore, expired bool) Key {
	t.Helper()
	key, err := ks.signingKey(expired, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDecodeKey_InvalidPEM(t *testing.T) {
	if _, err := decodeKey(1, []byte("invalid-pem"), 0); err == nil {
		t.Error("expected error decoding invalid pem")
	}
}

func TestSaveKey_ErrorOnClosedDB(t *testing.T) {
	ks, err := testKeyStore(t)
	if err != nil {
		t.Fatal(err)
	}
	key := mustSigningKey(t, ks, false)
	_ = ks.Close()
	if _, err := ks.saveKey(key); err == nil {
		t.Error("expected error saving to closed db")
	}
}

func TestSigningKey_ErrorOnClosedDB(t *testing.T) {
	ks, err := testKeyStore(t)
	if err != nil {
		t.Fatal(err)
	}
	_ = ks.Close()
	if _, err := ks.signingKey(false, time.Now()); err == nil {
		t.Error("expected error querying closed db")
	}
}

func TestUnexpiredJWKS_ErrorOnClosedDB(t *testing.T) {
	ks, err := testKeyStore(t)
	if err != nil {
		t.Fatal(err)
	}
	_ = ks.Close()
	if _, err := ks.unexpiredJWKS(time.Now()); err == nil {
		t.Error("expected error querying closed db")
	}
}
