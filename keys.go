package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math/big"
	"sync"
	"time"
)

// Random source used for key generation.
var randReader io.Reader = rand.Reader

// Key stores an RSA key with its ID and expiration time.
type Key struct {
	KID        string
	PrivateKey *rsa.PrivateKey
	ExpiresAt  time.Time
}

// KeyStore holds the valid and expired keys.
type KeyStore struct {
	mu      sync.RWMutex
	valid   Key
	expired Key
}

// NewKeyStore creates one valid key and one expired key.
func NewKeyStore() (*KeyStore, error) {
	valid, err := generateKey(time.Now().Add(1 * time.Hour))
	if err != nil {
		return nil, err
	}

	expired, err := generateKey(time.Now().Add(-1 * time.Hour))
	if err != nil {
		return nil, err
	}

	return &KeyStore{valid: valid, expired: expired}, nil
}

// generateKey creates a 2048-bit RSA key with a unique kid.
func generateKey(expiresAt time.Time) (Key, error) {
	priv, err := rsa.GenerateKey(randReader, 2048)
	if err != nil {
		return Key{}, err
	}

	kid, err := newKID()
	if err != nil {
		return Key{}, err
	}

	return Key{
		KID:        kid,
		PrivateKey: priv,
		ExpiresAt:  expiresAt,
	}, nil
}

// newKID generates a random key ID.
func newKID() (string, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ValidKey returns the valid key.
func (ks *KeyStore) ValidKey() Key {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.valid
}

// ExpiredKey returns the expired key.
func (ks *KeyStore) ExpiredKey() Key {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.expired
}

// JWK represents an RSA public key in JWK format.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS contains the public keys returned by the JWKS endpoint.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// toJWK converts an RSA public key to JWK format.
func toJWK(k Key) JWK {
	pub := k.PrivateKey.PublicKey

	// Convert the exponent to bytes.
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	if len(eBytes) == 0 {
		eBytes = []byte{0}
	}

	return JWK{
		Kty: "RSA",
		Kid: k.KID,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

// unexpiredJWKS returns only keys that have not expired.
func (ks *KeyStore) unexpiredJWKS(now time.Time) JWKS {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keys := make([]JWK, 0, 1)
	if now.Before(ks.valid.ExpiresAt) {
		keys = append(keys, toJWK(ks.valid))
	}
	return JWKS{Keys: keys}
}
