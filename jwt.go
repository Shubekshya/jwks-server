package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// jwtHeader contains the JWT header fields.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// jwtClaims contains the claims used in the token.
type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// base64URLEncode encodes data using base64url without padding.
func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// signJWT creates and signs an RS256 JWT.
func signJWT(key Key, expiresAt time.Time) (string, error) {
	header := jwtHeader{Alg: "RS256", Typ: "JWT", Kid: key.KID}
	claims := jwtClaims{
		Sub: "fake-user",
		Iat: time.Now().Unix(),
		Exp: expiresAt.Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signingInput := base64URLEncode(headerJSON) + "." + base64URLEncode(claimsJSON)

	hashed := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(randReader, key.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signingInput + "." + base64URLEncode(sig), nil
}
