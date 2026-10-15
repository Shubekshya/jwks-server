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

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func signJWT(key Key, expiresAt time.Time) (string, error) {
	return signJWTWithUser(key, expiresAt, "fake-user")
}

func signJWTWithUser(key Key, expiresAt time.Time, username string) (string, error) {
	header := jwtHeader{Alg: "RS256", Typ: "JWT", Kid: key.KID}
	claims := jwtClaims{
		Sub: username,
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
