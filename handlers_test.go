package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*httptest.Server, *KeyStore) {
	t.Helper()

	keys, err := testKeyStore(t)
	if err != nil {
		t.Fatalf("testKeyStore(t) error = %v", err)
	}

	srv := NewServer(keys)
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	return ts, keys
}

func TestNewKeyStore_GeneratesDistinctKeys(t *testing.T) {
	keys, err := testKeyStore(t)
	if err != nil {
		t.Fatalf("testKeyStore(t) error = %v", err)
	}

	valid := mustSigningKey(t, keys, false)
	expired := mustSigningKey(t, keys, true)

	if valid.KID == expired.KID {
		t.Errorf("expected distinct kids, both were %q", valid.KID)
	}
	if valid.KID == "" || expired.KID == "" {
		t.Error("expected non-empty kids")
	}
	if !valid.ExpiresAt.After(time.Now()) {
		t.Error("valid key should expire in the future")
	}
	if !expired.ExpiresAt.Before(time.Now()) {
		t.Error("expired key should already be expired")
	}
}

func TestUnexpiredJWKS_OnlyContainsValidKey(t *testing.T) {
	_, keys := newTestServer(t)

	jwks, err := keys.unexpiredJWKS(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected exactly 1 key in JWKS, got %d", len(jwks.Keys))
	}

	got := jwks.Keys[0]
	valid := mustSigningKey(t, keys, false)
	expired := mustSigningKey(t, keys, true)

	if got.Kid != valid.KID {
		t.Errorf("JWKS key id = %q, want valid key id %q", got.Kid, valid.KID)
	}
	if got.Kid == expired.KID {
		t.Error("expired key id leaked into JWKS")
	}
	if got.Kty != "RSA" || got.Alg != "RS256" || got.Use != "sig" {
		t.Errorf("unexpected JWK metadata: %+v", got)
	}
}

func TestToJWK_ModulusAndExponentDecodeToRealKey(t *testing.T) {
	_, keys := newTestServer(t)
	valid := mustSigningKey(t, keys, false)
	jwk := toJWK(valid)

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if n.Cmp(valid.PrivateKey.N) != 0 {
		t.Error("decoded modulus does not match original key")
	}
	if int(e.Int64()) != valid.PrivateKey.E {
		t.Error("decoded exponent does not match original key")
	}
}

func TestJWKSEndpoint_ReturnsOnlyUnexpiredKey(t *testing.T) {
	ts, keys := newTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode body: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != mustSigningKey(t, keys, false).KID {
		t.Errorf("kid = %q, want %q", jwks.Keys[0].Kid, mustSigningKey(t, keys, false).KID)
	}
	for _, k := range jwks.Keys {
		if k.Kid == mustSigningKey(t, keys, true).KID {
			t.Error("expired key must not appear in JWKS")
		}
	}
}

func TestJWKSEndpoint_RejectsNonGET(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Post(ts.URL+"/.well-known/jwks.json", "application/json", nil)
	if err != nil {
		t.Fatalf("POST jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestAuthEndpoint_ValidToken(t *testing.T) {
	ts, keys := newTestServer(t)

	resp, err := http.Post(ts.URL+"/auth", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	token := readBody(t, resp)
	header, claims := verifyAndParse(t, token, mustSigningKey(t, keys, false))

	if header.Kid != mustSigningKey(t, keys, false).KID {
		t.Errorf("token kid = %q, want %q", header.Kid, mustSigningKey(t, keys, false).KID)
	}
	if header.Alg != "RS256" {
		t.Errorf("token alg = %q, want RS256", header.Alg)
	}
	if time.Unix(claims.Exp, 0).Before(time.Now()) {
		t.Error("valid token should not be expired")
	}
}

func TestAuthEndpoint_ExpiredToken(t *testing.T) {
	ts, keys := newTestServer(t)

	resp, err := http.Post(ts.URL+"/auth?expired=true", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST auth?expired=true: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	token := readBody(t, resp)
	header, claims := verifyAndParse(t, token, mustSigningKey(t, keys, true))

	if header.Kid != mustSigningKey(t, keys, true).KID {
		t.Errorf("token kid = %q, want %q", header.Kid, mustSigningKey(t, keys, true).KID)
	}
	if !time.Unix(claims.Exp, 0).Before(time.Now()) {
		t.Error("expired token should carry a past exp claim")
	}
}

func TestAuthEndpoint_ExpiredParamPresenceIsEnoughRegardlessOfValue(t *testing.T) {
	ts, keys := newTestServer(t)

	resp, err := http.Post(ts.URL+"/auth?expired=", "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST auth?expired=: %v", err)
	}
	defer resp.Body.Close()

	token := readBody(t, resp)
	header, _ := verifyAndParse(t, token, mustSigningKey(t, keys, true))
	if header.Kid != mustSigningKey(t, keys, true).KID {
		t.Errorf("expected expired key to be used when 'expired' param is present with empty value")
	}
}

func TestAuthEndpoint_BasicAuthAndJSONPayload(t *testing.T) {
	ts, keys := newTestServer(t)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("basicUser", "pass123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	token := readBody(t, resp)
	_, claims := verifyAndParse(t, token, mustSigningKey(t, keys, false))
	if claims.Sub != "basicUser" {
		t.Errorf("claims.Sub = %q, want basicUser", claims.Sub)
	}

	body := []byte(`{"username":"userABC","password":"password123"}`)
	req2, err := http.NewRequest(http.MethodPost, ts.URL+"/auth", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	token2 := readBody(t, resp2)
	_, claims2 := verifyAndParse(t, token2, mustSigningKey(t, keys, false))
	if claims2.Sub != "userABC" {
		t.Errorf("claims2.Sub = %q, want userABC", claims2.Sub)
	}
}

func TestAuthEndpoint_RejectsNonPOST(t *testing.T) {
	ts, _ := newTestServer(t)

	resp, err := http.Get(ts.URL + "/auth")
	if err != nil {
		t.Fatalf("GET auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestJWKS_FailedToRead(t *testing.T) {
	keys, err := testKeyStore(t)
	if err != nil {
		t.Fatal(err)
	}
	_ = keys.Close()
	srv := NewServer(keys)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	srv.handleJWKS(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 status on closed db, got %d", rec.Code)
	}
}

func TestAuth_FailedToReadSigningKey(t *testing.T) {
	keys, err := testKeyStore(t)
	if err != nil {
		t.Fatal(err)
	}
	_ = keys.Close()
	srv := NewServer(keys)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	srv.handleAuth(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 status on closed db, got %d", rec.Code)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return strings.TrimSpace(string(data))
}

func verifyAndParse(t *testing.T, token string, signer Key) (jwtHeader, jwtClaims) {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 parts: %q", token)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	signingInput := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signingInput))
	pub := &signer.PrivateKey.PublicKey
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	return header, claims
}
