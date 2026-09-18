package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Server holds the key store used by the handlers.
type Server struct {
	keys *KeyStore
}

// NewServer creates a server with the given key store.
func NewServer(keys *KeyStore) *Server {
	return &Server{keys: keys}
}

// Routes registers the server endpoints.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	return mux
}

// handleJWKS returns the unexpired public keys.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jwks := s.keys.unexpiredJWKS(time.Now())

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Printf("encode jwks: %v", err)
	}
}

// handleAuth returns a signed JWT.
// If expired is present, the expired key is used.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var (
		key       Key
		expiresAt time.Time
	)

	if _, expired := r.URL.Query()["expired"]; expired {
		key = s.keys.ExpiredKey()
		expiresAt = key.ExpiresAt // already in the past
	} else {
		key = s.keys.ValidKey()
		expiresAt = time.Now().Add(5 * time.Minute)
	}

	token, err := signJWT(key, expiresAt)
	if err != nil {
		log.Printf("sign jwt: %v", err)
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}
