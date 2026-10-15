package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

type Server struct {
	keys *KeyStore
}

func NewServer(keys *KeyStore) *Server {
	return &Server{keys: keys}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jwks, err := s.keys.unexpiredJWKS(time.Now())
	if err != nil {
		http.Error(w, "failed to read keys", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Printf("encode jwks: %v", err)
	}
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := "fake-user"
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		username = u
	} else if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil && len(bodyBytes) > 0 {
			var payload struct {
				Username string `json:"username"`
			}
			if err := json.Unmarshal(bodyBytes, &payload); err == nil && payload.Username != "" {
				username = payload.Username
			}
		}
	}

	now := time.Now()
	_, expired := r.URL.Query()["expired"]
	key, err := s.keys.signingKey(expired, now)
	if err != nil {
		http.Error(w, "failed to read signing key", http.StatusInternalServerError)
		return
	}

	expiresAt := now.Add(5 * time.Minute)
	if expired || key.ExpiresAt.Before(expiresAt) {
		expiresAt = key.ExpiresAt
	}

	token, err := signJWTWithUser(key, expiresAt, username)
	if err != nil {
		log.Printf("sign jwt: %v", err)
		http.Error(w, "failed to issue token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}
