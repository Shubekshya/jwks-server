package main

import (
	"log"
	"net/http"
)

// Allows the server start function to be replaced during testing.
var listenAndServe = http.ListenAndServe

// run starts the server using a new key store.
func run(addr string) error {
	keys, err := NewKeyStore()
	if err != nil {
		return err
	}

	srv := NewServer(keys)
	log.Printf("jwks-server listening on %s", addr)
	return listenAndServe(addr, srv.Routes())
}

func main() {
	if err := run(":8080"); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
