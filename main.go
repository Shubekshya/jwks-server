package main

import (
	"log"
	"net/http"
)

var listenAndServe = http.ListenAndServe
var dbFile = "totally_not_my_privateKeys.db"

func run(addr string) error {
	keys, err := OpenKeyStore(dbFile)
	if err != nil {
		return err
	}
	defer keys.Close()

	srv := NewServer(keys)
	log.Printf("jwks-server listening on %s", addr)
	return listenAndServe(addr, srv.Routes())
}

func main() {
	if err := run(":8080"); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
