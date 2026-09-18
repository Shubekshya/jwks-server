package main

import (
	"errors"
	"net/http"
	"testing"
)

func TestRun_WiresServerAndUsesGivenAddr(t *testing.T) {
	orig := listenAndServe
	defer func() { listenAndServe = orig }()

	var gotAddr string
	var gotHandler http.Handler
	listenAndServe = func(addr string, handler http.Handler) error {
		gotAddr = addr
		gotHandler = handler
		return nil
	}

	if err := run(":9090"); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if gotAddr != ":9090" {
		t.Errorf("addr = %q, want :9090", gotAddr)
	}
	if gotHandler == nil {
		t.Error("expected a non-nil handler to be passed to listenAndServe")
	}
}

func TestRun_PropagatesListenError(t *testing.T) {
	orig := listenAndServe
	defer func() { listenAndServe = orig }()

	wantErr := errors.New("address already in use")
	listenAndServe = func(addr string, handler http.Handler) error {
		return wantErr
	}

	if err := run(":9090"); !errors.Is(err, wantErr) {
		t.Errorf("run() error = %v, want %v", err, wantErr)
	}
}

func TestRun_PropagatesKeyStoreError(t *testing.T) {
	origReader := randReader
	defer func() { randReader = origReader }()
	randReader = failingReader{}

	if err := run(":9090"); err == nil {
		t.Error("expected run() to propagate a key-generation error")
	}
}
