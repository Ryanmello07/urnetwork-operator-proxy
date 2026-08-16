package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The credential check exists to separate three outcomes the prober previously
// could not tell apart: accepted, refused, and unknown. Only the middle one may
// stop the process, so each is asserted on its own.

func TestCheckCredentialAcceptsOK(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := checkCredential(context.Background(), srv.Client(), srv.URL, "the-jwt"); err != nil {
		t.Fatalf("checkCredential: %s, want nil", err)
	}
	// Without the header the endpoint would answer 401 for a reason that has
	// nothing to do with the credential, and the check would condemn a working
	// token.
	if want := "Bearer the-jwt"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestCheckCredentialRejects401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := checkCredential(context.Background(), srv.Client(), srv.URL, "stale-jwt")
	if !errors.Is(err, errCredentialRejected) {
		t.Fatalf("checkCredential = %v, want errCredentialRejected", err)
	}
	// A rejection that also satisfied errCredentialUnverified would be
	// downgraded to a warning by main's switch, which is the whole failure this
	// change exists to prevent.
	if errors.Is(err, errCredentialUnverified) {
		t.Errorf("a rejection also matched errCredentialUnverified; main would let the prober start")
	}
}

// A server that predates the endpoint answers 404. That says nothing about the
// credential, so it must not stop the prober -- the same posture ingest takes
// when the due endpoint is missing.
func TestCheckCredentialTreats404AsUnverified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := checkCredential(context.Background(), srv.Client(), srv.URL, "fine-jwt")
	if !errors.Is(err, errCredentialUnverified) {
		t.Fatalf("checkCredential = %v, want errCredentialUnverified", err)
	}
	if errors.Is(err, errCredentialRejected) {
		t.Errorf("404 was reported as a rejected credential; an old server would stop the prober")
	}
}

func TestCheckCredentialTreatsTransportErrorAsUnverified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	err := checkCredential(context.Background(), http.DefaultClient, url, "fine-jwt")
	if !errors.Is(err, errCredentialUnverified) {
		t.Fatalf("checkCredential = %v, want errCredentialUnverified", err)
	}
	if errors.Is(err, errCredentialRejected) {
		t.Errorf("an unreachable server was reported as a rejected credential")
	}
}
