package ingest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
)

func TestSubmitPostsContractShape(t *testing.T) {
	var got map[string]any
	var gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSecret = r.Header.Get("X-UR-Operator-Secret")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"location_id":"019f0000-0000-0000-0000-000000000000"}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryCode:      "us",
		Country:          "United States",
		CountryConfident: true,
		ASN:              401486,
		Org:              "RAVNIX LLC",
		Hosting:          true,
		ProbedAt:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Submit err = %v", err)
	}
	if gotSecret != "s3cret" {
		t.Fatalf("operator secret header = %q", gotSecret)
	}
	for _, k := range []string{"client_id", "country_code", "country_confident", "observed_at"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("body missing %q: %v", k, got)
		}
	}
	if got["country_code"] != "us" {
		t.Fatalf("country_code = %v", got["country_code"])
	}
	if got["country_confident"] != true {
		t.Fatalf("country_confident = %v", got["country_confident"])
	}
}

func TestSubmitRefusesNotCountryConfident(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryConfident: false,
	})
	if err == nil {
		t.Fatal("a non-country-confident result must not be submitted")
	}
	if called {
		t.Fatal("must not reach the server at all")
	}
}

func TestSubmitSurfacesRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unknown client.", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	err := c.Submit(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", &geolocate.ConsensusLocation{
		CountryCode: "us", CountryConfident: true, ProbedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("a 400 must surface as an error")
	}
}
