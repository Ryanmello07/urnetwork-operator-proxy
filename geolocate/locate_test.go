package geolocate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func jsonServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestLocateAllAgree(t *testing.T) {
	s1 := jsonServer(`{"status":"success","countryCode":"US","country":"United States","city":"Fairfax","asn":401486}`)
	defer s1.Close()
	s2 := jsonServer(`{"countryCode":"US","countryName":"United States","cityName":"Denver","regionName":"Colorado","asn":"401486","isProxy":true}`)
	defer s2.Close()
	s3 := jsonServer(`{"country":"US","city":"Atlanta","region":"Georgia","org":"AS401486 RAVNIX LLC"}`)
	defer s3.Close()

	srcs := []source{
		{Name: "ip.pn", URL: s1.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: s2.URL, Parse: parseFreeIpApi},
		{Name: "ipinfo", URL: s3.URL, Parse: parseIpInfo},
	}
	loc, err := locate(context.Background(), &http.Client{}, srcs)
	if err != nil {
		t.Fatalf("locate err = %v", err)
	}
	if !loc.CountryConfident || loc.CountryCode != "us" {
		t.Fatalf("country = %q confident=%v", loc.CountryCode, loc.CountryConfident)
	}
	if loc.CityConfident {
		t.Fatal("cities disagree; CityConfident must be false")
	}
	if loc.ASN != 401486 {
		t.Fatalf("ASN = %d", loc.ASN)
	}
	if !loc.Proxy {
		t.Fatal("Proxy flag from freeipapi must OR true")
	}
	if len(loc.Sources) != 3 {
		t.Fatalf("expected 3 source records, got %d", len(loc.Sources))
	}
}

func TestLocateQuorumFail(t *testing.T) {
	ok := jsonServer(`{"status":"success","countryCode":"US","country":"United States"}`)
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	srcs := []source{
		{Name: "ip.pn", URL: ok.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: bad.URL, Parse: parseFreeIpApi},
		{Name: "ipinfo", URL: bad.URL, Parse: parseIpInfo},
	}
	if _, err := locate(context.Background(), &http.Client{}, srcs); err != ErrNoConsensus {
		t.Fatalf("err = %v, want ErrNoConsensus", err)
	}
}

func TestLocateTimeoutCountsAsFailure(t *testing.T) {
	old := PerSourceTimeout
	PerSourceTimeout = 100 * time.Millisecond
	defer func() { PerSourceTimeout = old }()

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"country":"US"}`))
	}))
	defer slow.Close()
	good := jsonServer(`{"status":"success","countryCode":"US","country":"United States"}`)
	defer good.Close()

	// two good, one slow -> still quorum; slow one recorded as a failure.
	srcs := []source{
		{Name: "ip.pn", URL: good.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: good.URL, Parse: parseIpPn},
		{Name: "ipinfo", URL: slow.URL, Parse: parseIpInfo},
	}
	loc, err := locate(context.Background(), &http.Client{}, srcs)
	if err != nil {
		t.Fatalf("locate err = %v", err)
	}
	var slowRec *SourceResult
	for i := range loc.Sources {
		if loc.Sources[i].Name == "ipinfo" {
			slowRec = &loc.Sources[i]
		}
	}
	if slowRec == nil || slowRec.OK {
		t.Fatal("slow source should be recorded as a failure")
	}
	if slowRec.Err == "" {
		t.Fatal("slow source should carry an error string")
	}
}

// TestLocateRunsSourcesConcurrently guards the fan-out: locate() must bound
// its total latency by the slowest single source, not the sum of all
// sources. Each of the 3 sources sleeps sleepPerSource before responding
// with a valid, mutually-agreeing payload. If locate() ever regresses to
// fetching sources sequentially, the elapsed wall-clock roughly triples and
// trips the concurrentBound assertion below.
func TestLocateRunsSourcesConcurrently(t *testing.T) {
	old := PerSourceTimeout
	PerSourceTimeout = 2 * time.Second
	defer func() { PerSourceTimeout = old }()

	const sleepPerSource = 200 * time.Millisecond
	// Comfortably above one sleep (concurrent) and comfortably below three
	// sleeps (sequential), so this fails decisively if the fan-out is
	// serialized while staying robust to a loaded CI machine.
	const concurrentBound = 450 * time.Millisecond

	slowJSONServer := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(sleepPerSource)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
	}

	s1 := slowJSONServer(`{"status":"success","countryCode":"US","country":"United States","city":"Fairfax","asn":401486}`)
	s2 := slowJSONServer(`{"countryCode":"US","countryName":"United States","cityName":"Fairfax","regionName":"Virginia","asn":"401486"}`)
	s3 := slowJSONServer(`{"country":"US","city":"Fairfax","region":"Virginia","org":"AS401486 RAVNIX LLC"}`)
	// Servers sleep before every response, so Close() would block on any
	// still-in-flight handler; deferring Close outside the timed region
	// avoids polluting the elapsed measurement (Close is still called at
	// the end of the test, after locate() has returned).
	defer s1.Close()
	defer s2.Close()
	defer s3.Close()

	srcs := []source{
		{Name: "ip.pn", URL: s1.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: s2.URL, Parse: parseFreeIpApi},
		{Name: "ipinfo", URL: s3.URL, Parse: parseIpInfo},
	}

	start := time.Now()
	loc, err := locate(context.Background(), &http.Client{}, srcs)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("locate err = %v", err)
	}
	if !loc.CountryConfident || loc.CountryCode != "us" {
		t.Fatalf("country = %q confident=%v", loc.CountryCode, loc.CountryConfident)
	}
	okCount := 0
	for _, s := range loc.Sources {
		if s.OK {
			okCount++
		}
	}
	if okCount != 3 {
		t.Fatalf("expected all 3 sources to succeed, got %d: %+v", okCount, loc.Sources)
	}

	if elapsed >= concurrentBound {
		t.Fatalf("locate() took %v, want < %v; sources appear to be fetched sequentially instead of concurrently", elapsed, concurrentBound)
	}
}

func TestLocateOversizedResponseRejected(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{" + strings.Repeat(" ", MaxResponseBytes+10) + "}"))
	}))
	defer big.Close()
	good := jsonServer(`{"status":"success","countryCode":"US","country":"United States"}`)
	defer good.Close()

	srcs := []source{
		{Name: "ip.pn", URL: good.URL, Parse: parseIpPn},
		{Name: "freeipapi", URL: good.URL, Parse: parseIpPn},
		{Name: "ipinfo", URL: big.URL, Parse: parseIpInfo},
	}
	loc, err := locate(context.Background(), &http.Client{}, srcs)
	if err != nil {
		t.Fatalf("locate err = %v", err)
	}
	for _, s := range loc.Sources {
		if s.Name == "ipinfo" && (s.OK || !strings.Contains(s.Err, "too large")) {
			t.Fatalf("oversized source not rejected: %+v", s)
		}
	}
}
