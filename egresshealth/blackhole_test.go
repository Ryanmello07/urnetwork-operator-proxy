package egresshealth

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubDests builds a connectivity table pointed at one server, plus a
// non-connectivity entry that must never be drawn.
func stubDests(url string, n int) []Destination {
	dests := []Destination{{
		Name: "not-connectivity", Class: ClassCDN, URL: url + "/cdn",
		Expect: ExpectStatus, Status: http.StatusNoContent,
	}}
	for i := 0; i < n; i++ {
		dests = append(dests, Destination{
			Name:  "conn-" + string(rune('a'+i)),
			Class: ClassConnectivity,
			URL:   url + "/conn",
			// the real connectivity entries are 204 probes
			Expect: ExpectStatus, Status: http.StatusNoContent,
		})
	}
	return dests
}

// A provider that carries traffic passes on the FIRST success, without paying
// for the rest of the sample.
func TestBlackholePassesOnFirstSuccess(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res := blackhole(context.Background(), srv.Client(), stubDests(srv.URL, 3),
		Options{Rand: rand.New(rand.NewSource(1))})

	if !res.OK {
		t.Fatalf("OK = false, want true: every destination answered correctly")
	}
	if res.Failure != "" {
		t.Errorf("Failure = %q, want empty on success", res.Failure)
	}
	if requests != 1 {
		t.Errorf("made %d requests, want 1: the question is answered by the first success, "+
			"and this runs hourly against the whole fleet", requests)
	}
}

// A blackhole fails only when EVERY drawn destination fails.
func TestBlackholeFailsOnlyWhenAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// a captive-portal shaped answer: 200 with a body where 204 was required
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hijacked"))
	}))
	defer srv.Close()

	res := blackhole(context.Background(), srv.Client(), stubDests(srv.URL, 3),
		Options{Rand: rand.New(rand.NewSource(1))})

	if res.OK {
		t.Fatalf("OK = true, want false: no destination met its contract")
	}
	if res.Failure != FailureAllDestinationsFailed {
		t.Errorf("Failure = %q, want %q", res.Failure, FailureAllDestinationsFailed)
	}
	if len(res.Results) != BlackholeSampleSize {
		t.Errorf("tried %d destinations, want the full sample of %d before declaring a blackhole",
			len(res.Results), BlackholeSampleSize)
	}
}

// One reachable destination among failures is NOT a blackhole. A provider
// reaching some destinations is degraded, which is Check's department -- calling
// it dark here would remove working providers on a signal that cannot tell the
// two apart.
func TestBlackholePartialReachabilityIsNotABlackhole(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	res := blackhole(context.Background(), srv.Client(), stubDests(srv.URL, 3),
		Options{Rand: rand.New(rand.NewSource(1))})

	if !res.OK {
		t.Errorf("OK = false, want true: the third destination answered, so traffic is getting through")
	}
}

// Only the connectivity class is ever drawn.
func TestBlackholeSampleDrawsConnectivityOnly(t *testing.T) {
	sample := blackholeSample(stubDests("http://x", 5), rand.New(rand.NewSource(7)))

	if len(sample) != BlackholeSampleSize {
		t.Fatalf("drew %d, want %d", len(sample), BlackholeSampleSize)
	}
	for _, d := range sample {
		if d.Class != ClassConnectivity {
			t.Errorf("drew %s from class %q, want %q only", d.Name, d.Class, ClassConnectivity)
		}
	}
}

// The real table must actually contain connectivity destinations, or the check
// silently degrades to "no sample, therefore a blackhole" and would condemn the
// entire fleet.
func TestBlackholeRealTableHasConnectivityDestinations(t *testing.T) {
	sample := blackholeSample(Destinations(), rand.New(rand.NewSource(1)))
	if len(sample) == 0 {
		t.Fatal("the real destination table drew no connectivity destinations: " +
			"every provider would be recorded as a blackhole")
	}
	if hosts := BlackholeHosts(); len(hosts) == 0 {
		t.Error("BlackholeHosts() is empty: the confinement self-check would not cover " +
			"the addresses this check dials, so a prober that could reach them directly would record every provider as ok")
	}
}
