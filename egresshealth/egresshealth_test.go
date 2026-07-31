package egresshealth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fastOptions keeps every test off the wall clock: no test here talks to a real
// network, and the only thing a long timeout would buy is a slow suite.
func fastOptions() Options {
	return Options{
		PerRequestTimeout: 200 * time.Millisecond,
		Budget:            5 * time.Second,
		Concurrency:       3,
	}
}

// handler describes what a stub destination does.
type handler func(w http.ResponseWriter, r *http.Request)

// okBody is a healthy destination: a non-error status and a real body.
func okBody(body string) handler {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}
}

// emptyBody200 is the blackhole signature at the http layer: a perfectly good
// status line and not one byte behind it.
func emptyBody200() handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// status204 is a healthy connectivity check: an empty body is the CORRECT
// answer, and it is only distinguishable from the blackhole above by the status
// the destination declared it expects.
func status204() handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}
}

// statusWithBody models a content provider REFUSING the request -- the
// datacenter-IP-rejection case. Bytes flow in both directions; the answer is no.
func statusWithBody(code int, body string) handler {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

// hangs never answers until the test tears down, modelling a provider that
// swallows the request.
func hangs(done <-chan struct{}) handler {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}
}

// spec is one stub destination: a name, a class, a handler, and the parts of
// the success contract a test wants to exercise. The contract fields are keyed
// and optional, so the common case stays a three-field literal.
type spec struct {
	name   string
	class  Class
	h      handler
	expect Expect
	status int
	verify func([]byte) error
}

// stubDestinations stands up one httptest server multiplexing every named
// destination and returns the table pointing at it. Order is preserved so
// assertions can index by position.
func stubDestinations(t *testing.T, specs []spec) []Destination {
	t.Helper()
	mux := http.NewServeMux()
	dests := make([]Destination, 0, len(specs))
	for _, s := range specs {
		path := "/" + s.name
		mux.HandleFunc(path, s.h)
		dests = append(dests, Destination{
			Name:   s.name,
			Class:  s.class,
			URL:    path,
			Expect: s.expect,
			Status: s.status,
			Verify: s.verify,
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	for i := range dests {
		dests[i].URL = srv.URL + dests[i].URL
	}
	return dests
}

// healthyTable is every scored class, three deep, all working. The
// connectivity entries deliberately mix both success contracts: two 204s where
// an empty body is correct, and one small body, which is exactly the shape of
// the production class.
func healthyTable(t *testing.T) []Destination {
	t.Helper()
	return stubDestinations(t, []spec{
		{name: "dns-a", class: ClassDNS, h: okBody(`{"Status":0}`)},
		{name: "dns-b", class: ClassDNS, h: okBody(`{"Status":0}`)},
		{name: "dns-c", class: ClassDNS, h: okBody(`{"Status":0}`)},
		{name: "conn-a", class: ClassConnectivity, h: status204(), expect: ExpectStatus, status: http.StatusNoContent},
		{name: "conn-b", class: ClassConnectivity, h: status204(), expect: ExpectStatus, status: http.StatusNoContent},
		{name: "conn-c", class: ClassConnectivity, h: okBody("success\n")},
		{name: "cdn-a", class: ClassCDN, h: okBody("/* css */")},
		{name: "cdn-b", class: ClassCDN, h: okBody("/* css */")},
		{name: "cdn-c", class: ClassCDN, h: okBody("/* css */")},
		{name: "site-a", class: ClassSite, h: okBody("User-agent: *")},
		{name: "site-b", class: ClassSite, h: okBody("User-agent: *")},
		{name: "site-c", class: ClassSite, h: okBody("User-agent: *")},
	})
}

func TestCheckAllHealthy(t *testing.T) {
	dests := healthyTable(t)
	res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
	if err != nil {
		t.Fatalf("check err = %v", err)
	}
	if res.OKCount != res.Total || res.Total != len(dests) {
		t.Fatalf("OKCount/Total = %d/%d, want %d/%d", res.OKCount, res.Total, len(dests), len(dests))
	}
	byName := map[string]Destination{}
	for _, d := range dests {
		byName[d.Name] = d
	}
	for _, c := range res.Checks {
		if !c.OK {
			t.Errorf("%s not OK: status=%d bytes=%d err=%q", c.Name, c.StatusCode, c.ByteCount, c.Err)
		}
		// Only an ExpectBody destination owes us bytes. Asserting it for the
		// whole table would make the 204 entries -- where an empty body is the
		// correct answer -- unrepresentable in a healthy table.
		if byName[c.Name].Expect == ExpectBody && c.ByteCount == 0 {
			t.Errorf("%s reported OK with zero bytes", c.Name)
		}
		if c.Err != "" {
			t.Errorf("%s is OK but carries Err %q", c.Name, c.Err)
		}
	}
	for _, class := range Classes {
		s := res.ByClass[class]
		if s.OK != 3 || s.Total != 3 {
			t.Errorf("ByClass[%s] = %d/%d, want 3/3", class, s.OK, s.Total)
		}
	}
	if got, want := res.Summary(), "ok=12/12 dns=3/3 connectivity=3/3 cdn=3/3 site=3/3"; got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}
}

// TestCheckTotalBlackhole is the case this package exists for, and it asserts
// BOTH halves of the requirement in one place: a blackhole is a successful run
// reporting 0/12 (err == nil), while a run that could not happen at all is an
// error and no Result. If those two collapsed into each other, "this provider
// delivers nothing" would be indistinguishable from "the prober was
// misconfigured", and the whole signal would be unusable.
func TestCheckTotalBlackhole(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	dests := stubDestinations(t, []spec{
		// Half swallow the request entirely, half return a status line with no
		// body -- the two shapes a blackholing provider produces. Note the
		// connectivity entries: a bare 200 where the destination declared 204 is
		// the synthesized-status-line case, and it must fail.
		{name: "dns-a", class: ClassDNS, h: hangs(done)},
		{name: "dns-b", class: ClassDNS, h: emptyBody200()},
		{name: "dns-c", class: ClassDNS, h: hangs(done)},
		{name: "conn-a", class: ClassConnectivity, h: emptyBody200(), expect: ExpectStatus, status: http.StatusNoContent},
		{name: "conn-b", class: ClassConnectivity, h: hangs(done), expect: ExpectStatus, status: http.StatusNoContent},
		{name: "conn-c", class: ClassConnectivity, h: emptyBody200()},
		{name: "cdn-a", class: ClassCDN, h: emptyBody200()},
		{name: "cdn-b", class: ClassCDN, h: hangs(done)},
		{name: "cdn-c", class: ClassCDN, h: emptyBody200()},
		{name: "site-a", class: ClassSite, h: hangs(done)},
		{name: "site-b", class: ClassSite, h: emptyBody200()},
		{name: "site-c", class: ClassSite, h: hangs(done)},
		// A blackhole takes the reputation class down too, and that must show as
		// reputation=0/2 without touching ok=N/M.
		{name: "rep-a", class: ClassReputation, h: hangs(done)},
		{name: "rep-b", class: ClassReputation, h: emptyBody200()},
	})

	res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
	if err != nil {
		t.Fatalf("a total blackhole must be a RESULT, not an error: %v", err)
	}
	if res.OKCount != 0 {
		t.Fatalf("OKCount = %d, want 0 for a total blackhole (%+v)", res.OKCount, res.Checks)
	}
	if res.Total != 12 {
		t.Fatalf("Total = %d, want the 12 scored destinations", res.Total)
	}
	if len(res.Checks) != len(dests) {
		t.Fatalf("len(Checks) = %d, want %d; every destination must be attempted", len(res.Checks), len(dests))
	}
	for _, class := range Classes {
		if s := res.ByClass[class]; s.OK != 0 || s.Total != 3 {
			t.Errorf("ByClass[%s] = %d/%d, want 0/3; a wholly failing class must still be reported", class, s.OK, s.Total)
		}
	}
	if got, want := res.Summary(), "ok=0/12 dns=0/3 connectivity=0/3 cdn=0/3 site=0/3 reputation=0/2"; got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}

	// ...and the structural failures, which must NOT look like a blackhole.
	t.Run("nil client is a structural error", func(t *testing.T) {
		res, err := check(context.Background(), nil, dests, fastOptions())
		if !errors.Is(err, ErrNilClient) || res != nil {
			t.Fatalf("check(nil client) = (%v, %v), want (nil, ErrNilClient)", res, err)
		}
	})
	t.Run("empty table is a structural error", func(t *testing.T) {
		res, err := check(context.Background(), http.DefaultClient, nil, fastOptions())
		if !errors.Is(err, ErrNoDestinations) || res != nil {
			t.Fatalf("check(no destinations) = (%v, %v), want (nil, ErrNoDestinations)", res, err)
		}
	})
	t.Run("no budget left is a structural error", func(t *testing.T) {
		// A run started on an already-dead context returns 0/9 for reasons that
		// have nothing to do with the provider. Reporting that as a blackhole
		// would frame the prober's own exhausted deadline as a provider fault.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		res, err := check(ctx, http.DefaultClient, dests, fastOptions())
		if !errors.Is(err, ErrNoBudget) || res != nil {
			t.Fatalf("check(dead ctx) = (%v, %v), want (nil, ErrNoBudget)", res, err)
		}
	})
}

// TestCheckSelectiveFailure is the datacenter-IP case and the main reason the
// class dimension exists: DNS resolves fine, every CDN refuses. A flat
// "ok=6/9" would be indistinguishable from six random flakes.
func TestCheckSelectiveFailure(t *testing.T) {
	dests := stubDestinations(t, []spec{
		{name: "dns-a", class: ClassDNS, h: okBody(`{"Status":0}`)},
		{name: "dns-b", class: ClassDNS, h: okBody(`{"Status":0}`)},
		{name: "dns-c", class: ClassDNS, h: okBody(`{"Status":0}`)},
		{name: "conn-a", class: ClassConnectivity, h: status204(), expect: ExpectStatus, status: http.StatusNoContent},
		{name: "conn-b", class: ClassConnectivity, h: status204(), expect: ExpectStatus, status: http.StatusNoContent},
		{name: "conn-c", class: ClassConnectivity, h: okBody("success\n")},
		{name: "cdn-a", class: ClassCDN, h: statusWithBody(http.StatusForbidden, "error 1015: rate limited")},
		{name: "cdn-b", class: ClassCDN, h: statusWithBody(http.StatusServiceUnavailable, "denied: datacenter range")},
		{name: "cdn-c", class: ClassCDN, h: statusWithBody(http.StatusForbidden, "access denied")},
		{name: "site-a", class: ClassSite, h: okBody("User-agent: *")},
		{name: "site-b", class: ClassSite, h: okBody("User-agent: *")},
		{name: "site-c", class: ClassSite, h: okBody("User-agent: *")},
	})

	res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
	if err != nil {
		t.Fatalf("check err = %v", err)
	}
	if got, want := res.Summary(), "ok=9/12 dns=3/3 connectivity=3/3 cdn=0/3 site=3/3"; got != want {
		t.Fatalf("Summary = %q, want %q", got, want)
	}
	if s := res.ByClass[ClassCDN]; s.OK != 0 || s.Total != 3 {
		t.Fatalf("ByClass[cdn] = %d/%d, want 0/3", s.OK, s.Total)
	}
	if s := res.ByClass[ClassDNS]; s.OK != 3 {
		t.Fatalf("ByClass[dns].OK = %d, want 3", s.OK)
	}

	// The refusals must be recorded as REFUSALS -- a status and a body -- not
	// as silence. This is what tells an operator "the tunnel carried bytes and
	// the CDN said no" rather than "nothing came back", and it is the whole
	// diagnostic difference between this case and a blackhole.
	for _, c := range res.Checks {
		if c.Class != ClassCDN {
			continue
		}
		if c.StatusCode == 0 {
			t.Errorf("%s: StatusCode = 0; a refusal must record the status it was refused with", c.Name)
		}
		if c.ByteCount == 0 {
			t.Errorf("%s: ByteCount = 0 on a refusal that carried a body; without this, a refusal is indistinguishable from a blackhole", c.Name)
		}
		if !strings.Contains(c.Err, "status") {
			t.Errorf("%s: Err = %q, want it to name the status", c.Name, c.Err)
		}
	}
	if names := res.FailedNames(); strings.Join(names, ",") != "cdn-a,cdn-b,cdn-c" {
		t.Errorf("FailedNames = %v, want the three cdn destinations in table order", names)
	}
}

// TestEmptyBodyIs200Failure is asserted on its own because it is the rule the
// whole package turns on. A provider that terminates connections locally, or
// whose upstream returns a stub, produces exactly this: a clean 200 and zero
// bytes. If that counted as success, the failure being hunted would pass the
// hunt.
func TestEmptyBodyIs200Failure(t *testing.T) {
	cases := []struct {
		name string
		h    handler
	}{
		{"explicit 200 with no body", emptyBody200()},
		{"200 with a zero-length write", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(nil)
		}},
		{"204 no content", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dests := stubDestinations(t, []spec{{name: "d", class: ClassDNS, h: tc.h}})
			res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
			if err != nil {
				t.Fatalf("check err = %v", err)
			}
			c := res.Checks[0]
			if c.OK {
				t.Fatalf("a %d with an empty body counted as SUCCESS; that is the blackhole signature", c.StatusCode)
			}
			if c.ByteCount != 0 {
				t.Fatalf("ByteCount = %d, want 0", c.ByteCount)
			}
			if c.StatusCode == 0 {
				t.Fatal("StatusCode = 0; the status line did arrive and must be recorded")
			}
			if !strings.Contains(c.Err, "empty body") && !strings.Contains(c.Err, "status") {
				t.Fatalf("Err = %q, want it to say why", c.Err)
			}
			if res.OKCount != 0 {
				t.Fatalf("OKCount = %d, want 0", res.OKCount)
			}
		})
	}
}

// TestBodyCapHonoured: a destination that streams far more than the cap must
// not cause an oversized read. Without the cap a hostile (or merely
// misconfigured) destination could spend the provider's entire byte budget --
// the budget this whole package is documented to stay inside.
func TestBodyCapHonoured(t *testing.T) {
	const streamed = 64 * MaxBodyBytes

	dests := stubDestinations(t, []spec{{name: "flood", class: ClassCDN, h: func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 4096)
		for i := range chunk {
			chunk[i] = 'x'
		}
		for written := 0; written < streamed; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}}})

	res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
	if err != nil {
		t.Fatalf("check err = %v", err)
	}
	c := res.Checks[0]
	if c.ByteCount > MaxBodyBytes {
		t.Fatalf("read %d bytes from a destination streaming %d; the cap is %d and an uncapped read spends the provider's byte budget", c.ByteCount, streamed, MaxBodyBytes)
	}
	if c.ByteCount != MaxBodyBytes {
		t.Fatalf("ByteCount = %d, want exactly the cap %d (the destination had far more to give)", c.ByteCount, MaxBodyBytes)
	}
	if !c.OK {
		t.Fatalf("a large healthy response must still be OK: %+v", c)
	}
}

// TestOneFailureDoesNotAbortTheRun: the pattern is the value, so a failure in
// the middle of the table must not stop the destinations after it from being
// attempted.
func TestOneFailureDoesNotAbortTheRun(t *testing.T) {
	dests := stubDestinations(t, []spec{
		{name: "first", class: ClassDNS, h: okBody("ok")},
		{name: "broken", class: ClassCDN, h: statusWithBody(http.StatusInternalServerError, "boom")},
		{name: "last", class: ClassSite, h: okBody("ok")},
	})
	res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
	if err != nil {
		t.Fatalf("one failing destination must not fail the run: %v", err)
	}
	if len(res.Checks) != 3 {
		t.Fatalf("len(Checks) = %d, want 3; every destination must be recorded", len(res.Checks))
	}
	if !res.Checks[2].OK {
		t.Fatalf("the destination after the failing one was not attempted or not recorded: %+v", res.Checks[2])
	}
	if got, want := res.Summary(), "ok=2/3 dns=1/1 cdn=0/1 site=1/1"; got != want {
		t.Fatalf("Summary = %q, want %q", got, want)
	}
}

// TestRequestShape: the per-destination headers must actually reach the
// destination (Cloudflare's DoH JSON form answers 400 without its Accept
// header), and every request must be a plain GET.
func TestRequestShape(t *testing.T) {
	var mu sync.Mutex
	var gotMethod, gotAccept, gotRange, gotUA string
	dests := stubDestinations(t, []spec{{name: "d", class: ClassDNS, h: func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMethod, gotAccept, gotRange = r.Method, r.Header.Get("Accept"), r.Header.Get("Range")
		gotUA = r.Header.Get("User-Agent")
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}}})
	dests[0].Headers = map[string]string{"Accept": acceptDNSJSON, "Range": rangeFirst2KiB}

	if _, err := check(context.Background(), http.DefaultClient, dests, fastOptions()); err != nil {
		t.Fatalf("check err = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotAccept != acceptDNSJSON {
		t.Errorf("Accept = %q, want %q", gotAccept, acceptDNSJSON)
	}
	if gotRange != rangeFirst2KiB {
		t.Errorf("Range = %q, want %q", gotRange, rangeFirst2KiB)
	}
	// The User-Agent is load-bearing, not cosmetic: Wikimedia's robot policy
	// answers 403 to Go's default "Go-http-client/1.1", which would make that
	// destination fail for every provider forever -- noise dressed as signal.
	if gotUA != UserAgent {
		t.Errorf("User-Agent = %q, want %q", gotUA, UserAgent)
	}
	if strings.Contains(gotUA, "Go-http-client") || gotUA == "" {
		t.Errorf("User-Agent = %q; the default agent is refused outright by at least one destination in the table", gotUA)
	}
}

// TestUserAgentIsIdentifiable: the probe hits other people's servers on a
// schedule. It must say who it is and how to reach the operator, and must not
// impersonate a browser.
func TestUserAgentIsIdentifiable(t *testing.T) {
	if !strings.Contains(UserAgent, "urnetwork") {
		t.Errorf("UserAgent %q does not name the project", UserAgent)
	}
	if !strings.Contains(UserAgent, "http") {
		t.Errorf("UserAgent %q carries no contact url", UserAgent)
	}
	if strings.HasPrefix(UserAgent, "Mozilla") {
		t.Errorf("UserAgent %q impersonates a browser", UserAgent)
	}
}

// TestConcurrencyIsBounded: the run must not open the whole table at once over
// a cold tunnel.
func TestConcurrencyIsBounded(t *testing.T) {
	const limit = 2
	var mu sync.Mutex
	inFlight, peak := 0, 0
	specs := make([]spec, 0, 9)
	for i := 0; i < 9; i++ {
		specs = append(specs, spec{name: fmt.Sprintf("d%d", i), class: ClassDNS, h: func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			inFlight++
			if peak < inFlight {
				peak = inFlight
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			mu.Lock()
			inFlight--
			mu.Unlock()
			_, _ = w.Write([]byte("ok"))
		}})
	}
	dests := stubDestinations(t, specs)

	opts := fastOptions()
	opts.Concurrency = limit
	opts.PerRequestTimeout = 2 * time.Second
	if _, err := check(context.Background(), http.DefaultClient, dests, opts); err != nil {
		t.Fatalf("check err = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if peak > limit {
		t.Fatalf("peak in-flight requests = %d, want at most Concurrency = %d", peak, limit)
	}
}

// TestBudgetBoundsTheRun: a provider that swallows everything must not hold the
// pass open for concurrency-batched multiples of the per-request timeout.
func TestBudgetBoundsTheRun(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	specs := make([]spec, 0, 9)
	for i := 0; i < 9; i++ {
		specs = append(specs, spec{name: fmt.Sprintf("d%d", i), class: ClassDNS, h: hangs(done)})
	}
	dests := stubDestinations(t, specs)

	opts := Options{PerRequestTimeout: 10 * time.Second, Budget: 300 * time.Millisecond, Concurrency: 1}
	start := time.Now()
	res, err := check(context.Background(), http.DefaultClient, dests, opts)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("check err = %v", err)
	}
	if res.OKCount != 0 {
		t.Fatalf("OKCount = %d, want 0", res.OKCount)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the run took %s with a 300ms budget; the budget does not bound it", elapsed)
	}
}

func TestOptionsDefaults(t *testing.T) {
	var zero Options
	if zero.perRequestTimeout() != DefaultPerRequestTimeout {
		t.Errorf("perRequestTimeout = %s, want the default", zero.perRequestTimeout())
	}
	if zero.budget() != DefaultBudget {
		t.Errorf("budget = %s, want the default", zero.budget())
	}
	if zero.concurrency() != DefaultConcurrency {
		t.Errorf("concurrency = %d, want the default", zero.concurrency())
	}
	neg := Options{PerRequestTimeout: -1, Budget: -1, Concurrency: -1}
	if neg.perRequestTimeout() != DefaultPerRequestTimeout || neg.budget() != DefaultBudget || neg.concurrency() != DefaultConcurrency {
		t.Error("a negative option must fall back to the default, not disable the bound")
	}
}

// TestDestinationsTable guards the production table's shape: names are what the
// log line and any future storage key on, so they must be unique and non-empty,
// and every destination must belong to a declared class.
func TestDestinationsTable(t *testing.T) {
	if len(destinations) < 8 {
		t.Fatalf("len(destinations) = %d; the table is meant to span several classes and operators", len(destinations))
	}
	// ClassReputation is declared here but deliberately NOT in Classes: it is a
	// real class of the table that is kept out of the health score. Everything
	// else must be in Classes or it would sort after the declared ones in every
	// summary.
	declared := map[Class]bool{ClassReputation: true}
	for _, c := range Classes {
		declared[c] = true
	}
	seen := map[string]bool{}
	perClass := map[Class]int{}
	for i, d := range destinations {
		if d.Name == "" {
			t.Fatalf("destinations[%d] has no name", i)
		}
		if seen[d.Name] {
			t.Fatalf("destinations[%d] repeats the name %q", i, d.Name)
		}
		seen[d.Name] = true
		if !declared[d.Class] {
			t.Fatalf("destination %q has class %q, which is not in Classes -- it would sort after the declared ones in every summary", d.Name, d.Class)
		}
		perClass[d.Class]++
	}
	for _, c := range Classes {
		if perClass[c] < 2 {
			t.Errorf("class %q has %d destination(s); a class with fewer than two cannot distinguish a class-wide fault from one flaky endpoint", c, perClass[c])
		}
	}
}

// TestEveryDestinationIsHTTPSOn443 encodes a constraint that is invisible in
// the table itself: cmd/egress-prober's confinement self-check dials ONE fixed
// port (443). A destination on any other port would be silently uncovered by
// that check while the check kept reporting a pass -- which is exactly why the
// Quad9 DoH JSON endpoint (port 5053) was rejected for this table.
func TestEveryDestinationIsHTTPSOn443(t *testing.T) {
	for _, d := range destinations {
		u, err := url.Parse(d.URL)
		if err != nil {
			t.Fatalf("destination %q has an unparseable URL %q: %s", d.Name, d.URL, err)
		}
		if u.Scheme != "https" {
			t.Errorf("destination %q is %q, not https; a plaintext destination could be forged by the provider on the path", d.Name, u.Scheme)
		}
		if p := u.Port(); p != "" && p != "443" {
			t.Errorf("destination %q is on port %q; the confinement self-check only dials 443, so this destination would not be covered by it", d.Name, p)
		}
	}
}

// TestDestinationsSpreadAcrossOperatorsWithinAClass: the point of the table is
// that a provider which whitelists one vendor cannot pass. Two destinations in
// the same class sharing a host would be one destination wearing two names.
func TestDestinationsSpreadAcrossOperatorsWithinAClass(t *testing.T) {
	perClass := map[Class]map[string]string{}
	for _, d := range destinations {
		u, err := url.Parse(d.URL)
		if err != nil {
			t.Fatalf("destination %q: %s", d.Name, err)
		}
		if perClass[d.Class] == nil {
			perClass[d.Class] = map[string]string{}
		}
		if other, dup := perClass[d.Class][u.Hostname()]; dup {
			t.Errorf("destinations %q and %q are both class %q on host %q; one blocked host would fail both", other, d.Name, d.Class, u.Hostname())
		}
		perClass[d.Class][u.Hostname()] = d.Name
	}
}

// TestDestinationHostsCoversEveryDestination is the anti-drift test. The
// operator translates this list into -confinement-address entries: if a
// destination is added to the table and its host does not come out here, the
// confinement check silently stops covering a real endpoint while still
// reporting success. Mirrors geolocate's TestSourceHostsCoversEverySource.
func TestDestinationHostsCoversEveryDestination(t *testing.T) {
	hosts := DestinationHosts()
	if len(hosts) == 0 {
		t.Fatal("DestinationHosts is empty; the confinement check would have nothing to test")
	}
	for _, d := range destinations {
		u, err := url.Parse(d.URL)
		if err != nil {
			t.Fatalf("destination %q has an unparseable URL %q: %s", d.Name, d.URL, err)
		}
		found := false
		for _, h := range hosts {
			if h == u.Hostname() {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("destination %q (%s) has no host in DestinationHosts %v; the confinement check would not cover it", d.Name, d.URL, hosts)
		}
	}

	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" {
			t.Fatalf("DestinationHosts contains an empty host: %v", hosts)
		}
		if seen[h] {
			t.Fatalf("DestinationHosts contains %q twice: %v", h, hosts)
		}
		seen[h] = true
		// Each entry must be a bare, dialable host: no scheme, no port, no path.
		if strings.ContainsAny(h, "/:") {
			t.Fatalf("DestinationHosts entry %q is not a bare host", h)
		}
		if u, err := url.Parse("https://" + h); err != nil || u.Hostname() != h {
			t.Fatalf("DestinationHosts entry %q does not parse back to itself", h)
		}
	}

	// One entry per DISTINCT host, no more and no fewer.
	distinct := map[string]bool{}
	for _, d := range destinations {
		u, _ := url.Parse(d.URL)
		distinct[u.Hostname()] = true
	}
	if len(hosts) != len(distinct) {
		t.Fatalf("DestinationHosts has %d entries for %d distinct hosts", len(hosts), len(distinct))
	}
}

// TestSummaryIsDeterministic: the summary is read from logs across passes, so
// it must not reorder itself between runs (ByClass is a map, and iterating it
// directly would).
func TestSummaryIsDeterministic(t *testing.T) {
	res := &Result{
		OKCount: 4,
		Total:   9,
		ByClass: map[Class]ClassSummary{
			ClassSite: {OK: 1, Total: 3},
			ClassDNS:  {OK: 3, Total: 3},
			ClassCDN:  {OK: 0, Total: 3},
		},
	}
	want := "ok=4/9 dns=3/3 cdn=0/3 site=1/3"
	for i := 0; i < 50; i++ {
		if got := res.Summary(); got != want {
			t.Fatalf("Summary = %q, want %q (iteration %d)", got, want, i)
		}
	}
}

// TestSummaryIncludesAnUndeclaredClass: a class added to the table but not to
// Classes must still be reported, sorted, rather than disappearing from the
// line.
func TestSummaryIncludesAnUndeclaredClass(t *testing.T) {
	res := &Result{
		OKCount: 1,
		Total:   2,
		ByClass: map[Class]ClassSummary{
			ClassDNS:     {OK: 1, Total: 1},
			Class("zzz"): {OK: 0, Total: 1},
		},
	}
	if got, want := res.Summary(), "ok=1/2 dns=1/1 zzz=0/1"; got != want {
		t.Fatalf("Summary = %q, want %q", got, want)
	}
}

func TestSummaryOfNilResult(t *testing.T) {
	var res *Result
	if got := res.Summary(); got != "ok=0/0" {
		t.Fatalf("Summary of a nil Result = %q", got)
	}
	if names := res.FailedNames(); names != nil {
		t.Fatalf("FailedNames of a nil Result = %v", names)
	}
}

// TestCheckUsesTheInjectedClientOnly is the trust property, asserted rather
// than assumed: the package must make every request through the *http.Client it
// was handed. If it ever built its own transport, the confined prober's
// "no path out except the tunnel" guarantee would be silently broken -- a
// request could then succeed without a working provider.
func TestCheckUsesTheInjectedClientOnly(t *testing.T) {
	var calls int64
	var mu sync.Mutex
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       http.NoBody,
			Header:     http.Header{},
			Request:    r,
		}, nil
	})
	client := &http.Client{Transport: rt}

	// URLs that resolve to nothing: if anything reached the network instead of
	// the injected transport, this would fail rather than silently pass.
	dests := []Destination{
		{Name: "a", Class: ClassDNS, URL: "https://egresshealth.invalid/a"},
		{Name: "b", Class: ClassCDN, URL: "https://egresshealth.invalid/b"},
	}
	res, err := check(context.Background(), client, dests, fastOptions())
	if err != nil {
		t.Fatalf("check err = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != int64(len(dests)) {
		t.Fatalf("injected transport saw %d requests, want %d; some request did not go through the supplied client", calls, len(dests))
	}
	// http.NoBody is a 200 with zero bytes: the empty-body rule applies.
	if res.OKCount != 0 {
		t.Fatalf("OKCount = %d, want 0 (every response was a bodiless 200)", res.OKCount)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestCheckProductionTableIsWiredUp: Check must run the production table, not
// an empty or stub one. It cannot reach the real hosts here (no network is
// used), but the shape of the result proves which table it used.
func TestCheckProductionTableIsWiredUp(t *testing.T) {
	rt := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("no network in tests")
	})
	res, err := Check(context.Background(), &http.Client{Transport: rt}, fastOptions())
	if err != nil {
		t.Fatalf("Check err = %v", err)
	}
	// Total counts the SCORED destinations, not the whole table: the reputation
	// entries are attempted and reported, but never scored.
	scoredCount, reputationCount := 0, 0
	for _, d := range destinations {
		if scored(d.Class) {
			scoredCount++
		} else {
			reputationCount++
		}
	}
	if res.Total != scoredCount {
		t.Fatalf("Total = %d, want the %d scored destinations", res.Total, scoredCount)
	}
	if res.Reputation.Total != reputationCount {
		t.Fatalf("Reputation.Total = %d, want %d", res.Reputation.Total, reputationCount)
	}
	if len(res.Checks) != len(destinations) {
		t.Fatalf("len(Checks) = %d, want the whole table %d; a reputation destination must still be ATTEMPTED and recorded", len(res.Checks), len(destinations))
	}
	names := map[string]bool{}
	for _, c := range res.Checks {
		names[c.Name] = true
	}
	for _, d := range destinations {
		if !names[d.Name] {
			t.Fatalf("Check did not run production destination %q", d.Name)
		}
	}

	// Sorted class tallies must still cover every scored destination.
	total := 0
	for _, s := range res.ByClass {
		total += s.Total
	}
	if total != scoredCount {
		t.Fatalf("ByClass totals sum to %d, want %d", total, scoredCount)
	}
	if _, present := res.ByClass[ClassReputation]; present {
		t.Fatal("ByClass carries a reputation entry; reputation is reported in Result.Reputation and must not appear among the scored classes")
	}
}

// TestClassesCoversTheTable keeps Classes (the render order) and the table from
// drifting apart in the other direction: a class declared but never used just
// makes the summary lie about what was checked.
func TestClassesCoversTheTable(t *testing.T) {
	used := map[Class]bool{}
	for _, d := range destinations {
		used[d.Class] = true
	}
	var unused []string
	for _, c := range Classes {
		if !used[c] {
			unused = append(unused, string(c))
		}
	}
	sort.Strings(unused)
	if len(unused) != 0 {
		t.Fatalf("Classes declares %v, which no destination uses", unused)
	}
}

// TestDestinationsReturnsACopy: the production table must not be reachable for
// mutation from outside. A caller that changed an entry -- or the Headers map
// inside one -- would change what every subsequent probe measures, invisibly
// from the table's own source.
func TestDestinationsReturnsACopy(t *testing.T) {
	got := Destinations()
	if len(got) != len(destinations) {
		t.Fatalf("Destinations() has %d entries, want %d", len(got), len(destinations))
	}
	for i := range got {
		if got[i].Name != destinations[i].Name || got[i].URL != destinations[i].URL || got[i].Class != destinations[i].Class {
			t.Fatalf("Destinations()[%d] = %+v, want %+v", i, got[i], destinations[i])
		}
	}

	got[0].URL = "https://mutated.example/"
	got[0].Name = "mutated"
	for k := range got[0].Headers {
		got[0].Headers[k] = "mutated"
	}
	if destinations[0].URL == "https://mutated.example/" || destinations[0].Name == "mutated" {
		t.Fatal("mutating the returned slice changed the production table")
	}
	for k, v := range destinations[0].Headers {
		if v == "mutated" {
			t.Fatalf("mutating a returned entry's Headers changed the production table (%s)", k)
		}
	}
}

// TestExpectStatusAcceptsAnEmptyBody is the new half of the success contract.
// Every generate_204 connectivity endpoint answers 204 with zero bytes -- that
// is the CORRECT answer, and 21 of 143 endpoints measured from a real
// datacenter host behave this way. Under the ExpectBody rule they would all be
// scored as failures.
//
// Read this together with TestEmptyBodyIs200Failure: the same handler, an empty
// 204, is a success here and a failure there. The only difference is what the
// destination declared, which is the whole point of Expect.
func TestExpectStatusAcceptsAnEmptyBody(t *testing.T) {
	dests := stubDestinations(t, []spec{
		{name: "c204", class: ClassConnectivity, h: status204(), expect: ExpectStatus, status: http.StatusNoContent},
	})
	res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
	if err != nil {
		t.Fatalf("check err = %v", err)
	}
	c := res.Checks[0]
	if !c.OK {
		t.Fatalf("a 204 with an empty body FAILED an ExpectStatus 204 destination (%+v); every generate_204 endpoint would read as a blackhole", c)
	}
	if c.StatusCode != http.StatusNoContent {
		t.Errorf("StatusCode = %d, want 204", c.StatusCode)
	}
	if c.ByteCount != 0 {
		t.Errorf("ByteCount = %d, want 0", c.ByteCount)
	}
	if c.Err != "" {
		t.Errorf("Err = %q, want empty", c.Err)
	}
	if res.OKCount != 1 || res.Total != 1 {
		t.Fatalf("OKCount/Total = %d/%d, want 1/1", res.OKCount, res.Total)
	}
}

// TestExpectStatusIsExactNotAny2xx keeps ExpectStatus from becoming a hole in
// the blackhole rule. A provider that terminates connections itself and
// synthesizes a bare status line produces a 200 with no body; if ExpectStatus
// accepted "any 2xx", every connectivity destination would pass for exactly the
// provider this package exists to catch. The match is EXACT, which makes these
// entries stricter than ExpectBody, not looser.
func TestExpectStatusIsExactNotAny2xx(t *testing.T) {
	cases := []struct {
		name string
		h    handler
	}{
		{"bare 200, no body -- the synthesized status line", emptyBody200()},
		{"200 with a body -- a portal answering instead", okBody("<html>sign in</html>")},
		{"206, still not the declared status", statusWithBody(http.StatusPartialContent, "partial")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dests := stubDestinations(t, []spec{
				{name: "c204", class: ClassConnectivity, h: tc.h, expect: ExpectStatus, status: http.StatusNoContent},
			})
			res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
			if err != nil {
				t.Fatalf("check err = %v", err)
			}
			c := res.Checks[0]
			if c.OK {
				t.Fatalf("status %d passed an ExpectStatus 204 destination; ExpectStatus must be an exact match, or a synthesized status line passes the check", c.StatusCode)
			}
			if !strings.Contains(c.Err, "want exactly") {
				t.Errorf("Err = %q, want it to say the status was not the declared one", c.Err)
			}
		})
	}
}

// TestExpectStatusWithoutAStatusFails: an entry that declares ExpectStatus and
// forgets the status must not silently accept anything that comes back.
// TestDestinationsTable keeps the production table free of this, and this keeps
// the runtime honest if one ever slips through.
func TestExpectStatusWithoutAStatusFails(t *testing.T) {
	dests := stubDestinations(t, []spec{{name: "broken", class: ClassConnectivity, h: okBody("anything"), expect: ExpectStatus}})
	res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
	if err != nil {
		t.Fatalf("check err = %v", err)
	}
	if res.Checks[0].OK {
		t.Fatal("a destination declaring ExpectStatus with no Status accepted the response; a misconfigured entry must fail, not pass everything")
	}
}

// TestVerifyRejectsAnInterceptedDNSAnswer is the captive-portal case. A 200
// with a body is NOT proof that a name was resolved: a portal, a transparent
// proxy or an interception box all return exactly that. Only an answer section
// proves resolution, which is why every DoH entry carries Verify.
func TestVerifyRejectsAnInterceptedDNSAnswer(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"a captive portal login page", "<html><body>Please sign in to continue</body></html>"},
		{"valid json that is not a dns answer", `{"result":"ok","message":"welcome"}`},
		{"a dns document with no answer section", `{"Status":3,"Question":[{"name":"example.com.","type":1}]}`},
		{"an answer section with empty data", `{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":""}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dests := stubDestinations(t, []spec{
				{name: "doh", class: ClassDNS, h: okBody(tc.body), verify: verifyDNSJSON},
			})
			res, err := check(context.Background(), http.DefaultClient, dests, fastOptions())
			if err != nil {
				t.Fatalf("check err = %v", err)
			}
			c := res.Checks[0]
			if c.OK {
				t.Fatalf("a 200 carrying %q passed a DoH destination; a status and some bytes are not proof a name was resolved", tc.body)
			}
			if c.StatusCode != http.StatusOK || c.ByteCount == 0 {
				t.Errorf("status=%d bytes=%d; the response DID arrive and must be recorded as such, so this is distinguishable from a blackhole", c.StatusCode, c.ByteCount)
			}
			if !strings.Contains(c.Err, "did not verify") {
				t.Errorf("Err = %q, want it to name the verification failure", c.Err)
			}
			if res.OKCount != 0 {
				t.Errorf("OKCount = %d, want 0", res.OKCount)
			}
		})
	}
}

// TestVerifyDNSJSONAcceptsEveryOperatorsShape is the other side of the same
// rule, and it is not hypothetical: the seven operators in the table disagree
// about the document AROUND the answer section. dns.alidns.com returns Question
// as an OBJECT where the others return an array, and dns.adguard-dns.com omits
// Status entirely. A validator that decoded either field would reject a working
// resolver as a captive portal -- for AliDNS on every single pass.
//
// The bodies below are the shapes captured from the live endpoints on
// 2026-07-31, trimmed.
func TestVerifyDNSJSONAcceptsEveryOperatorsShape(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"google/cloudflare/nextdns/dns.sb/doh.pub: Question is an array", `{"Status":0,"TC":false,"RD":true,"RA":true,"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"172.66.147.243"}]}`},
		{"alidns: Question is an OBJECT", `{"Status":0,"TC":false,"RD":true,"RA":true,"Question":{"name":"example.com","type":1},"Answer":[{"name":"example.com.","TTL":127,"type":1,"data":"104.20.23.154"}]}`},
		{"adguard: no Status field at all", `{"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","data":"172.66.147.243","TTL":101,"type":1,"class":1}]}`},
		{"dns.sb: extra per-record fields", `{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":21,"Expires":"Fri, 31 Jul 2026 08:57:28 UTC","data":"172.66.147.243"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyDNSJSON([]byte(tc.body)); err != nil {
				t.Fatalf("verifyDNSJSON rejected a real, working answer: %s\nbody: %s", err, tc.body)
			}
		})
	}
}

// TestVerifyContainsToleratesTrailingWhitespace: detectportal.firefox.com
// serves "success\n" -- eight bytes for a seven-character word. An equality
// check would fail for every provider forever, which is noise dressed as
// signal, exactly the failure the UserAgent comment warns about.
func TestVerifyContainsToleratesTrailingWhitespace(t *testing.T) {
	if err := verifyContains("success")([]byte("success\n")); err != nil {
		t.Fatalf("verifyContains rejected the real 8-byte body %q: %s", "success\n", err)
	}
	if err := verifyContains("Success")([]byte("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")); err != nil {
		t.Fatalf("verifyContains rejected captive.apple.com's real body: %s", err)
	}
	if err := verifyContains("success")([]byte("<html>Please sign in</html>")); err == nil {
		t.Fatal("verifyContains accepted a captive portal page")
	}
}

// TestVerifyIPText: the echo endpoints answer with an address and a newline
// (checkip.amazonaws.com) and may answer in v6 (icanhazip did, from the
// measuring host). A portal answers with html.
func TestVerifyIPText(t *testing.T) {
	for _, body := range []string{"74.50.11.113", "74.50.11.113\n", "2602:f7a3:0:2600::a\n"} {
		if err := verifyIPText([]byte(body)); err != nil {
			t.Errorf("verifyIPText(%q) = %s, want nil", body, err)
		}
	}
	for _, body := range []string{"", "<html>Please sign in</html>", "not-an-ip"} {
		if err := verifyIPText([]byte(body)); err == nil {
			t.Errorf("verifyIPText(%q) accepted a body that is not an address", body)
		}
	}
}

// TestReputationIsNotInTheHealthScore is the rule most likely to be "fixed"
// into a bug later, so it is asserted on its own.
//
// Every reputation destination refusing this exit is the NORMAL case for a
// hosted provider: those endpoints block datacenter ranges by policy. If that
// moved OKCount or Total, every hosted provider in the fleet would read as
// degraded and the health signal -- which is about whether the tunnel carries
// traffic at all -- would be buried under it.
func TestReputationIsNotInTheHealthScore(t *testing.T) {
	healthy := []spec{
		{name: "dns-a", class: ClassDNS, h: okBody(`{"Status":0}`)},
		{name: "dns-b", class: ClassDNS, h: okBody(`{"Status":0}`)},
		{name: "conn-a", class: ClassConnectivity, h: status204(), expect: ExpectStatus, status: http.StatusNoContent},
		{name: "conn-b", class: ClassConnectivity, h: okBody("success\n")},
		{name: "cdn-a", class: ClassCDN, h: okBody("/* css */")},
		{name: "cdn-b", class: ClassCDN, h: okBody("/* css */")},
		{name: "site-a", class: ClassSite, h: okBody("User-agent: *")},
		{name: "site-b", class: ClassSite, h: okBody("User-agent: *")},
	}

	// First: the health classes alone, so the baseline score is unambiguous.
	baseline, err := check(context.Background(), http.DefaultClient, stubDestinations(t, healthy), fastOptions())
	if err != nil {
		t.Fatalf("check err = %v", err)
	}
	if baseline.OKCount != 8 || baseline.Total != 8 {
		t.Fatalf("baseline OKCount/Total = %d/%d, want 8/8", baseline.OKCount, baseline.Total)
	}

	// Now the same health classes plus a reputation class that refuses
	// EVERYTHING -- the datacenter provider's normal day.
	withReputation := append(append([]spec{}, healthy...), []spec{
		{name: "rep-a", class: ClassReputation, h: statusWithBody(http.StatusForbidden, "Access Denied")},
		{name: "rep-b", class: ClassReputation, h: statusWithBody(http.StatusForbidden, "Access Denied")},
		{name: "rep-c", class: ClassReputation, h: statusWithBody(http.StatusUnauthorized, "unauthorized")},
		{name: "rep-d", class: ClassReputation, h: okBody("<html>a real page</html>")},
	}...)
	res, err := check(context.Background(), http.DefaultClient, stubDestinations(t, withReputation), fastOptions())
	if err != nil {
		t.Fatalf("check err = %v", err)
	}

	if res.OKCount != baseline.OKCount || res.Total != baseline.Total {
		t.Fatalf("adding a wholly failing reputation class moved the score to %d/%d (was %d/%d); reputation must not be scored -- a hosted provider failing all of it is still fully healthy",
			res.OKCount, res.Total, baseline.OKCount, baseline.Total)
	}
	if res.Reputation.OK != 1 || res.Reputation.Total != 4 {
		t.Errorf("Reputation = %d/%d, want 1/4; the class must still be measured and reported", res.Reputation.OK, res.Reputation.Total)
	}
	if _, present := res.ByClass[ClassReputation]; present {
		t.Error("ByClass carries a reputation entry; it must be reported separately, or a caller summing ByClass gets the contaminated total the split exists to prevent")
	}
	if got, want := res.Summary(), "ok=8/8 dns=2/2 connectivity=2/2 cdn=2/2 site=2/2 reputation=1/4"; got != want {
		t.Fatalf("Summary = %q, want %q; the reputation figure must ride alongside ok=N/M, never inside it", got, want)
	}

	// The failing reputation destinations must be reported -- separately. Which
	// vendor refused is the whole content of the signal, but it must not land in
	// the same list as a health failure.
	if names := res.FailedNames(); len(names) != 0 {
		t.Errorf("FailedNames = %v, want none; no health destination failed", names)
	}
	if got, want := strings.Join(res.ReputationFailedNames(), ","), "rep-a,rep-b,rep-c"; got != want {
		t.Errorf("ReputationFailedNames = %q, want %q", got, want)
	}

	// ...and every reputation check is still ATTEMPTED and recorded in full.
	for _, c := range res.Checks {
		if c.Class != ClassReputation || c.OK {
			continue
		}
		if c.StatusCode == 0 || c.ByteCount == 0 {
			t.Errorf("%s: status=%d bytes=%d; a refusal must be recorded as a refusal, not as silence", c.Name, c.StatusCode, c.ByteCount)
		}
	}
}

// TestWorstCaseBytesPerRunFitsTheBudget is the arithmetic the package documents,
// asserted rather than asserted-in-prose. The point of the wider table is that
// it is also a CHEAPER one; a destination added without a MaxBytes, or with a
// generous one, would quietly undo that.
func TestWorstCaseBytesPerRunFitsTheBudget(t *testing.T) {
	// The previous nine-entry table's worst case, and the ceiling the package
	// promises not to exceed.
	const budget = 9 * MaxBodyBytes // 36 KiB

	perClass := map[Class]int64{}
	var worst int64
	for _, d := range destinations {
		if d.MaxBytes <= 0 {
			t.Errorf("destination %q sets no MaxBytes; it would take the %d-byte default and the budget below stops being arithmetic", d.Name, MaxBodyBytes)
		}
		if d.MaxBytes > MaxBodyBytes {
			t.Errorf("destination %q has MaxBytes = %d, above the package ceiling %d; no single entry may raise the documented budget", d.Name, d.MaxBytes, MaxBodyBytes)
		}
		worst += d.maxBytes()
		perClass[d.Class] += d.maxBytes()
	}
	if worst > budget {
		t.Fatalf("worst-case body bytes per run = %d, above the documented budget %d", worst, budget)
	}
	t.Logf("worst case %d bytes (%.2f KiB) across %d destinations, budget %d", worst, float64(worst)/1024, len(destinations), budget)
	for _, c := range append(append([]Class{}, Classes...), ClassReputation) {
		t.Logf("  %-12s %5d bytes", c, perClass[c])
	}
}

// TestSuccessContractsAreDeclaredCoherently guards the table against the two
// ways an entry can be self-contradictory: an ExpectStatus with no status (it
// would accept nothing and fail every pass), and a status declared on an
// ExpectBody entry (it would be silently ignored, so the author's intent would
// not be what runs).
func TestSuccessContractsAreDeclaredCoherently(t *testing.T) {
	for _, d := range destinations {
		switch d.Expect {
		case ExpectStatus:
			if d.Status < 200 || 400 <= d.Status {
				t.Errorf("destination %q declares ExpectStatus with Status = %d; it must name the non-error status it actually answers", d.Name, d.Status)
			}
		case ExpectBody:
			if d.Status != 0 {
				t.Errorf("destination %q is ExpectBody but declares Status = %d, which is ignored; either drop it or declare ExpectStatus", d.Name, d.Status)
			}
		default:
			t.Errorf("destination %q has an unknown Expect %d", d.Name, d.Expect)
		}
	}
}

// TestEveryDNSDestinationVerifiesItsAnswer: a 200 with bytes from a DoH
// endpoint is not evidence of resolution, and this is the class where that
// distinction matters most -- name resolution is the shared precondition for
// every other destination in the table.
func TestEveryDNSDestinationVerifiesItsAnswer(t *testing.T) {
	for _, d := range destinations {
		if d.Class != ClassDNS {
			continue
		}
		if d.Verify == nil {
			t.Errorf("dns destination %q has no Verify; a captive portal returning 200 with a body would pass it", d.Name)
			continue
		}
		if err := d.Verify([]byte(`{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"93.184.216.34"}]}`)); err != nil {
			t.Errorf("dns destination %q rejects a well-formed answer: %s", d.Name, err)
		}
		if err := d.Verify([]byte(`<html>sign in</html>`)); err == nil {
			t.Errorf("dns destination %q accepts a portal page", d.Name)
		}
	}
	// Every DoH url must ask a question. A url without one answers 400 (or an
	// empty answer) for every provider forever.
	for _, d := range destinations {
		if d.Class == ClassDNS && !strings.Contains(d.URL, "name=") {
			t.Errorf("dns destination %q carries no name= query: %s", d.Name, d.URL)
		}
	}
}

// TestClassesExcludesReputation states the exclusion in the one place a future
// reader is most likely to look before "fixing" it.
func TestClassesExcludesReputation(t *testing.T) {
	for _, c := range Classes {
		if c == ClassReputation {
			t.Fatal("ClassReputation is in Classes; it is not part of the health score and must be rendered separately (see its doc comment -- folding it in makes every hosted provider read as broken)")
		}
	}
	if scored(ClassReputation) {
		t.Fatal("scored(ClassReputation) is true; reputation failures would move OKCount")
	}
	for _, c := range Classes {
		if !scored(c) {
			t.Errorf("class %q is declared in Classes but not scored", c)
		}
	}
	var reputation int
	for _, d := range destinations {
		if d.Class == ClassReputation {
			reputation++
		}
	}
	if reputation < 2 {
		t.Errorf("the table has %d reputation destination(s); with fewer than two, one vendor's policy change reads as an exit's reputation changing", reputation)
	}
}

// TestConnectivityClassIsCheapAndBroad: this class is the cheapest useful
// signal in the table, and it is only cheap if it stays that way.
func TestConnectivityClassIsCheapAndBroad(t *testing.T) {
	var n, status204Count int
	for _, d := range destinations {
		if d.Class != ClassConnectivity {
			continue
		}
		n++
		if d.Expect == ExpectStatus {
			status204Count++
		}
		if d.MaxBytes > 512 {
			t.Errorf("connectivity destination %q caps at %d bytes; this class answers in tens of bytes and a large cap gives that up", d.Name, d.MaxBytes)
		}
		if d.Expect == ExpectBody && d.Verify == nil {
			t.Errorf("connectivity destination %q reads a body but does not verify it; these endpoints exist to detect captive portals, which answer 200 with a page", d.Name)
		}
	}
	if n < 5 {
		t.Errorf("the connectivity class has %d destination(s), want a broad spread of operators", n)
	}
	if status204Count == 0 {
		t.Error("no connectivity destination uses ExpectStatus; the generate_204 endpoints are the reason the contract exists")
	}
}
