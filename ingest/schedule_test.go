package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDueRequestsTheContract locks the due request against the server's fixed
// contract: GET /network/provider-egress-due?limit=N with the operator secret
// header, decoding {"client_ids":[...]}.
func TestDueRequestsTheContract(t *testing.T) {
	var gotPath, gotQuery, gotMethod, gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotSecret = r.Header.Get("X-UR-Operator-Secret")
		_, _ = w.Write([]byte(`{"client_ids":["019f8835-158d-6fd8-e9dd-fd0e4c6d6792","019f8835-158d-6fd8-e9dd-fd0e4c6d6793"]}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	ids, err := c.Due(context.Background(), 250)
	if err != nil {
		t.Fatalf("Due err = %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotPath != "/network/provider-egress-due" {
		t.Errorf("path = %q, want /network/provider-egress-due", gotPath)
	}
	if gotQuery != "limit=250" {
		t.Errorf("query = %q, want limit=250", gotQuery)
	}
	// the same secret mechanism the submit path already uses; a second one
	// would be a second thing to get wrong in a deployment
	if gotSecret != "s3cret" {
		t.Errorf("operator secret header = %q", gotSecret)
	}
	if len(ids) != 2 || ids[0] != "019f8835-158d-6fd8-e9dd-fd0e4c6d6792" {
		t.Fatalf("Due = %v", ids)
	}
}

// TestDueHonoursDueURL: the operator can point the prober at a different due
// endpoint than the one derived from -api-url.
func TestDueHonoursDueURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"client_ids":[]}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: "http://unused.invalid", DueURL: srv.URL + "/elsewhere/due", OperatorSecret: "s", HTTP: srv.Client()}
	if _, err := c.Due(context.Background(), 10); err != nil {
		t.Fatalf("Due err = %v", err)
	}
	if gotPath != "/elsewhere/due" {
		t.Fatalf("path = %q, want the configured DueURL to win over ServerURL", gotPath)
	}
}

// TestDueReportsUnsupportedOn404 is what makes the prober work against a
// server that has not deployed the endpoint yet: 404 must be distinguishable
// so the caller can fall back to enumeration.
func TestDueReportsUnsupportedOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	_, err := c.Due(context.Background(), 10)
	if !errors.Is(err, ErrDueUnsupported) {
		t.Fatalf("Due err = %v, want ErrDueUnsupported so the caller can fall back to enumeration", err)
	}
}

// TestDueDoesNotReportUnsupportedOn401: a 401 is a wrong operator secret, not
// an old server. Folding it into the fallback would silently downgrade a
// misconfigured deployment to enumeration and hide the real fault -- while
// every submission it then made would be rejected by the same bad secret.
func TestDueDoesNotReportUnsupportedOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "wrong", HTTP: srv.Client()}
	_, err := c.Due(context.Background(), 10)
	if err == nil {
		t.Fatal("Due accepted a 401")
	}
	if errors.Is(err, ErrDueUnsupported) {
		t.Fatalf("Due err = %v, must NOT be ErrDueUnsupported: a 401 is a misconfigured secret and must be loud, not a silent fallback", err)
	}
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Due err = %v, want ErrUnauthorized", err)
	}
}

func TestDueRejectsOtherErrorStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	if _, err := c.Due(context.Background(), 10); !errors.Is(err, ErrRejected) {
		t.Fatalf("Due err = %v, want ErrRejected", err)
	}
}

// TestDueRejectsNonPositiveLimit: the server answers 400 to limit<1, because
// limit=0 comes back as an empty list that the prober cannot tell apart from
// "nothing is due". Catch it before the round trip.
func TestDueRejectsNonPositiveLimit(t *testing.T) {
	c := &Client{ServerURL: "http://unused.invalid", OperatorSecret: "s"}
	for _, limit := range []int{0, -1} {
		if _, err := c.Due(context.Background(), limit); err == nil {
			t.Fatalf("Due accepted limit=%d; an empty result is indistinguishable from \"nothing is due\"", limit)
		}
	}
}

// TestReportAttemptPostsTheContract locks the attempt request against
// controller.RecordProviderEgressProbeAttemptArgs.
func TestReportAttemptPostsTheContract(t *testing.T) {
	var got map[string]any
	var gotPath, gotMethod, gotSecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotSecret = r.Header.Get("X-UR-Operator-Secret")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"attempt_at":"2026-07-26T00:00:00Z"}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s3cret", HTTP: srv.Client()}
	if err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", "tunnel_failed"); err != nil {
		t.Fatalf("ReportAttempt err = %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/network/provider-egress-attempt" {
		t.Errorf("path = %q, want /network/provider-egress-attempt", gotPath)
	}
	if gotSecret != "s3cret" {
		t.Errorf("operator secret header = %q", gotSecret)
	}
	if got["client_id"] != "019f8835-158d-6fd8-e9dd-fd0e4c6d6792" {
		t.Errorf("client_id = %v", got["client_id"])
	}
	if got["probe_failure"] != "tunnel_failed" {
		t.Errorf("probe_failure = %v, want tunnel_failed", got["probe_failure"])
	}
}

// TestReportAttemptOmitsProbeFailureOnSuccess: "" means success on the wire.
func TestReportAttemptOmitsProbeFailureOnSuccess(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"attempt_at":"2026-07-26T00:00:00Z"}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	if err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", ""); err != nil {
		t.Fatalf("ReportAttempt err = %v", err)
	}
	if v, ok := got["probe_failure"]; ok && v != "" {
		t.Fatalf("probe_failure = %v, want it omitted or empty on success", v)
	}
}

// TestReportAttemptTruncatesProbeFailure: the server's column is varchar(64)
// and the controller rejects anything longer with a 400 -- which would turn a
// long failure class into a *lost attempt report*, i.e. straight back into the
// starvation this endpoint exists to fix.
func TestReportAttemptTruncatesProbeFailure(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"attempt_at":"2026-07-26T00:00:00Z"}`))
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	long := strings.Repeat("x", 200)
	if err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", long); err != nil {
		t.Fatalf("ReportAttempt err = %v", err)
	}
	sent, _ := got["probe_failure"].(string)
	if len(sent) != MaxProbeFailureLen {
		t.Fatalf("probe_failure length = %d, want it truncated to %d (the server's column width)", len(sent), MaxProbeFailureLen)
	}
}

func TestReportAttemptSurfacesUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "wrong", HTTP: srv.Client()}
	err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", "tunnel_failed")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ReportAttempt err = %v, want ErrUnauthorized", err)
	}
}

// TestReportAttemptTolerates404: an old server has no attempt endpoint. The
// prober must keep probing against it, so this is reported as unsupported
// rather than as a probe failure.
func TestReportAttemptTolerates404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := &Client{ServerURL: srv.URL, OperatorSecret: "s", HTTP: srv.Client()}
	err := c.ReportAttempt(context.Background(), "019f8835-158d-6fd8-e9dd-fd0e4c6d6792", "tunnel_failed")
	if !errors.Is(err, ErrAttemptUnsupported) {
		t.Fatalf("ReportAttempt err = %v, want ErrAttemptUnsupported", err)
	}
}
