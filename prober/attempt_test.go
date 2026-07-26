package prober

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
)

type attempt struct {
	id      string
	failure string
}

type stubReporter struct {
	mu       sync.Mutex
	attempts []attempt
	err      error
}

func (s *stubReporter) ReportAttempt(ctx context.Context, id string, probeFailure string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, attempt{id: id, failure: probeFailure})
	return s.err
}

func (s *stubReporter) snapshot() []attempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]attempt(nil), s.attempts...)
}

func okOpen(ctx context.Context, id string) (*http.Client, func() error, error) {
	return &http.Client{}, func() error { return nil }, nil
}

// TestProbeOneReportsAttemptOnSuccess. Every attempt is reported, success
// included: the rule has to be unconditional or there is a path through the
// prober that forgets.
func TestProbeOneReportsAttemptOnSuccess(t *testing.T) {
	rep := &stubReporter{}
	p := &Prober{
		Open: okOpen,
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit:   &stubSubmitter{},
		Attempts: rep,
	}
	if err := p.ProbeOne(context.Background(), "p1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}
	got := rep.snapshot()
	if len(got) != 1 {
		t.Fatalf("attempts = %v, want exactly one", got)
	}
	if got[0].id != "p1" {
		t.Errorf("attempt client id = %q, want p1", got[0].id)
	}
	if got[0].failure != "" {
		t.Errorf("probe_failure = %q, want empty on success", got[0].failure)
	}
}

// TestProbeOneReportsAttemptOnEveryFailureStage is the starvation fix's
// prober-side half. A provider that always fails to probe never gets a
// location row, so the server's due query hands it back on every poll forever
// and no healthy provider is ever refreshed -- silently, because the endpoint
// keeps returning a full plausible batch. The server can only defer such a
// provider if the prober tells it the attempt happened, so EVERY failure stage
// must report.
func TestProbeOneReportsAttemptOnEveryFailureStage(t *testing.T) {
	confident := &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}

	cases := []struct {
		name        string
		prober      func(rep *stubReporter) *Prober
		wantFailure string
	}{
		{
			name: "tunnel",
			prober: func(rep *stubReporter) *Prober {
				return &Prober{
					Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
						return nil, nil, errors.New("no contract")
					},
					Locate:   func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) { return nil, nil },
					Submit:   &stubSubmitter{},
					Attempts: rep,
				}
			},
			wantFailure: FailureTunnel,
		},
		{
			name: "no consensus",
			prober: func(rep *stubReporter) *Prober {
				return &Prober{
					Open: okOpen,
					Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
						return nil, geolocate.ErrNoConsensus
					},
					Submit:   &stubSubmitter{},
					Attempts: rep,
				}
			},
			wantFailure: FailureNoConsensus,
		},
		{
			name: "locate",
			prober: func(rep *stubReporter) *Prober {
				return &Prober{
					Open: okOpen,
					Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
						return nil, errors.New("something else")
					},
					Submit:   &stubSubmitter{},
					Attempts: rep,
				}
			},
			wantFailure: FailureLocate,
		},
		{
			name: "not confident",
			prober: func(rep *stubReporter) *Prober {
				return &Prober{
					Open: okOpen,
					Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
						return &geolocate.ConsensusLocation{}, nil
					},
					Submit:   &stubSubmitter{err: errors.New("not confident")},
					Attempts: rep,
				}
			},
			wantFailure: FailureNotConfident,
		},
		{
			name: "submit",
			prober: func(rep *stubReporter) *Prober {
				return &Prober{
					Open: okOpen,
					Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
						return confident, nil
					},
					Submit:   &stubSubmitter{err: errors.New("status 500")},
					Attempts: rep,
				}
			},
			wantFailure: FailureSubmit,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &stubReporter{}
			if err := tc.prober(rep).ProbeOne(context.Background(), "p1"); err == nil {
				t.Fatal("ProbeOne returned nil on a failing probe")
			}
			got := rep.snapshot()
			if len(got) != 1 {
				t.Fatalf("attempts = %v, want exactly one; an unreported attempt leaves this provider at the head of the due queue forever", got)
			}
			if got[0].failure != tc.wantFailure {
				t.Fatalf("probe_failure = %q, want %q", got[0].failure, tc.wantFailure)
			}
		})
	}
}

// TestFailureClassesFitTheServerColumn: the server rejects a class longer than
// 64 chars with a 400, and a rejected report is a lost report.
func TestFailureClassesFitTheServerColumn(t *testing.T) {
	for _, class := range []string{FailureTunnel, FailureNoConsensus, FailureLocate, FailureNotConfident, FailureSubmit} {
		if class == "" {
			t.Error("a failure class is empty; empty means success on the wire")
		}
		if 64 < len(class) {
			t.Errorf("failure class %q is longer than the server's varchar(64)", class)
		}
	}
}

// TestProbeOneDoesNotFailTheProbeWhenReportingFails: a broken attempt endpoint
// must not turn a good probe into a failure -- the location was submitted and
// is already recorded server-side.
func TestProbeOneDoesNotFailTheProbeWhenReportingFails(t *testing.T) {
	rep := &stubReporter{err: errors.New("attempt endpoint down")}
	p := &Prober{
		Open: okOpen,
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit:   &stubSubmitter{},
		Attempts: rep,
	}
	if err := p.ProbeOne(context.Background(), "p1"); err != nil {
		t.Fatalf("ProbeOne err = %v; a failed attempt report must not fail the probe itself", err)
	}
}

// TestProbeOneWithoutAReporterStillProbes keeps Attempts optional so a caller
// that has no reporter (a test, a one-shot manual probe) is not broken by it.
func TestProbeOneWithoutAReporterStillProbes(t *testing.T) {
	sub := &stubSubmitter{}
	p := &Prober{
		Open: okOpen,
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit: sub,
	}
	if err := p.ProbeOne(context.Background(), "p1"); err != nil {
		t.Fatalf("ProbeOne err = %v", err)
	}
	if sub.calls != 1 {
		t.Fatalf("submit calls = %d, want 1", sub.calls)
	}
}
