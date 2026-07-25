package prober

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
)

func okProber(probed *int32, mu *sync.Mutex, inflight *int32, maxSeen *int32) *Prober {
	return &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			cur := atomic.AddInt32(inflight, 1)
			mu.Lock()
			if cur > *maxSeen {
				*maxSeen = cur
			}
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			return &http.Client{}, func() error { atomic.AddInt32(inflight, -1); return nil }, nil
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			atomic.AddInt32(probed, 1)
			return &geolocate.ConsensusLocation{CountryCode: "us", CountryConfident: true}, nil
		},
		Submit: &stubSubmitter{},
	}
}

func TestSchedulerRespectsConcurrencyCap(t *testing.T) {
	var probed, inflight, maxSeen int32
	var mu sync.Mutex
	s := &Scheduler{Prober: okProber(&probed, &mu, &inflight, &maxSeen), Concurrency: 2, CacheTTL: time.Hour}

	ids := []string{"a", "b", "c", "d", "e", "f"}
	sum := s.Run(context.Background(), ids)

	if sum.Attempted != len(ids) {
		t.Fatalf("attempted = %d, want %d", sum.Attempted, len(ids))
	}
	if sum.Submitted != len(ids) {
		t.Fatalf("submitted = %d, want %d", sum.Submitted, len(ids))
	}
	mu.Lock()
	peak := maxSeen
	mu.Unlock()
	if peak > 2 {
		t.Fatalf("peak concurrency = %d, want <= 2", peak)
	}
}

func TestSchedulerCachesWithinTTL(t *testing.T) {
	var probed, inflight, maxSeen int32
	var mu sync.Mutex
	s := &Scheduler{Prober: okProber(&probed, &mu, &inflight, &maxSeen), Concurrency: 2, CacheTTL: time.Hour}

	s.Run(context.Background(), []string{"a", "b"})
	first := atomic.LoadInt32(&probed)
	sum := s.Run(context.Background(), []string{"a", "b"})

	if atomic.LoadInt32(&probed) != first {
		t.Fatal("a second run within the ttl must not re-probe")
	}
	if sum.Skipped != 2 {
		t.Fatalf("skipped = %d, want 2", sum.Skipped)
	}
}

func TestSchedulerReprobesAfterTTL(t *testing.T) {
	var probed, inflight, maxSeen int32
	var mu sync.Mutex
	now := time.Now()
	s := &Scheduler{
		Prober:      okProber(&probed, &mu, &inflight, &maxSeen),
		Concurrency: 2,
		CacheTTL:    time.Hour,
		Now:         func() time.Time { return now },
	}
	s.Run(context.Background(), []string{"a"})
	now = now.Add(2 * time.Hour)
	s.Run(context.Background(), []string{"a"})

	if atomic.LoadInt32(&probed) != 2 {
		t.Fatalf("probed = %d, want 2 (ttl expired)", probed)
	}
}

func TestSchedulerCountsFailuresAndDoesNotCache(t *testing.T) {
	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return nil, nil, errors.New("boom")
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, nil
		},
		Submit: &stubSubmitter{},
	}
	s := &Scheduler{Prober: p, Concurrency: 1, CacheTTL: time.Hour}
	sum := s.Run(context.Background(), []string{"a"})
	if sum.Failed != 1 {
		t.Fatalf("failed = %d, want 1", sum.Failed)
	}
	// a failure must not be cached; the next run retries
	sum2 := s.Run(context.Background(), []string{"a"})
	if sum2.Attempted != 1 {
		t.Fatal("a failed probe must be retried on the next run")
	}
}
