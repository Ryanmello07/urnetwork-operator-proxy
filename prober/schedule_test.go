package prober

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
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

// TestSchedulerPrunesProbedAfterTTL is the M2 regression test: probed must
// not grow unboundedly across the life of a long-running Scheduler. An
// entry past CacheTTL no longer affects recentlyProbed's decision either
// way, but it must still be evicted from the map so memory does not
// accumulate one entry per provider ever probed, forever, in a process
// that runs an unbounded number of passes (cmd/egress-prober's main loop).
// This drives Run with an EMPTY id list on the second call specifically to
// isolate pruning from re-probing: nothing is attempted or skipped, so any
// change to probed's size can only be prune's doing.
func TestSchedulerPrunesProbedAfterTTL(t *testing.T) {
	var probed, inflight, maxSeen int32
	var mu sync.Mutex
	now := time.Now()
	s := &Scheduler{
		Prober:      okProber(&probed, &mu, &inflight, &maxSeen),
		Concurrency: 2,
		CacheTTL:    time.Hour,
		Now:         func() time.Time { return now },
	}
	s.Run(context.Background(), []string{"a", "b"})

	s.mu.Lock()
	before := len(s.probed)
	s.mu.Unlock()
	if before != 2 {
		t.Fatalf("probed entries after first run = %d, want 2", before)
	}

	now = now.Add(2 * time.Hour)
	s.Run(context.Background(), nil)

	s.mu.Lock()
	after := len(s.probed)
	s.mu.Unlock()
	if after != 0 {
		t.Fatalf("probed entries after TTL elapsed = %d, want 0 (stale entries must be pruned)", after)
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

// TestSchedulerLogsCappedDistinctErrors is the I2 regression test: each
// provider here fails with a DISTINCT error message (so a naive
// once-per-message dedupe against a single global error would not
// coalesce them), and there are more of them than
// maxLoggedDistinctErrors. Run must log detail for only the first
// maxLoggedDistinctErrors distinct messages, plus exactly one suppression
// notice once the cap is hit -- not flood the log with all of them, and
// not silently drop all detail either. sum.Failed must still count every
// failure regardless of how many were logged in detail.
func TestSchedulerLogsCappedDistinctErrors(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	p := &Prober{
		Open: func(ctx context.Context, id string) (*http.Client, func() error, error) {
			return nil, nil, fmt.Errorf("boom-%s", id) // distinct per provider
		},
		Locate: func(ctx context.Context, c *http.Client) (*geolocate.ConsensusLocation, error) {
			return nil, nil
		},
		Submit: &stubSubmitter{},
	}

	const n = maxLoggedDistinctErrors + 5
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("p%d", i)
	}

	s := &Scheduler{Prober: p, Concurrency: 4, CacheTTL: time.Hour}
	sum := s.Run(context.Background(), ids)

	if sum.Failed != n {
		t.Fatalf("failed = %d, want %d", sum.Failed, n)
	}

	logged := buf.String()
	detailLines := strings.Count(logged, "probe failed provider=")
	if detailLines != maxLoggedDistinctErrors {
		t.Fatalf("detail lines logged = %d, want %d (the cap)", detailLines, maxLoggedDistinctErrors)
	}
	if strings.Count(logged, "suppressing further per-error detail") != 1 {
		t.Fatal("want exactly one suppression notice once the distinct-error cap was hit")
	}
}
