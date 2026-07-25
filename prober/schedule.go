package prober

import (
	"context"
	"log"
	"sync"
	"time"
)

// maxLoggedDistinctErrors caps how many DISTINCT probe error messages are
// logged in detail during a single Run (I2). Without a cap, a pass where
// every provider fails the same way (a wrong -platform-url, a revoked jwt)
// would flood the log with the same message hundreds of times, drowning
// out anything that could distinguish it from a handful of unrelated
// failures. 10 is chosen as "enough to see the shape of what's failing
// (one pin mismatch, one auth error, a few dial timeouts) without a flood";
// Run still logs a one-line notice once the cap is hit, and the pass's
// total Failed count is always visible via the Summary the caller logs.
const maxLoggedDistinctErrors = 10

// Summary reports one scheduler run.
type Summary struct {
	Attempted int
	Submitted int
	Skipped   int
	Failed    int
}

// Scheduler probes a set of providers with bounded concurrency, skipping any
// provider probed within CacheTTL. Only successful probes are cached, so a
// failure is retried on the next run.
type Scheduler struct {
	Prober      *Prober
	Concurrency int
	CacheTTL    time.Duration
	// Now defaults to time.Now; tests override it to advance the clock.
	Now func() time.Time

	mu     sync.Mutex
	probed map[string]time.Time
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scheduler) recentlyProbed(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.probed[id]
	if !ok {
		return false
	}
	return s.now().Sub(last) < s.CacheTTL
}

func (s *Scheduler) markProbed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.probed == nil {
		s.probed = map[string]time.Time{}
	}
	s.probed[id] = s.now()
}

// prune evicts entries from probed older than CacheTTL (M2). Without this,
// probed only ever grows: markProbed adds an entry per successfully probed
// provider and nothing ever removed one, so a long-lived process (this
// scheduler is driven from an infinite loop in cmd/egress-prober) would
// accumulate one map entry per provider ever seen, forever. An entry past
// CacheTTL no longer affects recentlyProbed's decision anyway (its age
// already exceeds the cache window), so evicting it changes no behavior --
// it only bounds memory. Pruning is O(n) over probed and runs once per Run
// call, which is cheap relative to the network calls Run is about to make.
func (s *Scheduler) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.probed == nil {
		return
	}
	now := s.now()
	for id, last := range s.probed {
		if s.CacheTTL <= now.Sub(last) {
			delete(s.probed, id)
		}
	}
}

// Run probes each provider that is not cached, with at most Concurrency
// tunnels open at once.
//
// Per-provider failures are logged as they occur (I2): before this, ProbeOne's
// error was discarded entirely (only aggregate counters ever left this
// function), so a wrong -platform-url, a revoked jwt, and a pin mismatch all
// produced an identical `failed=N` with nothing to distinguish them --
// making a broken prober running unattended on a VPS undebuggable without
// adding print statements and redeploying. To avoid flooding the log when
// every provider fails the same way, only the first maxLoggedDistinctErrors
// DISTINCT error messages are logged in detail (each with the provider id
// that first produced it); beyond that, one notice is logged noting further
// detail is suppressed. The total failure count is unaffected and always
// visible via the returned Summary.
func (s *Scheduler) Run(ctx context.Context, providerClientIds []string) Summary {
	s.prune()

	concurrency := s.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	var mu sync.Mutex
	var sum Summary
	loggedErrors := map[string]bool{}
	suppressedNoted := false

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, id := range providerClientIds {
		if s.recentlyProbed(id) {
			mu.Lock()
			sum.Skipped++
			mu.Unlock()
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()

			mu.Lock()
			sum.Attempted++
			mu.Unlock()

			err := s.Prober.ProbeOne(ctx, id)

			mu.Lock()
			if err != nil {
				sum.Failed++
				msg := err.Error()
				if !loggedErrors[msg] {
					if len(loggedErrors) < maxLoggedDistinctErrors {
						loggedErrors[msg] = true
						log.Printf("prober: probe failed provider=%s: %s", id, err)
					} else if !suppressedNoted {
						suppressedNoted = true
						log.Printf("prober: %d+ distinct probe errors this pass; suppressing further per-error detail (see the pass's failed count for the total)", maxLoggedDistinctErrors)
					}
				}
			} else {
				sum.Submitted++
			}
			mu.Unlock()

			if err == nil {
				s.markProbed(id)
			}
		}(id)
	}
	wg.Wait()
	return sum
}
