package prober

import (
	"context"
	"sync"
	"time"
)

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

// Run probes each provider that is not cached, with at most Concurrency
// tunnels open at once.
func (s *Scheduler) Run(ctx context.Context, providerClientIds []string) Summary {
	concurrency := s.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	var mu sync.Mutex
	var sum Summary

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
