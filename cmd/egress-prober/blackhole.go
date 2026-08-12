package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/operator-proxy/egresshealth"
	"github.com/urnetwork/operator-proxy/ingest"
	"github.com/urnetwork/operator-proxy/providertunnel"
)

// blackholeSweeper runs the cheap liveness check across the whole fleet on its
// own cadence, independently of the geolocation/health pass.
//
// The two must not share a loop. The full pass spends minutes per provider and
// sweeps the fleet over hours to days; in that window a provider that silently
// stops forwarding keeps its last passing measurement and stays in the public
// list. This exists to close that window, which only works if it runs on its
// own much shorter one.
type blackholeSweeper struct {
	operator    *ingest.Client
	tunnelCfg   providertunnel.Config
	pins        *pinSet
	timeout     time.Duration
	concurrency int
	limit       int
}

// maxBlackholeRounds bounds one sweep's batches. 40 rounds x the server's 5000
// ceiling is far above any real fleet, so it never truncates a legitimate
// sweep; it exists so a server that keeps handing back work cannot hold a pass
// open indefinitely and starve the interval.
const maxBlackholeRounds = 40

// blackholeResult carries one provider's outcome out of the worker pool.
type blackholeResult struct {
	check   ingest.BlackholeCheck
	dark    bool
	tunnel  bool
	details string
}

// sweep runs one pass: ask what is due, check each, report the batch.
//
// Returns the number checked, so the caller can tell "the fleet is covered"
// from "the queue handed us nothing", which look identical in a log line.
func (s *blackholeSweeper) sweep(ctx context.Context) (checked int, err error) {
	clientIds, err := s.operator.BlackholeDue(ctx, s.limit)
	if err != nil {
		return 0, err
	}
	if len(clientIds) == 0 {
		return 0, nil
	}

	results := make([]blackholeResult, len(clientIds))

	sem := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup
	for i, clientId := range clientIds {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i int, clientId string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = s.checkOne(ctx, clientId)
		}(i, clientId)
	}
	wg.Wait()

	checks := make([]ingest.BlackholeCheck, 0, len(results))
	var dark, tunnelFailed int
	for _, r := range results {
		if r.check.ClientId == "" {
			// never ran: the pass was cancelled before this slot started
			continue
		}
		checks = append(checks, r.check)
		if r.dark {
			dark++
			if r.tunnel {
				tunnelFailed++
			}
			log.Printf("blackhole: provider=%s DARK %s", r.check.ClientId, r.details)
		}
	}

	if len(checks) == 0 {
		return 0, nil
	}
	if err := s.operator.SubmitBlackholeChecks(ctx, checks); err != nil {
		// the whole batch is lost, not part of it -- the server validates before
		// writing -- so say how much
		return 0, fmt.Errorf("submitting %d checks: %w", len(checks), err)
	}

	log.Printf("blackhole: pass checked=%d dark=%d (tunnel_failed=%d) ok=%d",
		len(checks), dark, tunnelFailed, len(checks)-dark)
	return len(checks), nil
}

// checkOne opens a tunnel through one provider and asks whether anything gets
// through.
//
// A tunnel that cannot be opened counts as dark, and that is a deliberate
// choice rather than an oversight: from a client's point of view a provider it
// cannot establish a circuit through is exactly as useless as one that carries
// nothing, and the whole purpose of this signal is to stop advertising
// providers a client cannot use. It is recorded under its own failure class so
// the two remain distinguishable in the data.
func (s *blackholeSweeper) checkOne(ctx context.Context, clientId string) blackholeResult {
	checkedAt := time.Now().UTC()

	id, err := connect.ParseId(clientId)
	if err != nil {
		return blackholeResult{
			check:   ingest.BlackholeCheck{ClientId: clientId, OK: false, Failure: "bad_client_id", CheckedAt: checkedAt},
			dark:    true,
			details: err.Error(),
		}
	}

	cfg := s.tunnelCfg
	cfg.Pins = s.pins.get()
	t, err := providertunnel.Open(ctx, cfg, id)
	if err != nil {
		return blackholeResult{
			check:   ingest.BlackholeCheck{ClientId: clientId, OK: false, Failure: "tunnel_failed", CheckedAt: checkedAt},
			dark:    true,
			tunnel:  true,
			details: err.Error(),
		}
	}
	defer t.Close()

	// Only the blackhole destinations are allowed through this client. The full
	// pass allows the whole egress-health table and the bandwidth targets; this
	// check reaches three connectivity endpoints and nothing else, so the
	// allowlist says exactly that.
	client := t.HTTPClientForHosts(s.timeout, egresshealth.BlackholeHosts())

	res := egresshealth.Blackhole(ctx, client, egresshealth.Options{PerRequestTimeout: s.timeout})

	check := ingest.BlackholeCheck{ClientId: clientId, OK: res.OK, CheckedAt: checkedAt}
	if !res.OK {
		check.Failure = res.Failure
	}

	details := ""
	if !res.OK {
		for _, r := range res.Results {
			details += r.Name + "=" + r.Err + " "
		}
	}
	return blackholeResult{check: check, dark: !res.OK, details: details}
}

// run sweeps on the interval until the context ends.
//
// A pass that errors is logged and retried on the next tick rather than
// stopping the sweeper: the server being briefly unreachable must not silently
// end blackhole detection for the life of the process. ErrBlackholeUnsupported
// is the one exception -- an older server will never grow the endpoint mid-run,
// so it says so once and stops instead of logging the same 404 hourly.
func (s *blackholeSweeper) run(ctx context.Context, interval time.Duration) {
	for {
		start := time.Now()
		// Drain the queue, do not take one batch and sleep. The requirement is
		// that the WHOLE fleet is checked every interval, and the batch size is the
		// server's per-request ceiling, not the size of the fleet: at 500 per
		// request against ~2,700 eligible providers, one batch per hour covers
		// under a fifth of them and the oldest evidence would age out faster
		// than the sweep reaches it. Rounds are bounded so a server that keeps
		// returning work cannot hold a pass open forever.
		total, err := 0, error(nil)
		for round := 0; round < maxBlackholeRounds; round++ {
			var checked int
			checked, err = s.sweep(ctx)
			total += checked
			if err != nil || checked == 0 || ctx.Err() != nil {
				break
			}
		}
		checked := total
		switch {
		case err == nil:
			if checked == 0 {
				log.Printf("blackhole: pass found nothing due")
			} else {
				log.Printf("blackhole: sweep complete: %d checked in %s", checked, time.Since(start).Round(time.Second))
			}
		case errors.Is(err, ingest.ErrBlackholeUnsupported):
			log.Printf("blackhole: the server does not implement the blackhole endpoints; sweeping is disabled")
			return
		case errors.Is(err, ingest.ErrUnauthorized):
			// same posture as the credential self-check: a rejected secret is a
			// broken deployment, and retrying hourly would hide it behind a
			// sweep that never records anything
			log.Printf("blackhole: the server rejected the operator secret; sweeping is disabled. Fix -operator-secret and restart.")
			return
		default:
			log.Printf("blackhole: pass failed after %s: %s", time.Since(start).Round(time.Second), err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
