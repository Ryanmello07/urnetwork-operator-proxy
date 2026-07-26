// Package prober probes one provider's egress location: open a tunnel pinned to
// that provider, run the geolocation consensus through it, submit the result.
package prober

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
)

// Locator runs the geolocation consensus over a client. In production this is
// geolocate.Locate.
type Locator func(ctx context.Context, client *http.Client) (*geolocate.ConsensusLocation, error)

// TunnelOpener opens a tunnel to one provider and returns an http.Client that
// egresses through it, plus a close function.
type TunnelOpener func(ctx context.Context, providerClientId string) (*http.Client, func() error, error)

// Submitter records a probed location.
type Submitter interface {
	Submit(ctx context.Context, providerClientId string, loc *geolocate.ConsensusLocation) error
}

// AttemptReporter records that a probe was tried, whether or not it produced a
// location. In production this is *ingest.Client.
type AttemptReporter interface {
	ReportAttempt(ctx context.Context, providerClientId string, probeFailure string) error
}

// The failure classes reported to the server. They are short, stable strings
// (the server's column is varchar(64) and rejects anything longer), and "" is
// reserved to mean success.
const (
	// FailureTunnel: no tunnel to the provider. Refused contract, unreachable
	// platform, pin set rejected -- the probe never started.
	FailureTunnel = "tunnel_failed"
	// FailureNoConsensus: the tunnel worked but fewer than geolocate.MinSources
	// sources answered through it.
	FailureNoConsensus = "no_consensus"
	// FailureLocate: any other error running the lookups.
	FailureLocate = "locate_failed"
	// FailureNotConfident: sources answered but did not agree well enough to
	// record a location. Not an error in the provider -- it is what the free
	// sources did -- but the provider still has no location, so the attempt
	// must count.
	FailureNotConfident = "not_confident"
	// FailureSubmit: the location was country-confident and submitting it
	// still failed. Usually the server would not take it (a rejection, a 5xx,
	// a dead connection), but not always: the submitter also refuses some
	// results locally, before any request is made -- ingest.ErrMissingProbedAt
	// and ingest.ErrIncompleteCountry are pre-flight rejections in which the
	// server is never contacted. Either way the provider has no recorded
	// location, which is what this class reports.
	FailureSubmit = "submit_failed"
)

// Prober wires a tunnel opener, a locator, a submitter, and an attempt
// reporter. Each dependency is injected so the flow is testable without a live
// provider or server.
type Prober struct {
	Open   TunnelOpener
	Locate Locator
	Submit Submitter
	// Attempts reports every probe attempt. Optional -- a nil reporter simply
	// skips reporting -- but production must set it: see ProbeOne.
	Attempts AttemptReporter

	// attemptErr deduplicates attempt-reporting error messages. Whatever stops
	// the reports getting through -- an older server with no attempt endpoint,
	// a wrong secret, a dead network -- stops them for every provider, so
	// logging per provider would bury the pass's real output under one
	// identical line per provider, every pass.
	attemptErrMu     sync.Mutex
	attemptErrLogged map[string]bool
}

// ProbeOne probes a single provider. The tunnel is always closed, and nothing
// is submitted unless the geolocation reached consensus.
//
// The attempt is reported afterwards whatever happened, success or failure.
// That is not bookkeeping: the server defers a provider from the due queue when
// a probe was recently ATTEMPTED, not only when one succeeded. A provider that
// always fails to probe never gets a location row, so its observed_at stays
// NULL, and the due query sorts NULLs first -- it comes back at the head of
// every poll, forever, starving every healthy provider. The failure is silent,
// because the endpoint keeps returning a full and plausible batch. Reporting a
// success is redundant (the submitted location defers the provider for far
// longer than the attempt backoff) but harmless, and reporting unconditionally
// means no path through this function can forget.
//
// A failure to report never fails the probe itself: the location, if there was
// one, is already recorded server-side.
func (p *Prober) ProbeOne(ctx context.Context, providerClientId string) error {
	failure, err := p.probeOne(ctx, providerClientId)
	p.reportAttempt(ctx, providerClientId, failure)
	return err
}

// probeOne runs the probe and returns the failure class ("" on success)
// alongside the error, so ProbeOne can report an attempt for every outcome.
func (p *Prober) probeOne(ctx context.Context, providerClientId string) (string, error) {
	client, closeTunnel, err := p.Open(ctx, providerClientId)
	if err != nil {
		return FailureTunnel, fmt.Errorf("open tunnel to %s: %w", providerClientId, err)
	}
	defer func() {
		if closeTunnel != nil {
			_ = closeTunnel()
		}
	}()

	loc, err := p.Locate(ctx, client)
	if err != nil {
		if errors.Is(err, geolocate.ErrNoConsensus) {
			return FailureNoConsensus, err
		}
		return FailureLocate, err
	}

	if err := p.Submit.Submit(ctx, providerClientId, loc); err != nil {
		// Classified here rather than by matching ingest's sentinels, which
		// would couple this package to the submitter implementation the
		// Submitter interface exists to keep out. The distinction is the same
		// one ingest makes: a result that was never usable, versus a usable
		// result the server would not take.
		if loc == nil || !loc.CountryConfident {
			return FailureNotConfident, err
		}
		return FailureSubmit, err
	}
	return "", nil
}

func (p *Prober) reportAttempt(ctx context.Context, providerClientId string, failure string) {
	if p.Attempts == nil {
		return
	}
	err := p.Attempts.ReportAttempt(ctx, providerClientId, failure)
	if err == nil {
		return
	}

	msg := err.Error()
	p.attemptErrMu.Lock()
	logged := p.attemptErrLogged[msg]
	if !logged {
		if p.attemptErrLogged == nil {
			p.attemptErrLogged = map[string]bool{}
		}
		p.attemptErrLogged[msg] = true
	}
	p.attemptErrMu.Unlock()

	if !logged {
		log.Printf("prober: could not report a probe attempt (provider=%s failure=%q): %s -- while this persists, providers that always fail to probe stay at the head of the server's due queue. Logged once per distinct error.", providerClientId, failure, err)
	}
}
