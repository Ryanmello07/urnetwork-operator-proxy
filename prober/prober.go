// Package prober probes one provider's egress location: open a tunnel pinned to
// that provider, run the geolocation consensus through it, submit the result.
package prober

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/urnetwork/urnetwork-operator-proxy/egresshealth"
	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
)

// Locator runs the geolocation consensus over a client. In production this is
// geolocate.Locate.
type Locator func(ctx context.Context, client *http.Client) (*geolocate.ConsensusLocation, error)

// TunnelOpener opens a tunnel to one provider and returns an http.Client that
// egresses through it, plus a close function.
type TunnelOpener func(ctx context.Context, providerClientId string) (*http.Client, func() error, error)

// EgressHealthChecker runs the egress-health check over a client. In production
// this is egresshealth.Check, wired in cmd/egress-prober.
type EgressHealthChecker func(ctx context.Context, client *http.Client) (*egresshealth.Result, error)

// BandwidthSampler measures the provider's throughput over the tunnel the
// geolocation probe already opened, and records what it measured. In
// production this is bandwidth.Sampler.Sample plus the log line, wired in
// cmd/egress-prober.
//
// It returns nothing, deliberately. Bandwidth is a diagnostic riding along on
// a probe whose product is the geolocation: no outcome of the measurement --
// not a skipped budget reservation, not a dead target, not a zero sample --
// may change whether the probe succeeded or what failure class was reported
// for it.
type BandwidthSampler func(ctx context.Context, providerClientId string, client *http.Client)

// Submitter records a probed location.
type Submitter interface {
	Submit(ctx context.Context, providerClientId string, loc *geolocate.ConsensusLocation) error
}

// HealthReporter records one egress-health run. In production this is
// *ingest.Client.
//
// It is an interface on the Prober, like Submitter and AttemptReporter, so
// this package never imports the submitter implementation and a test can drive
// the whole flow without a server.
type HealthReporter interface {
	SubmitEgressHealth(ctx context.Context, providerClientId string, res *egresshealth.Result) error
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
	// Health runs the egress-health check over the SAME tunnel the geolocation
	// lookup used. Optional -- a nil checker skips it entirely.
	//
	// The result is logged and, if HealthResults is set, submitted. It is still
	// only a signal: no verdict is derived from it here, and nothing about the
	// outcome may de-list a provider. Shipping a verdict before the signal has
	// been watched in the field is how a probe starts de-listing working
	// providers.
	Health EgressHealthChecker
	// HealthResults records each egress-health run so it outlives the log line.
	// Optional -- a nil reporter simply skips submitting.
	//
	// Fire-and-forget, exactly like Attempts: a submission failure is logged
	// once per distinct error and never changes the probe's outcome. The
	// product of this pass is the geolocation, and a diagnostic that could fail
	// it would be worse than no diagnostic.
	HealthResults HealthReporter
	// Bandwidth measures throughput over the SAME tunnel, after the location
	// has been submitted. Optional -- a nil sampler skips it entirely.
	//
	// It runs last, and only after a probe that succeeded, for two reasons.
	// Last, because the location is the product this pass exists to deliver
	// and must never lose budget or fail because of a diagnostic. Only after
	// success, because the deployment-wide byte budget it spends is scarce
	// (each measurement pulls megabytes of real, paid contract traffic through
	// the provider's tunnel), and spending it on a tunnel that has already
	// demonstrated it cannot carry three small geolocation lookups buys a
	// number that describes the failure rather than the link.
	Bandwidth BandwidthSampler
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

	// healthErrLogged deduplicates health-submission error messages, for the
	// same reason attemptErrLogged does: whatever stops the submissions getting
	// through -- an older server with no health endpoint, a wrong secret, a
	// dead network -- stops them for every provider, so logging per provider
	// would bury the pass's real output under one identical line per provider,
	// every pass.
	//
	// A separate pair rather than a shared generic helper: the two reporters
	// fail for different reasons and say different things about what is lost,
	// and a shared map would let a noisy attempt error suppress the first
	// health error (or the reverse).
	healthErrMu     sync.Mutex
	healthErrLogged map[string]bool
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

	loc, locErr := p.Locate(ctx, client)

	// The egress-health check rides the tunnel that is already open, never a
	// second one: a second tunnel would double the contract cost per provider
	// and, worse, would be measuring a different session than the one the
	// geolocation verdict came from.
	//
	// It runs AFTER the lookups and regardless of how they went. After, because
	// the location is the product this pass exists to deliver and must not lose
	// budget to a diagnostic. Regardless, because a provider whose geolocation
	// failed is exactly the one whose egress pattern is worth having -- that is
	// where "carried nothing at all" separates from "carried everything except
	// the three geolocation APIs".
	p.checkEgressHealth(ctx, providerClientId, client)

	if locErr != nil {
		if errors.Is(locErr, geolocate.ErrNoConsensus) {
			return FailureNoConsensus, locErr
		}
		return FailureLocate, locErr
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

	// The bandwidth sample rides the tunnel that is still open, never a second
	// one, and cannot change what this function returns: the probe has already
	// succeeded by the time it runs.
	if p.Bandwidth != nil {
		p.Bandwidth(ctx, providerClientId, client)
	}
	return "", nil
}

// checkEgressHealth runs the egress-health check and logs one line per
// provider. It never affects the probe's outcome: the failure classes reported
// to the server describe geolocation, and a diagnostic must not be able to
// change the record of whether a location was obtained.
//
// A run started on an expired context comes back 0/N -- which reads in the log
// exactly like a total blackhole, but is the prober's own exhausted deadline
// rather than anything the provider did. That would be a false accusation
// against a working provider, so it is refused and logged as skipped instead.
// egresshealth.Check makes the same check itself (ErrNoBudget); this one keeps
// the log honest about WHY nothing ran.
func (p *Prober) checkEgressHealth(ctx context.Context, providerClientId string, client *http.Client) {
	if p.Health == nil {
		return
	}
	if err := ctx.Err(); err != nil {
		log.Printf("egress-health: provider=%s skipped: no budget left in this probe (%s) -- a run on an expired deadline would fail every destination and be indistinguishable from a blackhole", providerClientId, err)
		return
	}

	res, err := p.Health(ctx, client)
	if err != nil {
		// Structural: the check did not happen. Deliberately NOT rendered as a
		// zero score, for the same reason as above.
		log.Printf("egress-health: provider=%s did not run: %s", providerClientId, err)
		return
	}

	// The line reads:
	//
	//	egress-health: provider=<id> ok=25/26 dns=4/4 connectivity=5/5 cdn=4/5
	//	site=12/12 reputation=1/4 table=140 failed=cachefly
	//	reputation-failed=akamai,etsy,canva
	//
	// Summary carries the scored classes as ok=N/M plus the per-class tallies,
	// and the reputation figure alongside them -- never inside ok=N/M. The two
	// failure lists are kept apart for the same reason: "failed=" is a list of
	// things that mean the provider is not carrying traffic, while
	// "reputation-failed=" is a list of vendors that treat the exit as a
	// datacenter, which is the normal state of a hosted provider and not a
	// fault. Merging them would read as one longer failure list.
	//
	// Every tally is over the destinations this run SAMPLED, not the table:
	// egresshealth draws a bounded random subset of each class per run, so
	// cdn=4/5 is four of the five drawn today out of eighteen, and table=140
	// is on the line so that cannot be misread. It also means "failed=" is the
	// only record of WHICH destinations a given provider was asked for -- two
	// consecutive lines for the same provider name different endpoints, and
	// that is the check working, not drifting.
	line := fmt.Sprintf("egress-health: provider=%s %s", providerClientId, res.Summary())
	if failed := res.FailedNames(); 0 < len(failed) {
		line += " failed=" + strings.Join(failed, ",")
	}
	if refused := res.ReputationFailedNames(); 0 < len(refused) {
		line += " reputation-failed=" + strings.Join(refused, ",")
	}
	log.Print(line)

	// Submitted only on this path, after a run that actually produced a result.
	// Neither early return above has one, and sending a zero for them would be
	// indistinguishable from a total blackhole -- a false accusation against a
	// provider whose check was skipped for the prober's own exhausted deadline.
	p.reportEgressHealth(ctx, providerClientId, res)
}

// reportEgressHealth submits one health run, fire-and-forget. It returns
// nothing and can fail nothing: the probe's product is the geolocation, and a
// diagnostic must never be able to change whether a location was recorded.
//
// A server that does not implement the endpoint answers
// egresshealth.ErrUnsupported, which is a clean skip rather than an error --
// the prober keeps working against an older deployment, it just records no
// health. Every other failure is logged once per distinct message, because it
// will be the same failure for every provider in the pass.
func (p *Prober) reportEgressHealth(ctx context.Context, providerClientId string, res *egresshealth.Result) {
	if p.HealthResults == nil {
		return
	}
	err := p.HealthResults.SubmitEgressHealth(ctx, providerClientId, res)
	if err == nil {
		return
	}
	if errors.Is(err, egresshealth.ErrUnsupported) {
		// not a failure: this deployment has not shipped the endpoint. Still
		// deduplicated, since it holds for every provider in the pass.
		p.logHealthErrOnce(err, fmt.Sprintf("prober: this server does not store egress-health results (%s) -- health is logged but not persisted. Logged once.", err))
		return
	}
	p.logHealthErrOnce(err, fmt.Sprintf("prober: could not submit an egress-health result (provider=%s): %s -- while this persists, the health signal exists only in these logs and rolls off with them. Logged once per distinct error.", providerClientId, err))
}

func (p *Prober) logHealthErrOnce(err error, line string) {
	msg := err.Error()
	p.healthErrMu.Lock()
	logged := p.healthErrLogged[msg]
	if !logged {
		if p.healthErrLogged == nil {
			p.healthErrLogged = map[string]bool{}
		}
		p.healthErrLogged[msg] = true
	}
	p.healthErrMu.Unlock()

	if !logged {
		log.Print(line)
	}
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
