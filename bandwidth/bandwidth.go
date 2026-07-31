// Package bandwidth measures a provider's throughput over a tunnel that is
// already open, against two independent targets.
//
// It is deliberately adaptive rather than fixed-size: a fixed payload is either
// too small to mean anything on a fast link (the whole transfer finishes inside
// TCP slow start) or wastes budget on a slow one. Each measurement streams
// until either bound is hit -- 5 s elapsed or 5 MiB transferred, whichever
// comes first -- and reports the steady-state rate after discarding the first
// 500 ms of slow-start noise.
//
// # Two targets, never averaged
//
// A measurement is taken separately against the operator's own endpoint and
// against a public CDN, and the two figures are stored and logged separately.
// That separation is the entire point of having two targets: a provider that
// prioritises one path and not the other is invisible in a single figure and
// obvious in two. Averaging them destroys exactly the signal they exist to
// produce, so nothing in this package ever combines them.
//
// Both targets take the identical URL shape (`<url>?bytes=N`) and go through
// the identical measurement code, so neither figure is advantaged by a
// different request shape, redirect behaviour or transfer encoding.
package bandwidth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// MaxSampleBytes bounds one measurement. It matches the operator download
	// endpoint's own clamp and the per-probe figure the server's byte budget
	// reserves against, so a measurement can never transfer more than it
	// reserved.
	MaxSampleBytes = 5 * 1024 * 1024

	// WarmupDuration is discarded from the head of a measurement. A TCP
	// connection opens in slow start, so bytes carried in the first few round
	// trips arrive at a fraction of the link's steady rate; counting them
	// depresses the figure by an amount that depends on RTT rather than on
	// throughput, which would systematically penalise distant providers.
	WarmupDuration = 500 * time.Millisecond

	// DefaultTimeout is the per-target wall-clock cap.
	DefaultTimeout = 5 * time.Second

	// MinTimeBudget is the least remaining context budget worth starting a
	// measurement with. Below it the request would be cut off mid-transfer and
	// the resulting figure would describe the prober's exhausted deadline
	// rather than the provider.
	MinTimeBudget = time.Second
)

// The source tags a measurement is stored under. These are the wire values of
// the server's model.ProviderBandwidthSourceActiveOperator /
// ...ActiveCDN and must stay in step with them: the result endpoint validates
// the submitted source against its known set and rejects anything else.
const (
	SourceOperator = "active-operator"
	SourceCDN      = "active-cdn"
)

// CDNTestURL is the second target: Cloudflare's public speed-test download,
// size-parameterised exactly like the operator's own endpoint, so both targets
// share one URL shape and one code path.
//
// Two alternatives were measured and rejected. proof.ovh.net answered at
// ~1.0 MB/s from a datacenter host, which would dominate the per-provider time
// budget and measure the target rather than the provider.
// cachefly.cachefly.net/10mb.test is fast (~81 MB/s) but fixed-size with no
// byte parameter, so it could not share this package's byte cap.
const CDNTestURL = "https://speed.cloudflare.com/__down"

// The reasons a target can be skipped. They are distinct strings on purpose: a
// provider skipped because the deployment's hourly byte budget is spent is a
// normal, expected outcome that says the budget is working, while one skipped
// because the probe ran out of time says the probe's own deadline is too tight.
// Collapsing them into one "skipped" would hide the second behind the first.
const (
	SkipNoBudget    = "no byte budget this hour"
	SkipNoTime      = "no time left in this probe"
	SkipUnsupported = "server has no bandwidth endpoints"
)

// ErrNoBudget reports that the deployment's active-probe byte budget for the
// current hour is spent. A Reserver returns it (wrapped or not) when the
// server answers 429; it is a clean skip, not a probe failure.
var ErrNoBudget = errors.New("bandwidth: no active-probe byte budget for this hour")

// ErrUnsupported reports that the server does not implement the bandwidth
// endpoints (404). Like ErrNoBudget it is a clean skip: a prober running
// against a deployment that has not shipped them yet keeps probing
// geolocation, it simply records no bandwidth -- rather than logging a failure
// per provider, per pass, forever.
var ErrUnsupported = errors.New("bandwidth: the server does not implement the provider bandwidth endpoints")

// ErrNoSample reports that nothing measurable was transferred, so no rate can
// be computed. Distinct from a transport error: the request itself may have
// succeeded and simply delivered nothing.
var ErrNoSample = errors.New("bandwidth: no bytes transferred, cannot compute a rate")

// Target is one thing to download from. Both targets in production carry the
// same URL shape and differ only in host, source tag, and whether an operator
// secret is attached.
type Target struct {
	// Name is the short label used in the log line ("operator", "cdn").
	Name string
	// Source is the tag the figure is stored under server-side.
	Source string
	// URL is the base download url; the byte count is appended as a `bytes`
	// query parameter.
	URL string
	// Header carries per-target request headers (the operator secret, for the
	// operator target). Never logged.
	Header http.Header
}

// Sample is one measurement.
type Sample struct {
	BytesPerSecond  float64
	SampleByteCount int64
	// WarmupExcluded reports whether the rate was computed over the
	// steady-state window only. It is false when the whole transfer finished
	// inside WarmupDuration -- 5 MiB completes in under 500 ms on anything
	// above ~10 MB/s, which datacenter-hosted providers clear routinely -- in
	// which case the rate is computed over the full transfer instead and is a
	// LOWER BOUND on the real throughput, because it includes slow start.
	//
	// Reporting a lower bound rather than zero is deliberate: returning zero
	// here would make the fastest providers, the ones most worth measuring,
	// the only ones that produce no usable figure at all (the server rejects a
	// non-positive rate outright).
	WarmupExcluded bool
	Elapsed        time.Duration
}

// OperatorTarget builds the operator-endpoint target. The operator secret is
// carried in the same X-UR-Operator-Secret header the other operator routes
// use.
//
// publicServerURL is NOT the same value as the -api-url the prober uses for
// its control-plane calls, and conflating the two is a real bug that was
// deployed once: the control-plane url is reached prober -> api directly, so
// on a docker deployment it is an internal name like http://api:8080, but
// THIS request travels prober -> platform -> provider -> internet -> back to
// the api, so it must be the address the api answers on from the public
// internet. An internal name fails the same way for every provider
// ("context deadline exceeded"), which reads like a fleet-wide provider fault
// and is not one.
func OperatorTarget(publicServerURL string, operatorSecret string) Target {
	h := http.Header{}
	h.Set("X-UR-Operator-Secret", operatorSecret)
	return Target{
		Name:   "operator",
		Source: SourceOperator,
		URL:    strings.TrimRight(publicServerURL, "/") + "/network/provider-bandwidth-test",
		Header: h,
	}
}

// CDNTarget builds the public-CDN target. No credentials: it is an ordinary
// public download.
func CDNTarget() Target {
	return Target{Name: "cdn", Source: SourceCDN, URL: CDNTestURL}
}

// DefaultTargets is the production pair, in log order. An empty
// publicServerURL drops the operator target rather than emitting one that
// cannot resolve from the far side of the tunnel: a target that fails for
// every provider is worse than no target, because it looks like a finding.
func DefaultTargets(publicServerURL string, operatorSecret string) []Target {
	if strings.TrimSpace(publicServerURL) == "" {
		return []Target{CDNTarget()}
	}
	return []Target{OperatorTarget(publicServerURL, operatorSecret), CDNTarget()}
}

// TargetHosts returns the hostnames the targets are reached at, for the
// tunnel's host allowlist (providertunnel.Tunnel.HTTPClientForHosts). A host
// that is neither pinned nor allowlisted is refused by the tunnel dialer, so
// the measurement would fail before it started without this.
func TargetHosts(targets []Target) []string {
	hosts := []string{}
	for _, t := range targets {
		u, err := url.Parse(t.URL)
		if err != nil || u.Hostname() == "" {
			continue
		}
		hosts = append(hosts, u.Hostname())
	}
	return hosts
}

// sizedURL appends the byte count to the target url. Both targets are
// size-parameterised the same way, which is why they can share this.
func sizedURL(rawURL string, byteCount int64) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("bytes", strconv.FormatInt(byteCount, 10))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Measure streams from testURL and reports the throughput. It stops at
// MaxSampleBytes or at timeout, whichever comes first.
//
// This is the plain-url form used by tests and one-off diagnostics;
// MeasureTarget is what production uses, and both run the same code beneath.
func Measure(ctx context.Context, client *http.Client, testURL string, timeout time.Duration) (float64, int64, error) {
	sample, err := measure(ctx, client, testURL, nil, timeout)
	return sample.BytesPerSecond, sample.SampleByteCount, err
}

// MeasureTarget measures one target, requesting exactly MaxSampleBytes.
func MeasureTarget(ctx context.Context, client *http.Client, target Target, timeout time.Duration) (Sample, error) {
	sizedTargetURL, err := sizedURL(target.URL, MaxSampleBytes)
	if err != nil {
		return Sample{}, err
	}
	return measure(ctx, client, sizedTargetURL, target.Header, timeout)
}

func measure(
	ctx context.Context,
	client *http.Client,
	testURL string,
	header http.Header,
	timeout time.Duration,
) (Sample, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	// parent is kept so a read cut short by THIS measurement's own time cap can
	// be told apart from one cut short by the probe being cancelled: the former
	// is the designed stopping condition, the latter is not a measurement.
	parent := ctx
	// WithTimeout never extends an earlier parent deadline, so a probe whose
	// own budget is nearly spent still cannot be overrun by this.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return Sample{}, err
	}
	for k, values := range header {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return Sample{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Sample{}, fmt.Errorf(
			"bandwidth: %s answered %d: %s",
			testURL, resp.StatusCode, strings.TrimSpace(string(msg)),
		)
	}

	start := time.Now()
	end := start
	var total int64
	var steadyStart time.Time
	var steadyBytes int64
	buf := make([]byte, 32*1024)

	for {
		// Read into no more than the cap allows. Reading a whole buffer and
		// checking afterwards overshoots by up to one buffer -- 5243392 bytes
		// against a 5242880 cap, measured -- which is a transfer larger than
		// the reservation admitted, through a provider's tunnel, on every
		// measurement.
		readBuf := buf
		if remaining := int64(MaxSampleBytes) - total; remaining < int64(len(readBuf)) {
			readBuf = readBuf[:remaining]
		}
		n, readErr := resp.Body.Read(readBuf)
		now := time.Now()
		end = now
		total += int64(n)
		// The read that first crosses the warmup boundary opens the
		// steady-state window; its own bytes count towards it, which is a
		// fraction of one 32 KiB buffer either way.
		if steadyStart.IsZero() && WarmupDuration <= now.Sub(start) {
			steadyStart = now
		}
		if !steadyStart.IsZero() {
			steadyBytes += int64(n)
		}
		if MaxSampleBytes <= total {
			break
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			if errors.Is(readErr, context.DeadlineExceeded) && parent.Err() == nil {
				// the time cap fired while a read was in flight. That is this
				// measurement's designed stopping condition, reached a few
				// milliseconds before the loop's own check would have reached
				// it, so the bytes already timed are a valid (smaller) sample
				// rather than a failure.
				break
			}
			// Anything else -- including the probe itself being cancelled --
			// leaves a window shaped by something other than the link, so no
			// figure is reported.
			return Sample{SampleByteCount: total}, readErr
		}
		if timeout <= now.Sub(start) {
			break
		}
	}

	if total <= 0 {
		return Sample{}, ErrNoSample
	}

	if steadyElapsed := end.Sub(steadyStart); !steadyStart.IsZero() && 0 < steadyElapsed && 0 < steadyBytes {
		return Sample{
			BytesPerSecond:  float64(steadyBytes) / steadyElapsed.Seconds(),
			SampleByteCount: total,
			WarmupExcluded:  true,
			Elapsed:         steadyElapsed,
		}, nil
	}

	// The whole transfer finished inside the warmup window. Rather than report
	// no rate at all -- which would silently exclude every fast provider, since
	// 5 MiB at 10 MB/s takes 500 ms exactly -- fall back to the warmup-inclusive
	// rate over the full transfer. That figure includes slow start, so it
	// understates the link: it is a lower bound, and WarmupExcluded=false says
	// so.
	totalElapsed := end.Sub(start)
	if totalElapsed <= 0 {
		return Sample{SampleByteCount: total}, ErrNoSample
	}
	return Sample{
		BytesPerSecond:  float64(total) / totalElapsed.Seconds(),
		SampleByteCount: total,
		WarmupExcluded:  false,
		Elapsed:         totalElapsed,
	}, nil
}

// Reserver takes deployment-wide byte budget for one active probe. In
// production this is *ingest.Client, which posts to
// /network/provider-bandwidth-reserve and maps the server's 429 to
// ErrNoBudget.
type Reserver interface {
	ReserveBandwidth(ctx context.Context, providerClientId string, byteCount int64) error
}

// Submitter records one measured figure under its own source tag.
type Submitter interface {
	SubmitBandwidth(
		ctx context.Context,
		providerClientId string,
		source string,
		bytesPerSecond float64,
		sampleByteCount int64,
	) error
}

// Result is one target's outcome for one provider.
type Result struct {
	Target Target
	Sample Sample
	// Skip is "" when the target was measured, otherwise the reason it was
	// not (SkipNoBudget, SkipNoTime).
	Skip string
	Err  error
}

// Measured reports whether this target produced a usable figure.
func (r Result) Measured() bool {
	return r.Skip == "" && r.Err == nil && 0 < r.Sample.BytesPerSecond
}

// Sampler measures every target for one provider, over a tunnel that is
// already open, reserving budget for each separately.
//
// Budget is reserved per target, not once per provider: each target pulls its
// own MaxSampleBytes through the provider's tunnel, which is real paid
// contract traffic in both cases, and the reservation endpoint clamps a single
// request to the per-probe figure anyway. Reserving per target also makes the
// skip granular -- the second target can be skipped for budget while the first
// still produced a figure -- instead of losing both.
type Sampler struct {
	Targets []Target
	Reserve Reserver
	Submit  Submitter
	// Timeout is the per-target wall-clock cap; zero means DefaultTimeout.
	Timeout time.Duration
}

// Sample measures every target and submits each figure separately. It never
// returns an error: a bandwidth measurement is a diagnostic riding along on a
// probe whose product is the geolocation, and no outcome here may fail that
// probe.
//
// Nothing is measured before its budget is reserved, and nothing is combined:
// there is one Result per target, in Targets order.
func (s *Sampler) Sample(ctx context.Context, providerClientId string, client *http.Client) []Result {
	results := make([]Result, 0, len(s.Targets))
	for _, target := range s.Targets {
		results = append(results, s.sampleOne(ctx, providerClientId, client, target))
	}
	return results
}

func (s *Sampler) sampleOne(
	ctx context.Context,
	providerClientId string,
	client *http.Client,
	target Target,
) Result {
	// The probe's remaining budget is checked before the reservation, not
	// after: a reservation spends deployment-wide budget, and spending it on a
	// measurement that cannot finish would charge the fleet for nothing.
	if !hasTimeBudget(ctx) {
		return Result{Target: target, Skip: SkipNoTime}
	}

	if s.Reserve != nil {
		if err := s.Reserve.ReserveBandwidth(ctx, providerClientId, MaxSampleBytes); err != nil {
			if errors.Is(err, ErrNoBudget) {
				return Result{Target: target, Skip: SkipNoBudget}
			}
			if errors.Is(err, ErrUnsupported) {
				return Result{Target: target, Skip: SkipUnsupported}
			}
			// Any other reservation failure (server down, wrong secret) means
			// the transfer was never accounted for, so it must not happen.
			return Result{Target: target, Err: err}
		}
	}

	sample, err := MeasureTarget(ctx, client, target, s.timeout())
	if err != nil {
		return Result{Target: target, Sample: sample, Err: err}
	}
	if sample.BytesPerSecond <= 0 {
		return Result{Target: target, Sample: sample, Err: ErrNoSample}
	}

	if s.Submit != nil {
		if err := s.Submit.SubmitBandwidth(
			ctx, providerClientId, target.Source, sample.BytesPerSecond, sample.SampleByteCount,
		); err != nil {
			return Result{Target: target, Sample: sample, Err: err}
		}
	}
	return Result{Target: target, Sample: sample}
}

func (s *Sampler) timeout() time.Duration {
	if 0 < s.Timeout {
		return s.Timeout
	}
	return DefaultTimeout
}

// hasTimeBudget reports whether enough of the probe's deadline remains to take
// a measurement that describes the provider rather than the deadline.
func hasTimeBudget(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return MinTimeBudget <= time.Until(deadline)
}

// Summary renders one provider's results as `operator=12.4MB/s cdn=11.8MB/s`,
// per target and in Targets order. The two figures are always printed side by
// side and never combined, so a provider prioritising one path is visible at a
// glance -- which is the whole reason there are two targets.
//
// A skipped target says so explicitly rather than being omitted: a silently
// missing figure reads as "nothing was measured" when the truth is "the budget
// this deployment set was reached", and those need different responses.
func Summary(results []Result) string {
	parts := make([]string, 0, len(results))
	for _, r := range results {
		switch {
		case r.Skip != "":
			parts = append(parts, fmt.Sprintf("%s=skipped(%s)", r.Target.Name, r.Skip))
		case r.Err != nil:
			parts = append(parts, fmt.Sprintf("%s=failed(%s)", r.Target.Name, r.Err))
		default:
			figure := fmt.Sprintf("%s=%.1fMB/s", r.Target.Name, r.Sample.BytesPerSecond/(1024*1024))
			if !r.Sample.WarmupExcluded {
				// the transfer finished inside the warmup window, so this
				// figure includes slow start and understates the link
				figure += "(lower-bound)"
			}
			parts = append(parts, figure)
		}
	}
	return strings.Join(parts, " ")
}
