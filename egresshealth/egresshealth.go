// Package egresshealth checks whether a provider actually carries traffic to
// the real internet, across several independent classes of destination.
//
// All network access goes through an injected *http.Client; this package never
// constructs a client, a transport, or a dialer of its own. That is the whole
// trust argument. The prober runs on a docker network declared `internal: true`
// -- no gateway, no NAT, no direct route out -- so the only client that can
// reach anything is one bound to a provider tunnel, and a broken tunnel cannot
// masquerade as a healthy provider because there is no second path. A package
// that opened its own transport would quietly reintroduce that path.
//
// # Why this exists
//
// Provider reliability scoring on the server is presence-based:
// reliabilityRunningAggSql counts reported time blocks and sums
// 1.0/valid_client_count, and never consults delivered bytes. A provider that
// stays connected 24/7 while blackholing every byte therefore scores perfectly
// and stays selectable. That is not hypothetical -- a mainnet capture showed a
// provider accepting 87 KB and returning 0 bytes while connected = true and
// valid = true.
//
// The geolocation probe (see geolocate/) is not a sufficient answer, because it
// only ever touches one class of destination: three geolocation APIs. A
// provider needs to serve exactly those three hosts to look healthy, and the
// other client-visible failure -- CDNs and large sites rejecting datacenter IP
// ranges -- is invisible to it, since the geolocation APIs do not care where
// the request came from.
//
// # Classes
//
// Destinations are grouped so a PARTIAL failure is diagnosable. "ok=4/9" alone
// says nothing; "dns=3/3 cdn=0/3 site=1/3" says the tunnel carries bytes and
// resolves names but is being refused by content providers, which is the
// datacenter-IP-rejection case -- a completely different fault from a total
// blackhole (ok=0/9), and a different fault again from one flaky destination.
//
// The table deliberately spreads across DIFFERENT operators within each class,
// so a provider that special-cases one vendor's ranges cannot pass a class.
//
// # Ambiguity this cannot resolve on its own
//
// Name resolution is a shared precondition: the tunnel resolves every hostname
// through in-tunnel DoH (connect's DefaultDnsResolverSettings, which uses
// 1.1.1.1, 8.8.8.8, 9.9.9.9 and 208.67.222.222), and providertunnel
// deliberately disables the off-tunnel fallback. So a run that comes back 0/9
// is "this provider carried nothing useful", which covers both a blackhole and
// an in-tunnel DoH failure. The per-check Err strings are what separate them:
// a resolution failure names the lookup, a blackhole times out on the request.
// Do not read 0/9 as proof of a blackhole without them.
//
// # Byte budget
//
// Each check is a small GET whose body read is capped at MaxBodyBytes, so the
// worst case for a full run is len(destinations) * MaxBodyBytes = 9 * 4 KiB =
// 36 KiB of response body. Adding TLS handshakes, request/response headers and
// the DoH lookups behind them, a full run costs well under 128 KiB. Where it is
// honored, a Range header holds most destinations to ~2 KiB on the wire; a
// server that IGNORES Range can still put up to one TCP receive window in
// flight before the capped read closes the body, which is the one place the
// 36 KiB figure can be exceeded on the wire.
//
// This rides the same budget as the server's active bandwidth probe, which
// spends model.MaxProviderBandwidthBytesPerProbe = 5 MiB per probe and
// model.MaxProviderBandwidthBytesPerBucket = 200 MiB per hourly bucket. A full
// egress-health run is under 1% of one bandwidth probe.
package egresshealth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Class groups destinations so a partial failure is diagnosable: a provider
// that serves DNS but fails every CDN is the datacenter-IP-blocking case,
// which is a different fault from a total blackhole.
type Class string

const (
	ClassDNS  Class = "dns"
	ClassCDN  Class = "cdn"
	ClassSite Class = "site"
)

// Classes is the declared order classes are reported in. Result.ByClass is a
// map, so iterating it directly would render a different summary line on every
// pass; every ordered rendering goes through this slice instead.
var Classes = []Class{ClassDNS, ClassCDN, ClassSite}

// Destination is one endpoint to check.
type Destination struct {
	Name  string
	Class Class
	URL   string
	// Headers are sent with the request, and exist because two destinations
	// cannot be checked without them: cloudflare-dns.com answers 400 to the DoH
	// JSON GET form without an Accept header, and the CDN entries need a Range
	// header to keep a large asset from putting more than a couple of KiB on the
	// wire. See also UserAgent, which every request carries.
	Headers map[string]string
}

// MaxBodyBytes caps how much of any single response body is read. It is a cap
// on the READ, applied with io.LimitReader: a hostile or merely huge response
// cannot blow the byte budget documented on the package.
//
// 4 KiB is comfortably more than every destination in the table returns when it
// is working (the largest is ~2.7 KiB), so hitting the cap is itself a signal
// that something is answering with a body it should not be.
const MaxBodyBytes = 4096

// rangeFirst2KiB is the Range header used on destinations observed to honor
// one. The response is then a 206 of ~2 KiB rather than the whole asset. A
// server that ignores it simply returns 200 and the capped read applies.
const rangeFirst2KiB = "bytes=0-2047"

// acceptDNSJSON is Cloudflare's required Accept header for the DoH JSON GET
// form. Without it cloudflare-dns.com answers 400. Google and AdGuard serve
// JSON on their /resolve path with no header at all; sending it is harmless.
const acceptDNSJSON = "application/dns-json"

// UserAgent identifies this probe to every destination. It is deliberately
// descriptive rather than a browser impersonation: these are other people's
// servers, and an automated client that will not say who it is has no business
// on them.
//
// It is also load-bearing, not courtesy. Go's default "Go-http-client/1.1" is
// refused outright by Wikimedia's robot policy -- measured, not assumed: the
// same URL answered 403 `Please set a user-agent and respect our robot policy`
// under the default agent and 200 under this one, from the same host in the
// same minute. A destination that fails for every provider is not a signal, it
// is noise that would read as site=2/3 across the entire fleet forever.
const UserAgent = "urnetwork-egress-prober/0.1 (+https://github.com/urnetwork/urnetwork-operator-proxy; operator egress health probe)"

// destinations is the production table: small, well-known, individually
// operated endpoints, spread across operators WITHIN each class so that a
// provider which whitelists one vendor cannot pass a class.
//
// Every URL is https and on the default port 443. That is a hard requirement,
// not a coincidence -- the confinement self-check dials one fixed port
// (cmd/egress-prober's confinementPort), so a destination on any other port
// would silently fall outside the check. TestEveryDestinationIsHTTPSOn443
// enforces it.
//
// Choices worth recording, because the obvious pick was wrong:
//
//   - Quad9 was the natural third DoH operator and is NOT usable here.
//     https://dns.quad9.net/dns-query?name=... answers `400 DoH unable to
//     decode BASE64-URL` -- on 443 Quad9 serves only the RFC 8484 wire format,
//     which an ordinary *http.Client cannot speak. Its JSON API lives on port
//     5053, which both breaks the 443-only rule above and did not accept a
//     connection from this network. AdGuard's /resolve mirrors Google's JSON
//     API on 443 and was verified returning 200 with a parseable answer.
//
//   - cdnjs is used with a SMALL asset rather than a Range header: Cloudflare
//     was observed ignoring Range on cdnjs and returning the full 87 KB of
//     jquery.min.js. normalize.min.css is 1861 bytes whole.
//
//   - The Wikipedia entry points at the favicon, not the front page. The front
//     page is 120 KB and Wikimedia's ATS does not honor Range, so it is the one
//     destination that would routinely exceed the wire budget. The favicon is
//     2734 bytes, served by the same Wikimedia edge.
//
//   - amazon.com and reddit.com are in the table because they are the kind of
//     destination that rejects datacenter IP ranges -- the client-visible
//     failure the geolocation probe cannot see. That property is NOT yet
//     validated in the field: from one datacenter host on 2026-07-30 both
//     answered 206, so this host's range is not blocked by either. The
//     rejection is reputation- and range-dependent, so whether these two
//     actually discriminate is a question for the first weeks of field data,
//     not something to assert here.
//
//   - Wikipedia is the neutral control that keeps the class interpretable:
//     site=1/3 with wikipedia OK is selective rejection, site=0/3 is the class
//     failing outright.
//
// Status observed for every entry on 2026-07-30 from an unconfined host: 200 or
// 206, non-empty body, all well under MaxBodyBytes.
var destinations = []Destination{
	// DNS-over-HTTPS, JSON GET form, three distinct operators. A provider that
	// blocks DoH breaks name resolution for every client that uses it.
	{
		Name:    "cloudflare-doh",
		Class:   ClassDNS,
		URL:     "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
		Headers: map[string]string{"Accept": acceptDNSJSON},
	},
	{
		Name:    "google-doh",
		Class:   ClassDNS,
		URL:     "https://dns.google/resolve?name=example.com&type=A",
		Headers: map[string]string{"Accept": acceptDNSJSON},
	},
	{
		Name:    "adguard-doh",
		Class:   ClassDNS,
		URL:     "https://dns.adguard-dns.com/resolve?name=example.com&type=A",
		Headers: map[string]string{"Accept": acceptDNSJSON},
	},

	// CDN-hosted static assets, three distinct CDNs: Cloudflare, Fastly (via
	// code.jquery.com, which serves through Varnish/Fastly), and Amazon
	// CloudFront. This is the class that fails when a provider's egress range
	// is on a CDN blocklist.
	{
		Name:  "cloudflare-cdnjs",
		Class: ClassCDN,
		URL:   "https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css",
	},
	{
		Name:    "fastly-jquery",
		Class:   ClassCDN,
		URL:     "https://code.jquery.com/jquery-3.7.1.min.js",
		Headers: map[string]string{"Range": rangeFirst2KiB},
	},
	{
		// Version-pinned on purpose (an unversioned url would move under us),
		// with the tradeoff that if AWS ever prunes v2 of the browser SDK this
		// becomes a permanent 404 and a permanent false failure for every
		// provider. If cdn=2/3 with only this entry failing across the whole
		// fleet, suspect the URL before suspecting the providers.
		Name:    "cloudfront-awssdk",
		Class:   ClassCDN,
		URL:     "https://sdk.amazonaws.com/js/aws-sdk-2.1691.0.min.js",
		Headers: map[string]string{"Range": rangeFirst2KiB},
	},

	// Common sites. amazon and reddit plausibly reject datacenter ranges;
	// wikipedia is the control.
	{
		Name:  "wikipedia",
		Class: ClassSite,
		URL:   "https://www.wikipedia.org/static/favicon/wikipedia.ico",
	},
	{
		Name:    "amazon",
		Class:   ClassSite,
		URL:     "https://www.amazon.com/robots.txt",
		Headers: map[string]string{"Range": rangeFirst2KiB},
	},
	{
		Name:    "reddit",
		Class:   ClassSite,
		URL:     "https://www.reddit.com/robots.txt",
		Headers: map[string]string{"Range": rangeFirst2KiB},
	},
}

// CheckResult is one destination's outcome. It is recorded for failures as
// fully as for successes -- especially ByteCount, which is what separates "the
// destination refused us with a page of explanation" (bytes flowed; the tunnel
// works, the content provider said no) from "nothing came back at all" (the
// blackhole signature). Losing that distinction would defeat the point of
// grouping by class.
type CheckResult struct {
	Name       string
	Class      Class
	OK         bool
	StatusCode int   // 0 when the request never produced a response
	ByteCount  int64 // bytes of body actually read, capped at MaxBodyBytes; set on failures too
	Latency    time.Duration
	Err        string // "" when OK
}

// ClassSummary is the ok/total tally for one class.
type ClassSummary struct {
	OK    int
	Total int
}

// Result is one full run.
type Result struct {
	Checks  []CheckResult
	OKCount int
	Total   int
	ByClass map[Class]ClassSummary // ok/total per class
}

// Options tunes a single Check call. The zero value is valid and uses the
// defaults below.
type Options struct {
	// PerRequestTimeout bounds each individual request. Zero or negative uses
	// DefaultPerRequestTimeout.
	PerRequestTimeout time.Duration
	// Budget bounds the whole run, so a provider that swallows every request
	// cannot hold the pass open for Concurrency-batched multiples of the
	// per-request timeout. Zero or negative uses DefaultBudget.
	Budget time.Duration
	// Concurrency caps simultaneous requests. Zero or negative uses
	// DefaultConcurrency.
	Concurrency int
}

// Defaults for Options. They are vars so tests can lower them.
var (
	// DefaultPerRequestTimeout is generous because every probe runs over a COLD
	// tunnel: nothing is warm, keep-alives are disabled, and each request pays
	// an in-tunnel DoH resolution plus a full TLS handshake.
	DefaultPerRequestTimeout = 10 * time.Second
	// DefaultBudget bounds a whole run. With DefaultConcurrency and 9
	// destinations, three sequential rounds of the per-request timeout is the
	// worst case, so this is deliberately just under that: a run that is going
	// to be a total loss should end, not stall the pass.
	DefaultBudget = 30 * time.Second
	// DefaultConcurrency is modest on purpose. Nine simultaneous TLS handshakes
	// over one cold gvisor tunnel with keep-alives disabled contend with each
	// other and inflate every latency; geolocate runs three sources in parallel
	// for the same reason.
	DefaultConcurrency = 3
)

// ErrNilClient is returned when client is nil. Checks run in spawned
// goroutines, where a nil-client panic could not be recovered by the caller, so
// it is rejected up front. Mirrors geolocate.ErrNilClient.
var ErrNilClient = errors.New("egresshealth: client must not be nil")

// ErrNoDestinations is returned when the destination table is empty, which
// would make a run vacuous: 0/0 checks passed is not evidence of anything.
var ErrNoDestinations = errors.New("egresshealth: at least one destination is required")

// ErrNoBudget is returned when the context is already done on entry. This is a
// STRUCTURAL failure and must not be reported as a run, because a run started
// on a dead context returns 0/9 -- identical to a total blackhole. The caller
// (see prober) is expected to check for it and log "skipped" rather than a
// verdict.
var ErrNoBudget = errors.New("egresshealth: the context was already done before any check ran")

// Check runs every production destination through client and returns the full
// pattern of what worked.
//
// One destination failing never aborts the run: the pattern of failures IS the
// value, so every destination is attempted and every outcome recorded. An error
// is returned only when something structural stopped the run from happening at
// all (see ErrNilClient, ErrNoDestinations, ErrNoBudget) -- so
// `err == nil && OKCount == 0` is a real, trustworthy total-blackhole reading,
// distinguishable from a run that never took place.
//
// In production client egresses through one provider's tunnel, so what this
// measures is that provider's willingness and ability to carry ordinary
// traffic.
func Check(ctx context.Context, client *http.Client, opts Options) (*Result, error) {
	return check(ctx, client, destinations, opts)
}

func (o Options) perRequestTimeout() time.Duration {
	if 0 < o.PerRequestTimeout {
		return o.PerRequestTimeout
	}
	return DefaultPerRequestTimeout
}

func (o Options) budget() time.Duration {
	if 0 < o.Budget {
		return o.Budget
	}
	return DefaultBudget
}

func (o Options) concurrency() int {
	if 0 < o.Concurrency {
		return o.Concurrency
	}
	return DefaultConcurrency
}

// check is the seam Check is built on, taking the destination table explicitly
// so tests can drive httptest servers instead of the real internet. Same shape
// as geolocate's locate().
func check(ctx context.Context, client *http.Client, dests []Destination, opts Options) (*Result, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	if len(dests) == 0 {
		return nil, ErrNoDestinations
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoBudget, err)
	}

	ctx, cancel := context.WithTimeout(ctx, opts.budget())
	defer cancel()

	perRequest := opts.perRequestTimeout()
	results := make([]CheckResult, len(dests))
	sem := make(chan struct{}, opts.concurrency())
	var wg sync.WaitGroup
	for i := range dests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = fetch(ctx, client, dests[i], perRequest)
		}(i)
	}
	wg.Wait()

	// ByClass is seeded from the TABLE, not from the results that happened to
	// come back, so a class in which every single check failed still appears as
	// 0/n. Accumulating only from successes would make the datacenter-IP case
	// -- the whole reason the class dimension exists -- vanish from the map at
	// exactly the moment it matters.
	byClass := map[Class]ClassSummary{}
	for _, d := range dests {
		s := byClass[d.Class]
		s.Total++
		byClass[d.Class] = s
	}

	okCount := 0
	for _, r := range results {
		if !r.OK {
			continue
		}
		okCount++
		s := byClass[r.Class]
		s.OK++
		byClass[r.Class] = s
	}

	return &Result{
		Checks:  results,
		OKCount: okCount,
		Total:   len(results),
		ByClass: byClass,
	}, nil
}

// fetch performs one destination's check. It never returns an error: a failed
// destination is a RESULT, and the run keeps going.
func fetch(ctx context.Context, client *http.Client, d Destination, timeout time.Duration) CheckResult {
	r := CheckResult{Name: d.Name, Class: d.Class}
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		r.Latency = time.Since(start)
		r.Err = err.Error()
		return r
	}
	// Set first, so a destination's own Headers can still override it.
	req.Header.Set("User-Agent", UserAgent)
	for k, v := range d.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		r.Latency = time.Since(start)
		r.Err = err.Error()
		return r
	}
	defer resp.Body.Close()
	r.StatusCode = resp.StatusCode

	// The body is read even on an error status, and ByteCount is recorded
	// either way: a 403 with a page of explanation proves the tunnel carried
	// bytes in both directions and the CONTENT PROVIDER refused, which is a
	// different fault from nothing coming back at all.
	n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBodyBytes))
	r.ByteCount = n
	r.Latency = time.Since(start)

	switch {
	case readErr != nil:
		r.Err = readErr.Error()
	case resp.StatusCode < 200 || 300 <= resp.StatusCode:
		// 3xx counts as a failure, not a redirect to follow. The production
		// client refuses redirects outright (providertunnel's CheckRedirect), so
		// a 3xx here is a destination that did not serve what was asked for.
		r.Err = fmt.Sprintf("status %d", resp.StatusCode)
	case n == 0:
		// THE blackhole signature, and the reason this rule is spelled out: a
		// status line with no body is exactly what a provider that terminates
		// the connection itself, or one whose upstream returns a stub, produces.
		// Counting it as success would let the failure this package exists to
		// catch pass the check.
		r.Err = fmt.Sprintf("status %d with an empty body", resp.StatusCode)
	default:
		r.OK = true
	}
	return r
}

// DestinationHosts returns the host of every production destination,
// de-duplicated and in table order.
//
// This mirrors geolocate.SourceHosts and exists for the same reason: nothing
// outside this package should keep a second copy of the endpoint list. The
// prober's container cannot resolve DNS, so the operator passes explicit
// addresses to the confinement self-check with -confinement-address, and this
// is how they obtain the host list to translate. A hand-maintained copy would
// drift on the first table change while the check kept reporting success.
//
// A URL that does not parse, or carries no host, is skipped rather than
// panicking -- but destinations is a compile-time constant table and
// TestDestinationHostsCoversEveryDestination fails if any entry goes missing.
func DestinationHosts() []string {
	seen := map[string]bool{}
	hosts := make([]string, 0, len(destinations))
	for _, d := range destinations {
		u, err := url.Parse(d.URL)
		if err != nil {
			continue
		}
		host := u.Hostname()
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts
}

// Destinations returns a copy of the production table.
//
// A copy, not the table: a caller that mutated it -- or the Headers map inside
// an entry -- would silently change what every subsequent probe measures, and
// the drift would be invisible in the table's own source. Callers that only
// need the host list want DestinationHosts.
func Destinations() []Destination {
	out := make([]Destination, len(destinations))
	for i, d := range destinations {
		out[i] = d
		if d.Headers != nil {
			headers := make(map[string]string, len(d.Headers))
			for k, v := range d.Headers {
				headers[k] = v
			}
			out[i].Headers = headers
		}
	}
	return out
}

// Summary renders the one-line, per-pass form:
//
//	ok=7/9 dns=3/3 cdn=1/3 site=3/3
//
// Class order is Classes, never map iteration order, so successive passes are
// diffable. Classes absent from the table are omitted; a class present in the
// table but absent from Classes is appended in sorted order rather than
// silently dropped.
func (r *Result) Summary() string {
	if r == nil {
		return "ok=0/0"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ok=%d/%d", r.OKCount, r.Total)
	for _, c := range r.orderedClasses() {
		s := r.ByClass[c]
		fmt.Fprintf(&b, " %s=%d/%d", c, s.OK, s.Total)
	}
	return b.String()
}

// orderedClasses lists the classes present in ByClass: the declared ones first,
// in Classes order, then any others sorted, so a class added to the table but
// not to Classes still shows up.
func (r *Result) orderedClasses() []Class {
	out := make([]Class, 0, len(r.ByClass))
	declared := map[Class]bool{}
	for _, c := range Classes {
		declared[c] = true
		if _, ok := r.ByClass[c]; ok {
			out = append(out, c)
		}
	}
	var extra []string
	for c := range r.ByClass {
		if !declared[c] {
			extra = append(extra, string(c))
		}
	}
	sort.Strings(extra)
	for _, c := range extra {
		out = append(out, Class(c))
	}
	return out
}

// FailedNames lists the destinations that did not pass, in table order. The
// summary line says how many failed; this says which, which is what turns a log
// line into something actionable.
func (r *Result) FailedNames() []string {
	if r == nil {
		return nil
	}
	var names []string
	for _, c := range r.Checks {
		if !c.OK {
			names = append(names, c.Name)
		}
	}
	return names
}
