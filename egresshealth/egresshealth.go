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
// Destinations are grouped so a PARTIAL failure is diagnosable. "ok=14/27"
// alone says nothing; "dns=7/7 cdn=0/5 site=5/5" says the tunnel carries bytes
// and resolves names but is being refused by content providers, which is the
// datacenter-IP-rejection case -- a completely different fault from a total
// blackhole (ok=0/27), and a different fault again from one flaky destination.
//
// The table deliberately spreads across DIFFERENT operators within each class,
// so a provider that special-cases one vendor's ranges cannot pass a class.
//
// ClassReputation is scored SEPARATELY and deliberately excluded from
// OKCount/Total -- see its doc comment below, which is the one thing in this
// package most likely to be "fixed" into a bug.
//
// # Ambiguity this cannot resolve on its own
//
// Name resolution is a shared precondition: the tunnel resolves every hostname
// through in-tunnel DoH (connect's DefaultDnsResolverSettings, which uses
// 1.1.1.1, 8.8.8.8, 9.9.9.9 and 208.67.222.222), and providertunnel
// deliberately disables the off-tunnel fallback. So a run that comes back 0/27
// is "this provider carried nothing useful", which covers both a blackhole and
// an in-tunnel DoH failure. The per-check Err strings are what separate them:
// a resolution failure names the lookup, a blackhole times out on the request.
// Do not read 0/27 as proof of a blackhole without them.
//
// # Byte budget
//
// Each check is a small GET whose body read is capped -- per destination via
// Destination.MaxBytes, and never above MaxBodyBytes. The worst case for a full
// run is therefore the SUM of the per-destination caps, which is arithmetic the
// table can be checked against (TestWorstCaseBytesPerRunFitsTheBudget):
//
//	dns          7 x  768 =  5376
//	connectivity 8 x  256 =  2048
//	cdn          5 x 2048 = 10240
//	site         5 x 2048 = 10240
//	                        -----
//	health              =   27904
//	reputation   6 x 1024 =  6144
//	                        -----
//	total               =   34048 bytes = 33.25 KiB
//
// That is BELOW the 36 KiB (9 x 4 KiB) worst case of the smaller nine-entry
// table this replaces, which is the point: the connectivity class is
// purpose-built for this and answers in 0-69 bytes, so a table three times
// wider is also a cheaper one. Adding TLS handshakes, request/response headers
// and the DoH lookups behind them, a full run stays well under 128 KiB.
//
// Where it is honored, a Range header holds the larger destinations to ~2 KiB
// on the wire; a server that IGNORES Range can still put up to one TCP receive
// window in flight before the capped read closes the body, which is the one
// place these figures can be exceeded on the wire. www.canva.com was measured
// answering a 403 with 1.4 MB of body, so this is not theoretical -- the cap is
// what keeps it from mattering.
//
// This rides the same budget as the server's active bandwidth probe, which
// spends model.MaxProviderBandwidthBytesPerProbe = 5 MiB per probe and
// model.MaxProviderBandwidthBytesPerBucket = 200 MiB per hourly bucket. A full
// egress-health run is under 1% of one bandwidth probe.
package egresshealth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
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
	ClassDNS Class = "dns"
	// ClassConnectivity is the purpose-built captive-portal-detection endpoints
	// every operating system already ships with. They are unauthenticated, carry
	// no anti-bot machinery, and answer in tens of bytes -- the cheapest useful
	// signal in the table, and the class least likely to fail for a reason that
	// has nothing to do with the provider.
	ClassConnectivity Class = "connectivity"
	ClassCDN          Class = "cdn"
	ClassSite         Class = "site"

	// ClassReputation measures something the other classes do not, and is
	// EXCLUDED FROM THE HEALTH SCORE ON PURPOSE. Do not fold it into
	// Result.OKCount/Total. Every entry in it was measured refusing a datacenter
	// IP outright -- 403, 401 -- in four consecutive runs from a hosted host. On
	// a residential or cellular exit those same endpoints return clean. So a
	// failure here says "this exit is treated as a datacenter by bot-management
	// vendors", which is genuinely useful (a provider that passes is more useful
	// to a real user, because that is what the user will hit) but is NOT a
	// statement that the provider is broken. Scoring it would make every hosted
	// provider read as degraded and destroy the signal the health classes carry.
	//
	// One caveat that constrains how far this can be read, recorded because it
	// is measured rather than assumed. Three observations of www.reddit.com from
	// the SAME host and IP, within a day:
	//
	//	curl, default user-agent          -> 403 (4/4 runs)
	//	the Go prober through a provider  -> 200
	//	curl, this package's UserAgent    -> 206
	//
	// Same address, three different clients, three different answers. That is
	// TLS/client fingerprinting at least as much as it is IP reputation. So a
	// reputation failure is evidence about the CLIENT-AND-IP PAIR, not about the
	// address alone, and this class needs field data across many providers
	// before anyone treats it as a clean IP-quality score. It is a diagnostic
	// under observation, not a metric.
	ClassReputation Class = "reputation"
)

// Classes is the declared order the SCORED classes are reported in.
// Result.ByClass is a map, so iterating it directly would render a different
// summary line on every pass; every ordered rendering goes through this slice
// instead.
//
// ClassReputation is deliberately absent: it is not part of the health score
// and is reported on its own (Result.Reputation). See its doc comment.
var Classes = []Class{ClassDNS, ClassConnectivity, ClassCDN, ClassSite}

// unscoredClasses are the classes kept out of Result.OKCount/Total/ByClass.
//
// A class is scored unless it is named here, so a class added later lands in
// the health score by default -- which is the safe direction: a new class that
// should not be scored is a visible number nobody can miss, whereas a health
// class silently omitted from the score would be a signal quietly turned off.
var unscoredClasses = map[Class]bool{ClassReputation: true}

// scored reports whether a class counts towards the health score.
func scored(c Class) bool { return !unscoredClasses[c] }

// Expect declares what "success" means for one destination. The default,
// ExpectBody, is the original rule and the reason this check catches
// blackholes; ExpectStatus exists for the endpoints where an empty body is the
// correct answer.
type Expect int

const (
	// ExpectBody requires a 2xx AND a non-empty body. This is the default (the
	// zero value) and must stay that way: a status line with no data behind it
	// is exactly what a blackholing provider produces, so a 200 with an empty
	// body is a FAILURE. TestEmptyBodyIs200Failure guards it.
	ExpectBody Expect = iota
	// ExpectStatus requires exactly Destination.Status and permits an empty
	// body. It exists because 21 of 143 endpoints measured from a real
	// datacenter host are reachable while legitimately returning zero bytes --
	// every generate_204 connectivity check, and many 3xx redirects -- and the
	// ExpectBody rule would score all of them as failures.
	//
	// Note that this is STRICTER than ExpectBody about the status, not looser:
	// the status must match exactly. A provider that synthesizes a bare 200 does
	// not pass an ExpectStatus 204 destination. Relaxing this to "any 2xx" would
	// turn the class into a hole in the blackhole rule.
	ExpectStatus
)

// Destination is one endpoint to check.
type Destination struct {
	Name  string
	Class Class
	URL   string
	// Headers are sent with the request, and exist because destinations cannot
	// be checked without them: cloudflare-dns.com answers 400 to the DoH JSON GET
	// form without an Accept header, and the larger assets need a Range header to
	// keep them from putting more than a couple of KiB on the wire. See also
	// UserAgent, which every request carries.
	Headers map[string]string
	// Expect declares the success contract. The zero value is ExpectBody.
	Expect Expect
	// Status is the required status code, and is only read when Expect is
	// ExpectStatus. Leaving it zero there is a misconfiguration and is reported
	// as a failed check rather than silently accepting anything.
	Status int
	// MaxBytes caps the body read for this destination. Zero means MaxBodyBytes,
	// and a value above MaxBodyBytes is clamped to it -- the package-level cap is
	// the one documented in the byte budget and cannot be raised per entry.
	// Sizing this per destination is what let the table triple in width while
	// getting cheaper.
	MaxBytes int
	// Verify optionally proves the body is what the destination is supposed to
	// serve, and is the answer to a class of failure a status code cannot see: a
	// captive portal or an interception box happily returns 200 with a body.
	// Only parsing it proves the request was actually served by whom it was
	// addressed to. It runs after the status/body rules, on the (capped) body.
	Verify func(body []byte) error
}

// MaxBodyBytes is the ceiling on any single body read, and the clamp on
// Destination.MaxBytes. It is a cap on the READ, applied with io.LimitReader: a
// hostile or merely huge response cannot blow the byte budget documented on the
// package -- www.canva.com answers a 403 with 1.4 MB.
//
// Unlike the earlier single-cap version of this table, hitting a cap is NOT by
// itself a signal that something is wrong: several destinations are capped
// deliberately below what they serve when healthy (the Wikipedia favicon is
// 2734 bytes against a 2048-byte cap, and cachefly's test asset is unbounded).
// What matters is that the body is non-empty and, where Verify is set, parses.
const MaxBodyBytes = 4096

// rangeFirst2KiB is the Range header used on destinations observed to honor
// one. The response is then a 206 of ~2 KiB rather than the whole asset. A
// server that ignores it simply returns 200 and the capped read applies.
const rangeFirst2KiB = "bytes=0-2047"

// acceptDNSJSON is the Accept header for the DoH JSON GET form. Cloudflare
// answers 400 without it. The others serve JSON with no header at all; sending
// it is harmless and keeps the seven entries identical in shape.
const acceptDNSJSON = "application/dns-json"

// dnsQuery is the query every DoH destination asks. example.com is an IANA
// reserved name that will not disappear, and its A record is short.
const dnsQuery = "?name=example.com&type=A"

// Per-class read caps. They are sized just above the largest response measured
// from each class on 2026-07-31, so the byte budget on the package is real
// arithmetic rather than a hope.
const (
	maxDNSBytes          = 768  // largest measured: doh.dns.sb, 582 B
	maxConnectivityBytes = 256  // largest measured: captive.apple.com, 69 B
	maxAssetBytes        = 2048 // matches rangeFirst2KiB
	maxReputationBytes   = 1024 // enough of a refusal page to see what refused
)

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
// is noise that would read as site=4/5 across the entire fleet forever.
//
// It also demonstrably changes what ClassReputation measures -- see that
// class's comment, where the same host got 403 under curl's default agent and
// 206 under this one.
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
// Every entry below was measured from a datacenter host on 2026-07-31 with this
// package's UserAgent. Choices worth recording, because the obvious pick was
// wrong in a way only measurement showed:
//
//   - dns.alidns.com serves the JSON form on /resolve ONLY. Its /dns-query path
//     answers `400 no 'dns' query parameter found` -- it is wire-format only.
//     doh.dns.sb is the mirror image: /dns-query serves JSON, /resolve is a 301.
//     The path is not interchangeable between operators and cannot be guessed.
//
//   - Quad9, OpenDNS, CleanBrowsing, Mullvad and Control D were all rejected as
//     DoH entries. Quad9 and Mullvad serve only RFC 8484 wire format on 443
//     (400 to a JSON GET) and Quad9's JSON API is on port 5053, which breaks the
//     443-only rule above; Control D answers 200 with a non-JSON body, which is
//     precisely the shape Verify exists to reject.
//
//   - www.msftconnecttest.com is NOT here despite being an obvious connectivity
//     endpoint: https to it failed three times out of three from the measuring
//     host (connection never established) while http succeeded. A plaintext
//     destination is not an option -- it could be forged by the provider on the
//     path -- so it is unusable here.
//
//   - The Google, gstatic and connectivitycheck.gstatic generate_204 endpoints
//     are one operator wearing three hostnames; only one is in the table.
//     icanhazip.com and 1.1.1.1/cdn-cgi/trace are both Cloudflare, which
//     cp.cloudflare.com already covers.
//
//   - cdnjs is used with a SMALL asset rather than a Range header: Cloudflare
//     was observed ignoring Range on cdnjs and returning the full 87 KB of
//     jquery.min.js. normalize.min.css is 1861 bytes whole.
//
//   - cdn.jsdelivr.net was dropped: it answered 206 while returning the entire
//     6138-byte file, so the Range header buys nothing there, and its multi-CDN
//     fronting overlaps the Cloudflare and Fastly entries already in the class.
//     stackpath.bootstrapcdn.com was dropped for the same reason at 30x the size
//     (155 KB for bootstrap.min.css, Range ignored). unpkg.com is
//     Cloudflare-fronted and duplicates cdnjs's operator.
//
//   - The Wikipedia entry points at the favicon, not the front page. The front
//     page is 120 KB and Wikimedia's ATS does not honor Range, so it is the one
//     destination that would routinely exceed the wire budget. The favicon is
//     2734 bytes, served by the same Wikimedia edge.
//
//   - www.minecraft.net and www3.nhk.or.jp were candidates for ClassReputation
//     and are not here. minecraft.net never answered at all (a full timeout,
//     which costs an entire per-request round of wall clock for a class that
//     does not affect the score) and nhk answered 303 -- a redirect this client
//     refuses to follow, and a different answer from the timeout originally
//     recorded for it, so it is not stable enough to interpret.
var destinations = []Destination{
	// DNS-over-HTTPS, JSON GET form, SEVEN distinct operators including two
	// Chinese ones (dns.alidns.com, doh.pub) for deliberate jurisdictional
	// diversity: a provider whose upstream filters western resolvers, or the
	// reverse, shows up as a partial class rather than a clean pass. A provider
	// that blocks DoH breaks name resolution for every client that uses it.
	//
	// Every entry carries Verify: a 200 with bytes is not proof that a name was
	// resolved, because a captive portal or an interception box returns exactly
	// that. Only a parseable answer is.
	{
		Name:     "cloudflare-doh",
		Class:    ClassDNS,
		URL:      "https://cloudflare-dns.com/dns-query" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "google-doh",
		Class:    ClassDNS,
		URL:      "https://dns.google/resolve" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "adguard-doh",
		Class:    ClassDNS,
		URL:      "https://dns.adguard-dns.com/resolve" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "dnssb-doh",
		Class:    ClassDNS,
		URL:      "https://doh.dns.sb/dns-query" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "nextdns-doh",
		Class:    ClassDNS,
		URL:      "https://dns.nextdns.io/dns-query" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "alidns-doh",
		Class:    ClassDNS,
		URL:      "https://dns.alidns.com/resolve" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},
	{
		Name:     "dnspod-doh",
		Class:    ClassDNS,
		URL:      "https://doh.pub/dns-query" + dnsQuery,
		Headers:  map[string]string{"Accept": acceptDNSJSON},
		MaxBytes: maxDNSBytes,
		Verify:   verifyDNSJSON,
	},

	// Connectivity checks: the endpoints operating systems use to detect captive
	// portals. Eight distinct operators, none of them authenticated, none of them
	// behind anti-bot machinery, and all of them answering in under 70 bytes.
	//
	// The generate_204 entries are the reason Expect exists: 204 with no body is
	// the CORRECT answer, and the old rule would have scored all of them as
	// failures. They are also the strictest entries in the table -- an exact
	// status match, so a provider that synthesizes a bare 200 fails them.
	//
	// The body-bearing ones carry Verify for the captive-portal case those
	// endpoints were literally designed to detect: a portal returns 200 with a
	// login page, which is non-empty and would otherwise pass.
	{
		Name:     "google-204",
		Class:    ClassConnectivity,
		URL:      "https://www.google.com/generate_204",
		Expect:   ExpectStatus,
		Status:   http.StatusNoContent,
		MaxBytes: maxConnectivityBytes,
	},
	{
		Name:     "cloudflare-204",
		Class:    ClassConnectivity,
		URL:      "https://cp.cloudflare.com/generate_204",
		Expect:   ExpectStatus,
		Status:   http.StatusNoContent,
		MaxBytes: maxConnectivityBytes,
	},
	{
		Name:     "ubuntu-204",
		Class:    ClassConnectivity,
		URL:      "https://connectivity-check.ubuntu.com",
		Expect:   ExpectStatus,
		Status:   http.StatusNoContent,
		MaxBytes: maxConnectivityBytes,
	},
	{
		Name:     "firefox-portal",
		Class:    ClassConnectivity,
		URL:      "https://detectportal.firefox.com/success.txt",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyContains("success"),
	},
	{
		Name:     "apple-captive",
		Class:    ClassConnectivity,
		URL:      "https://captive.apple.com/hotspot-detect.html",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyContains("Success"),
	},
	{
		Name:     "gnome-nmcheck",
		Class:    ClassConnectivity,
		URL:      "https://nmcheck.gnome.org/check_network_status.txt",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyContains("online"),
	},
	{
		// The two echo services also happen to report the exit address, which is
		// the same fact geolocate already obtains; they leak nothing new.
		Name:     "ipify",
		Class:    ClassConnectivity,
		URL:      "https://api.ipify.org",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyIPText,
	},
	{
		Name:     "aws-checkip",
		Class:    ClassConnectivity,
		URL:      "https://checkip.amazonaws.com",
		MaxBytes: maxConnectivityBytes,
		Verify:   verifyIPText,
	},

	// CDN-hosted static assets, five distinct CDN operators: Cloudflare, Fastly
	// (via code.jquery.com), Amazon CloudFront, Google, and CacheFly. This is the
	// class that fails when a provider's egress range is on a CDN blocklist.
	{
		Name:     "cloudflare-cdnjs",
		Class:    ClassCDN,
		URL:      "https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css",
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "fastly-jquery",
		Class:    ClassCDN,
		URL:      "https://code.jquery.com/jquery-3.7.1.min.js",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// Version-pinned on purpose (an unversioned url would move under us),
		// with the tradeoff that if AWS ever prunes v2 of the browser SDK this
		// becomes a permanent 404 and a permanent false failure for every
		// provider. If cdn=4/5 with only this entry failing across the whole
		// fleet, suspect the URL before suspecting the providers. The same
		// applies to the pinned jquery entries.
		Name:     "cloudfront-awssdk",
		Class:    ClassCDN,
		URL:      "https://sdk.amazonaws.com/js/aws-sdk-2.1691.0.min.js",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "google-ajax",
		Class:    ClassCDN,
		URL:      "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		// CacheFly's own test asset: it exists to be fetched, and it honors Range,
		// so the 10 MB behind it never leaves their edge.
		Name:     "cachefly",
		Class:    ClassCDN,
		URL:      "https://cachefly.cachefly.net/10mb.test",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxAssetBytes,
	},

	// Ordinary sites, chosen for availability rather than for discrimination:
	// every one of these answered on four consecutive runs. The
	// "rejects datacenter ranges" role this class used to carry has moved to
	// ClassReputation, which is where it belongs and where it is not scored.
	// site=0/5 now means the tunnel is not carrying ordinary web traffic.
	{
		Name:     "wikipedia",
		Class:    ClassSite,
		URL:      "https://www.wikipedia.org/static/favicon/wikipedia.ico",
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "github",
		Class:    ClassSite,
		URL:      "https://github.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "example-com",
		Class:    ClassSite,
		URL:      "https://example.com/",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "cloudflare-www",
		Class:    ClassSite,
		URL:      "https://www.cloudflare.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxAssetBytes,
	},
	{
		Name:     "apple-www",
		Class:    ClassSite,
		URL:      "https://www.apple.com/robots.txt",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxAssetBytes,
	},

	// Reputation. NOT PART OF THE HEALTH SCORE -- see ClassReputation. Every one
	// of these refused a datacenter IP outright in four consecutive runs (403,
	// except reuters at 401), and on a residential or cellular exit they are
	// expected to return clean. A provider that passes them is more useful to a
	// real user; a provider that fails them is a hosted exit, not a broken one.
	{
		Name:     "akamai",
		Class:    ClassReputation,
		URL:      "https://www.akamai.com/",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxReputationBytes,
	},
	{
		Name:     "etsy",
		Class:    ClassReputation,
		URL:      "https://www.etsy.com/",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxReputationBytes,
	},
	{
		Name:     "epicgames",
		Class:    ClassReputation,
		URL:      "https://www.epicgames.com/",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxReputationBytes,
	},
	{
		Name:     "canva",
		Class:    ClassReputation,
		URL:      "https://www.canva.com/",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxReputationBytes,
	},
	{
		Name:     "reuters",
		Class:    ClassReputation,
		URL:      "https://www.reuters.com/",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxReputationBytes,
	},
	{
		// Kept deliberately even though it does NOT currently discriminate for
		// this client: it is the endpoint that produced the three contradictory
		// readings quoted on ClassReputation, and it is the control that keeps the
		// class honest about what it is measuring.
		Name:     "reddit",
		Class:    ClassReputation,
		URL:      "https://www.reddit.com/",
		Headers:  map[string]string{"Range": rangeFirst2KiB},
		MaxBytes: maxReputationBytes,
	},
}

// verifyDNSJSON proves a DoH response actually resolved the name, which a
// status code cannot: a captive portal, a transparent proxy or an interception
// box all answer 200 with a body. Only an answer section proves resolution.
//
// It decodes ONLY the Answer field, on purpose. The seven operators disagree
// about the rest of the document -- dns.alidns.com returns Question as an
// OBJECT where every other operator returns an array, so a struct that declared
// Question would fail to unmarshal AliDNS's perfectly good answer and score a
// working resolver as a captive portal.
//
// Status is not required to be 0 either. dns.adguard-dns.com omits the field
// entirely, and Go would leave it at 0 -- which happens to equal NOERROR, so a
// check on it would be passing by accident rather than by evidence. A non-empty
// answer with non-empty data is the evidence.
func verifyDNSJSON(body []byte) error {
	var doc struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("the response is not dns json (%w); a 200 with a body is not proof a name was resolved", err)
	}
	if len(doc.Answer) == 0 {
		return errors.New("the dns response carries no answer section; the request was answered by something that did not resolve the name")
	}
	for _, a := range doc.Answer {
		if strings.TrimSpace(a.Data) != "" {
			return nil
		}
	}
	return errors.New("every record in the dns answer section is empty")
}

// verifyIPText proves an echo endpoint returned an address rather than a
// portal's html. TrimSpace first: checkip.amazonaws.com terminates with a
// newline.
func verifyIPText(body []byte) error {
	text := strings.TrimSpace(string(body))
	if net.ParseIP(text) == nil {
		return fmt.Errorf("%q is not an ip address; this endpoint returns one, so something else answered", truncate(text, 64))
	}
	return nil
}

// verifyContains proves a fixed-text endpoint returned its fixed text.
//
// Substring, after TrimSpace, NOT equality: detectportal.firefox.com serves
// "success\n" -- eight bytes for a seven-character word -- so an equality check
// would fail for every provider forever, which is noise dressed as signal.
func verifyContains(want string) func([]byte) error {
	return func(body []byte) error {
		text := strings.TrimSpace(string(body))
		if !strings.Contains(text, want) {
			return fmt.Errorf("the body does not contain %q (got %q); a captive portal answers 200 with a page", want, truncate(text, 64))
		}
		return nil
	}
}

// truncate keeps an unexpected body from filling the log with someone's login
// page.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
	ByteCount  int64 // bytes of body actually read, capped; set on failures too
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
	Checks []CheckResult
	// OKCount and Total cover the SCORED classes only. A datacenter provider
	// that fails every reputation destination still reads as fully healthy here,
	// which is the intended behaviour -- see ClassReputation.
	OKCount int
	Total   int
	// ByClass is the per-class tally for the scored classes only.
	ByClass map[Class]ClassSummary
	// Reputation is the tally for ClassReputation, reported ALONGSIDE the score
	// and never inside it, so a log line can carry reputation=2/6 without that
	// figure contaminating ok=N/M.
	Reputation ClassSummary
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
//
// The three are one piece of arithmetic, not three independent knobs:
//
//	rounds = ceil(len(destinations)/DefaultConcurrency) = ceil(31/6) = 6
//	rounds * DefaultPerRequestTimeout = 6 * 10s = 60s = DefaultBudget
//
// Changing any one of them without the others either cuts off the last round
// (destinations fail for a reason the provider had nothing to do with) or lets
// a swallowing provider stall the pass for longer than one probe timeout.
// cmd/egress-prober derives the same ratio from -probe-timeout, and
// TestEgressHealthAddsAtMostOneProbeTimeout holds it.
var (
	// DefaultPerRequestTimeout is generous because every probe runs over a COLD
	// tunnel: nothing is warm, keep-alives are disabled, and each request pays
	// an in-tunnel DoH resolution plus a full TLS handshake. Treat it as a floor
	// rather than a preference -- it is what forced DefaultConcurrency up when
	// the table grew.
	DefaultPerRequestTimeout = 10 * time.Second
	// DefaultBudget bounds a whole run: rounds * DefaultPerRequestTimeout, so a
	// run that is going to be a total loss ends rather than stalling the pass,
	// and a healthy one is never cut off mid-round.
	DefaultBudget = 60 * time.Second
	// DefaultConcurrency was 3 while the table held 9 destinations. It is 6 for
	// 31 because the per-request timeout is a floor: at 3, a 60s probe budget
	// spread over ceil(31/3) = 11 rounds leaves ~5.5s per request, which is
	// BELOW the cold-tunnel figure above, and cold-start timeouts would then be
	// charged to providers as blackholes.
	//
	// The constraint it trades against is unchanged, and is about handshakes
	// rather than bytes: simultaneous TLS handshakes over one cold gvisor tunnel
	// with keep-alives disabled contend with each other and inflate every
	// latency. 31 destinations mean 31 handshakes however small the bodies are,
	// so the cheaper table does not by itself justify more parallelism -- the
	// per-request floor does.
	//
	// The field signal that this is set too high is specific: first-round
	// timeouts spread evenly across ALL classes, on providers whose geolocation
	// succeeded. That means lower it (and lengthen -probe-timeout to keep the
	// arithmetic above), not that the providers are bad.
	DefaultConcurrency = 6
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
// on a dead context returns 0/N -- identical to a total blackhole. The caller
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

// maxBytes is the body read cap for this destination: its own, clamped to the
// package ceiling so no single entry can raise the documented budget.
func (d Destination) maxBytes() int64 {
	if 0 < d.MaxBytes && d.MaxBytes < MaxBodyBytes {
		return int64(d.MaxBytes)
	}
	return MaxBodyBytes
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

	// ByClass and Reputation are seeded from the TABLE, not from the results
	// that happened to come back, so a class in which every single check failed
	// still appears as 0/n. Accumulating only from successes would make the
	// datacenter-IP case -- the whole reason the class dimension exists --
	// vanish from the map at exactly the moment it matters.
	byClass := map[Class]ClassSummary{}
	var reputation ClassSummary
	total := 0
	for _, d := range dests {
		if !scored(d.Class) {
			reputation.Total++
			continue
		}
		total++
		s := byClass[d.Class]
		s.Total++
		byClass[d.Class] = s
	}

	okCount := 0
	for _, r := range results {
		if !r.OK {
			continue
		}
		// An unscored class contributes to its own tally and to NOTHING else.
		// Folding it into okCount would make every hosted provider read as
		// degraded; see ClassReputation.
		if !scored(r.Class) {
			reputation.OK++
			continue
		}
		okCount++
		s := byClass[r.Class]
		s.OK++
		byClass[r.Class] = s
	}

	return &Result{
		Checks:     results,
		OKCount:    okCount,
		Total:      total,
		ByClass:    byClass,
		Reputation: reputation,
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
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, d.maxBytes()))
	r.ByteCount = int64(len(body))
	r.Latency = time.Since(start)

	if readErr != nil {
		r.Err = readErr.Error()
		return r
	}
	if err := d.judge(resp.StatusCode, body); err != nil {
		r.Err = err.Error()
		return r
	}
	r.OK = true
	return r
}

// judge applies the destination's success contract to what came back. It is
// separated from the transport so the rule can be read -- and reasoned about --
// without an http server in the way.
func (d Destination) judge(status int, body []byte) error {
	switch d.Expect {
	case ExpectStatus:
		if d.Status <= 0 {
			// A misconfigured entry must fail loudly rather than accept anything:
			// "expect exactly nothing in particular" is how ExpectStatus would
			// become a hole in the blackhole rule.
			return fmt.Errorf("destination declares ExpectStatus with no Status; it cannot be judged")
		}
		if status != d.Status {
			// Exact, not "any 2xx". A provider that synthesizes a bare 200 must
			// not pass a destination that is supposed to answer 204.
			return fmt.Errorf("status %d, want exactly %d", status, d.Status)
		}
	default: // ExpectBody
		if status < 200 || 300 <= status {
			// 3xx counts as a failure, not a redirect to follow. The production
			// client refuses redirects outright (providertunnel's CheckRedirect),
			// so a 3xx here is a destination that did not serve what was asked
			// for. A destination that legitimately answers 3xx should declare
			// ExpectStatus rather than be chased.
			return fmt.Errorf("status %d", status)
		}
		if len(body) == 0 {
			// THE blackhole signature, and the reason this rule is spelled out: a
			// status line with no body is exactly what a provider that terminates
			// the connection itself, or one whose upstream returns a stub,
			// produces. Counting it as success would let the failure this package
			// exists to catch pass the check. This stays the DEFAULT contract; an
			// endpoint where an empty body is correct must say so with
			// ExpectStatus.
			return fmt.Errorf("status %d with an empty body", status)
		}
	}
	if d.Verify == nil {
		return nil
	}
	if err := d.Verify(body); err != nil {
		return fmt.Errorf("status %d but the body did not verify: %w", status, err)
	}
	return nil
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
// Reputation hosts are included: they are reached through the tunnel like any
// other destination, so the confinement check must prove them unreachable
// directly. Being excluded from the SCORE has nothing to do with confinement.
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
//	ok=25/27 dns=7/7 connectivity=8/8 cdn=5/5 site=5/5 reputation=1/6
//
// The reputation figure sits OUTSIDE ok=N/M on purpose and is never added into
// it: it measures how the exit's address-and-client pair is treated by
// bot-management vendors, not whether the provider works. See ClassReputation.
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
	if 0 < r.Reputation.Total {
		fmt.Fprintf(&b, " %s=%d/%d", ClassReputation, r.Reputation.OK, r.Reputation.Total)
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

// FailedNames lists the SCORED destinations that did not pass, in table order.
// The summary line says how many failed; this says which, which is what turns a
// log line into something actionable.
//
// Reputation failures are not here, because they are not failures of the thing
// ok=N/M reports; ReputationFailedNames lists those separately so a log line
// can keep the two apart.
func (r *Result) FailedNames() []string {
	if r == nil {
		return nil
	}
	var names []string
	for _, c := range r.Checks {
		if !c.OK && scored(c.Class) {
			names = append(names, c.Name)
		}
	}
	return names
}

// ReputationFailedNames lists the reputation destinations that refused this
// exit, in table order. Which vendor refused is the whole content of the
// signal -- "akamai,etsy" and "reuters" say different things about what the
// exit looks like from outside.
func (r *Result) ReputationFailedNames() []string {
	if r == nil {
		return nil
	}
	var names []string
	for _, c := range r.Checks {
		if !c.OK && !scored(c.Class) {
			names = append(names, c.Name)
		}
	}
	return names
}
