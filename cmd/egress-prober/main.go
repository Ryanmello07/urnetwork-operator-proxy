// Command egress-prober probes each provider's egress location by routing
// geolocation lookups through that provider, and submits the results to the
// operator's server.
//
// The prober host never contacts a geolocation api directly: every lookup
// egresses through a provider tunnel. The only direct calls are to the
// operator's own server (provider list, ingest).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/urnetwork/connect"

	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
	"github.com/urnetwork/urnetwork-operator-proxy/ingest"
	"github.com/urnetwork/urnetwork-operator-proxy/prober"
	"github.com/urnetwork/urnetwork-operator-proxy/providertunnel"
)

func main() {
	apiURL := flag.String("api-url", "", "operator server api url, e.g. https://api.example.net (required)")
	platformURL := flag.String("platform-url", "", "operator platform websocket url, e.g. wss://connect.example.net (required)")
	// The two secret flags MUST declare an empty default and read their env
	// var only after Parse (see envFallback below). Passing os.Getenv(...) as
	// the flag default instead makes flag.PrintDefaults render the live secret
	// as `(default "...")`, so every flag.Usage() call -- any missing required
	// flag, any parse error, and plain -h, which an operator runs routinely --
	// echoes both secrets verbatim to stderr, into journald or a CI log. That
	// would invert the README's own advice, which presents these env vars as
	// the way to keep secrets out of logs and ps.
	byJwt := flag.String("by-jwt", "", "the prober's network client jwt; prefer the UR_PROBER_BY_JWT env var, which keeps it out of ps (required)")
	operatorSecret := flag.String("operator-secret", "", "ingest secret, must match ingest_secret in provider_egress.yml; prefer the UR_OPERATOR_SECRET env var, which keeps it out of ps (required)")
	concurrency := flag.Int("concurrency", 4, "max simultaneous provider tunnels")
	cacheTTL := flag.Duration("cache-ttl", 24*time.Hour, "do not re-probe a provider within this window")
	interval := flag.Duration("interval", time.Hour, "sleep between passes; 0 runs a single pass and exits")
	probeTimeout := flag.Duration("probe-timeout", 60*time.Second, "per-provider probe timeout, and the per-source deadline within a probe")
	flag.Parse()

	// Env fallback, applied only after parsing so the secret is never a flag
	// default and can never be rendered by flag.Usage(). An explicit flag
	// still wins, matching the previous precedence.
	envFallback(byJwt, "UR_PROBER_BY_JWT")
	envFallback(operatorSecret, "UR_OPERATOR_SECRET")

	var missing []string
	if *apiURL == "" {
		missing = append(missing, "-api-url")
	}
	if *platformURL == "" {
		missing = append(missing, "-platform-url")
	}
	if *byJwt == "" {
		missing = append(missing, "-by-jwt (or UR_PROBER_BY_JWT)")
	}
	if *operatorSecret == "" {
		missing = append(missing, "-operator-secret (or UR_OPERATOR_SECRET)")
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: missing required flag(s): %s\n\n", strings.Join(missing, ", "))
		flag.Usage()
		os.Exit(2)
	}

	// M1: a negative -interval would otherwise fall straight into
	// time.After, which treats a negative duration as "fire immediately" --
	// degenerating the sleep loop into back-to-back passes with no pause
	// between them and no indication why. Fail fast instead.
	if *interval < 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: -interval must not be negative (got %s)\n\n", *interval)
		flag.Usage()
		os.Exit(2)
	}

	// M5: -probe-timeout 0 disables BOTH the http.Client.Timeout and the
	// manual TLS handshake timeout in providertunnel's DialTLSContext (see
	// providertunnel/tunnel.go: `if timeout > 0`), since a zero
	// time.Duration is the Go idiom for "no timeout" in both places. A
	// negative value is nonsensical for either. Either way, a provider that
	// simply never responds would hang a probe (and the goroutine slot it
	// holds) forever instead of freeing up for the next pass.
	if *probeTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "egress-prober: -probe-timeout must be positive (got %s)\n\n", *probeTimeout)
		flag.Usage()
		os.Exit(2)
	}

	clientId, err := parseByJwtClientId(*byJwt)
	if err != nil {
		log.Fatalf("parse by-jwt client id: %s", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	tunnelCfg := providertunnel.Config{
		ApiURL:            *apiURL,
		PlatformURL:       *platformURL,
		ByJwt:             *byJwt,
		ClientId:          clientId,
		Pins:              geolocatePins(),
		DeviceDescription: "egress prober",
		DeviceSpec:        "egress-prober",
		Version:           "0.0.0",
	}

	submitter := &ingest.Client{
		ServerURL:      *apiURL,
		OperatorSecret: *operatorSecret,
		HTTP:           &http.Client{Timeout: 30 * time.Second},
	}

	p := &prober.Prober{
		Open: func(ctx context.Context, providerClientId string) (*http.Client, func() error, error) {
			id, err := connect.ParseId(providerClientId)
			if err != nil {
				return nil, nil, err
			}
			t, err := providertunnel.Open(ctx, tunnelCfg, id)
			if err != nil {
				return nil, nil, err
			}
			return t.HTTPClient(*probeTimeout), t.Close, nil
		},
		// -probe-timeout must govern the per-source deadline too, not just
		// the http.Client's overall timeout. geolocate caps each source fetch
		// independently, and until this was wired the cap was always the 5s
		// package default, so raising -probe-timeout could not extend the
		// deadline that actually matters. Every probe runs over a cold tunnel
		// -- no warm-up, closed again after each provider -- so that one
		// budget has to cover session establishment, an in-tunnel DoH
		// resolution, and two TLS handshakes.
		Locate: func(ctx context.Context, client *http.Client) (*geolocate.ConsensusLocation, error) {
			return geolocate.LocateWithOptions(ctx, client, geolocate.LocateOptions{
				PerSourceTimeout: *probeTimeout,
			})
		},
		Submit: submitter,
	}

	scheduler := &prober.Scheduler{
		Prober:      p,
		Concurrency: *concurrency,
		CacheTTL:    *cacheTTL,
	}

	// I3: a single-shot run (-interval 0) is the mode the README recommends
	// for external cron/systemd scheduling, which decides success or
	// failure purely from the exit code -- so this process must not report
	// success (exit 0) when it accomplished nothing. Two cases are treated
	// as failure below: the provider list could not be fetched at all, and
	// a pass that ran but submitted nothing while recording failures (e.g.
	// every probe hit the same wrong -platform-url, or the jwt was
	// revoked -- a permanently broken configuration, not a fluke). A pass
	// with zero providers to probe (submitted=0, failed=0) is NOT a
	// failure -- there was simply nothing to do.
	//
	// The long-running loop (-interval > 0) deliberately does NOT exit on
	// either condition: a systemd-managed process should keep retrying
	// through a transient server blip rather than dying, but it does still
	// log clearly so the failure is visible (e.g. via journalctl) even
	// though the process itself stays up.
	for {
		providers, err := listProviders(ctx, *apiURL, *byJwt)
		if err != nil {
			log.Printf("list providers: %s", err)
			if *interval == 0 {
				log.Printf("egress-prober: single-shot pass could not fetch the provider list; exiting non-zero")
				os.Exit(1)
			}
		} else {
			sum := scheduler.Run(ctx, providers)
			log.Printf("pass: attempted=%d submitted=%d skipped=%d failed=%d",
				sum.Attempted, sum.Submitted, sum.Skipped, sum.Failed)
			if *interval == 0 && sum.Submitted == 0 && 0 < sum.Failed {
				log.Printf("egress-prober: single-shot pass submitted nothing and recorded %d failure(s); exiting non-zero", sum.Failed)
				os.Exit(1)
			}
		}
		if *interval == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*interval):
		}
	}
}

// envFallback fills *value from the named environment variable when the flag
// was not given. Reading the environment here, rather than through the flag's
// default, is what keeps the value out of flag.Usage() output.
func envFallback(value *string, envName string) {
	if *value == "" {
		*value = os.Getenv(envName)
	}
}

// geolocatePins are the SPKI (subject public key info) pins for the
// geolocation endpoints probed by geolocate/sources.go. providertunnel.Open
// refuses to run with an empty pin map (see providertunnel.ErrPinsRequired),
// and any https host dialed through a tunnel that isn't a key in this map is
// refused outright -- so this set must stay in sync with geolocate/sources.go.
//
// Each host lists two pins: the current leaf certificate's key, and the
// issuing intermediate CA's key.
//
// providertunnel's checkPin (providertunnel/pinning.go) accepts a match
// against ANY certificate in the presented chain, not just the leaf. That
// means the intermediate pin below DOES provide rotation resilience: when a
// host's leaf certificate rotates (routine -- Let's Encrypt roughly every 90
// days, Google Trust Services on its own schedule), the new leaf is still
// signed by the same intermediate, so its SPKI still matches the
// intermediate pin and probing keeps working with no redeploy needed. The
// tradeoff is that pinning an intermediate trusts that whole CA for this
// host, not one specific certificate -- any certificate that CA issues for
// this host will pass. If a host's probing DOES start failing with a
// pin-mismatch error, that means the issuing intermediate itself changed
// (e.g. the CA rotated its intermediate, or the host switched CAs), and
// both pins should be re-captured and redeployed; see "Re-capturing" below.
//
// Captured 2026-07-25 from this sandbox, all three hosts reachable:
//
//	ip.pn               leaf: yNlfgRK6eIeC9nTBewXbeThe8SgisnFxPeeDB5yua20=
//	                     intermediate (Let's Encrypt YE2): s/tdAOmUzd8syaTuqfgGvFcn6DzA5Cmb+Vby1ST+U3Y=
//	free.freeipapi.com  leaf: 4RRfWDm6iNKBzkDWqytoa+NbLnfcBMicnrll6MgYJLA=
//	                     intermediate (Google Trust Services WE1): kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=
//	ipinfo.io            leaf: NnbPrbmZhsiaZL6QwNFVdj9ALZAi9/lUKbPSbGij/xY=
//	                     intermediate (Let's Encrypt YR1): LoMHBotttiDko50Gi13uXW71eIy7LAttI+rYT8wXF4w=
//
// Re-capturing: leaf certificates rotate (Let's Encrypt roughly every 90
// days; Google Trust Services on its own schedule), so operators should
// expect to refresh the leaf pins periodically -- if probing for a host
// starts failing with an x509/pin error, re-run the capture below and update
// the map. To recapture the leaf pin for a host:
//
//	openssl s_client -connect <host>:443 -servername <host> </dev/null 2>/dev/null \
//	  | openssl x509 -pubkey -noout \
//	  | openssl pkey -pubin -outform der \
//	  | openssl dgst -sha256 -binary | base64
//
// To recapture the issuing intermediate's pin, get the full chain and pin
// the second certificate (the first is the leaf, the last is usually the
// root, which is not pinned here):
//
//	openssl s_client -connect <host>:443 -servername <host> -showcerts </dev/null 2>/dev/null \
//	  | awk '/BEGIN CERTIFICATE/{n++} {print > ("cert."n".pem")}'
//	openssl x509 -in cert.2.pem -pubkey -noout \
//	  | openssl pkey -pubin -outform der \
//	  | openssl dgst -sha256 -binary | base64
func geolocatePins() map[string][]string {
	return map[string][]string{
		"ip.pn": {
			"yNlfgRK6eIeC9nTBewXbeThe8SgisnFxPeeDB5yua20=", // leaf
			"s/tdAOmUzd8syaTuqfgGvFcn6DzA5Cmb+Vby1ST+U3Y=", // intermediate: Let's Encrypt YE2
		},
		"free.freeipapi.com": {
			"4RRfWDm6iNKBzkDWqytoa+NbLnfcBMicnrll6MgYJLA=", // leaf
			"kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=", // intermediate: Google Trust Services WE1
		},
		"ipinfo.io": {
			"NnbPrbmZhsiaZL6QwNFVdj9ALZAi9/lUKbPSbGij/xY=", // leaf
			"LoMHBotttiDko50Gi13uXW71eIy7LAttI+rYT8wXF4w=", // intermediate: Let's Encrypt YR1
		},
	}
}

// findProvidersCountPerLocation is the count requested in each per-location
// find-providers2 call. It is intentionally high: the server's selection
// (model.FindProviders2) weighted-shuffles and then truncates to `count`
// (`clientIds[:min(count, len(clientIds))]`), so a count well above any
// single location's real provider population effectively returns all of
// them, not a sample -- which is the whole point of I1 (a stable, complete
// enumeration, not a moving subset).
const findProvidersCountPerLocation = 5000

// listProviders enumerates every provider client id the server currently
// knows about, broadly and stably. This directly fixes I1: the previous
// implementation asked for `{"best_available":true}`, which on the server
// resolves to `countryCodeLocationIds()["us"]` (model.FindProviders2 in
// model/network_client_location_model.go) -- so it only ever enumerated
// providers the server's OWN geo database already believes are in the US.
// That is backwards for a tool whose entire purpose is finding providers
// whose location the database gets wrong. It was also
// weighted-random-sampled and shuffled server-side, so successive passes
// returned different subsets rather than a stable enumeration.
//
// The fix enumerates by location instead of by (wrong) assumption:
//  1. GET /network/provider-locations -- no auth required
//     (router.WrapNoAuth in the server's
//     api/handlers/network_client_location_handlers.go) -- which returns
//     every location, at every granularity (city/region/country) that
//     currently has at least one provider (model.GetProviderLocations,
//     filtered to locations present in loadLocationStables). Verified
//     against the server source at api/api.go and
//     model/network_client_location_model.go: the response is a
//     model.FindLocationsResult, whose `locations` field is
//     []*model.LocationResult with `location_id` (model.LocationResult).
//  2. For each returned location, POST /network/find-providers2 with an
//     explicit `{"specs":[{"location_id":"<id>"}],"count":<high>}` spec
//     (model.FindProviders2Args / model.ProviderSpec), and union the
//     `client_id`s (model.FindProvidersProvider) across all locations,
//     de-duplicating. A single provider legitimately appears under more
//     than one location (its city, region, and country entries each
//     resolve back to it -- confirmed by how the server populates its
//     per-location score cache in model.go's export path), so
//     de-duplication here is expected, not defensive overkill.
//
// Resilient by design: if one location's find-providers2 call fails
// (timeout, transient 5xx), it is logged and skipped rather than aborting
// the whole pass -- a broad enumeration that misses one location out of
// what can be hundreds is far more useful than a pass that produces
// nothing because one of them hiccupped.
func listProviders(ctx context.Context, apiURL string, byJwt string) ([]string, error) {
	httpClient := &http.Client{Timeout: 30 * time.Second}

	locationIds, err := listProviderLocationIds(ctx, httpClient, apiURL)
	if err != nil {
		return nil, fmt.Errorf("list provider locations: %w", err)
	}

	seen := make(map[string]struct{})
	for _, locationId := range locationIds {
		clientIds, err := findProvidersAtLocation(ctx, httpClient, apiURL, byJwt, locationId)
		if err != nil {
			log.Printf("egress-prober: find-providers2 for location %s: %s (skipping this location for this pass)", locationId, err)
			continue
		}
		for _, id := range clientIds {
			seen[id] = struct{}{}
		}
	}

	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids, nil
}

// listProviderLocationIds calls GET /network/provider-locations and returns
// the location_id of every location in the response. See listProviders for
// the full rationale and the server-side source verified against.
func listProviderLocationIds(ctx context.Context, client *http.Client, apiURL string) ([]string, error) {
	url := strings.TrimRight(apiURL, "/") + "/network/provider-locations"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	// Mirrors model.FindLocationsResult / model.LocationResult
	// (model/network_client_location_model.go) exactly: only the fields
	// this CLI actually needs are decoded.
	var out struct {
		Locations []struct {
			LocationId string `json:"location_id"`
		} `json:"locations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(out.Locations))
	for _, l := range out.Locations {
		ids = append(ids, l.LocationId)
	}
	return ids, nil
}

// findProvidersAtLocation calls POST /network/find-providers2 with a
// single explicit location_id spec and returns the client_id of every
// provider returned for it. See listProviders for the full rationale and
// the server-side source verified against.
func findProvidersAtLocation(ctx context.Context, client *http.Client, apiURL string, byJwt string, locationId string) ([]string, error) {
	// Mirrors model.FindProviders2Args / model.ProviderSpec
	// (model/network_client_location_model.go) exactly: Specs is
	// []*ProviderSpec, here a single spec with only LocationId set (json
	// "location_id"); Count and RankMode (json "rank_mode") match the
	// struct's json tags.
	reqBody, err := json.Marshal(struct {
		Specs    []map[string]string `json:"specs"`
		Count    int                 `json:"count"`
		RankMode string              `json:"rank_mode"`
	}{
		Specs:    []map[string]string{{"location_id": locationId}},
		Count:    findProvidersCountPerLocation,
		RankMode: "quality",
	})
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(apiURL, "/") + "/network/find-providers2"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	// find-providers2 does not require auth (router.WrapWithInputNoAuth on
	// the server), but the byJwt is sent anyway, matching the previous
	// implementation and every other call this CLI makes -- harmless, and
	// keeps this call consistent with the rest of the CLI's requests should
	// that ever change.
	req.Header.Set("Authorization", "Bearer "+byJwt)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	// Mirrors model.FindProviders2Result / model.FindProvidersProvider
	// exactly: only client_id is decoded.
	var out struct {
		Providers []struct {
			ClientId string `json:"client_id"`
		} `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(out.Providers))
	for _, p := range out.Providers {
		ids = append(ids, p.ClientId)
	}
	return ids, nil
}

// parseByJwtClientId extracts the client_id claim from byJwt and parses it as
// a connect.Id. This mirrors the proven implementation in
// urnetwork/proxy/socks/main.go:parseByJwtClientId: the jwt is parsed
// unverified (the prober is not the one who issued it; the server it talks to
// is the authority that already validated it when minting a session from it),
// and the claim is type-switched rather than unmarshaled into a typed struct,
// since some issuers emit client_id as something other than a bare string.
func parseByJwtClientId(byJwt string) (connect.Id, error) {
	claims := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(byJwt, claims); err != nil {
		return connect.Id{}, fmt.Errorf("parse jwt: %w", err)
	}

	jwtClientId, ok := claims["client_id"]
	if !ok {
		return connect.Id{}, fmt.Errorf("byJwt does not contain claim client_id")
	}
	switch v := jwtClientId.(type) {
	case string:
		return connect.ParseId(v)
	default:
		return connect.Id{}, fmt.Errorf("byJwt has invalid type for client_id: %T", v)
	}
}
