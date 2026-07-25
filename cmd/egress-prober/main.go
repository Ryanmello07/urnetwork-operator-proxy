// Command egress-prober probes each provider's egress location by routing
// geolocation lookups through that provider, and submits the results to the
// operator's server.
//
// The prober host never contacts a geolocation api directly: every lookup
// egresses through a provider tunnel. The only direct calls are to the
// operator's own server (provider list, ingest).
package main

import (
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
	byJwt := flag.String("by-jwt", os.Getenv("UR_PROBER_BY_JWT"), "the prober's network client jwt (or UR_PROBER_BY_JWT) (required)")
	operatorSecret := flag.String("operator-secret", os.Getenv("UR_OPERATOR_SECRET"), "ingest secret, must match ingest_secret in provider_egress.yml (or UR_OPERATOR_SECRET) (required)")
	concurrency := flag.Int("concurrency", 4, "max simultaneous provider tunnels")
	cacheTTL := flag.Duration("cache-ttl", 24*time.Hour, "do not re-probe a provider within this window")
	interval := flag.Duration("interval", time.Hour, "sleep between passes; 0 runs a single pass and exits")
	probeTimeout := flag.Duration("probe-timeout", 60*time.Second, "per-provider probe timeout")
	flag.Parse()

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
		Locate: geolocate.Locate,
		Submit: submitter,
	}

	scheduler := &prober.Scheduler{
		Prober:      p,
		Concurrency: *concurrency,
		CacheTTL:    *cacheTTL,
	}

	for {
		providers, err := listProviders(ctx, *apiURL, *byJwt)
		if err != nil {
			log.Printf("list providers: %s", err)
		} else {
			sum := scheduler.Run(ctx, providers)
			log.Printf("pass: attempted=%d submitted=%d skipped=%d failed=%d",
				sum.Attempted, sum.Submitted, sum.Skipped, sum.Failed)
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

// geolocatePins are the SPKI (subject public key info) pins for the
// geolocation endpoints probed by geolocate/sources.go. providertunnel.Open
// refuses to run with an empty pin map (see providertunnel.ErrPinsRequired),
// and any https host dialed through a tunnel that isn't a key in this map is
// refused outright -- so this set must stay in sync with geolocate/sources.go.
//
// Each host lists two pins: the current leaf certificate's key, and the
// issuing intermediate CA's key.
//
// IMPORTANT: providertunnel's checkPin (providertunnel/pinning.go) only
// hashes and checks rawCerts[0] -- the leaf -- against the allowed list; it
// never inspects the rest of the chain. That means the intermediate pin
// below does NOT provide the rotation resilience a reader might expect from
// "pin the CA too": it cannot match anything, because it is never compared
// against anything but the leaf's own SPKI, which will never equal the
// intermediate's SPKI. It is recorded here (a) because the brief asked for
// it and (b) as a documented, ready-to-use value for the day
// providertunnel's pin check is extended to walk the chain -- but today it
// is inert. A leaf-key rotation WILL break probing for that host and
// requires re-capturing and redeploying the leaf pin; see "Re-capturing"
// below. Do not rely on the intermediate entry to survive a rotation.
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

// listProviders asks the operator's own server for current public providers.
// The request/response shape mirrors the server's
// model.FindProviders2Args/FindProviders2Result exactly
// (model/network_client_location_model.go): Specs is a []*ProviderSpec, here
// a single best-available spec; the response's Providers carry ClientId as
// json "client_id".
func listProviders(ctx context.Context, apiURL string, byJwt string) ([]string, error) {
	body := strings.NewReader(`{"specs":[{"best_available":true}],"count":1000,"rank_mode":"quality"}`)
	url := strings.TrimRight(apiURL, "/") + "/network/find-providers2"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+byJwt)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
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
