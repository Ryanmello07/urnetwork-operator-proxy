package main

// Manual, operator-driven probe of ONE named provider. Not part of the
// automated suite: it is skipped unless MANUAL_PROBE_PROVIDER is set, because
// it needs a live provider, a real network client jwt, and real egress.
//
// Build a runnable binary for a VPS with:
//
//	go test -c -o manualprobe ./cmd/egress-prober
//
// then run it there with MANUAL_PROBE_PROVIDER / UR_PROBER_BY_JWT set:
//
//	./manualprobe -test.run TestManualProbeOneProvider -test.v
//
// It prints what each geolocation source said individually alongside the
// consensus, so a disagreement between sources is visible rather than hidden
// behind the verdict, and then runs the egress-health check over the SAME
// tunnel and prints every destination's outcome. That second half is the
// end-to-end proof for the health signal: the same client, the same session,
// against nine real destinations the geolocation probe never touches.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/urnetwork-operator-proxy/egresshealth"
	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
	"github.com/urnetwork/urnetwork-operator-proxy/providertunnel"
)

func TestManualProbeOneProvider(t *testing.T) {
	providerStr := os.Getenv("MANUAL_PROBE_PROVIDER")
	if providerStr == "" {
		t.Skip("set MANUAL_PROBE_PROVIDER to the provider client id to probe")
	}
	byJwt := os.Getenv("UR_PROBER_BY_JWT")
	apiURL := os.Getenv("MANUAL_PROBE_API_URL")
	platformURL := os.Getenv("MANUAL_PROBE_PLATFORM_URL")
	if byJwt == "" || apiURL == "" || platformURL == "" {
		t.Fatal("UR_PROBER_BY_JWT, MANUAL_PROBE_API_URL and MANUAL_PROBE_PLATFORM_URL are all required")
	}

	providerId, err := connect.ParseId(providerStr)
	if err != nil {
		t.Fatalf("parse provider client id %q: %s", providerStr, err)
	}
	selfId, err := parseByJwtClientId(byJwt)
	if err != nil {
		t.Fatalf("parse by-jwt client id: %s", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// the same pins the real CLI uses, so this exercises the shipped
	// pinning path rather than a permissive one
	tun, err := providertunnel.Open(ctx, providertunnel.Config{
		ApiURL:            apiURL,
		PlatformURL:       platformURL,
		ByJwt:             byJwt,
		ClientId:          selfId,
		Pins:              geolocatePins(),
		DeviceDescription: "manual egress probe",
		DeviceSpec:        "egress-prober",
		Version:           "0.0.0",
	}, providerId)
	if err != nil {
		t.Fatalf("open tunnel to provider %s: %s", providerId, err)
	}
	defer tun.Close()

	// The same one client the CLI builds: geolocation hosts pinned, egress
	// health destinations allowed unpinned. Using tun.HTTPClient here instead
	// would refuse every health destination at the allowlist, so this also
	// keeps the manual probe honest about what the shipped path does.
	client := tun.HTTPClientForHosts(90*time.Second, egresshealth.DestinationHosts())

	loc, err := geolocate.LocateWithOptions(ctx, client,
		geolocate.LocateOptions{PerSourceTimeout: 45 * time.Second})
	if err != nil {
		t.Fatalf("geolocate through provider %s: %s", providerId, err)
	}

	t.Logf("provider            %s", providerId)
	t.Logf("country             %s (%s) confident=%t", loc.Country, loc.CountryCode, loc.CountryConfident)
	t.Logf("city / region       %q / %q confident=%t", loc.City, loc.Region, loc.CityConfident)
	t.Logf("asn / org           %d / %s", loc.ASN, loc.Org)
	t.Logf("hosting/proxy/mobile %t/%t/%t", loc.Hosting, loc.Proxy, loc.Mobile)
	for _, s := range loc.Sources {
		if s.OK {
			t.Logf("  source %-12s ok   cc=%-4s city=%-18q region=%-16q asn=%-8d org=%s",
				s.Name, s.CountryCode, s.City, s.Region, s.ASN, s.Org)
		} else {
			t.Logf("  source %-12s FAIL %s", s.Name, s.Err)
		}
	}

	// Egress health over the SAME tunnel -- never a second one.
	health, err := egresshealth.Check(ctx, client, egresshealth.Options{
		PerRequestTimeout: 45 * time.Second,
		Budget:            3 * time.Minute,
	})
	if err != nil {
		t.Fatalf("egress health through provider %s did not run: %s", providerId, err)
	}
	t.Logf("egress-health       %s", health.Summary())
	for _, c := range health.Checks {
		status := "FAIL"
		if c.OK {
			status = "ok  "
		}
		t.Logf("  %-4s %-18s %-5s status=%-4d bytes=%-6d %-8s %s",
			status, c.Name, c.Class, c.StatusCode, c.ByteCount, c.Latency.Round(time.Millisecond), c.Err)
	}
}
