package main

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/urnetwork-operator-proxy/confinement"
	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
)

// lookupFails is a resolver that cannot resolve anything, which is what a
// correctly confined deployment looks like (dns to a public resolver is
// blocked too). confinement.Addresses then falls back to the hostnames, which
// makes the derived address list directly comparable to geolocate.SourceHosts.
func lookupFails(ctx context.Context, host string) ([]string, error) {
	return nil, errors.New("lookup " + host + ": no such host")
}

// TestCheckConfinementProbesEveryGeolocationHost is the anti-drift assertion
// that matters most here: the addresses the check tests must be DERIVED from
// the same table geolocate will later fetch through a tunnel, not a second
// hand-maintained copy. A second copy drifts on the first endpoint change and
// the check keeps passing while no longer covering a real endpoint.
func TestCheckConfinementProbesEveryGeolocationHost(t *testing.T) {
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("connect: network is unreachable")
	}

	if err := checkConfinement(context.Background(), dial, lookupFails, time.Second); err != nil {
		t.Fatalf("checkConfinement: %s", err)
	}

	var want []string
	for _, host := range geolocate.SourceHosts() {
		want = append(want, net.JoinHostPort(host, confinementPort))
	}
	if len(want) == 0 {
		t.Fatal("geolocate.SourceHosts is empty; the check would have nothing to test")
	}
	sort.Strings(want)
	sort.Strings(dialed)
	if strings.Join(dialed, ",") != strings.Join(want, ",") {
		t.Fatalf("checkConfinement dialed %v, want every geolocate source host %v", dialed, want)
	}
}

// TestCheckConfinementRefusesWhenReachable: a successful direct connection
// means the operator's confinement is missing, so the prober must not run --
// every provider would otherwise be recorded at the operator's own location.
func TestCheckConfinementRefusesWhenReachable(t *testing.T) {
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, _ := net.Pipe()
		return c1, nil
	}
	err := checkConfinement(context.Background(), dial, lookupFails, time.Second)
	if err == nil {
		t.Fatal("checkConfinement returned nil while a geolocation address was directly reachable")
	}
	if !errors.Is(err, confinement.ErrNotConfined) {
		t.Fatalf("checkConfinement error = %v, want ErrNotConfined", err)
	}
}

// TestCheckConfinementUsesResolvedAddressesWhenDnsWorks: when dns is available
// the check must test the resolved ips, not just the names -- dialing a name
// that fails to resolve proves nothing about whether the ip behind it is
// reachable.
func TestCheckConfinementUsesResolvedAddressesWhenDnsWorks(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		return []string{"203.0.113.9"}, nil
	}
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return nil, errors.New("connect: network is unreachable")
	}
	if err := checkConfinement(context.Background(), dial, lookup, time.Second); err != nil {
		t.Fatalf("checkConfinement: %s", err)
	}
	if len(dialed) != 1 || dialed[0] != "203.0.113.9:"+confinementPort {
		t.Fatalf("checkConfinement dialed %v, want the resolved address 203.0.113.9:%s", dialed, confinementPort)
	}
}

// TestGeolocatePinsCoverEveryGeolocationHost: the pin allowlist is the other
// place the endpoint list is written down. providertunnel refuses any host
// that is not a key in it, so a source added to geolocate without a pin here
// fails every probe against that source; and a pin left behind for a removed
// source silently widens the allowlist.
func TestGeolocatePinsCoverEveryGeolocationHost(t *testing.T) {
	pins := geolocatePins()
	hosts := geolocate.SourceHosts()
	if len(pins) != len(hosts) {
		t.Fatalf("geolocatePins has %d hosts, geolocate.SourceHosts has %d; the two lists have drifted apart (%v vs %v)", len(pins), len(hosts), keysOf(pins), hosts)
	}
	for _, host := range hosts {
		if len(pins[host]) == 0 {
			t.Fatalf("geolocate source host %q has no entry in geolocatePins; every probe against it would be refused by providertunnel", host)
		}
	}
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestSkipConfinementCheckIsOffByDefault: a check that is off by default is not
// a check. This asserts on the built binary's own -h output, so it holds
// regardless of how the flag is wired internally.
func TestSkipConfinementCheckIsOffByDefault(t *testing.T) {
	out := runProberWithSecretsInEnv(t, "-h")
	if !strings.Contains(out, "-skip-confinement-check") {
		t.Fatalf("-h does not document -skip-confinement-check.\n--- output ---\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "skip-confinement-check") {
			// flag.PrintDefaults renders a true bool default as `(default true)`
			// and omits the clause entirely for false.
			if strings.Contains(line, "default true") {
				t.Fatalf("-skip-confinement-check defaults to true; the confinement check must be on unless explicitly disabled.\n--- line ---\n%s", line)
			}
		}
	}
}

// TestSkipConfinementCheckLogsLoudly: the escape hatch exists for the operator
// running a one-shot manual probe, but it disables the only thing standing
// between a misconfigured host and recording every provider at the operator's
// own location. It must be impossible to miss in the log.
//
// -api-url points at a closed port so the run fails immediately after the
// check without contacting anything real.
func TestSkipConfinementCheckLogsLoudly(t *testing.T) {
	out := runProberWithSecretsInEnv(t,
		"-skip-confinement-check",
		"-api-url", "http://127.0.0.1:1",
		"-platform-url", "ws://127.0.0.1:1",
		"-interval", "0",
	)
	if !strings.Contains(out, "WARNING") {
		t.Fatalf("-skip-confinement-check produced no WARNING line.\n--- output ---\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "confinement") {
		t.Fatalf("-skip-confinement-check did not say what was skipped.\n--- output ---\n%s", out)
	}
}
