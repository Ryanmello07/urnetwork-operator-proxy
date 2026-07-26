// Package confinement verifies at startup that this process cannot reach a
// geolocation api directly.
//
// The prober's entire guarantee is that every geolocation lookup egresses
// through a provider, so the api reports the provider's address and never the
// operator's. That is enforced outside this process -- a restricted network
// under docker compose, systemd IPAddressDeny/IPAddressAllow otherwise -- and
// the mechanism differs per deployment.
//
// Rather than inspect a mechanism it cannot portably know, the prober tests the
// property: it attempts a direct connection and refuses to run if one succeeds.
// Operator configuration therefore stops being an assumption and becomes a
// precondition.
//
// This is a precondition check, not the enforcement. The Go-level enforcement
// (every lookup is issued on an http.Client bound to a provider tunnel, and
// providertunnel refuses any host outside the pin allowlist) stays exactly as
// it was; this only refuses to start when the outer confinement that backs it
// is absent.
package confinement

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrNotConfined reports that a direct connection succeeded.
var ErrNotConfined = errors.New("confinement: a direct connection to a geolocation address succeeded; this process is not confined")

// ErrNoAddresses reports an empty address list, which would make the check
// vacuous.
var ErrNoAddresses = errors.New("confinement: at least one address is required")

// ErrNoHosts reports an empty host list passed to Addresses. Same defect as
// ErrNoAddresses, one step earlier.
var ErrNoHosts = errors.New("confinement: at least one host is required")

// ErrNoDialer reports a nil dial function.
var ErrNoDialer = errors.New("confinement: a dial function is required")

// ErrInvalidTimeout reports a non-positive per-address timeout. A zero or
// negative duration makes context.WithTimeout produce an already-expired
// context, so every dial fails instantly for a reason unrelated to
// confinement and the check passes vacuously.
var ErrInvalidTimeout = errors.New("confinement: timeout must be positive")

// DialFunc matches net.Dialer.DialContext.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// LookupFunc matches net.Resolver.LookupHost.
type LookupFunc func(ctx context.Context, host string) ([]string, error)

// Verify returns nil only when every address refuses a direct connection.
//
// A dial error is the expected, healthy outcome. A successful connection means
// the confinement is missing and returns ErrNotConfined. A timeout counts as
// refused: a dropped packet is what a deny rule looks like from inside.
//
// Every address is attempted even after one refuses, because partial
// confinement -- one allow rule too many, one endpoint added to geolocate
// after the firewall was written -- is the realistic failure, not a wholesale
// absence.
func Verify(ctx context.Context, dial DialFunc, addrs []string, timeout time.Duration) error {
	if dial == nil {
		return ErrNoDialer
	}
	if len(addrs) == 0 {
		return ErrNoAddresses
	}
	if timeout <= 0 {
		return fmt.Errorf("%w (got %s)", ErrInvalidTimeout, timeout)
	}
	for _, addr := range addrs {
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := dial(attemptCtx, "tcp", addr)
		cancel()
		if err == nil {
			if conn != nil {
				conn.Close()
			}
			return fmt.Errorf("%w: %s", ErrNotConfined, addr)
		}
	}
	return nil
}

// Addresses resolves hosts into the dialable "ip:port" addresses Verify should
// test, de-duplicated and in host order.
//
// A host that cannot be resolved is kept as a literal "host:port" rather than
// dropped. Under a real deny-all confinement, dns to a public resolver is
// itself blocked, so resolution of the geolocation hosts is expected to fail on
// a correctly configured deployment. Dropping those hosts would shrink the
// address list, and if every host failed it would empty it -- which Verify
// rejects, so the prober would refuse to start precisely when it is most
// correctly confined. Keeping the name preserves the check: dialing it still
// has to fail, whether at resolution or at connect.
func Addresses(ctx context.Context, lookup LookupFunc, hosts []string, port string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, ErrNoHosts
	}
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}

	seen := map[string]bool{}
	addrs := make([]string, 0, len(hosts))
	add := func(addr string) {
		if !seen[addr] {
			seen[addr] = true
			addrs = append(addrs, addr)
		}
	}

	for _, host := range hosts {
		ips, err := lookup(ctx, host)
		if err != nil || len(ips) == 0 {
			add(net.JoinHostPort(host, port))
			continue
		}
		for _, ip := range ips {
			add(net.JoinHostPort(ip, port))
		}
	}
	return addrs, nil
}
