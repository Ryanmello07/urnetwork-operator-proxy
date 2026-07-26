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
// The governing rule everywhere in this package is that inability to verify is
// not evidence of confinement. Every way the check could come out "passed"
// without having obtained real evidence -- no addresses, no resolvable host, a
// timeout too short for a connection to have completed, a hostname standing in
// for an address that could not be resolved -- is an error, not a pass. A check
// that cannot learn anything must refuse to run rather than report success.
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
	"strings"
	"time"
)

// MinTimeout is the smallest per-address timeout Verify accepts.
//
// The check reads a failed dial as "the packet did not get through", which is
// only sound if the budget was long enough that a connection could plausibly
// have completed within it. Below that, every dial fails because the clock ran
// out rather than because anything blocked it, and the check reports success
// having tested nothing -- the same vacuous pass as a zero timeout, reached by
// a smaller number. 500ms is comfortably above a loopback or same-region
// handshake and still short enough that three hosts cost under two seconds at
// startup.
const MinTimeout = 500 * time.Millisecond

// ErrNotConfined reports that a direct connection succeeded.
var ErrNotConfined = errors.New("confinement: a direct connection to a geolocation address succeeded; this process is not confined")

// ErrNoAddresses reports an empty address list, which would make the check
// vacuous.
var ErrNoAddresses = errors.New("confinement: at least one address is required")

// ErrNoEvidence reports that hosts were offered but not one of them resolved,
// so no direct connection could be attempted and the check learned nothing.
//
// This is distinct from ErrNotConfined: it does not say the process is
// unconfined, it says the check cannot tell. Both refuse to start, because a
// check that obtained no evidence must not be reported as a pass.
var ErrNoEvidence = errors.New("confinement: not one geolocation host could be resolved, so no direct connection was attempted and the check has no evidence this process is confined; allow dns resolution for this process, or supply the addresses to dial explicitly")

// ErrNoHosts reports an empty host list passed to Addresses. Same defect as
// ErrNoAddresses, one step earlier.
var ErrNoHosts = errors.New("confinement: at least one host is required")

// ErrNoDialer reports a nil dial function.
var ErrNoDialer = errors.New("confinement: a dial function is required")

// ErrNoLookup reports a nil lookup function. Addresses does not quietly
// substitute the real resolver: this package's whole job is refusing to
// proceed on an assumption, and resolving through a resolver the caller never
// passed is exactly that. Verify rejects a nil dialer for the same reason.
var ErrNoLookup = errors.New("confinement: a lookup function is required")

// ErrInvalidTimeout reports a per-address timeout below MinTimeout. A budget
// that expires before a connection could have completed makes every dial fail
// for a reason unrelated to confinement, and the check passes vacuously. A
// zero or negative duration is the extreme case: context.WithTimeout produces
// an already-expired context.
var ErrInvalidTimeout = errors.New("confinement: the per-address timeout is too short to be evidence of confinement")

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
// unresolved carries the hosts Addresses could not resolve. They are not
// dialed -- a bare hostname handed to the production dialer resolves through
// the same resolver that just failed, so it is a guaranteed failure carrying no
// signal -- but they are not ignored either: when they are the ONLY thing the
// caller had, addrs is empty and Verify returns ErrNoEvidence rather than nil.
// That is the deny-all deployment where dns is blocked too, in which the old
// hostname fallback made the check verify nothing and always pass.
//
// Every address is attempted even after one refuses, because partial
// confinement -- one allow rule too many, one endpoint added to geolocate
// after the firewall was written -- is the realistic failure, not a wholesale
// absence.
func Verify(ctx context.Context, dial DialFunc, addrs []string, unresolved []string, timeout time.Duration) error {
	if dial == nil {
		return ErrNoDialer
	}
	if timeout < MinTimeout {
		return fmt.Errorf("%w (got %s, minimum %s): every dial would expire before a connection could complete, so each address would look blocked whether or not it is", ErrInvalidTimeout, timeout, MinTimeout)
	}
	if len(addrs) == 0 {
		if len(unresolved) > 0 {
			return fmt.Errorf("%w (unresolved: %s)", ErrNoEvidence, strings.Join(unresolved, " "))
		}
		return ErrNoAddresses
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
// test, de-duplicated and in host order, and separately reports the hosts that
// could not be resolved.
//
// Only genuine ip literals are returned. A host that will not resolve is NEVER
// emitted as a bare "host:port": handing that to the production dialer just
// resolves it through the resolver that already failed, so the dial fails at
// resolution and proves nothing about whether the address behind the name is
// reachable. Under a deny-all confinement, where dns is blocked too, every host
// takes that path -- so the old fallback turned the check into a guaranteed
// pass that tested nothing, in precisely the deployment it was written for.
//
// Unresolved hosts are returned to the caller instead, which must treat them as
// a gap in coverage: a warning when some hosts did resolve, and a refusal to
// start when none did (Verify returns ErrNoEvidence). The remedy for a jail
// that legitimately cannot resolve is to supply the addresses explicitly and
// skip resolution altogether.
func Addresses(ctx context.Context, lookup LookupFunc, hosts []string, port string) (addrs []string, unresolved []string, err error) {
	if len(hosts) == 0 {
		return nil, nil, ErrNoHosts
	}
	if lookup == nil {
		return nil, nil, ErrNoLookup
	}

	seen := map[string]bool{}
	addrs = make([]string, 0, len(hosts))
	add := func(addr string) {
		if !seen[addr] {
			seen[addr] = true
			addrs = append(addrs, addr)
		}
	}

	for _, host := range hosts {
		ips, err := lookup(ctx, host)
		resolved := false
		if err == nil {
			for _, ip := range ips {
				// A record that is not an ip literal cannot serve as evidence:
				// it would just be re-resolved at dial time.
				if net.ParseIP(ip) == nil {
					continue
				}
				add(net.JoinHostPort(ip, port))
				resolved = true
			}
		}
		if !resolved {
			unresolved = append(unresolved, host)
		}
	}
	return addrs, unresolved, nil
}
