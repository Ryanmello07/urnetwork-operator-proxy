package confinement

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// dialRefused is the healthy production dialer from inside a confined
// process: the packet is dropped or rejected, so the dial errors.
func dialRefused(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errors.New("connect: network is unreachable")
}

func TestVerifyFailsWhenDirectConnectionSucceeds(t *testing.T) {
	// a dialer that connects means nothing is stopping the prober reaching a
	// geolocation api directly -- the confinement is absent and the whole
	// guarantee is void, so Verify must refuse
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c1, _ := net.Pipe()
		return c1, nil
	}
	err := Verify(context.Background(), dial, []string{"34.117.59.81:443"}, time.Second)
	if err == nil {
		t.Fatal("Verify returned nil when a direct connection succeeded; it must refuse to run")
	}
	if !errors.Is(err, ErrNotConfined) {
		t.Fatalf("Verify error = %v, want it to wrap ErrNotConfined so callers can tell this apart from a plumbing failure", err)
	}
}

func TestVerifyPassesWhenDirectConnectionRefused(t *testing.T) {
	if err := Verify(context.Background(), dialRefused, []string{"34.117.59.81:443"}, time.Second); err != nil {
		t.Fatalf("Verify errored when the connection was refused: %s", err)
	}
}

func TestVerifyRequiresAtLeastOneAddress(t *testing.T) {
	// an empty address list would vacuously "pass" and silently disable the
	// entire check
	if err := Verify(context.Background(), dialRefused, nil, time.Second); err == nil {
		t.Fatal("Verify accepted an empty address list; that would disable the check")
	}
}

// TestVerifyChecksEveryAddress guards the loop itself: a Verify that returned
// after the first refused address would pass a host that is reachable while a
// sibling host is not -- which is exactly the partial-confinement case (one
// allow rule too many) the check exists to catch.
func TestVerifyChecksEveryAddress(t *testing.T) {
	var dialed []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if addr == "2.2.2.2:443" {
			c1, _ := net.Pipe()
			return c1, nil
		}
		return nil, errors.New("connect: network is unreachable")
	}
	err := Verify(context.Background(), dial, []string{"1.1.1.1:443", "2.2.2.2:443"}, time.Second)
	if !errors.Is(err, ErrNotConfined) {
		t.Fatalf("Verify error = %v, want ErrNotConfined; the second address accepted a direct connection", err)
	}
	if len(dialed) != 2 {
		t.Fatalf("dialed %v, want every address attempted", dialed)
	}
}

// TestVerifyClosesTheConnectionItOpened: the failing path still opened a real
// socket to a third party. It must not be leaked -- this process is about to
// exit, but Verify is also callable from a test or a long-running caller.
func TestVerifyClosesTheConnectionItOpened(t *testing.T) {
	c1, c2 := net.Pipe()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return c1, nil
	}
	if err := Verify(context.Background(), dial, []string{"1.1.1.1:443"}, time.Second); err == nil {
		t.Fatal("Verify must refuse when a direct connection succeeded")
	}
	// the peer end of a closed pipe reports io.ErrClosedPipe rather than blocking
	_ = c2.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection Verify opened is still readable; it was not closed")
	}
}

// TestVerifyRejectsNonPositiveTimeout: context.WithTimeout with a zero or
// negative duration produces an already-expired context, so every dial would
// fail instantly for a reason that has nothing to do with confinement and the
// check would pass vacuously. That is the same defect as an empty address
// list, reached by a different route.
func TestVerifyRejectsNonPositiveTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		if err := Verify(context.Background(), dialRefused, []string{"1.1.1.1:443"}, timeout); err == nil {
			t.Fatalf("Verify accepted timeout=%s; an expired context makes every dial fail and the check vacuous", timeout)
		}
	}
}

func TestVerifyRequiresADialer(t *testing.T) {
	if err := Verify(context.Background(), nil, []string{"1.1.1.1:443"}, time.Second); err == nil {
		t.Fatal("Verify accepted a nil dialer")
	}
}

func TestAddressesResolvesEveryHost(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		switch host {
		case "a.example":
			return []string{"1.1.1.1", "2606:4700::1111"}, nil
		case "b.example":
			return []string{"2.2.2.2"}, nil
		}
		return nil, errors.New("no such host")
	}
	got, err := Addresses(context.Background(), lookup, []string{"a.example", "b.example"}, "443")
	if err != nil {
		t.Fatalf("Addresses: %s", err)
	}
	want := []string{"1.1.1.1:443", "[2606:4700::1111]:443", "2.2.2.2:443"}
	if len(got) != len(want) {
		t.Fatalf("Addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Addresses = %v, want %v", got, want)
		}
	}
}

// TestAddressesDeduplicates: two hosts behind the same anycast address must not
// be dialed twice, and a duplicate must not inflate an operator's sense of how
// much the check covers.
func TestAddressesDeduplicates(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		return []string{"1.1.1.1"}, nil
	}
	got, err := Addresses(context.Background(), lookup, []string{"a.example", "b.example"}, "443")
	if err != nil {
		t.Fatalf("Addresses: %s", err)
	}
	if len(got) != 1 || got[0] != "1.1.1.1:443" {
		t.Fatalf("Addresses = %v, want exactly [1.1.1.1:443]", got)
	}
}

// TestAddressesFallsBackToTheHostnameWhenLookupFails is the bootstrap case, and
// the reason resolution failure must not be fatal: under a real deny-all
// confinement, dns to a public resolver is itself blocked, so resolving the
// geolocation hosts fails. Dropping the host would shrink the address list --
// and if every host failed, empty it, which Verify rejects, so the prober
// would refuse to start precisely when it is correctly confined. Keeping the
// hostname preserves the check: dialing it still has to fail, whether at
// resolution or at connect.
func TestAddressesFallsBackToTheHostnameWhenLookupFails(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		if host == "a.example" {
			return []string{"1.1.1.1"}, nil
		}
		return nil, errors.New("lookup b.example: server misbehaving")
	}
	got, err := Addresses(context.Background(), lookup, []string{"a.example", "b.example"}, "443")
	if err != nil {
		t.Fatalf("Addresses: %s", err)
	}
	want := map[string]bool{"1.1.1.1:443": true, "b.example:443": true}
	if len(got) != 2 {
		t.Fatalf("Addresses = %v, want one entry per host (%v)", got, want)
	}
	for _, addr := range got {
		if !want[addr] {
			t.Fatalf("Addresses = %v, want %v", got, want)
		}
	}
}

// TestAddressesFallsBackWhenLookupReturnsNothing: a resolver that answers with
// an empty record set is the same situation as one that errors.
func TestAddressesFallsBackWhenLookupReturnsNothing(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		return nil, nil
	}
	got, err := Addresses(context.Background(), lookup, []string{"a.example"}, "443")
	if err != nil {
		t.Fatalf("Addresses: %s", err)
	}
	if len(got) != 1 || got[0] != "a.example:443" {
		t.Fatalf("Addresses = %v, want exactly [a.example:443]", got)
	}
}

func TestAddressesRequiresAtLeastOneHost(t *testing.T) {
	lookup := func(ctx context.Context, host string) ([]string, error) {
		return []string{"1.1.1.1"}, nil
	}
	if _, err := Addresses(context.Background(), lookup, nil, "443"); err == nil {
		t.Fatal("Addresses accepted an empty host list; the check must not be reducible to nothing")
	}
}
