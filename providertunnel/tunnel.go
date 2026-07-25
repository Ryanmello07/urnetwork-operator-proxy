// Package providertunnel builds an http.Client whose every request egresses
// through one specific urnetwork provider, so a geolocation lookup made with it
// reports that provider's egress location.
package providertunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// Config is the operator-provided identity and endpoints the prober uses to
// build tunnels. ClientId is the prober's own client id (so it can exclude
// itself when selecting providers); ByJwt is its network client jwt.
type Config struct {
	ApiURL            string
	PlatformURL       string
	ByJwt             string
	ClientId          connect.Id
	Pins              map[string][]string
	DeviceDescription string
	DeviceSpec        string
	Version           string
}

// ErrPinsRequired is returned by Open when Config.Pins is nil or empty. The
// geolocation endpoint set this tunnel exists to probe is closed and known
// (see geolocate/sources.go), so a tunnel opened with no pins at all could
// never pin any of them -- it would carry a probe with pinning silently
// disabled for every request. Refusing to open is cheaper than discovering
// that later from a skewed geolocation result.
var ErrPinsRequired = errors.New("providertunnel: Config.Pins must not be empty; a tunnel with no pins cannot safely carry a geolocation probe")

// Tunnel is a live data path pinned to exactly one provider. Every connection
// dialed through it egresses from that provider.
type Tunnel struct {
	cancel    context.CancelFunc
	tun       *connect.Tun
	mc        *connect.RemoteUserNatMultiClient
	pins      map[string][]string
	closeOnce sync.Once
	closeErr  error
}

// Open builds a tunnel that routes exclusively through providerClientId.
// It mirrors the proven construction in urnetwork/proxy socks/main.go: an api
// multiclient generator pinned to one ProviderSpec, a gvisor tun, and a packet
// pump in both directions.
func Open(ctx context.Context, cfg Config, providerClientId connect.Id) (*Tunnel, error) {
	if len(cfg.Pins) == 0 {
		return nil, ErrPinsRequired
	}

	ctx, cancel := context.WithCancel(ctx)

	generator := connect.NewApiMultiClientGenerator(
		ctx,
		[]*connect.ProviderSpec{
			{ClientId: &providerClientId},
		},
		connect.NewClientStrategyWithDefaults(ctx),
		// exclude self
		[]connect.Id{cfg.ClientId},
		cfg.ApiURL,
		cfg.ByJwt,
		cfg.PlatformURL,
		cfg.DeviceDescription,
		cfg.DeviceSpec,
		cfg.Version,
		&cfg.ClientId,
		connect.DefaultClientSettings,
		connect.DefaultApiMultiClientGeneratorSettings(),
	)

	tun, err := connect.CreateTunWithDefaults(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create tun: %w", err)
	}

	mc := connect.NewRemoteUserNatMultiClientWithDefaults(
		ctx,
		generator,
		func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
			_, _ = tun.Write(packet)
		},
		protocol.ProvideMode_Network,
	)

	// pump tun -> provider
	source := connect.SourceId(cfg.ClientId)
	go func() {
		for {
			packet, err := tun.Read()
			if err != nil {
				// Without this log, the tunnel looks alive (Close() has not
				// been called, no error is returned anywhere) while this
				// pump goroutine has silently exited and every subsequent
				// request blackholes. Matches the read-error handling in
				// urnetwork/proxy/socks/main.go.
				log.Println("providertunnel: tun read error:", err)
				return
			}
			mc.SendPacket(source, protocol.ProvideMode_Network, packet, 15*time.Second)
		}
	}()

	return &Tunnel{
		cancel: cancel,
		tun:    tun,
		mc:     mc,
		pins:   cfg.Pins,
	}, nil
}

// HTTPClient returns a client whose every connection is dialed through the
// tunnel, with the configured certificate pins applied.
func (t *Tunnel) HTTPClient(timeout time.Duration) *http.Client {
	return httpClientOverDialer(t.tun.DialContext, t.pins, timeout)
}

// Close tears the tunnel down. It is safe to call more than once; only the
// first call has effect and its result is what every call returns.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		// Close the multiclient explicitly rather than relying on it merely
		// observing ctx cancellation: t.cancel() below cancels the context
		// mc was built with, which does tear mc down eventually, but only
		// asynchronously via whatever goroutines happen to notice. Calling
		// mc.Close() directly makes teardown synchronous and immediate,
		// matching tun.Close() below. connect.RemoteUserNatMultiClient.Close
		// (ip_remote_multi_client.go) is non-blocking -- it cancels its own
		// context, clears in-memory maps, and closes windows/localUserNat,
		// none of which wait on a channel or another goroutine -- so this
		// cannot hang.
		t.mc.Close()
		t.cancel()
		t.closeErr = t.tun.Close()
	})
	return t.closeErr
}

type dialContextFunc func(ctx context.Context, network string, address string) (net.Conn, error)

// httpClientOverDialer builds an http.Client that dials exclusively through
// dial and applies certificate pinning per pins.
//
// pins is a map, not a prebuilt *tls.Config: Task 1's PinnedTLSConfig
// returns a TEMPLATE whose VerifyPeerCertificate closure reads the
// template's own ServerName field, not a clone's. Cloning it per host and
// mutating ServerName on the clone would copy the func value but leave it
// bound to the original (empty) ServerName -- the check would then find no
// pin entry and silently pass, defeating pinning entirely while ordinary CA
// validation kept working. Building a fresh config per host with
// PinnedTLSConfigForHost(pins, host) avoids that trap by construction: the
// verifier closes over host by value, not over any *tls.Config field.
func httpClientOverDialer(dial dialContextFunc, pins map[string][]string, timeout time.Duration) *http.Client {
	// Normalized once, up front: this is the allowlist of the closed set of
	// geolocation hosts this tunnel is permitted to speak TLS to (see
	// geolocate/sources.go). Any https host not in this set is refused
	// below, in DialTLSContext -- see the ErrPinHostUnknown check.
	allowed := normalizePins(pins)

	tr := &http.Transport{
		DialContext: dial,
		// TLSHandshakeTimeout is NOT set here: it only bounds the
		// transport's own internal TLS handshake, which never runs because
		// DialTLSContext (below) fully owns dialing and handshaking for
		// https requests. The timeout is instead applied explicitly to the
		// manual HandshakeContext call below, so the setting is real rather
		// than silently dead.
		//
		// IdleConnTimeout is NOT set here either: DisableKeepAlives is true,
		// so connections are never pooled or reused idle in the first
		// place -- there is nothing for an idle timeout to expire.
		DisableKeepAlives: true,
	}
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		// Allowlist-only: the geolocation endpoint set is closed and known,
		// so any host without a pin-map entry is refused outright rather
		// than allowed to connect unpinned. This is deliberately enforced
		// here, not in checkPin/PinnedTLSConfig (pinning.go), because
		// checkPin's "unpinned host passes" behavior is a documented,
		// tested contract other callers may rely on for a general-purpose
		// pinning verifier. This tunnel is the layer that actually knows
		// the endpoint set is closed, so it is where "unknown host" can
		// safely mean "reject" instead of "pass through".
		if _, pinned := allowed[normalizeHost(host)]; !pinned {
			return nil, fmt.Errorf("%w: %s", ErrPinHostUnknown, host)
		}

		raw, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		handshakeCtx := ctx
		if timeout > 0 {
			var cancel context.CancelFunc
			handshakeCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}

		cfg := PinnedTLSConfigForHost(pins, host)
		tlsConn := tls.Client(raw, cfg)
		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			raw.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// A geolocation probe has no legitimate reason to follow a
		// redirect: the three sources it talks to (geolocate/sources.go)
		// answer directly. Refusing redirects closes off a provider MITM
		// path where a pinned host's response 3xx's to a different host,
		// or downgrades to plain http://, either of which would be
		// followed outside of any pin check and could hand back a forged
		// location.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
