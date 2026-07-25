// Package providertunnel builds an http.Client whose every request egresses
// through one specific urnetwork provider, so a geolocation lookup made with it
// reports that provider's egress location.
package providertunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
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

// Tunnel is a live data path pinned to exactly one provider. Every connection
// dialed through it egresses from that provider.
type Tunnel struct {
	cancel context.CancelFunc
	tun    *connect.Tun
	mc     *connect.RemoteUserNatMultiClient
	pins   map[string][]string
}

// Open builds a tunnel that routes exclusively through providerClientId.
// It mirrors the proven construction in urnetwork/proxy socks/main.go: an api
// multiclient generator pinned to one ProviderSpec, a gvisor tun, and a packet
// pump in both directions.
func Open(ctx context.Context, cfg Config, providerClientId connect.Id) (*Tunnel, error) {
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

// Close tears the tunnel down.
func (t *Tunnel) Close() error {
	t.cancel()
	return t.tun.Close()
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
	tr := &http.Transport{
		DialContext:         dial,
		TLSHandshakeTimeout: timeout,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   true,
	}
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		raw, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		cfg := PinnedTLSConfigForHost(pins, host)
		tlsConn := tls.Client(raw, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}
