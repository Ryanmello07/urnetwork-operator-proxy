// Package controlplane builds the direct clients used to reach the operator's
// API and Connect services. Probe destinations use a separate, tunnel-only
// client and must never use anything from this package.
package controlplane

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/urnetwork/connect"
)

// DialContext is the part of net.Dialer used by the deterministic tests and
// by the HTTP transport below.
type DialContext func(context.Context, string, string) (net.Conn, error)

// ipv4DialContext maps an unspecified TCP dial to tcp4 and rejects an explicit
// tcp6 request. Control-plane calls must follow the same IPv4-only policy as
// the hosted proxy; silently accepting tcp6 here would make the two paths
// disagree again.
func ipv4DialContext(dialContext DialContext) DialContext {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4":
			return dialContext(ctx, "tcp4", address)
		case "tcp6":
			return nil, fmt.Errorf("controlplane: ipv6 dial refused for %s", address)
		default:
			return nil, fmt.Errorf("controlplane: unsupported network %q for %s", network, address)
		}
	}
}

// NewHTTPClient returns an IPv4-only client for direct API calls. The default
// transport is cloned so proxy, TLS, pooling, and HTTP/2 behavior stay aligned
// with net/http while its dial boundary is made explicit.
func NewHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	netDialer := &net.Dialer{}
	transport.DialContext = ipv4DialContext(netDialer.DialContext)
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// clientStrategySettings returns the normal Connect strategy with IPv6
// disabled. This covers both API requests and the Connect websocket used to
// build a provider tunnel; the data-plane TUN remains dual-stack and separate.
func clientStrategySettings() *connect.ClientStrategySettings {
	settings := connect.DefaultClientStrategySettings()
	settings.ConnectSettings.DisableIpv6 = true
	return settings
}

// NewClientStrategy returns the IPv4-only strategy used by provider tunnels.
func NewClientStrategy(ctx context.Context) *connect.ClientStrategy {
	return connect.NewClientStrategy(ctx, clientStrategySettings())
}
