// Package prober probes one provider's egress location: open a tunnel pinned to
// that provider, run the geolocation consensus through it, submit the result.
package prober

import (
	"context"
	"fmt"
	"net/http"

	"github.com/urnetwork/urnetwork-operator-proxy/geolocate"
)

// Locator runs the geolocation consensus over a client. In production this is
// geolocate.Locate.
type Locator func(ctx context.Context, client *http.Client) (*geolocate.ConsensusLocation, error)

// TunnelOpener opens a tunnel to one provider and returns an http.Client that
// egresses through it, plus a close function.
type TunnelOpener func(ctx context.Context, providerClientId string) (*http.Client, func() error, error)

// Submitter records a probed location.
type Submitter interface {
	Submit(ctx context.Context, providerClientId string, loc *geolocate.ConsensusLocation) error
}

// Prober wires a tunnel opener, a locator, and a submitter. Each dependency is
// injected so the flow is testable without a live provider or server.
type Prober struct {
	Open   TunnelOpener
	Locate Locator
	Submit Submitter
}

// ProbeOne probes a single provider. The tunnel is always closed, and nothing
// is submitted unless the geolocation reached consensus.
func (p *Prober) ProbeOne(ctx context.Context, providerClientId string) error {
	client, closeTunnel, err := p.Open(ctx, providerClientId)
	if err != nil {
		return fmt.Errorf("open tunnel to %s: %w", providerClientId, err)
	}
	defer func() {
		if closeTunnel != nil {
			_ = closeTunnel()
		}
	}()

	loc, err := p.Locate(ctx, client)
	if err != nil {
		return err
	}

	return p.Submit.Submit(ctx, providerClientId, loc)
}
