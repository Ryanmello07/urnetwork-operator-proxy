// Package geolocate resolves a location by cross-checking several free
// geolocation APIs. All network access goes through an injected *http.Client;
// the package never constructs its own client, so in production every request
// egresses through whatever provider tunnel the caller supplies.
package geolocate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// MinSources is the number of sources that must both respond and agree on the
// country for a confident country verdict, and the quorum below which Locate
// returns ErrNoConsensus.
const MinSources = 2

// MaxResponseBytes caps a single source's response body.
const MaxResponseBytes = 64 * 1024

// PerSourceTimeout bounds each individual source request. It is a var so tests
// can lower it.
var PerSourceTimeout = 5 * time.Second

// ErrNoConsensus is returned by Locate when fewer than MinSources sources
// responded successfully.
var ErrNoConsensus = errors.New("geolocate: fewer than MinSources sources responded")

// ErrNilClient is returned by Locate when client is nil. Sources are fetched
// from spawned goroutines, and a panic there cannot be recovered by the
// caller, so this is checked explicitly up front instead of being left to
// panic inside client.Do.
var ErrNilClient = errors.New("geolocate: client must not be nil")

// SourceResult is one source's normalized observation. It doubles as the
// per-source record attached to ConsensusLocation.Sources for observability.
// On a failed fetch/parse, OK is false and Err is set.
type SourceResult struct {
	Name        string
	OK          bool
	Err         string
	CountryCode string // ISO-3166 alpha-2 as returned by the source (not normalized)
	Country     string // human-readable country name, when the source provides one
	City        string
	Region      string
	ASN         int
	Org         string
	Hosting     bool
	Proxy       bool
	Mobile      bool
}

// ConsensusLocation is the cross-checked result across sources.
type ConsensusLocation struct {
	CountryCode string // lowercased alpha-2; "" when the country is not confident
	Country     string
	// CountryConfident is true only when the country record is complete and
	// usable: >= MinSources agreed on the code, the code is alpha-2, and a
	// name was resolved for it (from a source, or from the ISO-3166-1 table).
	// An agreed-upon code that cannot be named (XK, A1, ...) or is not
	// alpha-2 degrades to false with CountryCode and Country left empty,
	// because the server rejects both shapes and the rejection is not cached.
	CountryConfident bool

	City          string // set only when >= 2 sources agree on the normalized city
	Region        string
	CityConfident bool

	ASN int
	Org string

	Hosting bool
	Proxy   bool
	Mobile  bool

	Sources  []SourceResult // every source's outcome (including failures)
	ProbedAt time.Time
}

// Locate queries the production sources through client and returns a
// cross-checked consensus. client, in production, egresses through a specific
// provider, so each source's no-IP endpoint returns that provider's egress
// location. Returns ErrNoConsensus if fewer than MinSources sources responded.
//
// A non-nil, non-error result is not automatically usable: ErrNoConsensus
// only covers the quorum failure (fewer than MinSources sources responded).
// If quorum is met but the responding sources disagree -- or they agree on a
// code that is not alpha-2 or cannot be named -- Locate returns (result, nil)
// with CountryConfident == false and an empty CountryCode.
// Callers MUST check CountryConfident before treating the returned location
// as authoritative; a nil error alone does not mean the location is trustworthy.
func Locate(ctx context.Context, client *http.Client) (*ConsensusLocation, error) {
	return locate(ctx, client, sources)
}

func locate(ctx context.Context, client *http.Client, srcs []source) (*ConsensusLocation, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	results := make([]SourceResult, len(srcs))
	var wg sync.WaitGroup
	for i := range srcs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = fetchSource(ctx, client, srcs[i])
		}(i)
	}
	wg.Wait()

	ok := make([]SourceResult, 0, len(results))
	for _, r := range results {
		if r.OK {
			ok = append(ok, r)
		}
	}
	if len(ok) < MinSources {
		return nil, ErrNoConsensus
	}
	loc := consensus(ok)
	loc.Sources = results
	loc.ProbedAt = time.Now()
	return &loc, nil
}

func fetchSource(ctx context.Context, client *http.Client, s source) SourceResult {
	r := SourceResult{Name: s.Name}
	ctx, cancel := context.WithTimeout(ctx, PerSourceTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	resp, err := client.Do(req)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.Err = fmt.Sprintf("status %d", resp.StatusCode)
		return r
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		r.Err = err.Error()
		return r
	}
	if len(body) > MaxResponseBytes {
		r.Err = "response too large"
		return r
	}
	parsed, err := s.Parse(body)
	if err != nil {
		r.Err = err.Error()
		return r
	}
	parsed.Name = s.Name
	parsed.OK = true
	return parsed
}
