package geolocate

import "testing"

func TestConsensusCountryMajorityCityDisagree(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", Country: "United States", City: "Fairfax", ASN: 401486},
		{Name: "b", OK: true, CountryCode: "US", Country: "United States", City: "Denver", Region: "Colorado", ASN: 401486},
		{Name: "c", OK: true, CountryCode: "US", City: "Atlanta", Region: "Georgia", ASN: 401486},
	}
	loc := consensus(ok)
	if !loc.CountryConfident {
		t.Fatal("expected CountryConfident with 3 agreeing sources")
	}
	if loc.CountryCode != "us" {
		t.Fatalf("CountryCode = %q, want \"us\"", loc.CountryCode)
	}
	if loc.Country != "United States" {
		t.Fatalf("Country = %q, want \"United States\"", loc.Country)
	}
	if loc.CityConfident {
		t.Fatal("cities disagree (Fairfax/Denver/Atlanta); CityConfident must be false")
	}
	if loc.City != "" {
		t.Fatalf("City = %q, want empty on disagreement", loc.City)
	}
	if loc.ASN != 401486 {
		t.Fatalf("ASN = %d, want 401486", loc.ASN)
	}
}

func TestConsensusCityAgreementNormalized(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", City: "Denver", Region: "Colorado"},
		{Name: "b", OK: true, CountryCode: "US", City: "denver ", Region: "CO"},
		{Name: "c", OK: true, CountryCode: "US", City: "Atlanta"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("two sources agree on Denver (normalized); CityConfident must be true")
	}
	if got := loc.City; got != "Denver" && got != "denver" {
		t.Fatalf("City = %q, want a Denver display value", got)
	}
	if loc.Region == "" {
		t.Fatal("Region should be carried from an agreeing source")
	}
}

func TestConsensusCountryDisagreementNotConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US"},
		{Name: "b", OK: true, CountryCode: "CA"},
	}
	loc := consensus(ok)
	if loc.CountryConfident {
		t.Fatal("split country (US vs CA) must not be confident")
	}
	if loc.CountryCode != "" {
		t.Fatalf("CountryCode = %q, want empty on split", loc.CountryCode)
	}
}

// TestConsensusCountryTieBrokenBySourcePriority exercises a genuine 2-vs-2
// tie (both sides clear MinSources) where the lexicographically larger code
// ("us") comes from the higher-priority sources (ip.pn, ipinfo) and the
// lexicographically smaller code ("ca") comes from a lower-priority source
// (freeipapi) plus a repeated ipinfo vote. Under the old buggy tie-break
// (n == bestN && c < best), "ca" would win purely because it sorts before
// "us". The fix requires the higher-priority source's answer to win instead.
func TestConsensusCountryTieBrokenBySourcePriority(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", Country: "United States"},
		{Name: "ipinfo", OK: true, CountryCode: "US", Country: "United States"},
		{Name: "freeipapi", OK: true, CountryCode: "CA", Country: "Canada"},
		{Name: "ipinfo", OK: true, CountryCode: "CA", Country: "Canada"},
	}
	loc := consensus(ok)
	if !loc.CountryConfident {
		t.Fatal("2-vs-2 tie with both sides >= MinSources must still be confident")
	}
	if loc.CountryCode != "us" {
		t.Fatalf("CountryCode = %q, want \"us\" (ip.pn is highest-priority source and voted US)", loc.CountryCode)
	}
	if loc.Country != "United States" {
		t.Fatalf("Country = %q, want \"United States\"", loc.Country)
	}
}

// TestConsensusCityTieBrokenBySourcePriority is the city analogue of
// TestConsensusCountryTieBrokenBySourcePriority: a 2-vs-2 tie where the
// lexicographically larger city ("denver") is backed by the highest-priority
// source (ip.pn) while the lexicographically smaller city ("chicago") is
// backed only by lower-priority sources. The old lexicographic tie-break
// would pick "chicago"; the fix must pick "denver".
func TestConsensusCityTieBrokenBySourcePriority(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", City: "Denver", Region: "Colorado"},
		{Name: "ipinfo", OK: true, CountryCode: "US", City: "Denver", Region: "Colorado"},
		{Name: "freeipapi", OK: true, CountryCode: "US", City: "Chicago", Region: "Illinois"},
		{Name: "ipinfo", OK: true, CountryCode: "US", City: "Chicago", Region: "Illinois"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("2-vs-2 city tie with both sides >= 2 must still be confident")
	}
	if loc.City != "Denver" {
		t.Fatalf("City = %q, want \"Denver\" (ip.pn is highest-priority source and voted Denver)", loc.City)
	}
}

func TestConsensusFlagsOr(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", Hosting: false, Proxy: false, Mobile: false},
		{Name: "b", OK: true, CountryCode: "US", Hosting: true, Proxy: true, Mobile: false},
	}
	loc := consensus(ok)
	if !loc.Hosting {
		t.Fatal("Hosting must be OR-ed true")
	}
	if !loc.Proxy {
		t.Fatal("Proxy must be OR-ed true")
	}
	if loc.Mobile {
		t.Fatal("Mobile must remain false")
	}
}
