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

// TestConsensusCountryNameFallbackFromTable is the teeth-check for the
// ipinfo-name gap: ipinfo returns a country code but never a name (see
// parseIpInfo in sources.go). A quorum consisting only of sources that
// likewise contributed no name (simulated here as "ipinfo" plus another
// nameless source) must not surface CountryConfident==true with an empty
// Country -- the server rejects that with "Missing country." Country must
// be backfilled from the ISO-3166-1 table.
func TestConsensusCountryNameFallbackFromTable(t *testing.T) {
	ok := []SourceResult{
		{Name: "ipinfo", OK: true, CountryCode: "DE"},
		{Name: "freeipapi", OK: true, CountryCode: "DE"}, // no Country set, simulating a nameless response
	}
	loc := consensus(ok)
	if !loc.CountryConfident {
		t.Fatal("expected CountryConfident with 2 agreeing sources")
	}
	if loc.CountryCode != "de" {
		t.Fatalf("CountryCode = %q, want \"de\"", loc.CountryCode)
	}
	if loc.Country != "Germany" {
		t.Fatalf("Country = %q, want \"Germany\" (backfilled from the ISO table)", loc.Country)
	}
}

// TestConsensusCountryNameSourceWinsOverTable verifies the table is only a
// fallback: when a source does supply a name, that name wins even if it
// differs from the table's value (e.g. a source using the official long
// form where the table uses the common short form).
func TestConsensusCountryNameSourceWinsOverTable(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", Country: "United States of America"},
		{Name: "freeipapi", OK: true, CountryCode: "US", Country: "United States of America"},
	}
	loc := consensus(ok)
	if !loc.CountryConfident {
		t.Fatal("expected CountryConfident with 2 agreeing sources")
	}
	if loc.Country != "United States of America" {
		t.Fatalf("Country = %q, want the source-supplied name to win over the table's \"United States\"", loc.Country)
	}
}

// TestConsensusUnknownCountryCodeDegradesToNotConfident is the country
// analogue of TestConsensusCityAgreementNoRegionNotConfident, and replaces an
// earlier test that asserted the broken behavior (CountryConfident==true with
// an empty Country).
//
// A code outside the ISO-3166-1 table -- XK (Kosovo, user-assigned) and the
// MaxMind-lineage A1/A2/AP are all real codes free geolocation APIs emit --
// resolves to no name, and no name may be fabricated from the code. But
// "confident" must then mean confident about a record the server will accept:
// the server rejects an empty country with "Missing country.", the rejection
// is not cached by the scheduler, and the provider is therefore re-probed and
// re-rejected on every pass forever. CountryConfident must mean "I have a
// complete, usable country record", so an unnameable code degrades to
// not-confident instead of producing a doomed submission.
func TestConsensusUnknownCountryCodeDegradesToNotConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "ipinfo", OK: true, CountryCode: "XK"},
		{Name: "freeipapi", OK: true, CountryCode: "XK"},
	}
	loc := consensus(ok)
	if loc.CountryConfident {
		t.Fatal("a country code with no resolvable name must not be country-confident: the server rejects it with \"Missing country.\" and the failure is never cached, so the provider retries forever")
	}
	if loc.Country != "" {
		t.Fatalf("Country = %q, want empty: a name must never be fabricated from the code", loc.Country)
	}
	if loc.CountryCode != "" {
		t.Fatalf("CountryCode = %q, want empty when the result is not country-confident", loc.CountryCode)
	}
}

// TestConsensusNonAlpha2CountryCodeDegradesToNotConfident covers the second
// server rejection reachable from consensus: normalizeCountry lowercases and
// trims but never validates length, so two sources reporting "USA" used to
// yield CountryCode "usa" with CountryConfident true -- a guaranteed 400
// ("Country code must be alpha-2."), on every pass, forever.
func TestConsensusNonAlpha2CountryCodeDegradesToNotConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "ipinfo", OK: true, CountryCode: "USA", Country: "United States"},
		{Name: "freeipapi", OK: true, CountryCode: "USA", Country: "United States"},
	}
	loc := consensus(ok)
	if loc.CountryConfident {
		t.Fatal("a non-alpha-2 country code must not be country-confident: the server rejects it with \"Country code must be alpha-2.\"")
	}
	if loc.CountryCode != "" {
		t.Fatalf("CountryCode = %q, want empty when the result is not country-confident", loc.CountryCode)
	}
}

// TestConsensusCityAgreementNoRegionNotConfident is the regression test for
// the availability bug: two sources agree on a city but neither supplied a
// Region. The server rejects any submission with CityConfident==true and an
// empty region, which previously threw away a perfectly good country result
// too (the whole submission is one POST). CityConfident must therefore
// require a non-empty Region, not just city agreement; when the region is
// missing, City/Region must stay empty and CityConfident false so the result
// degrades cleanly to country granularity instead of being rejected outright.
func TestConsensusCityAgreementNoRegionNotConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", Country: "United States", City: "Denver"},
		{Name: "b", OK: true, CountryCode: "US", Country: "United States", City: "denver "},
	}
	loc := consensus(ok)
	if loc.CityConfident {
		t.Fatal("two sources agree on Denver but neither supplied a Region; CityConfident must be false")
	}
	if loc.City != "" {
		t.Fatalf("City = %q, want empty when no source supplied a Region", loc.City)
	}
	if loc.Region != "" {
		t.Fatalf("Region = %q, want empty when no source supplied a Region", loc.Region)
	}
	// The country result must be unaffected by the incomplete city data.
	if !loc.CountryConfident {
		t.Fatal("country agreement is independent of city completeness; CountryConfident must still be true")
	}
	if loc.CountryCode != "us" {
		t.Fatalf("CountryCode = %q, want \"us\"", loc.CountryCode)
	}
	if loc.Country != "United States" {
		t.Fatalf("Country = %q, want \"United States\"", loc.Country)
	}
}

// TestConsensusCityAgreementWithRegionConfident is the happy-path complement
// to TestConsensusCityAgreementNoRegionNotConfident: two sources agree on a
// city and at least one of them supplied a Region, so CityConfident must
// still be true and both City and Region populated.
func TestConsensusCityAgreementWithRegionConfident(t *testing.T) {
	ok := []SourceResult{
		{Name: "a", OK: true, CountryCode: "US", City: "Denver"},
		{Name: "b", OK: true, CountryCode: "US", City: "denver ", Region: "Colorado"},
	}
	loc := consensus(ok)
	if !loc.CityConfident {
		t.Fatal("two sources agree on Denver and one supplied a Region; CityConfident must be true")
	}
	if got := loc.City; got != "Denver" && got != "denver" {
		t.Fatalf("City = %q, want a Denver display value", got)
	}
	if loc.Region != "Colorado" {
		t.Fatalf("Region = %q, want \"Colorado\"", loc.Region)
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

// TestConsensusDisplayFieldsPreferHigherPrioritySource is the regression test
// for the inconsistent display-field rules: country name and region were
// last-writer-wins while the city's display casing was first-writer-wins, so
// which rendering survived depended only on a source's index in the results
// slice. Here every lower-priority source is deliberately placed FIRST and
// offers a worse rendering of the same agreed value: the abbreviation "CO"
// for the region, a shouted city name, and a long-form country name. Under
// either of the old rules at least one of the three assertions below fails.
//
// It matters beyond cosmetics because the server canonicalizes location_name
// permanently, so "CO" would be stored durably in place of "Colorado".
func TestConsensusDisplayFieldsPreferHigherPrioritySource(t *testing.T) {
	// ip.pn (rank 0) is bracketed by lower-priority sources so that BOTH old
	// rules pick wrong: ipinfo is first (beating first-writer-wins on the
	// city display) and freeipapi is last (beating last-writer-wins on the
	// country name and the region).
	ok := []SourceResult{
		{Name: "ipinfo", OK: true, CountryCode: "US", City: "DENVER", Region: "CO"},
		{Name: "ip.pn", OK: true, CountryCode: "US", Country: "United States", City: "Denver", Region: "Colorado"},
		{Name: "freeipapi", OK: true, CountryCode: "US", Country: "United States of America", City: "denver", Region: "Colo."},
	}
	loc := consensus(ok)

	if !loc.CountryConfident {
		t.Fatal("three sources agree on US; CountryConfident must be true")
	}
	if loc.Country != "United States" {
		t.Errorf("Country = %q, want \"United States\" from ip.pn (rank 0), not a later, less-trusted source's rendering", loc.Country)
	}
	if !loc.CityConfident {
		t.Fatal("three sources agree on Denver; CityConfident must be true")
	}
	if loc.City != "Denver" {
		t.Errorf("City = %q, want \"Denver\" from ip.pn (rank 0), not a lower-priority source's casing", loc.City)
	}
	if loc.Region != "Colorado" {
		t.Errorf("Region = %q, want \"Colorado\" from ip.pn (rank 0); the server canonicalizes this name permanently, so an abbreviation from a less-trusted source must not win on slice order", loc.Region)
	}
}

// TestConsensusDisplayFieldsIgnoreEmptyFromTrustedSource is the complement:
// priority decides between renderings that exist, but a more-trusted source
// that omitted the field entirely must not blank out a rendering a
// less-trusted source did supply. ip.pn (rank 0) here names neither the
// country nor the region.
func TestConsensusDisplayFieldsIgnoreEmptyFromTrustedSource(t *testing.T) {
	ok := []SourceResult{
		{Name: "ip.pn", OK: true, CountryCode: "US", City: "Denver"},
		{Name: "freeipapi", OK: true, CountryCode: "US", Country: "United States of America", City: "Denver", Region: "Colorado"},
	}
	loc := consensus(ok)

	if loc.Country != "United States of America" {
		t.Errorf("Country = %q, want freeipapi's name: the higher-priority source supplied none", loc.Country)
	}
	if !loc.CityConfident {
		t.Fatal("two sources agree on Denver and one supplied a Region; CityConfident must be true")
	}
	if loc.Region != "Colorado" {
		t.Errorf("Region = %q, want \"Colorado\": the higher-priority source supplied no region", loc.Region)
	}
}
