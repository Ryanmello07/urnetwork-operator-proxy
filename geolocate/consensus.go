package geolocate

import "strings"

func normalizeCountry(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

func normalizeCity(city string) string {
	return strings.ToLower(strings.TrimSpace(city))
}

// isAlpha2 reports whether code is exactly two ASCII letters, the shape the
// server requires of country_code. It is deliberately ASCII-only: ISO-3166-1
// alpha-2 codes are ASCII by definition, and a non-ASCII two-rune string is a
// source returning something that is not a country code at all.
func isAlpha2(code string) bool {
	if len(code) != 2 {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c < 'a' || 'z' < c {
			if c < 'A' || 'Z' < c {
				return false
			}
		}
	}
	return true
}

// SourcePriority ranks the free geolocation sources by trustworthiness, most
// trusted first. Lower value = more trusted. It is keyed by the exact
// SourceResult.Name values the sources in sources.go set.
//
// consensus uses this ordering to break exact vote-count ties: when two
// candidate answers (country codes or cities) receive the same number of
// votes, the answer contributed by the more trusted source wins, instead of
// an arbitrary lexicographically-smaller string winning by coincidence.
//
// With the current 3-source table, a qualifying tie is unreachable in
// production: breaking a tie AND clearing the confidence threshold
// (MinSources == 2) requires a 2-2 split, i.e. 4 votes, but only 3 sources
// run. (This is why the tie-break tests synthesize a 4-element slice with a
// duplicated source name — a shape locate() cannot actually produce today.)
// The comparator is kept correct and exercised anyway because it starts
// mattering the moment a 4th source is added.
var SourcePriority = map[string]int{
	"ip.pn":     0,
	"freeipapi": 1,
	"ipinfo":    2,
}

// unknownSourceRank is the rank assigned to a source name absent from
// SourcePriority. It is deliberately larger than any real entry so unknown
// sources always lose a tie-break against a known source.
const unknownSourceRank = 1 << 30

// sourceRank returns name's trust rank (lower = more trusted). Unknown or
// empty names get unknownSourceRank so they always lose ties.
func sourceRank(name string) int {
	if rank, ok := SourcePriority[name]; ok {
		return rank
	}
	return unknownSourceRank
}

// displayField picks the human-readable rendering of a winning candidate --
// the country name, the city's display casing, the region name -- from
// whichever contributing source is most trusted.
//
// It exists because these three fields used to resolve by three different and
// mutually inconsistent rules: country name and region were last-writer-wins
// while city display was first-writer-wins, so which rendering survived
// depended on nothing but a source's position in the results slice. With
// ip.pn reporting Region "Colorado" and ipinfo reporting "CO", ipinfo's "CO"
// won purely because it sorts later in `sources` -- the least-trusted source's
// rendering beating the most-trusted one's. That is not cosmetic: the server
// canonicalizes location_name permanently (model.CreateLocation dedupes and
// stores it), so a bad pick is durable.
//
// All three now use the same SourcePriority order that already decides the
// verdict, so the winning code/city and the words shown for it come from the
// same ranking. Ties keep the first offer, which makes the result independent
// of map iteration order.
type displayField struct {
	value map[string]string
	rank  map[string]int
}

func newDisplayField() displayField {
	return displayField{
		value: map[string]string{},
		rank:  map[string]int{},
	}
}

// offer records v as the rendering for candidate c if it is non-empty and
// comes from a strictly more trusted source than the rendering already held.
// Empty values are never recorded: a source that omitted the field cannot
// blank out one that supplied it, however trusted it is.
func (d displayField) offer(c string, v string, rank int) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if held, ok := d.rank[c]; ok && rank >= held {
		return
	}
	d.value[c] = v
	d.rank[c] = rank
}

// get returns the rendering held for c, or "" if no source supplied one.
func (d displayField) get(c string) string {
	return d.value[c]
}

// consensus computes a ConsensusLocation from successful source results.
// Callers pass only results with OK == true. It does not enforce the quorum
// (Locate does that before calling); with a single result it simply yields a
// non-confident country.
func consensus(ok []SourceResult) ConsensusLocation {
	var loc ConsensusLocation

	// country: plurality over non-empty normalized codes; confident only at >= MinSources.
	// Ties in vote count are broken by the most-trusted contributing source
	// (SourcePriority), falling back to lexicographic order only if ranks also tie.
	countryCounts := map[string]int{}
	countryName := newDisplayField()
	countryRank := map[string]int{}
	countryHasRank := map[string]bool{}
	for _, r := range ok {
		c := normalizeCountry(r.CountryCode)
		if c == "" {
			continue
		}
		countryCounts[c]++
		countryName.offer(c, r.Country, sourceRank(r.Name))
		rank := sourceRank(r.Name)
		if !countryHasRank[c] || rank < countryRank[c] {
			countryRank[c] = rank
			countryHasRank[c] = true
		}
	}
	bestCountry, bestCountryN, bestCountryRank := "", 0, 0
	for c, n := range countryCounts {
		rank := countryRank[c]
		switch {
		case n > bestCountryN:
			bestCountry, bestCountryN, bestCountryRank = c, n, rank
		case n == bestCountryN && rank < bestCountryRank:
			bestCountry, bestCountryRank = c, rank
		case n == bestCountryN && rank == bestCountryRank && c < bestCountry:
			bestCountry = c
		}
	}
	if bestCountryN >= MinSources {
		name := countryName.get(bestCountry)
		if name == "" {
			// No source supplied a human-readable name for the winning code
			// (e.g. ipinfo-only quorum: it returns a code but never a name).
			// Fall back to the ISO-3166-1 table so a confident country isn't
			// submitted with an empty name, which the server rejects. A
			// source-supplied name above always takes priority; this only
			// fires when none was given. countryNameForCode itself degrades
			// to "" for a code outside the table, which is the correct,
			// non-corrupting behavior: leave Country empty rather than
			// invent a placeholder.
			name = countryNameForCode(bestCountry)
		}
		// CountryConfident means "I have a complete, usable country record",
		// exactly as CityConfident means it for the city fields: agreement
		// alone is not enough. The server rejects a submission whose country
		// code is not alpha-2 ("Country code must be alpha-2.") or whose
		// country name is empty ("Missing country."), and neither rejection
		// is cached by the scheduler -- so a provider that produces one is
		// re-probed and re-rejected on every pass, forever, burning a tunnel
		// and three lookups each time. Both shapes are reachable: XK (Kosovo,
		// user-assigned) and the MaxMind-lineage A1/A2/AP are two characters
		// but absent from the ISO table, and normalizeCountry never validates
		// length, so two sources reporting "USA" would otherwise sail through.
		// Degrade to not-country-confident (and leave the fields empty, as
		// the no-majority path does) rather than emit a doomed submission.
		if isAlpha2(bestCountry) && name != "" {
			loc.CountryCode = bestCountry
			loc.Country = name
			loc.CountryConfident = true
		}
	}

	// city: set only if >= 2 sources agree on the normalized city.
	// Same tie-break as country: most-trusted contributing source first,
	// lexicographic order only as a last-resort tiebreaker.
	cityCounts := map[string]int{}
	cityDisplay := newDisplayField()
	cityRegion := newDisplayField()
	cityRank := map[string]int{}
	cityHasRank := map[string]bool{}
	for _, r := range ok {
		c := normalizeCity(r.City)
		if c == "" {
			continue
		}
		cityCounts[c]++
		cityDisplay.offer(c, r.City, sourceRank(r.Name))
		cityRegion.offer(c, r.Region, sourceRank(r.Name))
		rank := sourceRank(r.Name)
		if !cityHasRank[c] || rank < cityRank[c] {
			cityRank[c] = rank
			cityHasRank[c] = true
		}
	}
	bestCity, bestCityN, bestCityRank := "", 0, 0
	for c, n := range cityCounts {
		rank := cityRank[c]
		switch {
		case n > bestCityN:
			bestCity, bestCityN, bestCityRank = c, n, rank
		case n == bestCityN && rank < bestCityRank:
			bestCity, bestCityRank = c, rank
		case n == bestCityN && rank == bestCityRank && c < bestCity:
			bestCity = c
		}
	}
	// CityConfident requires both city agreement AND a resolved Region: the
	// server rejects any city-confident submission with an empty region,
	// and that rejection kills the whole POST -- including a perfectly good
	// country result. Region is only populated when some source supplied
	// one (never fabricated), so when no agreeing source named a region,
	// degrade cleanly to country granularity instead of submitting an
	// incomplete record: leave City/Region empty and CityConfident false.
	if bestCityN >= 2 && cityRegion.get(bestCity) != "" {
		loc.City = cityDisplay.get(bestCity)
		loc.Region = cityRegion.get(bestCity)
		loc.CityConfident = true
	}

	// asn: plurality over non-zero ASNs (a single vote is enough; it's a bonus signal).
	// Tie-break note: on an exact vote-count tie this picks the numerically
	// smaller ASN (map iteration order plus "a < bestASN" below), not the
	// most-trusted source as country/city do via SourcePriority. This
	// deviates from the design spec's "0 if none/tie" wording; documenting
	// the deviation here rather than changing established behavior.
	asnCounts := map[int]int{}
	asnOrg := map[int]string{}
	for _, r := range ok {
		if r.ASN == 0 {
			continue
		}
		asnCounts[r.ASN]++
		if r.Org != "" {
			asnOrg[r.ASN] = r.Org
		}
	}
	bestASN, bestASNN := 0, 0
	for a, n := range asnCounts {
		if n > bestASNN || (n == bestASNN && a < bestASN) {
			bestASN, bestASNN = a, n
		}
	}
	loc.ASN = bestASN
	loc.Org = asnOrg[bestASN]

	// net_type flags: OR across sources.
	for _, r := range ok {
		loc.Hosting = loc.Hosting || r.Hosting
		loc.Proxy = loc.Proxy || r.Proxy
		loc.Mobile = loc.Mobile || r.Mobile
	}

	return loc
}
