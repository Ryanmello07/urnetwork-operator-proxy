package geolocate

import "strings"

func normalizeCountry(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

func normalizeCity(city string) string {
	return strings.ToLower(strings.TrimSpace(city))
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
	countryName := map[string]string{}
	countryRank := map[string]int{}
	countryHasRank := map[string]bool{}
	for _, r := range ok {
		c := normalizeCountry(r.CountryCode)
		if c == "" {
			continue
		}
		countryCounts[c]++
		if r.Country != "" {
			countryName[c] = r.Country
		}
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
		loc.CountryCode = bestCountry
		loc.Country = countryName[bestCountry]
		if loc.Country == "" {
			// No source supplied a human-readable name for the winning code
			// (e.g. ipinfo-only quorum: it returns a code but never a name).
			// Fall back to the ISO-3166-1 table so a confident country isn't
			// submitted with an empty name, which the server rejects. A
			// source-supplied name above always takes priority; this only
			// fires when none was given. countryNameForCode itself degrades
			// to "" for a code outside the table, which is the correct,
			// non-corrupting behavior: leave Country empty rather than
			// invent a placeholder.
			loc.Country = countryNameForCode(bestCountry)
		}
		loc.CountryConfident = true
	}

	// city: set only if >= 2 sources agree on the normalized city.
	// Same tie-break as country: most-trusted contributing source first,
	// lexicographic order only as a last-resort tiebreaker.
	cityCounts := map[string]int{}
	cityDisplay := map[string]string{}
	cityRegion := map[string]string{}
	cityRank := map[string]int{}
	cityHasRank := map[string]bool{}
	for _, r := range ok {
		c := normalizeCity(r.City)
		if c == "" {
			continue
		}
		cityCounts[c]++
		if _, seen := cityDisplay[c]; !seen {
			cityDisplay[c] = strings.TrimSpace(r.City)
		}
		if r.Region != "" {
			cityRegion[c] = r.Region
		}
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
	if bestCityN >= 2 {
		loc.City = cityDisplay[bestCity]
		loc.Region = cityRegion[bestCity]
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
