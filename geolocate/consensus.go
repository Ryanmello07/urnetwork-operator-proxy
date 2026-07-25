package geolocate

import "strings"

func normalizeCountry(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

func normalizeCity(city string) string {
	return strings.ToLower(strings.TrimSpace(city))
}

// consensus computes a ConsensusLocation from successful source results.
// Callers pass only results with OK == true. It does not enforce the quorum
// (Locate does that before calling); with a single result it simply yields a
// non-confident country.
func consensus(ok []SourceResult) ConsensusLocation {
	var loc ConsensusLocation

	// country: plurality over non-empty normalized codes; confident only at >= MinSources.
	countryCounts := map[string]int{}
	countryName := map[string]string{}
	for _, r := range ok {
		c := normalizeCountry(r.CountryCode)
		if c == "" {
			continue
		}
		countryCounts[c]++
		if r.Country != "" {
			countryName[c] = r.Country
		}
	}
	bestCountry, bestCountryN := "", 0
	for c, n := range countryCounts {
		if n > bestCountryN || (n == bestCountryN && c < bestCountry) {
			bestCountry, bestCountryN = c, n
		}
	}
	if bestCountryN >= MinSources {
		loc.CountryCode = bestCountry
		loc.Country = countryName[bestCountry]
		loc.CountryConfident = true
	}

	// city: set only if >= 2 sources agree on the normalized city.
	cityCounts := map[string]int{}
	cityDisplay := map[string]string{}
	cityRegion := map[string]string{}
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
	}
	bestCity, bestCityN := "", 0
	for c, n := range cityCounts {
		if n > bestCityN || (n == bestCityN && c < bestCity) {
			bestCity, bestCityN = c, n
		}
	}
	if bestCityN >= 2 {
		loc.City = cityDisplay[bestCity]
		loc.Region = cityRegion[bestCity]
		loc.CityConfident = true
	}

	// asn: plurality over non-zero ASNs (a single vote is enough; it's a bonus signal).
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
