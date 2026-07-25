package geolocate

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type source struct {
	Name  string
	URL   string
	Parse func([]byte) (SourceResult, error)
}

// sources are the production geolocation endpoints. Each uses the no-IP
// "my location" form, so a request routed through a provider returns that
// provider's egress location.
var sources = []source{
	{Name: "ip.pn", URL: "https://ip.pn/json", Parse: parseIpPn},
	{Name: "freeipapi", URL: "https://free.freeipapi.com/api/json", Parse: parseFreeIpApi},
	{Name: "ipinfo", URL: "https://ipinfo.io/json", Parse: parseIpInfo},
}

func parseIpPn(b []byte) (SourceResult, error) {
	var v struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		RegionName  string `json:"regionName"`
		ASN         int    `json:"asn"`
		Mobile      bool   `json:"mobile"`
		Proxy       bool   `json:"proxy"`
		Hosting     bool   `json:"hosting"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return SourceResult{}, err
	}
	if v.Status != "" && v.Status != "success" {
		return SourceResult{}, fmt.Errorf("ip.pn status %q", v.Status)
	}
	return SourceResult{
		CountryCode: v.CountryCode,
		Country:     v.Country,
		City:        v.City,
		Region:      v.RegionName,
		ASN:         v.ASN,
		Mobile:      v.Mobile,
		Proxy:       v.Proxy,
		Hosting:     v.Hosting,
	}, nil
}

func parseFreeIpApi(b []byte) (SourceResult, error) {
	var v struct {
		CountryName string `json:"countryName"`
		CountryCode string `json:"countryCode"`
		CityName    string `json:"cityName"`
		RegionName  string `json:"regionName"`
		ASN         string `json:"asn"`
		IsProxy     bool   `json:"isProxy"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return SourceResult{}, err
	}
	asn := 0
	if s := strings.TrimPrefix(strings.TrimSpace(v.ASN), "AS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			asn = n
		}
	}
	return SourceResult{
		CountryCode: v.CountryCode,
		Country:     v.CountryName,
		City:        v.CityName,
		Region:      v.RegionName,
		ASN:         asn,
		Proxy:       v.IsProxy,
	}, nil
}

func parseIpInfo(b []byte) (SourceResult, error) {
	var v struct {
		City    string `json:"city"`
		Region  string `json:"region"`
		Country string `json:"country"` // alpha-2, e.g. "US"
		Org     string `json:"org"`     // e.g. "AS401486 RAVNIX LLC"
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return SourceResult{}, err
	}
	asn, org := parseASNOrg(v.Org)
	// ipinfo gives only the alpha-2 country code, no human-readable name.
	return SourceResult{
		CountryCode: v.Country,
		City:        v.City,
		Region:      v.Region,
		ASN:         asn,
		Org:         org,
	}, nil
}

// parseASNOrg splits ipinfo's org field "AS401486 RAVNIX LLC" into
// (401486, "RAVNIX LLC"). On any unexpected shape it returns (0, org).
func parseASNOrg(org string) (int, string) {
	org = strings.TrimSpace(org)
	if org == "" {
		return 0, ""
	}
	fields := strings.SplitN(org, " ", 2)
	name := ""
	if len(fields) == 2 {
		name = fields[1]
	}
	if strings.HasPrefix(fields[0], "AS") {
		if n, err := strconv.Atoi(fields[0][2:]); err == nil {
			return n, name
		}
	}
	return 0, org
}
