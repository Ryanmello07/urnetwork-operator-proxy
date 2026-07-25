package geolocate

import "testing"

func TestParseIpPn(t *testing.T) {
	b := []byte(`{"query":"74.50.11.113","status":"success","country":"United States","countryCode":"US","city":"Fairfax","regionName":"","asn":401486,"mobile":false,"proxy":false,"hosting":false}`)
	r, err := parseIpPn(b)
	if err != nil {
		t.Fatalf("parseIpPn err = %v", err)
	}
	if r.CountryCode != "US" || r.Country != "United States" || r.City != "Fairfax" || r.ASN != 401486 {
		t.Fatalf("parseIpPn = %+v", r)
	}
}

func TestParseIpPnFailStatus(t *testing.T) {
	b := []byte(`{"status":"fail","message":"reserved range"}`)
	if _, err := parseIpPn(b); err == nil {
		t.Fatal("expected error on status != success")
	}
}

func TestParseFreeIpApi(t *testing.T) {
	b := []byte(`{"ipVersion":6,"countryName":"United States","countryCode":"US","cityName":"Denver (North Capitol Hill)","regionName":"Colorado","asn":"401486","isProxy":false}`)
	r, err := parseFreeIpApi(b)
	if err != nil {
		t.Fatalf("parseFreeIpApi err = %v", err)
	}
	if r.CountryCode != "US" || r.Country != "United States" || r.City != "Denver (North Capitol Hill)" || r.Region != "Colorado" || r.ASN != 401486 {
		t.Fatalf("parseFreeIpApi = %+v", r)
	}
}

func TestParseIpInfo(t *testing.T) {
	b := []byte(`{"ip":"74.50.11.113","city":"Atlanta","region":"Georgia","country":"US","org":"AS401486 RAVNIX LLC"}`)
	r, err := parseIpInfo(b)
	if err != nil {
		t.Fatalf("parseIpInfo err = %v", err)
	}
	if r.CountryCode != "US" || r.City != "Atlanta" || r.Region != "Georgia" || r.ASN != 401486 || r.Org != "RAVNIX LLC" {
		t.Fatalf("parseIpInfo = %+v", r)
	}
	if r.Country != "" {
		t.Fatalf("ipinfo provides no country name; Country should be empty, got %q", r.Country)
	}
}

func TestParseASNOrg(t *testing.T) {
	asn, org := parseASNOrg("AS401486 RAVNIX LLC")
	if asn != 401486 || org != "RAVNIX LLC" {
		t.Fatalf("parseASNOrg = (%d, %q)", asn, org)
	}
	if a, o := parseASNOrg(""); a != 0 || o != "" {
		t.Fatalf("empty org = (%d, %q)", a, o)
	}
}

func TestSourcesTable(t *testing.T) {
	if len(sources) != 3 {
		t.Fatalf("len(sources) = %d, want 3", len(sources))
	}
	for _, s := range sources {
		if s.Name == "" || s.URL == "" || s.Parse == nil {
			t.Fatalf("incomplete source %+v", s)
		}
	}
}
