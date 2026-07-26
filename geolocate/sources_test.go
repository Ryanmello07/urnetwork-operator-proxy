package geolocate

import (
	"net/url"
	"testing"
)

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
	cases := []struct {
		name    string
		org     string
		wantASN int
		wantOrg string
	}{
		{"exact AS+space+name", "AS401486 RAVNIX LLC", 401486, "RAVNIX LLC"},
		{"bare org no AS prefix", "RAVNIX LLC", 0, "RAVNIX LLC"},
		{"org merely starts with letters AS", "ASIA PACIFIC NETWORK INFORMATION CENTRE", 0, "ASIA PACIFIC NETWORK INFORMATION CENTRE"},
		{"AS number with no name", "AS401486", 401486, ""},
		{"empty string", "", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			asn, org := parseASNOrg(c.org)
			if asn != c.wantASN || org != c.wantOrg {
				t.Fatalf("parseASNOrg(%q) = (%d, %q), want (%d, %q)", c.org, asn, org, c.wantASN, c.wantOrg)
			}
		})
	}
}

func TestParseIpPnASNTypeTolerance(t *testing.T) {
	cases := []struct {
		name    string
		asnJSON string
		wantASN int
	}{
		{"raw number", `401486`, 401486},
		{"quoted number", `"401486"`, 401486},
		{"quoted AS-prefixed", `"AS401486"`, 401486},
		{"null", `null`, 0},
		{"garbage object", `{"foo":"bar"}`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := []byte(`{"status":"success","country":"United States","countryCode":"US","city":"Fairfax","regionName":"","asn":` + c.asnJSON + `,"mobile":false,"proxy":false,"hosting":false}`)
			r, err := parseIpPn(b)
			if err != nil {
				t.Fatalf("parseIpPn err = %v", err)
			}
			if r.CountryCode != "US" || r.Country != "United States" || r.City != "Fairfax" {
				t.Fatalf("parseIpPn = %+v", r)
			}
			if r.ASN != c.wantASN {
				t.Fatalf("parseIpPn ASN = %d, want %d", r.ASN, c.wantASN)
			}
		})
	}
}

func TestParseFreeIpApiASNTypeTolerance(t *testing.T) {
	cases := []struct {
		name    string
		asnJSON string
		wantASN int
	}{
		{"quoted AS-prefixed", `"AS401486"`, 401486},
		{"raw number", `401486`, 401486},
		{"quoted number", `"401486"`, 401486},
		{"null", `null`, 0},
		{"garbage array", `[1,2,3]`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := []byte(`{"ipVersion":6,"countryName":"United States","countryCode":"US","cityName":"Denver (North Capitol Hill)","regionName":"Colorado","asn":` + c.asnJSON + `,"isProxy":false}`)
			r, err := parseFreeIpApi(b)
			if err != nil {
				t.Fatalf("parseFreeIpApi err = %v", err)
			}
			if r.CountryCode != "US" || r.Country != "United States" || r.City != "Denver (North Capitol Hill)" || r.Region != "Colorado" {
				t.Fatalf("parseFreeIpApi = %+v", r)
			}
			if r.ASN != c.wantASN {
				t.Fatalf("parseFreeIpApi ASN = %d, want %d", r.ASN, c.wantASN)
			}
		})
	}
}

func TestSourcesTable(t *testing.T) {
	wantNames := []string{"ip.pn", "freeipapi", "ipinfo"}
	if len(sources) != len(wantNames) {
		t.Fatalf("len(sources) = %d, want %d", len(sources), len(wantNames))
	}
	for i, s := range sources {
		if s.Name != wantNames[i] {
			t.Fatalf("sources[%d].Name = %q, want %q", i, s.Name, wantNames[i])
		}
		if s.URL == "" {
			t.Fatalf("sources[%d] (%s) has empty URL", i, s.Name)
		}
		if s.Parse == nil {
			t.Fatalf("sources[%d] (%s) has nil Parse", i, s.Name)
		}
	}

	// The consensus tie-break in consensus.go is keyed on these exact Name
	// strings via SourcePriority. If the two tables drift apart, tie-breaking
	// silently degrades to the unknown-source fallback rank with no other
	// test failure, so assert the tables stay in lockstep here.
	if len(sources) != len(SourcePriority) {
		t.Fatalf("len(sources) = %d, len(SourcePriority) = %d; tables have drifted apart", len(sources), len(SourcePriority))
	}
	for _, s := range sources {
		if _, ok := SourcePriority[s.Name]; !ok {
			t.Fatalf("source %q has no entry in SourcePriority (consensus.go); tables have drifted apart", s.Name)
		}
	}
}

// TestSourceHostsCoversEverySource is an anti-drift test. SourceHosts is what
// the confinement self-check probes: if a source is added to the table above
// and its host does not come out of SourceHosts, the check silently stops
// covering a real geolocation endpoint while still reporting success.
func TestSourceHostsCoversEverySource(t *testing.T) {
	hosts := SourceHosts()
	if len(hosts) == 0 {
		t.Fatal("SourceHosts is empty; the confinement check would have nothing to test")
	}
	for _, s := range sources {
		u, err := url.Parse(s.URL)
		if err != nil {
			t.Fatalf("source %q has an unparseable URL %q: %s", s.Name, s.URL, err)
		}
		found := false
		for _, h := range hosts {
			if h == u.Hostname() {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("source %q (%s) has no host in SourceHosts %v; the confinement check would not cover it", s.Name, s.URL, hosts)
		}
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" {
			t.Fatalf("SourceHosts contains an empty host: %v", hosts)
		}
		if seen[h] {
			t.Fatalf("SourceHosts contains %q twice: %v", h, hosts)
		}
		seen[h] = true
	}
}
