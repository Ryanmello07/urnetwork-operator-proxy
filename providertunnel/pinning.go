// Package providertunnel builds an http.Client whose every request egresses
// through one specific urnetwork provider, so a geolocation lookup made with it
// reports that provider's egress location.
package providertunnel

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
)

// ErrPinMismatch is returned by the pin check when a pinned host presents a
// leaf certificate whose public key is not in the allowed set. A provider is
// the network path for these requests, so pinning is what stops it forging a
// location by MITMing a geolocation api.
var ErrPinMismatch = errors.New("providertunnel: certificate pin mismatch")

// SPKIPin is the base64 sha-256 of a certificate's subject public key info.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// PinnedTLSConfig returns a tls.Config that keeps normal chain verification and
// additionally requires, for each host in pins, that the leaf certificate's
// SPKI pin is one of the allowed values. Hosts absent from pins are not
// pin-checked.
func PinnedTLSConfig(pins map[string][]string) *tls.Config {
	// normalize keys to lowercase for host matching
	normalized := make(map[string][]string, len(pins))
	for host, allowed := range pins {
		normalized[strings.ToLower(host)] = allowed
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrPinMismatch
		}
		host := strings.ToLower(cfg.ServerName)
		allowed, pinned := normalized[host]
		if !pinned {
			return nil
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		got := SPKIPin(leaf)
		for _, want := range allowed {
			if got == want {
				return nil
			}
		}
		return ErrPinMismatch
	}
	return cfg
}
