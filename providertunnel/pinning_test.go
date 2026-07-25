package providertunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, host string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestSPKIPinStableAndDistinct(t *testing.T) {
	a, _ := selfSigned(t, "a.example")
	b, _ := selfSigned(t, "b.example")
	if SPKIPin(a) == "" {
		t.Fatal("pin must not be empty")
	}
	if SPKIPin(a) != SPKIPin(a) {
		t.Fatal("pin must be stable for the same cert")
	}
	if SPKIPin(a) == SPKIPin(b) {
		t.Fatal("different keys must produce different pins")
	}
}

func TestPinnedTLSConfigAcceptsMatchingPin(t *testing.T) {
	cert, _ := selfSigned(t, "pinned.example")
	cfg := PinnedTLSConfig(map[string][]string{
		"pinned.example": {SPKIPin(cert)},
	})
	cfg.ServerName = "pinned.example"
	err := cfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil)
	if err != nil {
		t.Fatalf("matching pin must verify, got %v", err)
	}
}

func TestPinnedTLSConfigRejectsWrongPin(t *testing.T) {
	good, _ := selfSigned(t, "pinned.example")
	evil, _ := selfSigned(t, "pinned.example")
	cfg := PinnedTLSConfig(map[string][]string{
		"pinned.example": {SPKIPin(good)},
	})
	cfg.ServerName = "pinned.example"
	err := cfg.VerifyPeerCertificate([][]byte{evil.Raw}, nil)
	if err != ErrPinMismatch {
		t.Fatalf("err = %v, want ErrPinMismatch (a provider must not be able to MITM)", err)
	}
}

func TestPinnedTLSConfigIgnoresUnpinnedHost(t *testing.T) {
	cert, _ := selfSigned(t, "other.example")
	cfg := PinnedTLSConfig(map[string][]string{
		"pinned.example": {"someotherpin"},
	})
	cfg.ServerName = "other.example"
	if err := cfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil); err != nil {
		t.Fatalf("unpinned host must pass the pin check, got %v", err)
	}
}

// TestPinnedTLSConfigCloneWithDifferentServerNameFailsClosed reproduces the
// critical fail-open defect: PinnedTLSConfig returns a template, a later
// caller does the idiomatic-looking `clone := template.Clone(); clone.ServerName
// = host`, and presents a certificate with the WRONG key for a pinned host.
// Under the old implementation the closure still read the ORIGINAL template's
// (empty) ServerName, found no matching pin-map entry, and returned nil --
// silently accepting an attacker certificate. It must be rejected.
func TestPinnedTLSConfigCloneWithDifferentServerNameFailsClosed(t *testing.T) {
	good, _ := selfSigned(t, "pinned.example")
	evil, _ := selfSigned(t, "pinned.example")
	template := PinnedTLSConfig(map[string][]string{
		"pinned.example": {SPKIPin(good)},
	})

	perHost := template.Clone()
	perHost.ServerName = "pinned.example"

	err := perHost.VerifyPeerCertificate([][]byte{evil.Raw}, nil)
	if err == nil {
		t.Fatal("FAIL-OPEN: clone accepted an attacker cert with the wrong key for a pinned host")
	}
}

func TestPinnedTLSConfigForHostAcceptsMatchingPin(t *testing.T) {
	cert, _ := selfSigned(t, "pinned.example")
	cfg := PinnedTLSConfigForHost(map[string][]string{
		"pinned.example": {SPKIPin(cert)},
	}, "pinned.example")

	if cfg.ServerName != "pinned.example" {
		t.Fatalf("ServerName = %q, want %q", cfg.ServerName, "pinned.example")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want at least TLS 1.2", cfg.MinVersion)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{cert.Raw}, nil); err != nil {
		t.Fatalf("matching pin must verify, got %v", err)
	}
}

func TestPinnedTLSConfigForHostRejectsWrongKey(t *testing.T) {
	good, _ := selfSigned(t, "pinned.example")
	evil, _ := selfSigned(t, "pinned.example")
	cfg := PinnedTLSConfigForHost(map[string][]string{
		"pinned.example": {SPKIPin(good)},
	}, "pinned.example")

	err := cfg.VerifyPeerCertificate([][]byte{evil.Raw}, nil)
	if err != ErrPinMismatch {
		t.Fatalf("err = %v, want ErrPinMismatch (a provider must not be able to MITM)", err)
	}
}

// TestPinnedTLSConfigForHostSurvivesCloneMutation demonstrates that, unlike
// PinnedTLSConfig, a config built by PinnedTLSConfigForHost is safe to
// Clone() and does not depend on the clone's ServerName field at all: the
// verifier closes over its own immutable copy of the host.
func TestPinnedTLSConfigForHostSurvivesCloneMutation(t *testing.T) {
	good, _ := selfSigned(t, "pinned.example")
	cfg := PinnedTLSConfigForHost(map[string][]string{
		"pinned.example": {SPKIPin(good)},
	}, "pinned.example")

	clone := cfg.Clone()
	clone.ServerName = "unrelated.example"

	if err := clone.VerifyPeerCertificate([][]byte{good.Raw}, nil); err != nil {
		t.Fatalf("PinVerifier must not depend on the config's mutable ServerName, got %v", err)
	}
}

// TestSPKIPinStableAcrossReissuance proves SPKI pinning survives certificate
// renewal: the same key, re-issued with a different serial number, CN, and
// validity window, must produce an identical pin. This is the whole point of
// pinning the key instead of the certificate.
func TestSPKIPinStableAcrossReissuance(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl1 := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "original.example"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		DNSNames:     []string{"pinned.example"},
	}
	der1, err := x509.CreateCertificate(rand.Reader, tmpl1, tmpl1, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert1, err := x509.ParseCertificate(der1)
	if err != nil {
		t.Fatal(err)
	}

	tmpl2 := &x509.Certificate{
		SerialNumber: big.NewInt(987654),
		Subject:      pkix.Name{CommonName: "renewed.example"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{"pinned.example"},
	}
	der2, err := x509.CreateCertificate(rand.Reader, tmpl2, tmpl2, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert2, err := x509.ParseCertificate(der2)
	if err != nil {
		t.Fatal(err)
	}

	if SPKIPin(cert1) != SPKIPin(cert2) {
		t.Fatal("same key across re-issuance must produce an identical SPKI pin")
	}
}

var _ = tls.Config{}
