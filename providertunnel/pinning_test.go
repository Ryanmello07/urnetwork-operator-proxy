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

var _ = tls.Config{}
