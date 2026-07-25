package providertunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCACert and testCAKey are a self-signed test CA, installed as a
// trusted root for this test binary only (see TestMain). The two TLS
// end-to-end tests below issue leaf certificates signed by this CA, so that
// normal certificate-chain verification succeeds and the pin check --
// PinnedTLSConfigForHost's VerifyPeerCertificate -- is what actually
// isolates pass/fail. A bare self-signed leaf (no CA in the chain) would
// always be rejected at the chain-trust step, regardless of whether the pin
// matched, and would not prove pinning does anything.
var (
	testCACert *x509.Certificate
	testCAKey  *ecdsa.PrivateKey
)

// TestMain installs testCACert as a trusted root for this process by
// pointing SSL_CERT_FILE at it before any test runs. crypto/x509's Linux
// loader (root_unix.go) honors SSL_CERT_FILE to build the system root pool,
// and that pool is loaded lazily and cached for the life of the process, so
// this must happen before the first TLS handshake -- which is exactly what
// TestMain guarantees relative to m.Run(). This lets the TLS regression
// tests below exercise real chain verification plus the pin check, without
// touching pinning.go's contract (pins are additive to normal verification,
// not a replacement for it) and without relying on any real, publicly
// trusted certificate for a fake test host.
func TestMain(m *testing.M) {
	cert, key, err := generateTestCA()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate test CA:", err)
		os.Exit(1)
	}
	testCACert, testCAKey = cert, key

	dir, err := os.MkdirTemp("", "providertunnel-test-ca")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdir temp:", err)
		os.Exit(1)
	}
	caPath := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write ca file:", err)
		os.Exit(1)
	}
	os.Setenv("SSL_CERT_FILE", caPath)

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func generateTestCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "providertunnel test root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// issueLeaf mints a certificate for host, signed by testCACert/testCAKey,
// so it chains to a trusted root under the SSL_CERT_FILE override installed
// by TestMain.
func issueLeaf(t *testing.T, host string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, testCACert, &key.PublicKey, testCAKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// httpClientOverDialer is the contract Tunnel.HTTPClient must satisfy: every
// request is dialed through the supplied dialer (the tunnel), never the host
// network. This test exercises that wiring with a stub dialer, so it runs
// without a live provider.
func TestHTTPClientUsesSuppliedDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		})}
		_ = srv.Serve(ln)
	}()

	dialed := 0
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed++
		// ignore the requested address; always reach the stub listener,
		// modelling "the tunnel decides where bytes actually go"
		return net.Dial("tcp", ln.Addr().String())
	}

	client := httpClientOverDialer(dial, nil, 5*time.Second)
	resp, err := client.Get("http://geolocation.example/json")
	if err != nil {
		t.Fatalf("get err = %v", err)
	}
	defer resp.Body.Close()
	if dialed == 0 {
		t.Fatal("request did not go through the supplied dialer")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// TestHTTPClientAppliesPinnedTLSPerHost asserts the transport is wired to
// dial through the tunnel and to build its TLS config per host (via
// DialTLSContext), rather than sharing one mutated *tls.Config template
// across hosts -- the latter is exactly the fail-open shape Task 1's
// security review found (see ErrPinHostUnknown doc in pinning.go) and
// PinnedTLSConfigForHost exists to avoid.
func TestHTTPClientAppliesPinnedTLSPerHost(t *testing.T) {
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, context.Canceled // never actually connects
	}
	client := httpClientOverDialer(dial, map[string][]string{"ipinfo.io": {"pin"}}, time.Second)
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if tr.DialContext == nil {
		t.Fatal("transport must dial through the tunnel")
	}
	if tr.DialTLSContext == nil {
		t.Fatal("transport must build a per-host pinned tls config via DialTLSContext")
	}
}

// startTLSTestServer serves plain 200 responses over TLS using cert/key,
// on a random loopback port, and returns the raw (non-TLS-wrapping)
// net.Listener address to dial. The server owns the listener and is torn
// down by the returned cleanup func.
func startTLSTestServer(t *testing.T, cert *x509.Certificate, key *ecdsa.PrivateKey) (addr string, cleanup func()) {
	t.Helper()
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() {
		_ = srv.Serve(ln)
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// dialerToAddr returns a dial func that ignores the requested host:port and
// always connects to addr, modelling "the tunnel decides where bytes
// actually go" -- exactly like the stub dialer in
// TestHTTPClientUsesSuppliedDialer, but reused for the TLS tests below.
func dialerToAddr(addr string) dialContextFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
}

// TestHTTPClientRejectsWrongKeyCertForPinnedHost is the pinning regression
// test at the http.Client layer: Task 1's own tests only prove the verifier
// rejects a mismatched pin in isolation (calling VerifyPeerCertificate
// directly). This proves the same thing through the actual client
// httpClientOverDialer builds -- a real TLS handshake, dialed through the
// tunnel's dial func, against a server presenting a certificate whose key
// does NOT match the configured pin for a pinned host, must fail the
// request. This is the layer a wiring mistake (e.g. accidentally using an
// unpinned config, or the clone-and-mutate bug Task 1's review caught)
// would actually bite: a malicious provider MITMing its own geolocation
// lookup to forge a favorable country.
func TestHTTPClientRejectsWrongKeyCertForPinnedHost(t *testing.T) {
	const pinnedHost = "pinned.example"

	// The server presents a CA-signed cert for pinnedHost -- chain
	// verification succeeds under the SSL_CERT_FILE override from
	// TestMain, isolating the pin check as the thing under test.
	serverCert, serverKey := issueLeaf(t, pinnedHost)
	// The pin set trusts a DIFFERENT key for the same host -- simulating a
	// MITM presenting a chain-valid certificate the pin set does not trust
	// (e.g. issued by a different, also-trusted CA for a key it controls).
	trustedCert, _ := issueLeaf(t, pinnedHost)

	addr, cleanup := startTLSTestServer(t, serverCert, serverKey)
	defer cleanup()

	client := httpClientOverDialer(dialerToAddr(addr), map[string][]string{
		pinnedHost: {SPKIPin(trustedCert)},
	}, 5*time.Second)

	resp, err := client.Get("https://" + pinnedHost + "/json")
	if err == nil {
		resp.Body.Close()
		t.Fatal("FAIL-OPEN: request to a pinned host succeeded despite a wrong-key certificate")
	}
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("err = %v, want it to wrap ErrPinMismatch", err)
	}
}

// TestHTTPClientAcceptsMatchingPinnedCert is the positive counterpart: with
// the correct pin configured, the same real TLS handshake through the same
// client construction succeeds. Without this, a bug that made pinning
// reject everything (fail-closed but broken, e.g. wrong host normalization)
// would not be caught by the rejection test above.
func TestHTTPClientAcceptsMatchingPinnedCert(t *testing.T) {
	const pinnedHost = "pinned.example"

	serverCert, serverKey := issueLeaf(t, pinnedHost)
	addr, cleanup := startTLSTestServer(t, serverCert, serverKey)
	defer cleanup()

	client := httpClientOverDialer(dialerToAddr(addr), map[string][]string{
		pinnedHost: {SPKIPin(serverCert)},
	}, 5*time.Second)

	resp, err := client.Get("https://" + pinnedHost + "/json")
	if err != nil {
		t.Fatalf("get err = %v, want success with a matching pin", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
