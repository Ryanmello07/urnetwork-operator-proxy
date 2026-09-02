package controlplane

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestIPv4DialContextMapsUnspecifiedTCPToTCP4(t *testing.T) {
	wantErr := errors.New("stop after observing the network")
	gotNetwork := ""
	dialContext := ipv4DialContext(func(_ context.Context, network string, _ string) (net.Conn, error) {
		gotNetwork = network
		return nil, wantErr
	})

	_, err := dialContext(context.Background(), "tcp", "api.bringyour.com:443")
	if !errors.Is(err, wantErr) {
		t.Fatalf("dial error = %v, want injected error", err)
	}
	if gotNetwork != "tcp4" {
		t.Fatalf("underlying network = %q, want tcp4", gotNetwork)
	}
}

func TestIPv4DialContextKeepsTCP4(t *testing.T) {
	wantErr := errors.New("stop after observing the network")
	gotNetwork := ""
	dialContext := ipv4DialContext(func(_ context.Context, network string, _ string) (net.Conn, error) {
		gotNetwork = network
		return nil, wantErr
	})

	_, err := dialContext(context.Background(), "tcp4", "connect.bringyour.com:443")
	if !errors.Is(err, wantErr) {
		t.Fatalf("dial error = %v, want injected error", err)
	}
	if gotNetwork != "tcp4" {
		t.Fatalf("underlying network = %q, want tcp4", gotNetwork)
	}
}

func TestIPv4DialContextRejectsTCP6BeforeDial(t *testing.T) {
	called := false
	dialContext := ipv4DialContext(func(_ context.Context, _ string, _ string) (net.Conn, error) {
		called = true
		return nil, nil
	})

	if _, err := dialContext(context.Background(), "tcp6", "[2001:db8::1]:443"); err == nil {
		t.Fatal("explicit tcp6 dial succeeded")
	}
	if called {
		t.Fatal("explicit tcp6 request reached the underlying dialer")
	}
}

func TestClientStrategySettingsDisableOnlyIPv6(t *testing.T) {
	settings := clientStrategySettings()
	if !settings.ConnectSettings.DisableIpv6 {
		t.Fatal("Connect strategy permits IPv6 control-plane dials")
	}
	if settings.ConnectSettings.DisableIpv4 {
		t.Fatal("Connect strategy also disabled IPv4")
	}
}
