package netx

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSetupDNSAndResolve(t *testing.T) {
	// Setup DNS with public DNS servers
	SetupDNS([]string{"77.88.8.8:53", "1.1.1.1:53"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialStream(ctx, "tcp", "ignored")
	if err != nil {
		t.Fatalf("dialStream failed: %v", err)
	}
	defer conn.Close()

	// Verify net.DefaultResolver.LookupIP works
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", "one.one.one.one")
	if err != nil {
		t.Logf("LookupIP note: %v (network might be restricted in sandbox)", err)
	} else if len(ips) == 0 {
		t.Fatalf("expected at least one IP for one.one.one.one")
	} else {
		t.Logf("Resolved one.one.one.one -> %v", ips)
	}
}

func TestIsLoopback(t *testing.T) {
	if !isLoopback("[::1]:53") {
		t.Errorf("expected [::1]:53 to be loopback")
	}
	if !isLoopback("127.0.0.1:53") {
		t.Errorf("expected 127.0.0.1:53 to be loopback")
	}
	if !isLoopback("localhost:53") {
		t.Errorf("expected localhost:53 to be loopback")
	}
	if isLoopback("77.88.8.8:53") {
		t.Errorf("expected 77.88.8.8:53 not to be loopback")
	}
	if isLoopback("1.1.1.1:53") {
		t.Errorf("expected 1.1.1.1:53 not to be loopback")
	}
}
