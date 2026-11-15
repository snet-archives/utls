package tls

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestRealityServerPropagatesUpstreamTCPResetOnNonTLSProbe(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })

	go func() {
		for {
			c, aErr := targetLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				var buf [64]byte
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				_, _ = conn.Read(buf[:])
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					_ = tcpConn.SetLinger(0)
				}
				_ = conn.Close()
			}(c)
		}
	}()

	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	cfg := &RealityConfig{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		},
		Type:        "tcp",
		Dest:        targetLn.Addr().String(),
		ServerNames: map[string]bool{"example.com": true},
		PrivateKey:  privKey,
		ShortIds:    map[[8]byte]bool{{1, 2, 3, 4, 5, 6, 7, 8}: true},
		MaxTimeDiff: time.Minute,
	}

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	t.Cleanup(func() { _ = serverLn.Close() })

	go func() {
		for {
			c, aErr := serverLn.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_, _ = RealityServer(ctx, conn, cfg)
			}(c)
		}
	}()

	client, err := net.DialTimeout("tcp", serverLn.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial reality server: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write probe: %v", err)
	}

	var out [32]byte
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, readErr := client.Read(out[:])
	if !errors.Is(readErr, syscall.ECONNRESET) {
		t.Fatalf("expected ECONNRESET propagated from upstream target, got %v", readErr)
	}
}
