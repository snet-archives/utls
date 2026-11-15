package tls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"
)

func captureClientHelloWire(t *testing.T, id ClientHelloID, preBuild bool, sessionIDGenerator func(clientHello, sessionID []byte) error) ([]byte, []byte) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	helloCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		defer close(helloCh)
		_ = serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 5)
		if _, err := io.ReadFull(serverConn, header); err != nil {
			errCh <- err
			return
		}
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(serverConn, payload); err != nil {
			errCh <- err
			return
		}
		helloCh <- payload
		_ = serverConn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	uConn := UClient(clientConn, &Config{
		ServerName:         "www.microsoft.com",
		SessionIDGenerator: sessionIDGenerator,
	}, id)
	var preBuilt []byte
	if preBuild {
		if err := uConn.BuildHandshakeState(); err != nil {
			t.Fatalf("BuildHandshakeState failed: %v", err)
		}
		preBuilt = bytes.Clone(uConn.HandshakeState.Hello.Raw)
	}
	_ = uConn.HandshakeContext(ctx)

	select {
	case err := <-errCh:
		t.Fatalf("failed reading ClientHello: %v", err)
	case hello := <-helloCh:
		if len(hello) < 71 || hello[0] != typeClientHello {
			t.Fatalf("invalid ClientHello payload length=%d", len(hello))
		}
		return hello, preBuilt
	}
	return nil, nil
}

func parseClientHelloExtensionIDs(t *testing.T, hello []byte) []uint16 {
	t.Helper()
	if len(hello) < 4+2+32+1 {
		t.Fatalf("ClientHello too short: %d", len(hello))
	}
	pos := 4 + 2 + 32
	sessionIDLen := int(hello[pos])
	pos += 1 + sessionIDLen
	cipherSuitesLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	compLen := int(hello[pos])
	pos += 1 + compLen
	extsLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	end := pos + extsLen
	if end > len(hello) {
		t.Fatalf("extensions exceed ClientHello: end=%d len=%d", end, len(hello))
	}
	var ids []uint16
	for pos+4 <= end {
		extID := binary.BigEndian.Uint16(hello[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(hello[pos+2 : pos+4]))
		ids = append(ids, extID)
		pos += 4 + extLen
	}
	return ids
}

func isGREASEValue(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

func TestUTLSSessionIDGeneratorPreservesPresetFingerprint(t *testing.T) {
	// 1. Pre-built HelloChrome_Auto: wire bytes must match pre-built ClientHello everywhere except sessionID [39:71].
	var seenInput []byte
	var generatedSessionID [32]byte
	for i := range generatedSessionID {
		generatedSessionID[i] = byte(0xa0 + i)
	}
	gen := func(clientHello, sessionID []byte) error {
		seenInput = append([]byte(nil), clientHello...)
		if len(sessionID) != 32 {
			return errors.New("unexpected sessionID length")
		}
		copy(sessionID, generatedSessionID[:])
		return nil
	}

	shadowHello, preBuilt := captureClientHelloWire(t, HelloChrome_Auto, true, gen)
	if len(seenInput) == 0 {
		t.Fatal("SessionIDGenerator was not called")
	}
	if len(shadowHello) != len(preBuilt) {
		t.Fatalf("wire length mismatch: preBuilt=%d wire=%d", len(preBuilt), len(shadowHello))
	}
	if !bytes.Equal(preBuilt[:39], shadowHello[:39]) || !bytes.Equal(preBuilt[71:], shadowHello[71:]) {
		t.Fatal("ShadowTLS modified uTLS ClientHello bytes outside legacy_session_id")
	}
	if !bytes.Equal(seenInput[39:71], make([]byte, 32)) {
		t.Fatalf("expected zeroed sessionID in SessionIDGenerator input, got %x", seenInput[39:71])
	}
	if !bytes.Equal(shadowHello[39:71], generatedSessionID[:]) {
		t.Fatalf("wire sessionID mismatch: got %x want %x", shadowHello[39:71], generatedSessionID[:])
	}
	if !bytes.Equal(seenInput[:39], shadowHello[:39]) || !bytes.Equal(seenInput[71:], shadowHello[71:]) {
		t.Fatal("ClientHello passed to SessionIDGenerator differs from wire ClientHello outside sessionID")
	}

	chromeAutoExts := parseClientHelloExtensionIDs(t, shadowHello)
	if slices.Contains(chromeAutoExts, extensionSignatureAlgorithmsCert) {
		t.Fatalf("HelloChrome_Auto + ShadowTLS leaked Go stdlib extension 50: %v", chromeAutoExts)
	}
	if !slices.Contains(chromeAutoExts, extensionEncryptedClientHello) {
		t.Fatalf("HelloChrome_Auto + ShadowTLS lost GREASE ECH extension 65037: %v", chromeAutoExts)
	}
	if !slices.Contains(chromeAutoExts, utlsExtensionApplicationSettingsNew) && !slices.Contains(chromeAutoExts, utlsExtensionApplicationSettings) {
		t.Fatalf("HelloChrome_Auto + ShadowTLS lost ALPS extension: %v", chromeAutoExts)
	}

	// 2. Direct HandshakeContext (no preBuild) with unshuffled HelloChrome_102: exact extension sequence must match baseline.
	baseline102, _ := captureClientHelloWire(t, HelloChrome_102, false, nil)
	baselineExts := parseClientHelloExtensionIDs(t, baseline102)
	shadow102, _ := captureClientHelloWire(t, HelloChrome_102, false, gen)
	shadowExts := parseClientHelloExtensionIDs(t, shadow102)
	if len(shadowExts) != len(baselineExts) {
		t.Fatalf("Chrome_102 extension count mismatch: baseline=%d shadowtls=%d", len(baselineExts), len(shadowExts))
	}
	for i := range baselineExts {
		if isGREASEValue(baselineExts[i]) && isGREASEValue(shadowExts[i]) {
			continue
		}
		if baselineExts[i] != shadowExts[i] {
			t.Fatalf("Chrome_102 extension[%d] mismatch: baseline=%d shadowtls=%d", i, baselineExts[i], shadowExts[i])
		}
	}
}
