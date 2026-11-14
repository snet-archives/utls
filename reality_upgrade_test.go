package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	stdRand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/hkdf"
)

func generateTestTargetCert(t *testing.T, serverName string) stdtls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), stdRand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dnsNames := []string{serverName}
	for i := 0; i < 120; i++ {
		dnsNames = append(dnsNames, "cdn-"+string(rune('a'+i%26))+"-node.example.com")
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(stdRand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return stdtls.Certificate{
		Certificate: [][]byte{der, der},
		PrivateKey:  priv,
	}
}

func startMockRealityTarget(t *testing.T, serverName string) (string, func()) {
	t.Helper()
	cert := generateTestTargetCert(t, serverName)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tlsConn := stdtls.Server(conn, &stdtls.Config{
					Certificates:     []stdtls.Certificate{cert},
					MinVersion:       stdtls.VersionTLS13,
					MaxVersion:       stdtls.VersionTLS13,
					CurvePreferences: []stdtls.CurveID{stdtls.X25519MLKEM768, stdtls.X25519},
					NextProtos:       []string{"h2", "http/1.1"},
				})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				// Mirror incoming HTTP/fallback payload briefly until client closes.
				_, _ = io.Copy(tlsConn, tlsConn)
			}(c)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		wg.Wait()
	}
}

func buildRealityAuthClientConn(t *testing.T, tcpConn net.Conn, serverName string, serverPub, shortID, mldsaVerify []byte, helloID ClientHelloID) (*UConn, error) {
	t.Helper()
	var authKey []byte
	var uConn *UConn
	cfg := &Config{
		ServerName:             serverName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("empty cert chain")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("unexpected cert public key type")
			}
			h := hmac.New(sha512.New, authKey)
			h.Write(pub)
			if !bytes.Equal(h.Sum(nil), cert.Signature) {
				return errors.New("reality ed25519 hmac mismatch")
			}
			if len(mldsaVerify) > 0 {
				if len(cert.Extensions) == 0 {
					return errors.New("missing mldsa65 cert extension")
				}
				h.Write(uConn.HandshakeState.Hello.Raw)
				h.Write(uConn.HandshakeState.ServerHello.Raw)
				var pk mldsa65.PublicKey
				if err := pk.UnmarshalBinary(mldsaVerify); err != nil {
					return err
				}
				if !mldsa65.Verify(&pk, h.Sum(nil), nil, cert.Extensions[0].Value) {
					return errors.New("reality mldsa65 transcript verification failed")
				}
			}
			return nil
		},
	}
	uConn = UClient(tcpConn, cfg, helloID)
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], shortID)

	pubKey, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, err
	}
	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errors.New("nil ecdhe key")
	}
	sharedKey, err := ecdhe.ECDH(pubKey)
	if err != nil {
		return nil, err
	}
	authKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, sharedKey, hello.Random[:20], []byte("REALITY")), authKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	return uConn, nil
}

func TestRealityUpgradePQAndMLDSA65AndDeadline(t *testing.T) {
	const serverName = "example.com"
	targetAddr, stopTarget := startMockRealityTarget(t, serverName)
	defer stopTarget()

	serverKey, err := ecdh.X25519().GenerateKey(stdRand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var seed [mldsa65.SeedSize]byte
	if _, err := io.ReadFull(stdRand.Reader, seed[:]); err != nil {
		t.Fatal(err)
	}
	mldsaPub, _ := mldsa65.NewKeyFromSeed(&seed)
	mldsaPubBytes, err := mldsaPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var shortID [8]byte
	copy(shortID[:], []byte{1, 2, 3, 4})

	rcfg := &RealityConfig{
		DialContext: (&net.Dialer{}).DialContext,
		Type:        "tcp",
		Dest:        targetAddr,
		ServerNames: map[string]bool{serverName: true},
		PrivateKey:  serverKey.Bytes(),
		Mldsa65Seed: seed[:],
		MaxTimeDiff: time.Minute,
		ShortIds:    map[[8]byte]bool{shortID: true},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// 1. Authenticated PQ + ML-DSA-65 handshake, verify handshake deadline is cleared after completion.
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		rConn, err := RealityServer(ctx, conn, rcfg)
		if err != nil {
			serverErr <- err
			return
		}
		defer rConn.Close()
		// Wait past the 200ms handshake timeout to prove deadline was cleared on success.
		time.Sleep(250 * time.Millisecond)
		buf := make([]byte, 4)
		if _, err := io.ReadFull(rConn, buf); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(buf, []byte("ping")) {
			serverErr <- errors.New("unexpected payload")
			return
		}
		_, err = rConn.Write([]byte("pong"))
		serverErr <- err
	}()

	cConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	uConn, err := buildRealityAuthClientConn(t, cConn, serverName, serverKey.PublicKey().Bytes(), shortID[:], mldsaPubBytes, HelloChrome_133)
	if err != nil {
		t.Fatal(err)
	}
	defer uConn.Close()
	if err := uConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if uConn.HandshakeState.ServerHello.ServerShare.Group != X25519MLKEM768 {
		t.Fatalf("expected X25519MLKEM768 keyshare, got %v", uConn.HandshakeState.ServerHello.ServerShare.Group)
	}
	if _, err := uConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(uConn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, []byte("pong")) {
		t.Fatalf("expected pong, got %q", reply)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}

	// 2. Wrong ML-DSA-65 verification key must fail even with valid X25519 AuthKey.
	var wrongSeed [mldsa65.SeedSize]byte
	wrongSeed[0] = 0x55
	wrongPub, _ := mldsa65.NewKeyFromSeed(&wrongSeed)
	wrongPubBytes, _ := wrongPub.MarshalBinary()

	serverErr2 := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr2 <- err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err = RealityServer(ctx, conn, rcfg)
		serverErr2 <- err
	}()

	cConn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	uConn2, err := buildRealityAuthClientConn(t, cConn2, serverName, serverKey.PublicKey().Bytes(), shortID[:], wrongPubBytes, HelloChrome_133)
	if err != nil {
		t.Fatal(err)
	}
	if err := uConn2.Handshake(); err == nil {
		t.Fatal("expected handshake failure with mismatched mldsa65 public key")
	}
	uConn2.Close()
	if err := <-serverErr2; err == nil {
		t.Fatal("expected server error on aborted mismatched client")
	}

	// 3. Stalled client must abort cleanly when ctx deadline fires.
	serverErr3 := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr3 <- err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err = RealityServer(ctx, conn, rcfg)
		serverErr3 <- err
	}()
	cConn3, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cConn3.Close()
	start := time.Now()
	if err := <-serverErr3; err == nil {
		t.Fatal("expected timeout error for stalled client")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("expected prompt ctx timeout abort, took %v", elapsed)
	}
}

func TestRealityFallbackRateLimit(t *testing.T) {
	const serverName = "example.com"
	targetAddr, stopTarget := startMockRealityTarget(t, serverName)
	defer stopTarget()

	serverKey, err := ecdh.X25519().GenerateKey(stdRand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rcfg := &RealityConfig{
		DialContext:           (&net.Dialer{}).DialContext,
		Type:                  "tcp",
		Dest:                  targetAddr,
		ServerNames:           map[string]bool{serverName: true},
		PrivateKey:            serverKey.Bytes(),
		MaxTimeDiff:           time.Minute,
		ShortIds:              map[[8]byte]bool{{1, 2, 3, 4}: true},
		LimitFallbackUpload:   RealityLimitFallback{AfterBytes: 64, BytesPerSec: 16384, BurstBytesPerSec: 16384},
		LimitFallbackDownload: RealityLimitFallback{AfterBytes: 64, BytesPerSec: 16384, BurstBytesPerSec: 16384},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = RealityServer(ctx, conn, rcfg)
		serverErr <- err
	}()

	// Plain TLS client without REALITY SessionID triggers transparent fallback to target.
	cConn, err := stdtls.Dial("tcp", ln.Addr().String(), &stdtls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("fallback-echo-test")
	if _, err := cConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(cConn, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("expected %q, got %q", payload, echo)
	}
	cConn.Close()
	if err := <-serverErr; err == nil {
		t.Fatal("expected fallback error return from RealityServer")
	}
}
