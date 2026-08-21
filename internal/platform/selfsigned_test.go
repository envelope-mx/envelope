package platform_test

import (
	"crypto/tls"
	"io"
	"testing"

	"github.com/isaiahiroko/envelope/internal/platform"
)

func TestSelfSignedTLSConfigHandshakes(t *testing.T) {
	cfg, err := platform.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatalf("SelfSignedTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("hello"))
	}()

	clientConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer clientConn.Close()

	buf := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("got %q, want %q", buf, "hello")
	}
	<-done
}

// TestSelfSignedTLSConfigRejectsBelowTLS12 proves NFR-SEC-1 with a real
// handshake attempt, not just an assertion on the Config struct's field:
// a client capped at TLS 1.1 must be refused.
func TestSelfSignedTLSConfigRejectsBelowTLS12(t *testing.T) {
	cfg, err := platform.SelfSignedTLSConfig("localhost")
	if err != nil {
		t.Fatalf("SelfSignedTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Drive the handshake so the server side observes and rejects the
		// client's max version; ignore the (expected) resulting error.
		_ = conn.(*tls.Conn).Handshake()
	}()

	_, err = tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
	})
	if err == nil {
		t.Fatal("expected a TLS 1.1-capped client to be rejected by a MinVersion: TLS 1.2 server")
	}
}
