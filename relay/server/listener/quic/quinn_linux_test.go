//go:build linux && (amd64 || arm64)

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	goquic "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func nativeQuinnListener(t *testing.T) (*Listener, *tls.Config) {
	t.Helper()
	if os.Getenv(EnvQuinnLibrary) == "" {
		t.Skip("explicit native Quinn library required")
	}
	t.Setenv(EnvQUICBackend, "quinn")
	cfg := testTLSConfig(t)
	l := &Listener{Address: "127.0.0.1:0", TLSConfig: cfg}
	require.NoError(t, l.Bind())
	t.Cleanup(func() {
		require.NoError(t, l.Shutdown(context.Background()))
		requireUDPAddressFree(t, l.listener.Addr().String())
	})
	return l, cfg
}
func verifiedGoClient(t *testing.T, l *Listener, cfg *tls.Config) *goquic.Conn {
	t.Helper()
	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	require.NoError(t, err)
	roots.AddCert(cert)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := goquic.DialAddr(ctx, l.listener.Addr().String(), &tls.Config{RootCAs: roots, NextProtos: cfg.NextProtos}, &goquic.Config{EnableDatagrams: true, InitialPacketSize: 1232})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.CloseWithError(0, "") })
	return c
}
func TestQuinnVerifiedDatagramInterop(t *testing.T) {
	l, cfg := nativeQuinnListener(t)
	client := verifiedGoClient(t, l, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := l.listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	for _, size := range []int{0, 1, 1150} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		require.NoError(t, client.SendDatagram(payload))
		b := make([]byte, 2000)
		n, err := server.Read(ctx, b)
		require.NoError(t, err)
		require.Equal(t, payload, b[:n], "Go to Quinn size=%d", size)
		n, err = server.Write(ctx, payload)
		require.NoError(t, err)
		require.Equal(t, size, n)
		clear(payload)
		got, err := client.ReceiveDatagram(ctx)
		require.NoError(t, err)
		require.Equal(t, bytes.Repeat([]byte{byte(size)}, size), got, "Quinn must own sent bytes size=%d", size)
	}
	_, err = server.Write(ctx, make([]byte, 64*1024))
	require.Error(t, err, "oversized DATAGRAM must fail")
	require.NoError(t, server.Close())
	_, err = server.Read(ctx, make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)
}
func TestQuinnReadCancellationAndClose(t *testing.T) {
	l, cfg := nativeQuinnListener(t)
	_ = verifiedGoClient(t, l, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := l.listener.Accept(ctx)
	require.NoError(t, err)
	native := server.(*quinnConn)
	short, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { _, err := server.Read(short, make([]byte, 2000)); done <- err }()
	waitForQuinnRead(t, native.id)
	stop()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-ctx.Done():
		t.Fatal("Quinn read did not cancel")
	}
	go func() { _, err := server.Read(ctx, make([]byte, 2000)); done <- err }()
	waitForQuinnRead(t, native.id)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := server.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-done:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-ctx.Done():
		t.Fatal("Quinn close did not unblock read")
	}
}
func TestQuinnTLSRejectsUntrustedCertificate(t *testing.T) {
	l, cfg := nativeQuinnListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := goquic.DialAddr(ctx, l.listener.Addr().String(), &tls.Config{RootCAs: x509.NewCertPool(), NextProtos: cfg.NextProtos}, &goquic.Config{EnableDatagrams: true})
	require.Error(t, err, "untrusted certificate must fail")
	var unknown x509.UnknownAuthorityError
	require.True(t, errors.As(err, &unknown), "failure must be certificate trust: %v", err)
}
func TestQuinnTLSRejectsWrongALPN(t *testing.T) {
	l, cfg := nativeQuinnListener(t)
	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	require.NoError(t, err)
	roots.AddCert(cert)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = goquic.DialAddr(ctx, l.listener.Addr().String(), &tls.Config{RootCAs: roots, NextProtos: []string{"wrong-relay-protocol"}}, &goquic.Config{EnableDatagrams: true})
	require.Error(t, err, "ALPN mismatch must fail")
	snapshot, snapshotErr := QuinnSnapshot()
	require.NoError(t, snapshotErr)
	var stats struct {
		Listeners []struct {
			Error string `json:"last_handshake_error"`
		} `json:"listeners"`
	}
	require.NoError(t, json.Unmarshal(snapshot, &stats))
	require.Len(t, stats.Listeners, 1)
	require.Contains(t, stats.Listeners[0].Error, "peer doesn't support any known protocol", "native TLS must reject ALPN, not merely time out")
}
func TestQuinnRejectsUnsupportedTLSConfiguration(t *testing.T) {
	cfg := testTLSConfig(t)
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cfg.Certificates[0], nil }
	_, err := quinnTLSBlob("127.0.0.1:0", cfg)
	require.Error(t, err, "dynamic TLS callbacks cannot be silently ignored")
	cfg.GetCertificate = nil
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	_, err = quinnTLSBlob("127.0.0.1:0", cfg)
	require.Error(t, err, "client-auth policy cannot be silently ignored")
}
func TestListenerRejectsUnknownBackend(t *testing.T) {
	t.Setenv(EnvQUICBackend, "invalid-backend")
	l := &Listener{Address: "127.0.0.1:0", TLSConfig: testTLSConfig(t)}
	require.Error(t, l.Bind(), "unknown backend must fail without fallback")
}

func waitForQuinnRead(t *testing.T, id uint64) {
	t.Helper()
	require.Eventually(t, func() bool {
		data, err := QuinnSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		var stats struct {
			Connections []struct {
				ID          uint64 `json:"id"`
				ReadWaiters uint64 `json:"read_waiters"`
			} `json:"connections"`
		}
		if err = json.Unmarshal(data, &stats); err != nil {
			t.Fatal(err)
		}
		for _, c := range stats.Connections {
			if c.ID == id {
				return c.ReadWaiters > 0
			}
		}
		return false
	}, 5*time.Second, time.Millisecond, "native read must be waiting before cancellation/close")
}

func TestQuinnBurstDeliveryAndConcurrentWriters(t *testing.T) {
	l, cfg := nativeQuinnListener(t)
	client := verifiedGoClient(t, l, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := l.listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	for i := 0; i < 32; i++ {
		require.NoError(t, client.SendDatagram(bytes.Repeat([]byte{byte(i)}, 100)))
	}
	for i := 0; i < 32; i++ {
		b := make([]byte, 2000)
		n, err := server.Read(ctx, b)
		require.NoError(t, err)
		require.Equal(t, bytes.Repeat([]byte{byte(i)}, 100), b[:n], "receive batch must preserve each payload")
	}
	received := make(chan error, 1)
	go func() {
		seen := make(map[byte]bool)
		for i := 0; i < 64; i++ {
			b, e := client.ReceiveDatagram(ctx)
			if e != nil {
				received <- e
				return
			}
			if len(b) != 100 || seen[b[0]] || !bytes.Equal(b, bytes.Repeat(b[:1], 100)) {
				received <- errors.New("corrupt or duplicate native send")
				return
			}
			seen[b[0]] = true
		}
		received <- nil
	}()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(base byte) {
			defer wg.Done()
			for j := byte(0); j < 8; j++ {
				b := bytes.Repeat([]byte{base + j}, 100)
				_, e := server.Write(ctx, b)
				if e != nil {
					t.Error(e)
					return
				}
				clear(b)
			}
		}(byte(i * 8))
	}
	wg.Wait()
	require.NoError(t, <-received, "native async sender must retain its own payload bytes")
}
func TestQuinnWildcardAddress(t *testing.T) {
	if os.Getenv(EnvQuinnLibrary) == "" {
		t.Skip("explicit native Quinn library required")
	}
	l, err := newQuinnListener(":0", testTLSConfig(t))
	require.NoError(t, err)
	require.NotZero(t, l.Addr().(*net.UDPAddr).Port)
	require.NoError(t, l.Close())
	requireUDPAddressFree(t, l.Addr().String())
}

func TestQuinnCloseDuringConcurrentWrites(t *testing.T) {
	l, cfg := nativeQuinnListener(t)
	_ = verifiedGoClient(t, l, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := l.listener.Accept(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	started := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 1150)
			for n := 0; ; n++ {
				_, err := server.Write(ctx, b)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("concurrent writer after close: %v", err)
					}
					return
				}
				if n == 0 {
					started <- struct{}{}
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("writers did not enter native sender")
		}
	}
	require.NoError(t, server.Close())
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("native close did not unblock writers")
	}
}

// Every connection of a listener shares its socket, so each must be served
// with its own state: a decrypting receive thread with one connection's keys
// lost most of the others' packets, and one waker lost the others' turns.
func TestQuinnConcurrentConnectionsEcho(t *testing.T) {
	l, cfg := nativeQuinnListener(t)
	const clients, rounds = 4, 300
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conns := make([]*goquic.Conn, clients)
	for i := range conns {
		conns[i] = verifiedGoClient(t, l, cfg)
	}
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		server, err := l.listener.Accept(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = server.Close() })
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 2000)
			for j := 0; j < rounds; j++ {
				n, err := server.Read(ctx, b)
				if err != nil {
					return
				}
				if _, err := server.Write(ctx, b[:n]); err != nil {
					return
				}
			}
		}()
	}
	errs := make(chan error, clients)
	for i, c := range conns {
		go func() {
			for j := 0; j < rounds; j++ {
				payload := []byte(fmt.Sprintf("client %d round %d %s", i, j, bytes.Repeat([]byte{'x'}, 900)))
				if err := c.SendDatagram(payload); err != nil {
					errs <- fmt.Errorf("client %d round %d send: %w", i, j, err)
					return
				}
				rctx, rcancel := context.WithTimeout(ctx, 2*time.Second)
				got, err := c.ReceiveDatagram(rctx)
				rcancel()
				if err != nil {
					errs <- fmt.Errorf("client %d round %d: no echo: %w", i, j, err)
					return
				}
				if !bytes.Equal(got, payload) {
					errs <- fmt.Errorf("client %d round %d: echo differs", i, j)
					return
				}
			}
			errs <- nil
		}()
	}
	for range conns {
		require.NoError(t, <-errs)
	}
	wg.Wait()
}
