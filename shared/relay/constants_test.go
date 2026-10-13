package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestInitialPacketSizeFromEnv(t *testing.T) {
	for _, c := range []struct {
		env  string
		want uint16
	}{
		{"", 1232},
		{"1350", 1350},
		{"1200", 1200},
		{"1452", 1452},
		// The nearest values it must refuse: one under and one over what
		// the library takes, and something that is no number.
		{"1199", 1232},
		{"1453", 1232},
		{"1350 ", 1232},
		{"large", 1232},
	} {
		t.Setenv(EnvQUICInitialPacketSize, c.env)
		if got := InitialPacketSize(); got != c.want {
			t.Errorf("%s=%q: got %d, want %d", EnvQUICInitialPacketSize, c.env, got, c.want)
		}
	}
}

// A full packet of the overlay at an MTU of 1240, as the relay's client hands
// it to QUIC: 1240, WireGuard's 32 and the relay's transport header of 38.
const fullRelayedPacket = 1240 + 32 + 38

// A connection that never finds its path's packet size keeps the size it
// started at. Path discovery is switched off here to make that connection on
// purpose: started at 1232 it refuses every full packet, started at 1350 it
// carries them. The same library, the same datagram, the one number changed.
func TestAConnectionThatFindsNoLargerSizeCarriesAFullPacketOnlyFromALargerStart(t *testing.T) {
	for _, c := range []struct {
		start   uint16
		carries bool
	}{
		{QUICInitialPacketSize, false},
		{1346, false}, // one byte short: 1346-37 is 1309
		{1347, true},
		{1350, true},
	} {
		err := sendOneDatagram(t, c.start, fullRelayedPacket)
		var tooLarge *quic.DatagramTooLargeError
		switch {
		case c.carries && err != nil:
			t.Errorf("started at %d: a %d-byte datagram was refused: %v", c.start, fullRelayedPacket, err)
		case !c.carries && !errors.As(err, &tooLarge):
			t.Errorf("started at %d: a %d-byte datagram was not refused as too large: %v", c.start, fullRelayedPacket, err)
		case !c.carries && tooLarge.MaxDatagramPayloadSize != int64(c.start)-37:
			t.Errorf("started at %d: the budget is %d, want %d", c.start, tooLarge.MaxDatagramPayloadSize, int64(c.start)-37)
		}
	}
}

// sendOneDatagram dials a listener of its own over loopback, both ends started
// at the given packet size with path discovery off, sends one datagram of n
// bytes and waits for it at the other end.
func sendOneDatagram(t *testing.T, start uint16, n int) error {
	t.Helper()
	cfg := &quic.Config{EnableDatagrams: true, InitialPacketSize: start, DisablePathMTUDiscovery: true}
	ln, err := quic.ListenAddr("127.0.0.1:0", selfSigned(t), cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := make(chan int, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		b, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		got <- len(b)
	}()

	conn, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"onv-test"}}, cfg) //nolint:gosec
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()

	if err := conn.SendDatagram(make([]byte, n)); err != nil {
		return err
	}
	select {
	case size := <-got:
		if size != n {
			t.Fatalf("started at %d: %d bytes arrived of %d sent", start, size, n)
		}
		return nil
	case <-ctx.Done():
		t.Fatalf("started at %d: the datagram was accepted and never arrived", start)
		return nil
	}
}

func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "onv-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"onv-test"},
	}
}
