//go:build linux

package net

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func pacingOf(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	v, err := getSockoptInt(raw, unix.SO_MAX_PACING_RATE)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func sendBufferOf(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	v, err := getSockoptInt(raw, unix.SO_SNDBUF)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestBoundPacedRelaySocket(t *testing.T) {
	listen := func(t *testing.T) *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		// As the QUIC library leaves it: far larger than what a paced socket is to have.
		if err := conn.SetWriteBuffer(1 << 20); err != nil {
			t.Fatal(err)
		}
		return conn
	}

	t.Run("a paced socket's send buffer is brought down", func(t *testing.T) {
		t.Setenv(relayPaceEnv, "700")
		conn := listen(t)
		before := sendBufferOf(t, conn)
		BoundPacedRelaySocket(conn)
		// The kernel reports twice what it was asked for.
		if got := sendBufferOf(t, conn); got != 2*pacedRelaySendBuffer || got >= before {
			t.Fatalf("the send buffer is %d bytes (was %d), want %d", got, before, 2*pacedRelaySendBuffer)
		}
	})
	t.Run("a socket not paced keeps its send buffer", func(t *testing.T) {
		t.Setenv(relayPaceEnv, "")
		os.Unsetenv(relayPaceEnv)
		conn := listen(t)
		before := sendBufferOf(t, conn)
		BoundPacedRelaySocket(conn)
		if got := sendBufferOf(t, conn); got != before {
			t.Fatalf("the send buffer moved from %d to %d with no pacing asked", before, got)
		}
	})
}

func TestPaceRelaySocket(t *testing.T) {
	listen := func(t *testing.T) *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}

	t.Run("the socket takes the rate asked", func(t *testing.T) {
		t.Setenv(relayPaceEnv, "700")
		conn := listen(t)
		PaceRelaySocket(conn)
		if got := pacingOf(t, conn); got != 87500000 {
			t.Fatalf("the socket's pacing rate is %d bytes/s, want 87500000", got)
		}
	})
	t.Run("with none asked the socket is as it was made", func(t *testing.T) {
		t.Setenv(relayPaceEnv, "")
		os.Unsetenv(relayPaceEnv)
		conn := listen(t)
		before := pacingOf(t, conn)
		PaceRelaySocket(conn)
		if got := pacingOf(t, conn); got != before {
			t.Fatalf("the socket's pacing rate moved from %d to %d with none asked", before, got)
		}
		if before == 87500000 {
			t.Fatalf("a new socket already reports the test's rate: the test above proves nothing")
		}
	})
	t.Run("a connection of our own kind is paced too", func(t *testing.T) {
		t.Setenv(relayPaceEnv, "700")
		conn := listen(t)
		PaceRelaySocket(&UDPConn{UDPConn: conn})
		if got := pacingOf(t, conn); got != 87500000 {
			t.Fatalf("the wrapped socket's pacing rate is %d bytes/s, want 87500000", got)
		}
	})
}
