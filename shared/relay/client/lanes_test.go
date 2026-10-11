package client

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// pktConn is one end of a packet connection made of two channels: what is
// written to one end is read, whole, at the other.
type pktConn struct {
	in, out chan []byte
	once    sync.Once
	done    chan struct{}
}

func pktPair() (*pktConn, *pktConn) {
	ab, ba := make(chan []byte, 4096), make(chan []byte, 4096)
	return &pktConn{in: ba, out: ab, done: make(chan struct{})}, &pktConn{in: ab, out: ba, done: make(chan struct{})}
}

func (c *pktConn) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	select {
	case c.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *pktConn) Read(b []byte) (int, error) {
	select {
	case p := <-c.in:
		return copy(b, p), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *pktConn) Close() error                     { c.once.Do(func() { close(c.done) }); return nil }
func (c *pktConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *pktConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *pktConn) SetDeadline(time.Time) error      { return nil }
func (c *pktConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pktConn) SetWriteDeadline(time.Time) error { return nil }

// data is a WireGuard data packet of the session idx with the counter ctr.
func data(idx uint32, ctr uint64) []byte {
	p := make([]byte, 64)
	p[0] = wgData
	binary.LittleEndian.PutUint32(p[4:8], idx)
	binary.LittleEndian.PutUint64(p[8:16], ctr)
	return p
}

func counter(p []byte) uint64 { return binary.LittleEndian.Uint64(p[8:16]) }

func entry() *log.Entry { return log.WithField("test", "lanes") }

func readN(t *testing.T, c net.Conn, n int, within time.Duration) [][]byte {
	t.Helper()
	got := make(chan []byte, n)
	go func() {
		buf := make([]byte, lanePktCap)
		for i := 0; i < n; i++ {
			k, err := c.Read(buf)
			if err != nil {
				return
			}
			got <- append([]byte(nil), buf[:k]...)
		}
	}()
	var out [][]byte
	deadline := time.After(within)
	for len(out) < n {
		select {
		case p := <-got:
			out = append(out, p)
		case <-deadline:
			t.Fatalf("read %d of %d packets in %s", len(out), n, within)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

// linked is two laneConns joined by `lanes` connections, the first included.
func linked(lanes int) (*laneConn, *laneConn, []*pktConn) {
	a0, b0 := pktPair()
	a, b := newLaneConn(a0, entry()), newLaneConn(b0, entry())
	far := []*pktConn{b0}
	for i := 1; i < lanes; i++ {
		ai, bi := pktPair()
		a.addLane(ai)
		b.addLane(bi)
		far = append(far, bi)
	}
	return a, b, far
}

func usable(l *laneConn) int {
	n := 0
	for _, ln := range *l.lanes.Load() {
		if ln.usable() {
			n++
		}
	}
	return n
}

func TestLanesWanted(t *testing.T) {
	for v, want := range map[string]int{"": 1, "0": 1, "-3": 1, "x": 1, "1": 1, "3": 3, "8": 8, "99": maxLanes} {
		t.Setenv(lanesEnv, v)
		if got := lanesWanted(); got != want {
			t.Errorf("NB_RELAY_LANES=%q: %d lanes, want %d", v, got, want)
		}
	}
	if laneKey("k", 1) == laneKey("k", 2) || laneKey("k", 1) == "k" {
		t.Error("two lanes, or a lane and the peer itself, share a name")
	}
}

// One connection and no lane: read and written directly, nothing held, and
// no hello ever reaches the other end.
func TestOneLaneIsTheConnectionItself(t *testing.T) {
	a, b, _ := linked(1)
	defer a.Close()
	defer b.Close()
	for i := uint64(0); i < 50; i++ {
		if _, err := a.Write(data(7, 49-i)); err != nil {
			t.Fatal(err)
		}
	}
	got := readN(t, b, 50, 2*time.Second)
	for i, p := range got {
		if counter(p) != uint64(49-i) {
			t.Fatalf("packet %d has counter %d: a single connection was reordered", i, counter(p))
		}
	}
	if a.multi.Load() || b.multi.Load() {
		t.Fatal("a connection with one lane was treated as several")
	}
}

// Three lanes, both ends answering: all three carry, and what was written in
// order is read in order though it crossed three ways.
func TestLanesCarryInOrder(t *testing.T) {
	// Nothing is lost between these ends, so no gap is ever a loss: with a
	// wait this long the order must be exact however the goroutines run.
	defer func(d time.Duration) { reorderWait = d }(reorderWait)
	reorderWait = 10 * time.Second
	defer func(n int) { reorderWindow = n }(reorderWindow)
	reorderWindow = 1 << 20
	a, b, _ := linked(3)
	defer a.Close()
	defer b.Close()
	waitFor(t, "three lanes answered at each end", func() bool { return usable(a) == 3 && usable(b) == 3 })

	const n = 20000
	go func() {
		for i := uint64(0); i < n; i++ {
			_, _ = a.Write(data(9, i))
		}
	}()
	got := readN(t, b, n, 20*time.Second)
	for i, p := range got {
		if isLaneHello(p) {
			t.Fatal("a hello reached the reader")
		}
		if counter(p) != uint64(i) {
			t.Fatalf("packet %d has counter %d", i, counter(p))
		}
	}
}

// A lane whose far end never speaks is never written to.
func TestALaneNeverAnsweredCarriesNothing(t *testing.T) {
	a0, b0 := pktPair()
	a := newLaneConn(a0, entry())
	defer a.Close()
	silent, far := pktPair() // the far end is open, and nobody reads or answers on it
	a.addLane(silent)
	for i := uint64(0); i < 200; i++ {
		if _, err := a.Write(data(3, i)); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, lanePktCap)
	for i := 0; i < 200; i++ {
		k, err := b0.Read(buf)
		if err != nil || counter(buf[:k]) != uint64(i) {
			t.Fatalf("packet %d on the first lane: %v", i, err)
		}
	}
	for {
		select {
		case p := <-far.in:
			if !isLaneHello(p) {
				t.Fatalf("a packet was written to a lane nobody answered on: % x", p[:8])
			}
			continue
		default:
		}
		break
	}
}

// A packet lost on the way is waited for briefly and then given up: the ones
// after it are not held back for good.
func TestALostPacketIsNotWaitedForLong(t *testing.T) {
	defer func(d time.Duration) { reorderWait = d }(reorderWait)
	reorderWait = 3 * time.Millisecond
	a, b, far := linked(2)
	defer a.Close()
	defer b.Close()
	waitFor(t, "two lanes answered", func() bool { return usable(a) == 2 && usable(b) == 2 })
	_ = far
	// Written past the laneConn, straight onto the lanes, with counter 5 missing.
	ls := *a.lanes.Load()
	// The later packets first and by the other lane, so that they wait for
	// the earlier ones, which follow by the first.
	_, _ = ls[0].conn.Write(data(11, 0))
	first := readN(t, b, 1, 2*time.Second)
	for _, c := range []uint64{6, 7, 8, 9} {
		_, _ = ls[1].conn.Write(data(11, c))
	}
	time.Sleep(time.Millisecond)
	for _, c := range []uint64{1, 2, 3, 4} {
		_, _ = ls[0].conn.Write(data(11, c))
	}
	start := time.Now()
	got := append(first, readN(t, b, 8, 2*time.Second)...)
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("a lost packet held the rest for %s", waited)
	}
	want := []uint64{0, 1, 2, 3, 4, 6, 7, 8, 9}
	for i, p := range got {
		if counter(p) != want[i] {
			t.Fatalf("packet %d has counter %d, want %d", i, counter(p), want[i])
		}
	}
}

// What is not a data packet (a handshake) is never held, and a new session
// does not wait for the old one's counters.
func TestHandshakesAndNewSessionsPass(t *testing.T) {
	a, b, _ := linked(2)
	defer a.Close()
	defer b.Close()
	waitFor(t, "two lanes answered", func() bool { return usable(a) == 2 && usable(b) == 2 })
	ls := *a.lanes.Load()
	_, _ = ls[1].conn.Write(data(21, 1000)) // the session's first packet seen sets what is expected
	_, _ = ls[1].conn.Write(data(21, 1002)) // held: 1001 is missing
	_, _ = ls[0].conn.Write([]byte{1, 0, 0, 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}) // a handshake
	_, _ = ls[0].conn.Write(data(22, 0))                                                           // a new session
	// The two lanes are read by two goroutines, so which of them is first is
	// not defined; what is, is that all four come out, the held one among them.
	got := readN(t, b, 4, 2*time.Second)
	seenFirst, seenHandshake, seenNew, seenHeld := false, false, false, false
	for _, p := range got {
		switch {
		case p[0] == 1:
			seenHandshake = true
		case binary.LittleEndian.Uint32(p[4:8]) == 22:
			seenNew = true
		case counter(p) == 1000:
			seenFirst = true
		case counter(p) == 1002:
			seenHeld = true
		}
	}
	if !seenFirst || !seenHandshake || !seenNew || !seenHeld {
		t.Fatalf("the first %v, the handshake %v, the new session %v, the old session's held packet %v", seenFirst, seenHandshake, seenNew, seenHeld)
	}
}

// Closing the connection closes every lane under it.
func TestCloseClosesEveryLane(t *testing.T) {
	a, b, far := linked(3)
	defer b.Close()
	waitFor(t, "three lanes answered", func() bool { return usable(a) == 3 })
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	for i, ln := range *a.lanes.Load() {
		if _, err := ln.conn.Write([]byte{1}); err == nil {
			t.Errorf("lane %d is still open", i)
		}
	}
	if _, err := a.Write(data(1, 1)); err == nil {
		t.Error("a closed connection took a packet")
	}
	_ = far
}
