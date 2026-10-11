package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// Several connections to one relay for one peer (omnuv, 11 October 2026).
//
// A relayed peer has one connection to its relay, and every stage of it is one
// goroutine: the write with its encryption, the relay's forward, the read.
// The slowest of them is the ceiling of everything two peers send each other,
// and it is well below a 1 Gbit/s line. Two relayed pairs side by side carry
// 1.6 times what one does (omnuv's docs/plans/multi-node-llm.md), so a pair
// given several connections of its own should gain the same.
//
// With NB_RELAY_LANES=n a peer keeps n-1 more connections to its home relay,
// each under a name of its own derived from its key ("<key>#lane<i>"); the
// relay's credential is not bound to a name, so the relay needs no change and
// sees n peers. A relayed connection to another peer is then a laneConn: the
// connection it always was, and a lane for each further one both ends open.
//
// A lane carries nothing until the peer has spoken on it. A hello is sent on
// each lane until one comes back; a peer that never answers (a client without
// lanes has no such name on the relay, so the lane never even opens) leaves
// the connection exactly what it was, written to and read from directly.
//
// Packets are spread over the lanes in short runs and arrive out of order
// across them. They are WireGuard's, and its data packets carry their counter
// in clear, so the receiver puts them back in order by it before WireGuard
// sees them: an earlier packet is waited for a few milliseconds and no more,
// since one that was lost never comes.

const (
	lanesEnv = "NB_RELAY_LANES"
	maxLanes = 8

	// laneOpenWait is how long a lane waits for the peer's end of it to reach
	// the relay. In the background: the connection itself is not held up.
	laneOpenWait = 15 * time.Second
	// laneQueueLen is a lane's packets waiting to be written. A full queue
	// holds the writer back; it drops nothing.
	laneQueueLen = 512
	// laneRun is how many packets one lane takes before the next has its turn.
	laneRun = 16
	// laneOutLen is the packets in order waiting to be read.
	laneOutLen = 2048

	laneHelloByte  = 0xF7 // WireGuard's own first bytes are 1 to 4
	laneHelloAsk   = 1
	laneHelloAck   = 2
	laneHelloEvery = 300 * time.Millisecond
	laneHelloTries = 60

	// sessionStart is how far into a session a first packet seen is still
	// taken for its beginning.
	sessionStart = 1024

	wgData       = 4
	wgDataHeader = 16
	lanePktCap   = 2048
)

var laneHelloMagic = [3]byte{'O', 'N', 'V'}

// reorderWindow is how many packets wait for an earlier one, and reorderWait
// how long, before the gap is given up as a loss.
//
// A lane over TCP loses nothing and delays everything behind a packet it has
// to send again, by a round trip or more, while the other lanes run on. Given
// up too early, those packets come late and the stream inside reads disorder;
// waited for, the stream stops for as long as one connection alone would have
// stopped. So the wait is of the order of a round trip to the relay and back,
// and the window is what several lanes carry in that time. What makes a wait
// end at all is the relay, which may drop a packet when a peer's queue is full.
var (
	reorderWindow = 4096
	reorderWait   = laneWait()
)

// laneWait is NB_RELAY_LANE_WAIT_MS, or 20 ms.
func laneWait() time.Duration {
	if n, err := strconv.Atoi(os.Getenv("NB_RELAY_LANE_WAIT_MS")); err == nil && n > 0 {
		return time.Duration(n) * time.Millisecond
	}
	return 20 * time.Millisecond
}

var lanePool = sync.Pool{New: func() any {
	b := make([]byte, 0, lanePktCap)
	return &b
}}

func lanePkt(p []byte) *[]byte {
	b := lanePool.Get().(*[]byte)
	*b = append((*b)[:0], p...)
	return b
}

// lanesWanted is NB_RELAY_LANES, between 1 (no lanes, the default) and maxLanes.
func lanesWanted() int {
	n, err := strconv.Atoi(os.Getenv(lanesEnv))
	if err != nil || n < 1 {
		return 1
	}
	if n > maxLanes {
		return maxLanes
	}
	return n
}

// laneKey is the name lane i (1 and up) of the peer with this key takes on the relay.
func laneKey(key string, i int) string {
	return fmt.Sprintf("%s#lane%d", key, i)
}

func isLaneHello(p []byte) bool {
	return len(p) == 5 && p[0] == laneHelloByte && p[1] == laneHelloMagic[0] && p[2] == laneHelloMagic[1] && p[3] == laneHelloMagic[2]
}

func laneHello(kind byte) []byte {
	return []byte{laneHelloByte, laneHelloMagic[0], laneHelloMagic[1], laneHelloMagic[2], kind}
}

type lane struct {
	conn  net.Conn
	q     chan *[]byte
	ready atomic.Bool // the peer has spoken on it
	dead  atomic.Bool
}

func (ln *lane) usable() bool { return ln.ready.Load() && !ln.dead.Load() }

// laneConn is a relayed connection to one peer over one or more lanes.
// lanes[0] is the connection a client without lanes would have, and until a
// second lane is ready it is used directly, as that client uses it.
type laneConn struct {
	log *log.Entry

	mu    sync.Mutex // guards changes to lanes
	lanes atomic.Pointer[[]*lane]
	turn  atomic.Uint64
	multi atomic.Bool // more than one lane is, or has been, in use

	out       chan *[]byte
	closed    chan struct{}
	closeOnce sync.Once

	order reorder
}

func newLaneConn(first net.Conn, entry *log.Entry) *laneConn {
	l := &laneConn{log: entry, out: make(chan *[]byte, laneOutLen), closed: make(chan struct{})}
	ln := &lane{conn: first, q: make(chan *[]byte, laneQueueLen)}
	ln.ready.Store(true)
	ls := []*lane{ln}
	l.lanes.Store(&ls)
	l.order.held = make(map[uint64]*[]byte)
	return l
}

// addLane takes a further connection to the same peer. It is read from now and
// written to once the peer has spoken on it.
func (l *laneConn) addLane(conn net.Conn) {
	ln := &lane{conn: conn, q: make(chan *[]byte, laneQueueLen)}
	l.mu.Lock()
	select {
	case <-l.closed:
		l.mu.Unlock()
		_ = conn.Close()
		return
	default:
	}
	old := *l.lanes.Load()
	ls := append(append(make([]*lane, 0, len(old)+1), old...), ln)
	l.lanes.Store(&ls)
	first := !l.multi.Swap(true)
	l.mu.Unlock()

	if first {
		// From here every lane is read by a goroutine of its own into the
		// order, and written by one from its queue.
		go l.reader(old[0], true)
		go l.writer(old[0], true)
		go l.flushLoop()
	}
	go l.reader(ln, false)
	go l.writer(ln, false)
	go l.hello(ln)
}

func (l *laneConn) hello(ln *lane) {
	t := time.NewTicker(laneHelloEvery)
	defer t.Stop()
	for i := 0; i < laneHelloTries && !ln.ready.Load() && !ln.dead.Load(); i++ {
		if _, err := ln.conn.Write(laneHello(laneHelloAsk)); err != nil {
			ln.dead.Store(true)
			return
		}
		select {
		case <-t.C:
		case <-l.closed:
			return
		}
	}
	if !ln.ready.Load() {
		l.log.Infof("relay lane to %s was never answered, left unused", ln.conn.RemoteAddr())
	}
}

func (l *laneConn) onHello(ln *lane, p []byte) {
	if !ln.ready.Swap(true) {
		l.log.Infof("relay lane to %s is answered, in use", ln.conn.RemoteAddr())
		// From now the peer may spread its packets at any moment, and the
		// first sign of it can be a gap on the first lane: gaps wait from here.
		l.order.mu.Lock()
		l.order.spread = true
		l.order.mu.Unlock()
	}
	if p[4] == laneHelloAsk {
		if _, err := ln.conn.Write(laneHello(laneHelloAck)); err != nil {
			ln.dead.Store(true)
		}
	}
}

func (l *laneConn) writer(ln *lane, first bool) {
	for {
		select {
		case b := <-ln.q:
			_, err := ln.conn.Write(*b)
			lanePool.Put(b)
			if err != nil {
				ln.dead.Store(true)
				if first {
					_ = l.Close()
				}
				return
			}
		case <-l.closed:
			return
		}
	}
}

func (l *laneConn) reader(ln *lane, first bool) {
	const batch = 32
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, lanePktCap)
	}
	br, batched := ln.conn.(BatchReader)
	for {
		n := 1
		var err error
		if batched {
			n, err = br.ReadBatch(bufs, sizes)
		} else {
			sizes[0], err = ln.conn.Read(bufs[0])
		}
		if err != nil || n == 0 {
			ln.dead.Store(true)
			if first {
				_ = l.Close()
			}
			return
		}
		for i := 0; i < n; i++ {
			p := bufs[i][:sizes[i]]
			if !first && isLaneHello(p) {
				l.onHello(ln, p)
				continue
			}
			l.order.push(l, p, !first)
		}
	}
}

// Write sends one packet to the peer, on the lane whose turn it is.
func (l *laneConn) Write(p []byte) (int, error) {
	ls := *l.lanes.Load()
	if !l.multi.Load() {
		return ls[0].conn.Write(p)
	}
	select {
	case <-l.closed:
		return 0, net.ErrClosed
	default:
	}
	k := int((l.turn.Add(1) - 1) / laneRun % uint64(len(ls)))
	for j := 0; j < len(ls); j++ {
		ln := ls[(k+j)%len(ls)]
		if !ln.usable() {
			continue
		}
		select {
		case ln.q <- lanePkt(p):
			return len(p), nil
		case <-l.closed:
			return 0, net.ErrClosed
		}
	}
	return 0, net.ErrClosed
}

func (l *laneConn) Read(b []byte) (int, error) {
	if !l.multi.Load() {
		return (*l.lanes.Load())[0].conn.Read(b)
	}
	select {
	case p := <-l.out:
		n := copy(b, *p)
		lanePool.Put(p)
		return n, nil
	case <-l.closed:
		return 0, net.ErrClosed
	}
}

// ReadBatch implements BatchReader: it blocks for one packet and takes what
// else is already in order.
func (l *laneConn) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if !l.multi.Load() {
		first := (*l.lanes.Load())[0].conn
		if br, ok := first.(BatchReader); ok {
			return br.ReadBatch(bufs, sizes)
		}
		n, err := first.Read(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		return 1, nil
	}
	var p *[]byte
	select {
	case p = <-l.out:
	case <-l.closed:
		return 0, net.ErrClosed
	}
	sizes[0] = copy(bufs[0], *p)
	lanePool.Put(p)
	n := 1
	for n < len(bufs) {
		select {
		case p = <-l.out:
			sizes[n] = copy(bufs[n], *p)
			lanePool.Put(p)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

func (l *laneConn) emit(b *[]byte) {
	select {
	case l.out <- b:
	case <-l.closed:
		lanePool.Put(b)
	}
}

func (l *laneConn) flushLoop() {
	t := time.NewTicker(time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			l.order.flushStale(l)
		case <-l.closed:
			return
		}
	}
}

// Close closes every lane. The first lane's close is the connection's.
func (l *laneConn) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.mu.Lock()
		close(l.closed)
		ls := *l.lanes.Load()
		l.mu.Unlock()
		for i, ln := range ls {
			if e := ln.conn.Close(); e != nil && i == 0 {
				err = e
			}
		}
	})
	return err
}

func (l *laneConn) first() net.Conn                    { return (*l.lanes.Load())[0].conn }
func (l *laneConn) LocalAddr() net.Addr                { return l.first().LocalAddr() }
func (l *laneConn) RemoteAddr() net.Addr               { return l.first().RemoteAddr() }
func (l *laneConn) SetDeadline(t time.Time) error      { return l.first().SetDeadline(t) }
func (l *laneConn) SetReadDeadline(t time.Time) error  { return l.first().SetReadDeadline(t) }
func (l *laneConn) SetWriteDeadline(t time.Time) error { return l.first().SetWriteDeadline(t) }

// reorder puts WireGuard's data packets back in the order of their counter.
// Anything else (a handshake, a cookie) passes at once, as does everything
// while no packet has come by a lane other than the first: a peer that does
// not spread its packets is not made to wait for the ones it lost. Its
// counter is followed all the same, so that the order is known the moment it
// begins to.
type reorder struct {
	mu      sync.Mutex
	spread  bool   // the peer has a further lane and may be spreading
	have    bool   // a session is being ordered
	idx     uint32 // its receiver index
	prev    uint32 // the session before it, whose stragglers pass at once
	next    uint64 // the counter expected next
	held    map[uint64]*[]byte
	since   time.Time // when the oldest gap began
	skipped uint64    // gaps given up, for the log
}

func (r *reorder) push(l *laneConn, p []byte, further bool) {
	b := lanePkt(p)
	if len(p) < wgDataHeader || p[0] != wgData {
		l.emit(b)
		return
	}
	idx := binary.LittleEndian.Uint32(p[4:8])
	ctr := binary.LittleEndian.Uint64(p[8:16])

	r.mu.Lock()
	defer r.mu.Unlock()
	if further {
		r.spread = true
	}
	if r.have && idx == r.prev && idx != r.idx {
		l.emit(b)
		return
	}
	if !r.have || idx != r.idx {
		r.release(l)
		r.prev, r.idx, r.next, r.have = r.idx, idx, ctr, true
		// A session counts from nothing, and its first packets may come by
		// several lanes at once: one seen early in it waits for those before
		// it. One seen far in (this end began to listen late) does not.
		if r.spread && ctr < sessionStart {
			r.next = 0
		}
	}
	if !r.spread {
		// Nothing is held, but the counter is followed: when the peer begins
		// to spread, what is expected next is already known, and a packet
		// that comes early by another lane waits for the ones before it.
		if ctr >= r.next {
			r.next = ctr + 1
		}
		l.emit(b)
		return
	}
	switch {
	case ctr == r.next:
		l.emit(b)
		r.next++
		r.drain(l)
	case ctr < r.next:
		l.emit(b)
	default:
		if len(r.held) == 0 {
			r.since = time.Now()
		}
		r.held[ctr] = b
		if len(r.held) > reorderWindow {
			r.skip(l)
		}
	}
}

// drain emits what is held from the expected counter on.
func (r *reorder) drain(l *laneConn) {
	for {
		b, ok := r.held[r.next]
		if !ok {
			break
		}
		delete(r.held, r.next)
		l.emit(b)
		r.next++
	}
	if len(r.held) > 0 {
		r.since = time.Now()
	}
}

// skip gives the gap up: the lowest packet held is the next.
func (r *reorder) skip(l *laneConn) {
	if len(r.held) == 0 {
		return
	}
	first := true
	var low uint64
	for c := range r.held {
		if first || c < low {
			low, first = c, false
		}
	}
	r.next = low
	r.skipped++
	r.drain(l)
}

// release emits everything held, lowest first, when a session ends.
func (r *reorder) release(l *laneConn) {
	for len(r.held) > 0 {
		r.skip(l)
	}
}

func (r *reorder) flushStale(l *laneConn) {
	r.mu.Lock()
	if len(r.held) > 0 && time.Since(r.since) > reorderWait {
		r.skip(l)
	}
	r.mu.Unlock()
}

// withLanes makes the connection to a peer one that further lanes can join,
// and opens them in the background. Without NB_RELAY_LANES it is the
// connection itself.
func (m *Manager) withLanes(first net.Conn, peerKey string) net.Conn {
	n := lanesWanted()
	if n < 2 {
		return first
	}
	lc := newLaneConn(first, log.WithField("peer", peerKey))
	for i := 1; i < n; i++ {
		go m.openLane(lc, peerKey, i)
	}
	return lc
}

func (m *Manager) openLane(lc *laneConn, peerKey string, i int) {
	c, err := m.laneClient(i)
	if err != nil {
		log.Infof("relay lane %d is not connected: %s", i, err)
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, laneOpenWait)
	defer cancel()
	conn, err := c.OpenConn(ctx, laneKey(peerKey, i))
	if err != nil {
		// A peer whose client has no lanes has no such name on the relay.
		log.Debugf("relay lane %d to %s did not open: %s", i, peerKey, err)
		return
	}
	lc.addLane(conn)
}

// laneClient is this peer's lane i to its home relay, connected.
func (m *Manager) laneClient(i int) (*Client, error) {
	m.relayClientMu.RLock()
	home := m.relayClient
	m.relayClientMu.RUnlock()
	if home == nil {
		return nil, ErrRelayClientNotConnected
	}

	m.lanesMu.Lock()
	defer m.lanesMu.Unlock()
	if m.lanes == nil {
		m.lanes = make(map[int]*Client)
	}
	c, ok := m.lanes[i]
	if !ok || c.connectionURL != home.connectionURL {
		if ok {
			_ = c.Close()
		}
		c = NewClientWithServerIP(home.connectionURL, home.serverIP, m.tokenStore, laneKey(m.peerID, i), m.mtu)
		c.SetTransportFallback(m.transportFallback)
		c.netEvents = m.netEvents
		m.lanes[i] = c
	}
	if err := c.Connect(m.ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// connectLanes brings this peer's lanes up as soon as its home relay is, so
// that a peer opening a connection to it finds them there.
func (m *Manager) connectLanes() {
	for i := 1; i < lanesWanted(); i++ {
		if _, err := m.laneClient(i); err != nil {
			log.Infof("relay lane %d is not connected: %s", i, err)
		}
	}
}
