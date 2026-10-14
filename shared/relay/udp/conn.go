package udp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

// Timers are the waits of one attempt and of a connection in service. None
// of them delays a pair: it is up on the QUIC relay while this runs.
type Timers struct {
	// Allocate bounds one request to the relay's API.
	Allocate time.Duration
	// Rebind is how often a bind is sent again until the path is proved. The
	// relay never says a bind succeeded, and one lost packet must not cost
	// the attempt.
	Rebind time.Duration
	// Attempt bounds the whole of Dial, allocation to proof. Under the 30 s
	// the relay keeps an allocation nobody bound.
	Attempt time.Duration
	// Ping is the period of the ping a connection in service sends its peer.
	Ping time.Duration
	// Missed is how many Ping periods may pass with nothing received before
	// the connection is closed as dead. The relay does not say it forgot an
	// endpoint: silence is the only sign.
	Missed int
}

// DefaultTimers are unmeasured, and say so in docs/plans/udp-relay.md.
func DefaultTimers() Timers {
	return Timers{Allocate: 3 * time.Second, Rebind: 500 * time.Millisecond, Attempt: 10 * time.Second, Ping: 5 * time.Second, Missed: 3}
}

// Config is one pair's attempt at the relay.
type Config struct {
	// APIURL is the relay's allocation API: https://host:port.
	APIURL string
	// Token returns NetBird's relay token as its relay client sends it.
	Token func() []byte
	// Key is this client's relay key, Peer the other's public half.
	Key  *Key
	Peer [keyLen]byte
	// HTTP asks the API. Nil: a client of its own, with the system's roots.
	HTTP *http.Client
	// ListenPacket opens the socket packets are relayed on. Nil: the
	// standard library's. A client that routes its own traffic gives the one
	// that keeps this socket out of the tunnel.
	ListenPacket func(ctx context.Context, network, address string) (net.PacketConn, error)
	Timers       Timers
	Logf         func(format string, args ...any)
}

var (
	// ErrRefused is the API refusing the request: trying again at once will
	// be refused again.
	ErrRefused = errors.New("the relay refused the allocation")
	// ErrDead is a connection closed because nothing arrived for Ping*Missed.
	ErrDead = errors.New("nothing received through the relay")
)

type endpoint struct {
	serverKey [keyLen]byte
	vni       uint32
	addrs     []netip.AddrPort
}

type allocateRequest struct {
	Keys [2]string `json:"keys"`
}

type allocateResponse struct {
	ServerKey string   `json:"server_key"`
	VNI       uint32   `json:"vni"`
	Addrs     []string `json:"addrs"`
}

// allocate asks the relay for the pair's endpoint. Both peers ask, and the
// relay gives both the same one: it is keyed on the two keys.
func allocate(ctx context.Context, cfg *Config) (*endpoint, error) {
	mine := cfg.Key.Public()
	body, err := json.Marshal(allocateRequest{Keys: [2]string{
		base64.StdEncoding.EncodeToString(mine[:]),
		base64.StdEncoding.EncodeToString(cfg.Peer[:]),
	}})
	if err != nil {
		return nil, err
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{}
	}
	for {
		reqCtx, cancel := context.WithTimeout(ctx, cfg.Timers.Allocate)
		ep, retry, err := allocateOnce(reqCtx, client, cfg, body)
		cancel()
		if err == nil {
			return ep, nil
		}
		if retry <= 0 {
			return nil, err
		}
		select {
		case <-time.After(retry):
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (last: %v)", ctx.Err(), err)
		}
	}
}

func allocateOnce(ctx context.Context, client *http.Client, cfg *Config, body []byte) (*endpoint, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.APIURL+"/v1/allocate", bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(cfg.Token()))
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ask the relay's API: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		after, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		if after <= 0 {
			after = 3
		}
		return nil, time.Duration(after) * time.Second, errors.New("the relay is not ready")
	case resp.StatusCode != http.StatusOK:
		return nil, 0, fmt.Errorf("%w: %d %s", ErrRefused, resp.StatusCode, bytes.TrimSpace(raw))
	}
	var ar allocateResponse
	if err := json.Unmarshal(raw, &ar); err != nil {
		return nil, 0, fmt.Errorf("the relay's answer: %w", err)
	}
	sk, err := base64.StdEncoding.DecodeString(ar.ServerKey)
	if err != nil || len(sk) != keyLen || ar.VNI == 0 || ar.VNI >= 1<<24 {
		return nil, 0, errors.New("the relay's answer names no key or no VNI")
	}
	ep := &endpoint{serverKey: [keyLen]byte(sk), vni: ar.VNI}
	for _, s := range ar.Addrs {
		ap, err := netip.ParseAddrPort(s)
		if err == nil && ap.Addr().Is4() { // the socket below is IPv4
			ep.addrs = append(ep.addrs, ap)
		}
	}
	if len(ep.addrs) == 0 {
		return nil, 0, errors.New("the relay's answer names no IPv4 address")
	}
	return ep, 0, nil
}

// addrPortConn is what *net.UDPConn has beyond net.PacketConn: reads and
// writes that allocate no address.
type addrPortConn interface {
	ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error)
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

// Conn is one pair's path through the relay, proved in both directions
// before Dial returns it. Read and Write carry WireGuard packets.
type Conn struct {
	pc   net.PacketConn
	fast addrPortConn // pc itself, when it can; nil otherwise

	key          *Key
	peer         [keyLen]byte
	serverKey    [keyLen]byte
	serverShared *[keyLen]byte
	peerShared   *[keyLen]byte
	vni          uint32
	relay        netip.AddrPort
	relayAddr    *net.UDPAddr
	timers       Timers
	logf         func(string, ...any)

	lastRx    atomic.Int64 // unix nanoseconds of the last packet of any kind
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error

	rbuf  []byte
	wpool sync.Pool
	// batch reads several datagrams a system call (recvmmsg), for ReadBatch;
	// nil when the socket is not one it can read.
	batch *ipv4.PacketConn
	msgs  []ipv4.Message
	// gro is set when the kernel coalesces datagrams for this socket;
	// pending holds the packets of the last batch not handed out yet. They
	// point into msgs, which is read again only when pending is empty.
	gro     bool
	pending [][]byte

	// Counters, read by Stats.
	rxPackets, txPackets, rxOther atomic.Uint64
	// rxCoalesced counts buffers that held more than one datagram.
	rxCoalesced atomic.Uint64
}

// Dial allocates the pair's endpoint, binds this side to it, and returns once
// a packet from the peer has crossed the relay: its pong, or its data. Until
// then nothing proves the peer bound too, and the relay drops data.
func Dial(ctx context.Context, cfg Config) (*Conn, error) {
	if cfg.Key == nil || cfg.Token == nil || cfg.APIURL == "" {
		return nil, errors.New("udp relay: no key, token or API")
	}
	if cfg.Timers == (Timers{}) {
		cfg.Timers = DefaultTimers()
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timers.Attempt)
	defer cancel()

	ep, err := allocate(ctx, &cfg)
	if err != nil {
		return nil, err
	}
	listen := cfg.ListenPacket
	if listen == nil {
		listen = (&net.ListenConfig{}).ListenPacket
	}
	pc, err := listen(ctx, "udp4", ":0")
	if err != nil {
		return nil, fmt.Errorf("open the relayed socket: %w", err)
	}
	c := &Conn{
		pc:           pc,
		key:          cfg.Key,
		peer:         cfg.Peer,
		serverKey:    ep.serverKey,
		serverShared: cfg.Key.shared(ep.serverKey),
		peerShared:   cfg.Key.shared(cfg.Peer),
		vni:          ep.vni,
		timers:       cfg.Timers,
		logf:         cfg.Logf,
		closed:       make(chan struct{}),
		rbuf:         make([]byte, 65535),
	}
	c.fast, _ = pc.(addrPortConn)
	if _, ok := pc.(syscall.Conn); ok {
		c.batch = ipv4.NewPacketConn(pc)
		c.msgs = make([]ipv4.Message, readBatchSize)
		for i := range c.msgs {
			c.msgs[i].Buffers = [][]byte{make([]byte, readBatchBuffer)}
		}
	}
	c.wpool.New = func() any { b := make([]byte, 0, 2048); return &b }
	if err := c.establish(ctx, ep.addrs); err != nil {
		_ = pc.Close()
		return nil, err
	}
	// After the handshake, which reads one datagram at a time: from here a
	// buffer may hold many, and only the batched read splits them.
	// NB_RELAY_UDP_GRO=false keeps one a datagram, for a comparison.
	if c.batch != nil && os.Getenv("NB_RELAY_UDP_GRO") != "false" && enableGRO(pc) {
		c.gro = true
		c.msgs = make([]ipv4.Message, readBatchSizeGRO)
		for i := range c.msgs {
			c.msgs[i].Buffers = [][]byte{make([]byte, 65535)}
			c.msgs[i].OOB = make([]byte, groOOB)
		}
	}
	c.lastRx.Store(time.Now().UnixNano())
	go c.keepalive()
	return c, nil
}

func (c *Conn) header(proto uint16, control bool) []byte {
	b := make([]byte, GeneveLen, 160)
	putGeneve(b, c.vni, proto, control)
	return b
}

func (c *Conn) sendBind(typ byte, generation uint32, challenge [challengeLen]byte, to netip.AddrPort) error {
	m := bindBody{vni: c.vni, generation: generation, remote: c.peer, challenge: challenge}
	pkt, err := seal(c.header(protoDisco, true), c.key.public, c.serverShared, m.marshal(typ))
	if err != nil {
		return err
	}
	_, err = c.pc.WriteTo(pkt, net.UDPAddrFromAddrPort(to))
	return err
}

func (c *Conn) sendPing(typ byte, id [pingIDLen]byte, to netip.AddrPort) error {
	pkt, err := seal(c.header(protoDisco, false), c.key.public, c.peerShared, marshalPing(typ, id))
	if err != nil {
		return err
	}
	_, err = c.pc.WriteTo(pkt, net.UDPAddrFromAddrPort(to))
	return err
}

func newPingID() (id [pingIDLen]byte) {
	_, _ = rand.Read(id[:])
	return id
}

// establish binds and proves the path. Every Rebind without proof it binds
// again under a new generation: a bind that was answered stays in force at
// the relay until the next answer replaces it, so repeating costs nothing.
func (c *Conn) establish(ctx context.Context, addrs []netip.AddrPort) error {
	var genSeed [4]byte
	_, _ = rand.Read(genSeed[:])
	generation := binary.BigEndian.Uint32(genSeed[:]) | 1 // never zero: the relay drops a zero generation
	bind := func() error {
		generation += 2
		targets := addrs
		if c.relay.IsValid() {
			targets = []netip.AddrPort{c.relay}
		}
		var last error
		sent := false
		for _, a := range targets {
			if err := c.sendBind(typeBind, generation, [challengeLen]byte{}, a); err != nil {
				last = err
				continue
			}
			sent = true
		}
		if !sent {
			return fmt.Errorf("send the bind: %w", last)
		}
		return nil
	}
	if err := bind(); err != nil {
		return err
	}
	next := time.Now().Add(c.timers.Rebind)
	var pinged [pingIDLen]byte
	challenged := false
	for {
		if err := ctx.Err(); err != nil {
			if challenged {
				return fmt.Errorf("bound at the relay, but nothing came from the peer: %w", err)
			}
			return fmt.Errorf("the relay did not answer the bind: %w", err)
		}
		wait := next
		if d, ok := ctx.Deadline(); ok && d.Before(wait) {
			wait = d
		}
		_ = c.pc.SetReadDeadline(wait)
		n, from, err := c.readFrom(c.rbuf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if time.Now().Before(next) {
					continue
				}
				if err := bind(); err != nil {
					return err
				}
				next = time.Now().Add(c.timers.Rebind)
				continue
			}
			return err
		}
		pkt := c.rbuf[:n]
		vni, proto, control, err := parseGeneve(pkt)
		if err != nil || vni != c.vni {
			continue
		}
		if c.relay.IsValid() && from != c.relay {
			continue
		}
		body := pkt[GeneveLen:]
		switch {
		case control && proto == protoDisco:
			clear, ok := open(body, c.serverKey, c.serverShared)
			if !ok {
				continue
			}
			typ, m, err := parseBind(clear)
			if err != nil || typ != typeChallenge || m.vni != c.vni || m.generation != generation || m.remote != c.peer {
				continue
			}
			if !c.relay.IsValid() {
				c.relay = from
				c.relayAddr = net.UDPAddrFromAddrPort(from)
			}
			if err := c.sendBind(typeAnswer, generation, m.challenge, c.relay); err != nil {
				return fmt.Errorf("send the answer: %w", err)
			}
			challenged = true
			pinged = newPingID()
			_ = c.sendPing(typePing, pinged, c.relay)
		case !control && proto == protoDisco && c.relay.IsValid():
			clear, ok := open(body, c.peer, c.peerShared)
			if !ok {
				continue
			}
			typ, id, err := parsePing(clear)
			if err != nil {
				continue
			}
			switch typ {
			case typePing:
				// The peer's ping proves it bound and that the relay
				// forwards to us. Answer it, and it is our proof too.
				_ = c.sendPing(typePong, id, c.relay)
				_ = c.pc.SetReadDeadline(time.Time{})
				return nil
			case typePong:
				if id == pinged {
					_ = c.pc.SetReadDeadline(time.Time{})
					return nil
				}
			}
		case !control && proto == protoWireGuard && c.relay.IsValid():
			// The peer is ahead of us and already sends data: the relay
			// forwards only between two bound sides. This one packet is
			// dropped; WireGuard sends it again.
			_ = c.pc.SetReadDeadline(time.Time{})
			return nil
		}
	}
}

func (c *Conn) readFrom(b []byte) (int, netip.AddrPort, error) {
	if c.fast != nil {
		n, ap, err := c.fast.ReadFromUDPAddrPort(b)
		return n, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), err
	}
	n, addr, err := c.pc.ReadFrom(b)
	if err != nil {
		return n, netip.AddrPort{}, err
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return n, netip.AddrPort{}, nil
	}
	ap := ua.AddrPort()
	return n, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// keepalive pings the peer every period and closes the connection when
// nothing at all arrived for Missed of them.
func (c *Conn) keepalive() {
	t := time.NewTicker(c.timers.Ping)
	defer t.Stop()
	limit := time.Duration(c.timers.Missed) * c.timers.Ping
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			if time.Since(time.Unix(0, c.lastRx.Load())) > limit {
				c.logf("udp relay: vni=%d nothing received for %s, closing", c.vni, limit)
				c.fail(ErrDead)
				return
			}
			_ = c.sendPing(typePing, newPingID(), c.relay)
		}
	}
}

func (c *Conn) fail(err error) {
	c.closeOnce.Do(func() {
		c.closeErr = err
		close(c.closed)
		_ = c.pc.Close()
	})
}

const (
	// readBatchSize is how many datagrams ReadBatch asks the kernel for at
	// once; readBatchBuffer, the room for one: a WireGuard packet of the
	// largest wt0 and the relay's header fit with room to spare.
	readBatchSize   = 64
	readBatchBuffer = 2048
	// readBatchSizeGRO is how many buffers are read at once when each may
	// hold up to 64 datagrams.
	readBatchSizeGRO = 16
)

// accept takes one datagram from the socket: the WireGuard packet it carries,
// or nothing when it was a ping (answered) or not this connection's (counted).
func (c *Conn) accept(pkt []byte, from netip.AddrPort) ([]byte, bool) {
	if from != c.relay {
		c.rxOther.Add(1)
		return nil, false
	}
	vni, proto, control, err := parseGeneve(pkt)
	if err != nil || vni != c.vni || control {
		c.rxOther.Add(1)
		return nil, false
	}
	switch proto {
	case protoWireGuard:
		c.lastRx.Store(time.Now().UnixNano())
		c.rxPackets.Add(1)
		return pkt[GeneveLen:], true
	case protoDisco:
		clear, ok := open(pkt[GeneveLen:], c.peer, c.peerShared)
		if !ok {
			c.rxOther.Add(1)
			return nil, false
		}
		c.lastRx.Store(time.Now().UnixNano())
		if typ, id, err := parsePing(clear); err == nil && typ == typePing {
			_ = c.sendPing(typePong, id, c.relay)
		}
		return nil, false
	default:
		c.rxOther.Add(1)
		return nil, false
	}
}

func (c *Conn) readErr(err error) error {
	select {
	case <-c.closed:
		if c.closeErr != nil {
			return c.closeErr
		}
		return net.ErrClosed
	default:
	}
	return err
}

// Read returns the next WireGuard packet from the peer. Pings and pongs are
// answered and counted on the way.
func (c *Conn) Read(b []byte) (int, error) {
	if c.batch != nil {
		// One path for both reads, so a coalesced buffer is always split.
		var size [1]int
		if _, err := c.ReadBatch([][]byte{b}, size[:]); err != nil {
			return 0, err
		}
		return size[0], nil
	}
	for {
		n, from, err := c.readFrom(c.rbuf)
		if err != nil {
			return 0, c.readErr(err)
		}
		if payload, ok := c.accept(c.rbuf[:n], from); ok {
			return copy(b, payload), nil
		}
	}
}

// ReadBatch is the relay client's BatchReader: up to len(bufs) WireGuard
// packets from one system call, which the proxy injects into WireGuard with
// one more. It blocks for the first datagram and takes what the kernel has
// queued beside it; a batch that held only pings is read again.
func (c *Conn) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	if c.batch == nil {
		n, err := c.Read(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		return 1, nil
	}
	for {
		n := 0
		for n < len(bufs) && len(c.pending) > 0 {
			sizes[n] = copy(bufs[n], c.pending[0])
			c.pending = c.pending[1:]
			n++
		}
		if n > 0 {
			return n, nil
		}
		want := len(c.msgs)
		if !c.gro {
			want = min(len(bufs), want)
		}
		got, err := c.batch.ReadBatch(c.msgs[:want], 0)
		if err != nil {
			return 0, c.readErr(err)
		}
		c.pending = c.pending[:0]
		for i := 0; i < got; i++ {
			m := &c.msgs[i]
			ua, _ := m.Addr.(*net.UDPAddr)
			if ua == nil {
				c.rxOther.Add(1)
				continue
			}
			ap := ua.AddrPort()
			from := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			data := m.Buffers[0][:m.N]
			seg := 0
			if c.gro && m.NN > 0 {
				seg = groSize(m.OOB[:m.NN])
			}
			if seg <= 0 || seg >= len(data) {
				if payload, ok := c.accept(data, from); ok {
					c.pending = append(c.pending, payload)
				}
				continue
			}
			c.rxCoalesced.Add(1)
			for off := 0; off < len(data); off += seg {
				if payload, ok := c.accept(data[off:min(off+seg, len(data))], from); ok {
					c.pending = append(c.pending, payload)
				}
			}
		}
	}
}

// Write sends one WireGuard packet to the peer.
func (c *Conn) Write(b []byte) (int, error) {
	bp := c.wpool.Get().(*[]byte)
	pkt := append((*bp)[:0], 0, 0, 0, 0, 0, 0, 0, 0)
	putGeneve(pkt, c.vni, protoWireGuard, false)
	pkt = append(pkt, b...)
	var err error
	if c.fast != nil {
		_, err = c.fast.WriteToUDPAddrPort(pkt, c.relay)
	} else {
		_, err = c.pc.WriteTo(pkt, c.relayAddr)
	}
	*bp = pkt
	c.wpool.Put(bp)
	if err != nil {
		select {
		case <-c.closed:
			if c.closeErr != nil {
				return 0, c.closeErr
			}
			return 0, net.ErrClosed
		default:
		}
		return 0, err
	}
	c.txPackets.Add(1)
	return len(b), nil
}

// Close ends the connection. The relay forgets the endpoint by itself, five
// minutes after the last packet.
func (c *Conn) Close() error {
	c.fail(nil)
	return nil
}

// Done is closed when the connection ended, by Close or as dead.
func (c *Conn) Done() <-chan struct{} { return c.closed }

// Stats are what the connection carried: WireGuard packets each way, and
// packets that were not for it (another source, another VNI, not openable).
type Stats struct {
	VNI                  uint32
	Relay                netip.AddrPort
	RxPackets, TxPackets uint64
	RxNotOurs            uint64
	RxCoalesced          uint64
	GRO                  bool
	SinceLastReceive     time.Duration
}

func (c *Conn) Stats() Stats {
	return Stats{
		VNI: c.vni, Relay: c.relay,
		RxPackets: c.rxPackets.Load(), TxPackets: c.txPackets.Load(), RxNotOurs: c.rxOther.Load(),
		RxCoalesced: c.rxCoalesced.Load(), GRO: c.gro,
		SinceLastReceive: time.Since(time.Unix(0, c.lastRx.Load())),
	}
}

func (c *Conn) LocalAddr() net.Addr  { return c.pc.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.relayAddr }

func (c *Conn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }

var _ net.Conn = (*Conn)(nil)
