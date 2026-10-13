package peer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	relayUDP "github.com/netbirdio/netbird/shared/relay/udp"
)

// fakeProxy records what a connection asked of a proxy, in order, and tells
// its disconnect listener when the conn it serves ends, as the real ones do.
type fakeProxy struct {
	mu       sync.Mutex
	ep       *net.UDPAddr
	calls    []string
	remote   net.Conn
	listener func()
	closed   bool
}

func (p *fakeProxy) record(call string) {
	p.mu.Lock()
	p.calls = append(p.calls, call)
	p.mu.Unlock()
}

func (p *fakeProxy) did() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.calls...)
}

func (p *fakeProxy) AddRelayedConn(_ context.Context, _ *net.UDPAddr, remote net.Conn) error {
	p.remote = remote
	go func() {
		buf := make([]byte, 2000)
		for {
			if _, err := remote.Read(buf); err != nil {
				p.mu.Lock()
				l, closed := p.listener, p.closed
				p.mu.Unlock()
				if l != nil && !closed {
					l()
				}
				return
			}
		}
	}()
	return nil
}
func (p *fakeProxy) EndpointAddr() *net.UDPAddr { return p.ep }
func (p *fakeProxy) SetDisconnectListener(l func()) {
	p.mu.Lock()
	p.listener = l
	p.mu.Unlock()
}
func (p *fakeProxy) Work()                      { p.record("work") }
func (p *fakeProxy) Pause()                     { p.record("pause") }
func (p *fakeProxy) RedirectAs(ep *net.UDPAddr) { p.record("redirect " + ep.String()) }
func (p *fakeProxy) InjectPacket([]byte) error  { return nil }
func (p *fakeProxy) CloseConn() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.record("close")
	if p.remote != nil {
		return p.remote.Close()
	}
	return nil
}

// fakeWG is WireGuard's interface as a connection sees it: where the peer's
// endpoint was set, in order, and the proxies it handed out.
type fakeWG struct {
	mu        sync.Mutex
	endpoints []string
	removed   int
	failNext  bool
	nextPort  int
	proxies   []*fakeProxy
}

func (w *fakeWG) UpdatePeer(_ string, _ []netip.Prefix, _ time.Duration, endpoint *net.UDPAddr, _ *wgtypes.Key) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failNext {
		w.failNext = false
		return errors.New("refused by the test")
	}
	w.endpoints = append(w.endpoints, endpoint.String())
	return nil
}
func (w *fakeWG) RemovePeer(string) error { return nil }
func (w *fakeWG) GetStats() (map[string]configurer.WGStats, error) {
	return map[string]configurer.WGStats{}, nil
}
func (w *fakeWG) GetProxy() wgproxy.Proxy {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.nextPort++
	p := &fakeProxy{ep: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000 + w.nextPort}}
	w.proxies = append(w.proxies, p)
	return p
}
func (w *fakeWG) Address() wgaddr.Address { return wgaddr.Address{} }
func (w *fakeWG) RemoveEndpointAddress(string) error {
	w.mu.Lock()
	w.removed++
	w.mu.Unlock()
	return nil
}
func (w *fakeWG) last() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.endpoints) == 0 {
		return ""
	}
	return w.endpoints[len(w.endpoints)-1]
}

// onRelay is a connection that is up on the QUIC or WebSocket relay, with
// nothing direct: the state the UDP relay is climbed to from.
func onRelay(t *testing.T) (*Conn, *fakeWG, *fakeProxy) {
	t.Helper()
	wg := &fakeWG{}
	cfg := ConnConfig{
		Key:      "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey: "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		WgConfig: WgConfig{
			RemoteKey:   "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
			WgInterface: wg,
			AllowedIps:  []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logger := log.WithField("peer", cfg.Key)
	conn := &Conn{
		ctx:             ctx,
		config:          cfg,
		Log:             logger,
		metricsStages:   &MetricsStages{},
		statusRecorder:  NewRecorder("test"),
		statusRelay:     worker.NewAtomicStatus(),
		statusICE:       worker.NewAtomicStatus(),
		endpointUpdater: NewEndpointUpdater(logger, cfg.WgConfig, true),
	}
	relayProxy := wg.GetProxy().(*fakeProxy)
	conn.wgProxyRelay = relayProxy
	conn.currentConnPriority = conntype.Relay
	conn.statusRelay.SetConnected()
	conn.relayServerAddr = "rels://relay.test:443"
	return conn, wg, relayProxy
}

func pipeConn(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestRelayUDP_AProvedPathTakesOverAndTheOtherRelayIsKept(t *testing.T) {
	conn, wg, relayProxy := onRelay(t)
	udpConn, _ := pipeConn(t)

	require.True(t, conn.onRelayUDPReady(udpConn), "a pair on the relay must take a proved UDP path")

	udpProxy := wg.proxies[1]
	assert.Equal(t, conntype.RelayUDP, conn.currentConnPriority)
	assert.Equal(t, udpProxy.ep.String(), wg.last(), "WireGuard's endpoint must be the UDP path's proxy")
	assert.Equal(t, []string{"work"}, udpProxy.did())
	assert.Equal(t, []string{"pause", "redirect " + udpProxy.ep.String()}, relayProxy.did(),
		"the other relay's proxy is paused and what it still receives redirected, never closed")
	assert.True(t, conn.isRelayed(), "the UDP relay is a relay")
	assert.Equal(t, StatusConnected, conn.evalStatus())
}

func TestRelayUDP_APathIsTakenOnlyFromTheOtherRelay(t *testing.T) {
	for name, set := range map[string]func(c *Conn){
		"nothing connected":        func(c *Conn) { c.currentConnPriority = conntype.None },
		"a direct path":            func(c *Conn) { c.currentConnPriority = conntype.ICEP2P },
		"a direct path over TURN":  func(c *Conn) { c.currentConnPriority = conntype.ICETurn },
		"already on the UDP relay": func(c *Conn) { c.currentConnPriority = conntype.RelayUDP },
		"the relay's proxy gone":   func(c *Conn) { c.wgProxyRelay = nil },
	} {
		t.Run(name, func(t *testing.T) {
			conn, wg, relayProxy := onRelay(t)
			set(conn)
			before := conn.currentConnPriority
			udpConn, _ := pipeConn(t)
			assert.False(t, conn.onRelayUDPReady(udpConn))
			assert.Equal(t, before, conn.currentConnPriority)
			assert.Empty(t, wg.last(), "WireGuard's endpoint must not move")
			assert.Empty(t, relayProxy.did())
			assert.Nil(t, conn.wgProxyUDP)
		})
	}
}

func TestRelayUDP_AnEndpointThatCannotBeSetLeavesThePairOnTheOtherRelay(t *testing.T) {
	conn, wg, relayProxy := onRelay(t)
	wg.failNext = true
	udpConn, _ := pipeConn(t)

	assert.False(t, conn.onRelayUDPReady(udpConn))
	assert.Equal(t, conntype.Relay, conn.currentConnPriority)
	assert.Nil(t, conn.wgProxyUDP)
	assert.Equal(t, []string{"pause", "work"}, relayProxy.did(), "the other relay's proxy must be working again")
	assert.Equal(t, []string{"work", "close"}, wg.proxies[1].did())
}

func TestRelayUDP_WhenThePathEndsThePairIsBackOnTheOtherRelay(t *testing.T) {
	conn, wg, relayProxy := onRelay(t)
	udpConn, far := pipeConn(t)
	require.True(t, conn.onRelayUDPReady(udpConn))
	udpProxy := wg.proxies[1]

	// The path ends under the proxy, as a dead relay connection does.
	_ = far.Close()
	_ = udpConn.Close()
	require.Eventually(t, func() bool {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.currentConnPriority == conntype.Relay
	}, 2*time.Second, 10*time.Millisecond, "the pair did not fall back")

	conn.mu.Lock()
	defer conn.mu.Unlock()
	assert.Nil(t, conn.wgProxyUDP)
	assert.Equal(t, relayProxy.ep.String(), wg.last(), "WireGuard's endpoint must be the other relay's proxy again")
	assert.Equal(t, []string{"pause", "redirect " + udpProxy.ep.String(), "work"}, relayProxy.did())
	assert.Contains(t, udpProxy.did(), "close")
	assert.Zero(t, wg.removed, "the endpoint is switched, never removed, while the other relay is there")
}

func TestRelayUDP_WhenThePathEndsAndTheOtherRelayIsGoneNothingIsLeft(t *testing.T) {
	conn, wg, _ := onRelay(t)
	udpConn, _ := pipeConn(t)
	require.True(t, conn.onRelayUDPReady(udpConn))

	conn.mu.Lock()
	// The other relay drops while the pair is on this one. Its status is set
	// first because this connection has no guard to tell of the change.
	conn.statusRelay.SetDisconnected()
	conn.handleRelayDisconnectedLocked()
	assert.Equal(t, conntype.RelayUDP, conn.currentConnPriority, "the other relay dropping must not take the UDP path down")
	assert.Zero(t, wg.removed)
	assert.Equal(t, StatusConnected, conn.evalStatus(), "on the UDP relay the pair is connected whatever the other relay's state")
	conn.handleRelayUDPDisconnectedLocked()
	conn.mu.Unlock()

	assert.Equal(t, conntype.None, conn.currentConnPriority)
	assert.Equal(t, 1, wg.removed, "with no relay left the endpoint is removed")
}

func TestRelayUDP_AWireGuardTimeoutOnThePathFallsBackAndKeepsTheOtherRelay(t *testing.T) {
	conn, wg, relayProxy := onRelay(t)
	udpConn, _ := pipeConn(t)
	require.True(t, conn.onRelayUDPReady(udpConn))

	conn.onWGDisconnected(conn.ctx)

	assert.Equal(t, conntype.Relay, conn.currentConnPriority)
	assert.Equal(t, relayProxy.ep.String(), wg.last())
	assert.NotContains(t, relayProxy.did(), "close", "the timeout was the UDP path's, not the other relay's")
}

func TestRelayUDP_ADirectPathEndsTheUDPPathWithoutTouchingTheEndpoint(t *testing.T) {
	conn, wg, _ := onRelay(t)
	udpConn, _ := pipeConn(t)
	require.True(t, conn.onRelayUDPReady(udpConn))
	moved := wg.last()

	conn.mu.Lock()
	conn.dropRelayUDPLocked()
	conn.mu.Unlock()

	assert.Nil(t, conn.wgProxyUDP)
	assert.Contains(t, wg.proxies[1].did(), "close")
	assert.Equal(t, moved, wg.last(), "the path that outranks it sets the endpoint, not this")
}

func TestRelayUDP_TheAPIIsOnThePairsRelayServersHost(t *testing.T) {
	for server, want := range map[string]string{
		"rels://relay01-pt.omnuv.com:443": "https://relay01-pt.omnuv.com:4443",
		"rel://192.0.2.7:80":              "https://192.0.2.7:4443",
		"rels://[2001:db8::1]:443":        "https://[2001:db8::1]:4443",
	} {
		got, err := relayUDPAPI(server, "4443")
		require.NoError(t, err, server)
		assert.Equal(t, want, got)
	}
	for _, server := range []string{"", "rels://", "::not a url"} {
		_, err := relayUDPAPI(server, "4443")
		assert.Error(t, err, "%q names no host", server)
	}
}

func TestRelayUDP_AWorkerThatIsOffOffersNoKeyAndDoesNothing(t *testing.T) {
	var w *WorkerRelayUDP
	assert.Nil(t, w.PublicKey())
	w.Start()
	w.Stop()
	w.OnNewOffer(&OfferAnswer{})

	off := &WorkerRelayUDP{} // made while the setting is unset
	assert.Nil(t, off.PublicKey())
	off.Start()
	off.OnNewOffer(&OfferAnswer{RelayUDPKey: make([]byte, 32), RelaySrvAddress: "rels://relay.test:443"})
	assert.Nil(t, off.cancel, "a worker that is off must never start an attempt")
}

func TestRelayUDP_APeerWithoutAKeyIsNeverTried(t *testing.T) {
	key, err := relayUDP.NewKey()
	require.NoError(t, err)
	w := &WorkerRelayUDP{
		peerCtx: context.Background(), log: log.WithField("peer", "t"),
		shared:       &relayUDPShared{key: key, apiPort: "4443"},
		relayAddress: func() (string, error) { return "rels://relay.test:443", nil },
	}
	for name, offer := range map[string]*OfferAnswer{
		"no key":          {RelaySrvAddress: "rels://relay.test:443"},
		"a short key":     {RelaySrvAddress: "rels://relay.test:443", RelayUDPKey: make([]byte, 31)},
		"no relay server": {RelayUDPKey: make([]byte, 32)},
	} {
		w.OnNewOffer(offer)
		w.Start()
		assert.Nil(t, w.cancel, name)
	}
	assert.Len(t, w.PublicKey(), 32, "this side still offers its own key")
}

// The rest runs against the real relay, started by
// deployment/udp-relay/bench/run.sh of the omnuv repository, and is skipped
// without it (see shared/relay/udp/real_test.go).
func realRelayWorker(t *testing.T, conn *Conn, ctrl bool, key *relayUDP.Key) *WorkerRelayUDP {
	t.Helper()
	api, ca, secret := os.Getenv("ONV_UDP_TEST_API"), os.Getenv("ONV_UDP_TEST_CA"), os.Getenv("ONV_UDP_TEST_SECRET")
	if api == "" || ca == "" || secret == "" {
		t.Skip("no relay to test against: ONV_UDP_TEST_API, ONV_UDP_TEST_CA, ONV_UDP_TEST_SECRET")
	}
	pem, err := os.ReadFile(ca)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem))
	_, port, err := net.SplitHostPort(api[len("https://"):])
	require.NoError(t, err)
	w := &WorkerRelayUDP{
		peerCtx: conn.ctx, log: conn.Log, isController: ctrl, conn: conn,
		shared: &relayUDPShared{key: key, apiPort: port, http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}},
		// The pair's relay server is on the host the test's relay is on.
		relayAddress: func() (string, error) { return "rels://127.0.0.1:443", nil },
		token: func() []byte {
			payload := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(payload))
			return append(append([]byte{1}, mac.Sum(nil)...), payload...)
		},
	}
	conn.workerRelayUDP = w
	return w
}

func priorityOf(c *Conn) conntype.ConnPriority {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentConnPriority
}

func TestRealRelayUDP_APairClimbsFallsWhenItsPeerGoesSilentAndClimbsAgain(t *testing.T) {
	if os.Getenv("ONV_UDP_TEST_API") == "" {
		t.Skip("no relay to test against")
	}
	relayUDPRetryBase = 300 * time.Millisecond
	relayUDPTimers = relayUDP.Timers{Allocate: 3 * time.Second, Rebind: 100 * time.Millisecond, Attempt: 2 * time.Second, Ping: 100 * time.Millisecond, Missed: 3}
	t.Cleanup(func() { relayUDPRetryBase = 5 * time.Second; relayUDPTimers = relayUDP.Timers{} })

	connA, wgA, relayA := onRelay(t)
	connB, _, _ := onRelay(t)
	keyA, err := relayUDP.NewKey()
	require.NoError(t, err)
	keyB, err := relayUDP.NewKey()
	require.NoError(t, err)
	wA := realRelayWorker(t, connA, true, keyA)
	wB := realRelayWorker(t, connB, false, keyB)

	offer := func(w *WorkerRelayUDP, from *WorkerRelayUDP) {
		w.OnNewOffer(&OfferAnswer{RelayUDPKey: from.PublicKey(), RelaySrvAddress: "rels://127.0.0.1:443"})
	}
	offer(wA, wB)
	offer(wB, wA)
	wA.Start()
	wB.Start()

	climbed := func(c *Conn) func() bool { return func() bool { return priorityOf(c) == conntype.RelayUDP } }
	require.Eventually(t, climbed(connA), 3*time.Second, 10*time.Millisecond, "a did not climb")
	require.Eventually(t, climbed(connB), 3*time.Second, 10*time.Millisecond, "b did not climb")
	assert.Equal(t, wgA.proxies[1].ep.String(), wgA.last())

	// b goes: its attempt and its path end, and it says nothing to a.
	connB.mu.Lock()
	connB.dropRelayUDPLocked()
	connB.mu.Unlock()
	began := time.Now()
	require.Eventually(t, func() bool { return priorityOf(connA) == conntype.Relay }, 3*time.Second, 10*time.Millisecond,
		"a did not fall back when its peer went silent")
	assert.Less(t, time.Since(began), time.Second, "three periods of 100 ms and the tick that notices")
	assert.Equal(t, relayA.ep.String(), wgA.last(), "a is on the other relay's proxy again")

	// a keeps trying by itself and proves nothing while b is away.
	time.Sleep(700 * time.Millisecond) // wait: two retries of a's; nothing to poll for an absence
	assert.Equal(t, conntype.Relay, priorityOf(connA), "a climbed with no peer on the other side")

	// b returns, with the same key: a's own retry finds it.
	connB.mu.Lock()
	connB.currentConnPriority = conntype.Relay
	connB.mu.Unlock()
	wB.Start()
	require.Eventually(t, climbed(connA), 5*time.Second, 10*time.Millisecond, "a did not climb again")
	require.Eventually(t, climbed(connB), 5*time.Second, 10*time.Millisecond, "b did not climb again")
}
