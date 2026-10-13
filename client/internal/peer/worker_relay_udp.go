package peer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/client/net"
	relayUDP "github.com/netbirdio/netbird/shared/relay/udp"
)

const (
	// EnvRelayUDPAPIPort turns the plain-UDP relay on: the TCP port of its
	// allocation API, on the host of the relay server a pair uses. Unset or
	// not a port: this client never tries one and says so to no peer.
	EnvRelayUDPAPIPort = "NB_RELAY_UDP_API_PORT"
	// EnvRelayUDPAPICA names a PEM file trusted for that API beside the
	// system's roots. For a relay whose certificate no public authority
	// signed; unset everywhere else.
	EnvRelayUDPAPICA = "NB_RELAY_UDP_API_CA"
)

// A failed attempt is tried again after relayUDPRetryBase, doubling to
// relayUDPRetryMax. Unmeasured. relayUDPTimers are one attempt's and one
// connection's waits; zero, the package's defaults. Variables for the tests.
var (
	relayUDPRetryBase = 5 * time.Second
	relayUDPRetryMax  = 5 * time.Minute
	relayUDPTimers    relayUDP.Timers
)

// relayUDPShared is what every peer connection of this client shares: one
// relay key, made at first use and never written, and one API client.
type relayUDPShared struct {
	key     *relayUDP.Key
	apiPort string
	http    *http.Client
}

var (
	relayUDPOnce   sync.Once
	relayUDPGlobal *relayUDPShared
)

// relayUDPSettings returns nil when the plain-UDP relay is off.
func relayUDPSettings() *relayUDPShared {
	relayUDPOnce.Do(func() {
		port := os.Getenv(EnvRelayUDPAPIPort)
		if port == "" {
			return
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			log.Warnf("%s=%q is not a port: the UDP relay is off", EnvRelayUDPAPIPort, port)
			return
		}
		key, err := relayUDP.NewKey()
		if err != nil {
			log.Warnf("no relay key could be made: the UDP relay is off: %v", err)
			return
		}
		tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
		if ca := os.Getenv(EnvRelayUDPAPICA); ca != "" {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			pem, err := os.ReadFile(ca)
			if err != nil || !pool.AppendCertsFromPEM(pem) {
				log.Warnf("%s=%q holds no certificate: the UDP relay is off", EnvRelayUDPAPICA, ca)
				return
			}
			tlsConf.RootCAs = pool
		}
		relayUDPGlobal = &relayUDPShared{
			key:     key,
			apiPort: port,
			http: &http.Client{Transport: &http.Transport{
				// The client's own dialer: the request must not be routed into the tunnel.
				DialContext:         nbnet.NewDialer().DialContext,
				TLSClientConfig:     tlsConf,
				TLSHandshakeTimeout: 3 * time.Second,
				IdleConnTimeout:     30 * time.Second,
			}},
		}
		log.Infof("the UDP relay is on: its API is asked on port %s of a pair's relay server", port)
	})
	return relayUDPGlobal
}

// relayUDPAPI is the allocation API of the UDP relay beside a relay server:
// that server's host, and the port this client was told.
func relayUDPAPI(relayServer, port string) (string, error) {
	u, err := url.Parse(relayServer)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("the relay server's address names no host")
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

// relayUDPDial is relayUDP.Dial, a variable so a test can stand in for the relay.
var relayUDPDial = relayUDP.Dial

// WorkerRelayUDP climbs a pair from the QUIC or WebSocket relay to a relay
// that forwards plain UDP, and climbs again whenever that path ends. It never
// delays the pair: it runs only while the pair is up on the other relay.
type WorkerRelayUDP struct {
	peerCtx      context.Context
	log          *log.Entry
	isController bool
	conn         *Conn
	shared       *relayUDPShared
	// relayAddress is the relay server this client is on; token, the relay
	// token as a relay is sent it.
	relayAddress func() (string, error)
	token        func() []byte

	mu      sync.Mutex
	peerKey [32]byte
	hasPeer bool
	api     string
	cancel  context.CancelFunc
}

func NewWorkerRelayUDP(ctx context.Context, log *log.Entry, ctrl bool, conn *Conn, relayAddress func() (string, error), token func() []byte) *WorkerRelayUDP {
	return &WorkerRelayUDP{
		peerCtx:      ctx,
		log:          log,
		isController: ctrl,
		conn:         conn,
		shared:       relayUDPSettings(),
		relayAddress: relayAddress,
		token:        token,
	}
}

// PublicKey is this client's relay key for an offer or an answer; nil when
// the UDP relay is off.
func (w *WorkerRelayUDP) PublicKey() []byte {
	if w == nil || w.shared == nil {
		return nil
	}
	pub := w.shared.key.Public()
	return pub[:]
}

// OnNewOffer records what the peer said: its relay key, and with it which
// relay server the pair uses. A peer that names no key ends any attempt; a
// new key (the peer started again) starts the attempt over.
func (w *WorkerRelayUDP) OnNewOffer(remote *OfferAnswer) {
	if w == nil || w.shared == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(remote.RelayUDPKey) != len(w.peerKey) || remote.RelaySrvAddress == "" {
		if w.hasPeer {
			w.log.Infof("UDP relay: the peer no longer offers a relay key")
		}
		w.hasPeer = false
		w.stopLocked()
		return
	}
	// The pair's relay server, chosen as WorkerRelay chooses it: both peers
	// must ask the same relay.
	server := remote.RelaySrvAddress
	if w.isController {
		mine, err := w.relayAddress()
		if err != nil {
			return
		}
		server = mine
	}
	api, err := relayUDPAPI(server, w.shared.apiPort)
	if err != nil {
		w.log.Warnf("UDP relay: no API for relay server %q: %v", server, err)
		return
	}
	key := [32]byte(remote.RelayUDPKey)
	changed := !w.hasPeer || key != w.peerKey || api != w.api
	w.peerKey, w.hasPeer, w.api = key, true, api
	if changed && w.cancel != nil {
		w.log.Infof("UDP relay: the peer's relay key or relay changed, starting over")
		w.stopLocked()
		w.startLocked()
	}
}

// Start begins climbing, if the peer offered a key and nothing is running.
// Called when the pair is up on the other relay with no direct path.
func (w *WorkerRelayUDP) Start() {
	if w == nil || w.shared == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.startLocked()
}

// Stop ends the attempt or the connection in service. It does not wait.
func (w *WorkerRelayUDP) Stop() {
	if w == nil || w.shared == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopLocked()
}

func (w *WorkerRelayUDP) stopLocked() {
	if w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
}

func (w *WorkerRelayUDP) startLocked() {
	if w.cancel != nil || !w.hasPeer || w.peerCtx.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(w.peerCtx)
	w.cancel = cancel
	go w.run(ctx, w.api, w.peerKey)
}

func (w *WorkerRelayUDP) run(ctx context.Context, api string, peerKey [32]byte) {
	retry := relayUDPRetryBase
	for {
		began := time.Now()
		c, err := relayUDPDial(ctx, relayUDP.Config{
			APIURL:       api,
			Token:        w.token,
			Key:          w.shared.key,
			Peer:         peerKey,
			HTTP:         w.shared.http,
			ListenPacket: nbnet.NewListener().ListenPacket,
			Timers:       relayUDPTimers,
			Logf:         w.log.Debugf,
		})
		if ctx.Err() != nil {
			if c != nil {
				_ = c.Close()
			}
			return
		}
		if err == nil {
			w.log.Infof("UDP relay: path proved through %s in %s", c.RemoteAddr(), time.Since(began).Round(time.Millisecond))
			if !w.conn.onRelayUDPReady(c) {
				// The pair moved on while this ran (a direct path, or closed).
				_ = c.Close()
				w.clear(ctx)
				return
			}
			retry = relayUDPRetryBase
			select {
			case <-c.Done():
				w.log.Infof("UDP relay: the path through %s ended", c.RemoteAddr())
			case <-ctx.Done():
				_ = c.Close()
				return
			}
		} else {
			w.log.Infof("UDP relay: not this time (%v); again in %s", err, retry)
		}
		select {
		case <-time.After(retry):
		case <-ctx.Done():
			return
		}
		if err != nil && retry < relayUDPRetryMax {
			retry = min(2*retry, relayUDPRetryMax)
		}
	}
}

// clear forgets a run that ended by itself, so Start can begin another.
func (w *WorkerRelayUDP) clear(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx.Err() == nil && w.cancel != nil {
		w.cancel()
		w.cancel = nil
	}
}
