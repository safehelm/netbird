package udp

// These tests run against the real relay, onv-udp-relay, and are skipped
// without one: it is Tailscale's server, which this module cannot build.
// deployment/udp-relay/bench/run.sh in the omnuv repository starts it and
// sets:
//
//	ONV_UDP_TEST_API     https://127.0.0.1:<port>
//	ONV_UDP_TEST_CA      the certificate the API serves, PEM
//	ONV_UDP_TEST_SECRET  the relay's NB_AUTH_SECRET
import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

type realRelay struct {
	api    string
	secret string
	http   *http.Client
}

func real(t *testing.T) *realRelay {
	t.Helper()
	api, ca, secret := os.Getenv("ONV_UDP_TEST_API"), os.Getenv("ONV_UDP_TEST_CA"), os.Getenv("ONV_UDP_TEST_SECRET")
	if api == "" || ca == "" || secret == "" {
		t.Skip("no relay to test against: ONV_UDP_TEST_API, ONV_UDP_TEST_CA, ONV_UDP_TEST_SECRET")
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("%s holds no certificate", ca)
	}
	return &realRelay{api: api, secret: secret, http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}}
}

// relayToken is NetBird's: an algorithm byte, an HMAC-SHA256 of the payload,
// and the payload, the expiry as decimal unix time.
func relayToken(secret string, expiry time.Time) []byte {
	payload := strconv.FormatInt(expiry.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return append(append([]byte{1}, mac.Sum(nil)...), payload...)
}

func (r *realRelay) config(t *testing.T, key *Key, peer [keyLen]byte) Config {
	return Config{
		APIURL: r.api,
		Token:  func() []byte { return relayToken(r.secret, time.Now().Add(time.Hour)) },
		Key:    key,
		Peer:   peer,
		HTTP:   r.http,
		Timers: Timers{Allocate: 3 * time.Second, Rebind: 200 * time.Millisecond, Attempt: 5 * time.Second, Ping: 200 * time.Millisecond, Missed: 3},
		Logf:   t.Logf,
	}
}

func newKey(t *testing.T) *Key {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pair dials both sides at once, as two peers do.
func (r *realRelay) pair(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	ka, kb := newKey(t), newKey(t)
	var a, b *Conn
	var errA, errB error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a, errA = Dial(context.Background(), r.config(t, ka, kb.Public())) }()
	go func() { defer wg.Done(); b, errB = Dial(context.Background(), r.config(t, kb, ka.Public())) }()
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("the pair did not come up: a: %v, b: %v", errA, errB)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestRealAPairCarriesPacketsBothWaysUnchanged(t *testing.T) {
	r := real(t)
	a, b := r.pair(t)
	if a.Stats().VNI != b.Stats().VNI {
		t.Fatalf("the two sides were given different endpoints: %d and %d", a.Stats().VNI, b.Stats().VNI)
	}
	for _, dir := range []struct {
		name     string
		from, to *Conn
	}{{"a to b", a, b}, {"b to a", b, a}} {
		const count = 200
		got := make(chan []byte, count)
		go func() {
			buf := make([]byte, 2000)
			for i := 0; i < count; i++ {
				_ = dir.to.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, err := dir.to.Read(buf)
				if err != nil {
					close(got)
					return
				}
				got <- bytes.Clone(buf[:n])
			}
			close(got)
		}()
		for i := 0; i < count; i++ {
			// The sizes a WireGuard packet has: a keepalive's 32 to a full 1272.
			pkt := bytes.Repeat([]byte{byte(i)}, 32+(i*1240)/(count-1))
			copy(pkt, fmt.Sprintf("%s %04d", dir.name, i))
			if _, err := dir.from.Write(pkt); err != nil {
				t.Fatalf("%s: write %d: %v", dir.name, i, err)
			}
			time.Sleep(200 * time.Microsecond) // not a load: a loopback socket would drop a burst
		}
		n := 0
		for pkt := range got {
			want := bytes.Repeat([]byte{byte(n)}, 32+(n*1240)/(count-1))
			copy(want, fmt.Sprintf("%s %04d", dir.name, n))
			if !bytes.Equal(pkt, want) {
				t.Fatalf("%s: packet %d arrived changed (%d bytes, want %d)", dir.name, n, len(pkt), len(want))
			}
			n++
		}
		if n != count {
			t.Fatalf("%s: %d of %d packets arrived", dir.name, n, count)
		}
	}
}

func TestRealBothSidesAskAndAreGivenOneEndpointInEitherOrder(t *testing.T) {
	r := real(t)
	ka, kb := newKey(t), newKey(t)
	ca, cb := r.config(t, ka, kb.Public()), r.config(t, kb, ka.Public())
	ea, err := allocate(context.Background(), &ca)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := allocate(context.Background(), &cb)
	if err != nil {
		t.Fatal(err)
	}
	if ea.vni != eb.vni || ea.serverKey != eb.serverKey {
		t.Fatalf("a was given VNI %d and b %d", ea.vni, eb.vni)
	}
	// Another pair is another endpoint.
	cc := r.config(t, ka, newKey(t).Public())
	ec, err := allocate(context.Background(), &cc)
	if err != nil {
		t.Fatal(err)
	}
	if ec.vni == ea.vni {
		t.Fatalf("two pairs share VNI %d", ec.vni)
	}
}

func TestRealAnAllocationIsRefusedWithoutTheRelaysToken(t *testing.T) {
	r := real(t)
	for name, token := range map[string][]byte{
		"expired":        relayToken(r.secret, time.Now().Add(-time.Minute)),
		"another secret": relayToken(r.secret+"x", time.Now().Add(time.Hour)),
		"empty":          nil,
	} {
		cfg := r.config(t, newKey(t), newKey(t).Public())
		cfg.Token = func() []byte { return token }
		began := time.Now()
		_, err := Dial(context.Background(), cfg)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
		if took := time.Since(began); took > 2*time.Second {
			t.Errorf("%s: the refusal took %s: it must not wait out the attempt", name, took)
		}
	}
}

func TestRealAPeerThatNamesAnotherNeverProvesThePath(t *testing.T) {
	r := real(t)
	ka, kb := newKey(t), newKey(t)
	cfgA := r.config(t, ka, kb.Public())
	cfgA.Timers.Attempt = 1500 * time.Millisecond
	cfgB := r.config(t, kb, newKey(t).Public()) // b believes its peer is someone else
	cfgB.Timers.Attempt = 1500 * time.Millisecond
	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(2)
	go func() { defer wg.Done(); _, errA = Dial(context.Background(), cfgA) }()
	go func() { defer wg.Done(); _, errB = Dial(context.Background(), cfgB) }()
	wg.Wait()
	if errA == nil || errB == nil {
		t.Fatalf("a path was proved between peers that do not name each other: a: %v, b: %v", errA, errB)
	}
}

// low is a client driven by hand, to send the relay what Dial never would.
type low struct {
	t    *testing.T
	c    *Conn
	sock *net.UDPConn
}

func (r *realRelay) low(t *testing.T, key *Key, peer [keyLen]byte) (*low, *endpoint) {
	t.Helper()
	cfg := r.config(t, key, peer)
	ep, err := allocate(context.Background(), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	sock, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	c := &Conn{pc: sock, key: key, peer: peer, serverKey: ep.serverKey, serverShared: key.shared(ep.serverKey),
		peerShared: key.shared(peer), vni: ep.vni, relay: ep.addrs[0], relayAddr: net.UDPAddrFromAddrPort(ep.addrs[0]),
		closed: make(chan struct{}), rbuf: make([]byte, 65535), logf: t.Logf}
	return &low{t: t, c: c, sock: sock}, ep
}

// challenge waits for the relay's challenge to a bind of this generation.
func (l *low) challenge(generation uint32, within time.Duration) ([challengeLen]byte, bool) {
	_ = l.sock.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 2000)
	for {
		n, _, err := l.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			return [challengeLen]byte{}, false
		}
		_, proto, control, err := parseGeneve(buf[:n])
		if err != nil || !control || proto != protoDisco {
			continue
		}
		clear, ok := open(buf[GeneveLen:n], l.c.serverKey, l.c.serverShared)
		if !ok {
			continue
		}
		if typ, m, err := parseBind(clear); err == nil && typ == typeChallenge && m.generation == generation {
			return m.challenge, true
		}
	}
}

func TestRealTheRelayChallengesOnlyABindItCanHoldToTheAllocation(t *testing.T) {
	r := real(t)
	ka, kb := newKey(t), newKey(t)
	l, ep := r.low(t, ka, kb.Public())

	// The right bind is challenged: without this, the silences below prove nothing.
	if err := l.c.sendBind(typeBind, 7, [challengeLen]byte{}, ep.addrs[0]); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.challenge(7, time.Second); !ok {
		t.Fatal("the relay did not challenge a right bind")
	}

	// A body naming another VNI than the header's allocation.
	m := bindBody{vni: ep.vni + 1, generation: 9, remote: kb.Public()}
	pkt, _ := seal(l.c.header(protoDisco, true), ka.public, l.c.serverShared, m.marshal(typeBind))
	_, _ = l.sock.WriteToUDPAddrPort(pkt, ep.addrs[0])
	if _, ok := l.challenge(9, 400*time.Millisecond); ok {
		t.Error("the relay challenged a bind whose sealed VNI is not the header's")
	}

	// A body naming a peer the allocation does not hold.
	m = bindBody{vni: ep.vni, generation: 11, remote: newKey(t).Public()}
	pkt, _ = seal(l.c.header(protoDisco, true), ka.public, l.c.serverShared, m.marshal(typeBind))
	_, _ = l.sock.WriteToUDPAddrPort(pkt, ep.addrs[0])
	if _, ok := l.challenge(11, 400*time.Millisecond); ok {
		t.Error("the relay challenged a bind naming a peer the allocation does not hold")
	}

	// A key the allocation does not hold, on its VNI.
	stranger := newKey(t)
	m = bindBody{vni: ep.vni, generation: 13, remote: kb.Public()}
	pkt, _ = seal(l.c.header(protoDisco, true), stranger.public, stranger.shared(ep.serverKey), m.marshal(typeBind))
	_, _ = l.sock.WriteToUDPAddrPort(pkt, ep.addrs[0])
	_ = l.sock.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	if n, _, err := l.sock.ReadFromUDPAddrPort(make([]byte, 2000)); err == nil {
		t.Errorf("the relay answered a key the allocation does not hold (%d bytes)", n)
	}

	// A zero generation.
	if err := l.c.sendBind(typeBind, 0, [challengeLen]byte{}, ep.addrs[0]); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.challenge(0, 400*time.Millisecond); ok {
		t.Error("the relay challenged a bind of generation zero")
	}
}

// An answer binds the address it comes from, and only if the challenge was
// made for that address. b's Dial is the witness: it is proved only when a is
// bound and a's ping reaches it.
func TestRealAnAnswerFromAnotherPortDoesNotBind(t *testing.T) {
	r := real(t)
	for _, tc := range []struct {
		name      string
		otherPort bool
		wantUp    bool
	}{
		{"the answer from the port that was challenged", false, true},
		{"the answer from another port", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ka, kb := newKey(t), newKey(t)
			l, ep := r.low(t, ka, kb.Public())
			cfgB := r.config(t, kb, ka.Public())
			cfgB.Timers.Attempt = 1500 * time.Millisecond
			done := make(chan error, 1)
			go func() {
				c, err := Dial(context.Background(), cfgB)
				if err == nil {
					_ = c.Close()
				}
				done <- err
			}()

			if err := l.c.sendBind(typeBind, 21, [challengeLen]byte{}, ep.addrs[0]); err != nil {
				t.Fatal(err)
			}
			ch, ok := l.challenge(21, time.Second)
			if !ok {
				t.Fatal("no challenge")
			}
			answerer := l.c
			if tc.otherPort {
				other, err := net.ListenUDP("udp4", nil)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				answerer = &Conn{pc: other, key: ka, peer: kb.Public(), serverKey: ep.serverKey,
					serverShared: l.c.serverShared, peerShared: l.c.peerShared, vni: ep.vni}
			}
			if err := answerer.sendBind(typeAnswer, 21, ch, ep.addrs[0]); err != nil {
				t.Fatal(err)
			}
			// a pings from the challenged port, as a bound side would, until b decides.
			stop := make(chan struct{})
			go func() {
				for {
					select {
					case <-stop:
						return
					case <-time.After(100 * time.Millisecond):
						_ = l.c.sendPing(typePing, newPingID(), ep.addrs[0])
					}
				}
			}()
			err := <-done
			close(stop)
			if up := err == nil; up != tc.wantUp {
				t.Fatalf("b's path proved: %v (%v), want %v", up, err, tc.wantUp)
			}
		})
	}
}

func TestRealAConnectionWhosePeerWentSilentIsClosedAsDead(t *testing.T) {
	r := real(t)
	a, b := r.pair(t)
	_ = b.Close()
	began := time.Now()
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, 2000)
		for {
			if _, err := a.Read(buf); err != nil {
				errc <- err
				return
			}
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrDead) {
			t.Fatalf("the read ended with %v, want ErrDead", err)
		}
		// Three periods of 200 ms, and the tick that notices.
		if took := time.Since(began); took < 500*time.Millisecond || took > 2*time.Second {
			t.Fatalf("declared dead after %s", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a silent peer was never noticed")
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Fatal("a write on a dead connection succeeded")
	}
}

func TestRealAPacketFromAnotherSourceIsNotTakenAsThePeers(t *testing.T) {
	r := real(t)
	a, b := r.pair(t)
	// Someone who knows a's port and the VNI, but is not the relay.
	forger, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer forger.Close()
	pkt := make([]byte, GeneveLen, 64)
	putGeneve(pkt, a.vni, protoWireGuard, false)
	pkt = append(pkt, "forged"...)
	local := a.LocalAddr().(*net.UDPAddr)
	if _, err := forger.WriteToUDPAddrPort(pkt, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(local.Port))); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("from the peer")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := a.Read(buf)
	if err != nil || string(buf[:n]) != "from the peer" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}
	if a.Stats().RxNotOurs == 0 {
		t.Fatal("the forged packet was not counted as not ours: it never reached the socket, and this test proved nothing")
	}
}
