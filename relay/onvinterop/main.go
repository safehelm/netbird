// onvinterop holds a relay server to NetBird's own relay client
// (shared/relay/client): the handshake and the instance URL, a relayed
// connection opened from both ends (the peer-state subscription), messages
// both ways, a burst, a peer leaving, a reconnection under one id, and a
// refused token. Each check prints ok or FAILED; any failure exits 1.
// Built with -tags devcert, its QUIC dial does not verify the certificate;
// its WebSocket dial does, against the system's roots (SSL_CERT_FILE).
//
//	onvinterop -url rels://localhost:18443 -secret S -transport quic|ws
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay/auth/hmac"
	authv2 "github.com/netbirdio/netbird/shared/relay/auth/hmac/v2"
	"github.com/netbirdio/netbird/shared/relay/client"
)

var failed bool

func check(name string, err error) bool {
	if err != nil {
		failed = true
		fmt.Printf("FAILED %s: %v\n", name, err)
		return false
	}
	fmt.Printf("ok %s\n", name)
	return true
}

func tokens(secret string) *hmac.TokenStore {
	store := &hmac.TokenStore{}
	hashed := sha256.Sum256([]byte(secret))
	gen, err := authv2.NewGenerator(authv2.AuthAlgoHMACSHA256, hashed[:], time.Hour)
	if err != nil {
		panic(err)
	}
	tok, err := gen.GenerateToken()
	if err != nil {
		panic(err)
	}
	if err := store.UpdateToken(&hmac.Token{Payload: string(tok.Payload), Signature: base64.StdEncoding.EncodeToString(tok.Signature)}); err != nil {
		panic(err)
	}
	return store
}

// relayCounters reads the Rust relay's counters: bytes received from peers,
// bytes forwarded to peers, and messages it did not deliver
func relayCounters(url string) (recv, sent, dropped float64, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return 0, 0, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, 0, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(line, "#") {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch {
		case f[0] == "relay_transfer_received_bytes_total":
			recv = v
		case f[0] == "relay_transfer_sent_bytes_total":
			sent = v
		case strings.HasPrefix(f[0], "relay_transport_dropped_total"):
			dropped += v
		}
	}
	return recv, sent, dropped, nil
}

func main() {
	url := flag.String("url", "", "the relay, rels://host:port")
	secret := flag.String("secret", "", "the relay's auth secret")
	transport := flag.String("transport", "quic", "quic or ws")
	metrics := flag.String("metrics", "", "the Rust relay's metrics URL: the burst is then held to the relay's own counters")
	flag.Parse()
	if *url == "" || *secret == "" {
		fmt.Fprintln(os.Stderr, "usage: onvinterop -url rels://host:port -secret S -transport quic|ws")
		os.Exit(2)
	}
	_ = os.Setenv(client.EnvRelayTransport, *transport)
	log.SetLevel(log.WarnLevel)
	ctx := context.Background()
	good := tokens(*secret)
	run := fmt.Sprintf("%d", time.Now().UnixNano())

	a := client.NewClient(*url, good, "onvinterop-a-"+run, 1280)
	b := client.NewClient(*url, good, "onvinterop-b-"+run, 1280)
	if !check("connect", errors.Join(a.Connect(ctx), b.Connect(ctx))) {
		os.Exit(1)
	}
	defer a.Close()
	var err error
	if a.Transport() != *transport || b.Transport() != *transport {
		err = fmt.Errorf("transports %s and %s, wanted %s", a.Transport(), b.Transport(), *transport)
	}
	check("transport "+*transport, err)
	got, err := a.ServerInstanceURL()
	if err == nil && got != *url {
		err = fmt.Errorf("instance URL %q, wanted %q", got, *url)
	}
	check("instance URL", err)

	// Each end waits for the other to be online: the subscription
	type opened struct {
		c   *client.Conn
		err error
	}
	cha, chb := make(chan opened, 1), make(chan opened, 1)
	octx, cancel := context.WithTimeout(ctx, 15*time.Second)
	go func() { c, err := a.OpenConn(octx, "onvinterop-b-"+run); cha <- opened{c, err} }()
	time.Sleep(300 * time.Millisecond) // b comes second, so a waits for it
	go func() { c, err := b.OpenConn(octx, "onvinterop-a-"+run); chb <- opened{c, err} }()
	oa, ob := <-cha, <-chb
	cancel()
	if !check("open from both ends", errors.Join(oa.err, ob.err)) {
		os.Exit(1)
	}
	ca, cb := oa.c, ob.c

	// b echoes. a's reads go to a channel, closed when its connection ends:
	// the client's connection has no read deadline
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := cb.Read(buf)
			if err != nil {
				return
			}
			if _, err := cb.Write(buf[:n]); err != nil {
				return
			}
		}
	}()
	in := make(chan []byte, 8192)
	go func() {
		defer close(in)
		for {
			buf := make([]byte, 65536)
			n, err := ca.Read(buf)
			if err != nil {
				return
			}
			in <- buf[:n]
		}
	}()
	const echoes = 2000
	retries := 0
	err = func() error {
		for i := 0; i < echoes; i++ {
			msg := bytes.Repeat([]byte{byte(i)}, 1000)
			binary.BigEndian.PutUint32(msg, uint32(i))
		attempts:
			for attempt := 0; ; attempt++ {
				if attempt == 5 {
					return fmt.Errorf("message %d: no echo in 5 attempts", i)
				}
				if _, err := ca.Write(msg); err != nil {
					return fmt.Errorf("write %d: %w", i, err)
				}
				timeout := time.After(time.Second)
				for {
					select {
					case got, ok := <-in:
						if !ok {
							return errors.New("a's connection closed")
						}
						if bytes.Equal(got, msg) {
							break attempts
						}
						// an earlier attempt's echo, late
					case <-timeout:
						retries++
						continue attempts
					}
				}
			}
		}
		return nil
	}()
	check(fmt.Sprintf("%d messages each way, %d resent", echoes, retries), err)

	// A burst: what a peer sends as fast as it can, echoed and counted
	const burst = 5000
	var r0, s0, d0 float64
	if *metrics != "" {
		r0, s0, d0, _ = relayCounters(*metrics)
	}
	start := time.Now()
	go func() {
		msg := make([]byte, 1100)
		for i := 0; i < burst; i++ {
			if _, err := ca.Write(msg); err != nil {
				return
			}
		}
	}()
	back := 0
count:
	for back < burst {
		select {
		case _, ok := <-in:
			if !ok {
				break count
			}
			back++
		case <-time.After(2 * time.Second):
			break count
		}
	}
	// What comes back is not the relay's alone: the client drops what
	// arrives while its connection's queue (100 messages) is full. With the
	// relay's counters, the relay is held to forwarding all it received
	err = nil
	name := fmt.Sprintf("burst: %d of %d back in %.2f s", back, burst, time.Since(start).Seconds())
	if *metrics != "" {
		r1, s1, d1, merr := relayCounters(*metrics)
		switch {
		case merr != nil:
			err = merr
		case r1-r0 != s1-s0 || d1 != d0:
			err = fmt.Errorf("the relay received %.0f bytes and forwarded %.0f, %.0f undelivered", r1-r0, s1-s0, d1-d0)
		case r1-r0 < float64(burst)*1138:
			err = fmt.Errorf("the relay received %.0f bytes, under one burst", r1-r0)
		default:
			name += fmt.Sprintf("; the relay forwarded all %.0f bytes it received", r1-r0)
		}
	} else if back*100 < burst*95 {
		err = fmt.Errorf("%d of %d came back", back, burst)
	}
	check(name, err)

	// b leaves: a's connection to it ends
	_ = b.Close()
	err = func() error {
		deadline := time.After(10 * time.Second)
		for {
			select {
			case _, ok := <-in:
				if !ok {
					return nil
				}
			case <-deadline:
				return errors.New("a's connection still open 10 s after b left")
			}
		}
	}()
	check("peer left", err)

	// The same id again: the first is disconnected
	c1 := client.NewClient(*url, good, "onvinterop-c-"+run, 1280)
	gone := make(chan struct{}, 1)
	c1.SetOnDisconnectListener(func(string) { gone <- struct{}{} })
	err = c1.Connect(ctx)
	if err == nil {
		c2 := client.NewClient(*url, good, "onvinterop-c-"+run, 1280)
		err = c2.Connect(ctx)
		defer c2.Close()
		if err == nil {
			select {
			case <-gone:
			case <-time.After(10 * time.Second):
				err = errors.New("the first connection under the id still up 10 s on")
			}
		}
	}
	check("reconnection under one id", err)

	// A token under another secret is refused
	bad := client.NewClient(*url, tokens(*secret+"-not"), "onvinterop-d-"+run, 1280)
	err = bad.Connect(ctx)
	if err == nil {
		_ = bad.Close()
		err = errors.New("connected with a token under another secret")
	} else {
		err = nil
	}
	check("refused token", err)

	if failed {
		os.Exit(1)
	}
	fmt.Println("ALL OK")
}
