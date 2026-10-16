//go:build linux && (amd64 || arm64)

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"

	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
)

// EnvQuinnLibrary specifies the absolute path to the experimental native backend.
const EnvQuinnLibrary = "NB_RELAY_QUINN_LIBRARY"

// EnvQuinnServerName is the name a certificate is asked for when the TLS
// configuration fetches its certificate (Let's Encrypt), not holds it.
const EnvQuinnServerName = "NB_RELAY_QUINN_SERVER_NAME"

// How often a fetched certificate is asked for again: until there is one, and
// after (a renewal reaches the listener within an hour).
var (
	quinnCertificateRetry = 10 * time.Second
	quinnCertificateRenew = time.Hour
)

// Native waits are cancellable; this bounds context cancellation observation.
const quinnContextQuantum = 50 * time.Millisecond

type quinnAPI struct {
	listen  func(*byte, uintptr, *byte, uintptr) uint64
	address func(uint64, *byte, uintptr) int64
	accept  func(uint64, uint64) int64
	remote  func(uint64, *byte, uintptr) int64
	read    func(uint64, *byte, uintptr, uint64) int64
	write   func(uint64, *byte, uintptr, uint64) int64
	close   func(uint64) int64
	stop    func(uint64) int64
	stats   func(*byte, uintptr) int64
	setCert func(uint64, *byte, uintptr, *byte, uintptr) int64
}

var quinnLibraries = struct {
	sync.Mutex
	entries map[string]*quinnAPI
}{entries: make(map[string]*quinnAPI)}

func loadQuinn() (*quinnAPI, error) {
	path := os.Getenv(EnvQuinnLibrary)
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s must name an absolute native-library path", EnvQuinnLibrary)
	}
	quinnLibraries.Lock()
	defer quinnLibraries.Unlock()
	if api := quinnLibraries.entries[path]; api != nil {
		return api, nil
	}
	lib, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("load Quinn: %w", err)
	}
	api := new(quinnAPI)
	var version func() uint64
	symbols := []struct {
		name   string
		target any
	}{{"onv_quinn_abi_version", &version}, {"onv_quinn_listen", &api.listen}, {"onv_quinn_address", &api.address}, {"onv_quinn_accept", &api.accept}, {"onv_quinn_remote", &api.remote}, {"onv_quinn_read", &api.read}, {"onv_quinn_write", &api.write}, {"onv_quinn_close", &api.close}, {"onv_quinn_stop", &api.stop}, {"onv_quinn_stats", &api.stats}, {"onv_quinn_set_certificate", &api.setCert}}
	for _, symbol := range symbols {
		address, err := purego.Dlsym(lib, symbol.name)
		if err != nil {
			_ = purego.Dlclose(lib)
			return nil, fmt.Errorf("Quinn symbol %s: %w", symbol.name, err)
		}
		purego.RegisterFunc(symbol.target, address)
	}
	if version() != 2 {
		_ = purego.Dlclose(lib)
		return nil, fmt.Errorf("unsupported Quinn bridge ABI")
	}
	// Rust owns runtime threads; keep their code loaded for the process lifetime.
	quinnLibraries.entries[path] = api
	return api, nil
}
func quinnPointer(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}
func appendQuinnField(b, field []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(field)))
	return append(b, field...)
}

// appendQuinnCertificate adds a chain and its key, or two empty fields for none.
func appendQuinnCertificate(b []byte, cert *tls.Certificate) ([]byte, error) {
	if cert == nil {
		return appendQuinnField(appendQuinnField(b, nil), nil), nil
	}
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Quinn TLS private key: %w", err)
	}
	defer clear(key)
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("empty Quinn TLS certificate")
	}
	for _, der := range cert.Certificate {
		if len(der) == 0 {
			return nil, fmt.Errorf("empty Quinn TLS certificate")
		}
		b = appendQuinnField(b, der)
	}
	b = appendQuinnField(b, nil)
	return appendQuinnField(b, key), nil
}

// quinnFetched says whether the configuration fetches its certificate, and
// refuses one that both holds and fetches.
func quinnFetched(cfg *tls.Config) (bool, error) {
	if cfg.GetCertificate == nil {
		return false, nil
	}
	if len(cfg.Certificates) != 0 {
		return false, fmt.Errorf("Quinn takes a TLS certificate held or fetched, not both")
	}
	if os.Getenv(EnvQuinnServerName) == "" {
		return false, fmt.Errorf("%s must name the certificate fetched for Quinn", EnvQuinnServerName)
	}
	return true, nil
}

// fetchQuinnCertificate asks the configuration for the certificate of the
// relay's name, as a handshake naming it would.
func fetchQuinnCertificate(cfg *tls.Config) (*tls.Certificate, error) {
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: os.Getenv(EnvQuinnServerName), SupportedProtos: cfg.NextProtos})
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, fmt.Errorf("no certificate for %s", os.Getenv(EnvQuinnServerName))
	}
	return cert, nil
}

func quinnTLSBlob(address string, cfg *tls.Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("Quinn requires TLS certificates")
	}
	fetched, err := quinnFetched(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.GetConfigForClient != nil || cfg.VerifyConnection != nil || cfg.VerifyPeerCertificate != nil || cfg.ClientAuth != tls.NoClientCert || len(cfg.CurvePreferences) > 0 {
		return nil, fmt.Errorf("experimental Quinn backend requires static certificates and no custom TLS callbacks or client-auth policy")
	}
	if (!fetched && len(cfg.Certificates) != 1) || len(cfg.NextProtos) == 0 {
		return nil, fmt.Errorf("experimental Quinn backend requires one certificate chain and explicit ALPN")
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return nil, fmt.Errorf("Quinn requires TLS 1.3")
	}
	// A fetched certificate is given after the bind (refreshQuinnCertificate):
	// Let's Encrypt may need the TCP listener up to issue it.
	var held *tls.Certificate
	if !fetched {
		held = &cfg.Certificates[0]
	}
	b, err := appendQuinnCertificate(appendQuinnField(nil, []byte(address)), held)
	if err != nil {
		return nil, err
	}
	for _, alpn := range cfg.NextProtos {
		if len(alpn) == 0 || len(alpn) > 255 {
			clear(b)
			return nil, fmt.Errorf("invalid Quinn ALPN")
		}
		b = appendQuinnField(b, []byte(alpn))
	}
	return appendQuinnField(b, nil), nil
}

type quinnListener struct {
	api    *quinnAPI
	id     uint64
	addr   net.Addr
	closed atomic.Bool
	done   chan struct{}
	wg     sync.WaitGroup
}

func newQuinnListener(address string, cfg *tls.Config) (sessionListener, error) {
	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	if resolved.IP == nil {
		resolved.IP = net.IPv6zero
	}
	blob, err := quinnTLSBlob(resolved.String(), cfg)
	if err != nil {
		return nil, err
	}
	defer clear(blob)
	api, err := loadQuinn()
	if err != nil {
		return nil, err
	}
	details := make([]byte, 4096)
	id := api.listen(quinnPointer(blob), uintptr(len(blob)), quinnPointer(details), uintptr(len(details)))
	runtime.KeepAlive(blob)
	if id == 0 {
		return nil, fmt.Errorf("Quinn listen: %s", bytes.TrimRight(details, "\x00"))
	}
	b := make([]byte, 256)
	n := api.address(id, quinnPointer(b), uintptr(len(b)))
	if n < 0 {
		api.stop(id)
		return nil, fmt.Errorf("Quinn local address: %d", n)
	}
	addr, err := net.ResolveUDPAddr("udp", string(b[:n]))
	if err != nil {
		api.stop(id)
		return nil, err
	}
	l := &quinnListener{api: api, id: id, addr: addr, done: make(chan struct{})}
	if fetched, _ := quinnFetched(cfg); fetched {
		l.wg.Add(1)
		go l.refreshQuinnCertificate(cfg)
	}
	return l, nil
}

// refreshQuinnCertificate gives the listener the certificate the configuration
// fetches, and gives it again whenever the fetch returns another (a renewal).
func (l *quinnListener) refreshQuinnCertificate(cfg *tls.Config) {
	defer l.wg.Done()
	var given []byte
	for {
		wait := quinnCertificateRenew
		cert, err := fetchQuinnCertificate(cfg)
		switch {
		case err != nil:
			log.Errorf("Quinn certificate for %s: %v", os.Getenv(EnvQuinnServerName), err)
			if given == nil {
				wait = quinnCertificateRetry
			}
		case !bytes.Equal(cert.Certificate[0], given):
			if err := l.setCertificate(cert); err != nil {
				log.Errorf("Quinn certificate for %s: %v", os.Getenv(EnvQuinnServerName), err)
				if given == nil {
					wait = quinnCertificateRetry
				}
				break
			}
			given = bytes.Clone(cert.Certificate[0])
			log.Infof("Quinn presents the certificate for %s", os.Getenv(EnvQuinnServerName))
		}
		select {
		case <-l.done:
			return
		case <-time.After(wait):
		}
	}
}

func (l *quinnListener) setCertificate(cert *tls.Certificate) error {
	blob, err := appendQuinnCertificate(nil, cert)
	if err != nil {
		return err
	}
	defer clear(blob)
	details := make([]byte, 1024)
	code := l.api.setCert(l.id, quinnPointer(blob), uintptr(len(blob)), quinnPointer(details), uintptr(len(details)))
	runtime.KeepAlive(blob)
	if code != 0 {
		return fmt.Errorf("Quinn set certificate: %d %s", code, bytes.TrimRight(details, "\x00"))
	}
	return nil
}
func (l *quinnListener) Addr() net.Addr { return l.addr }
func (l *quinnListener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	close(l.done)
	l.wg.Wait()
	if code := l.api.stop(l.id); code != 0 {
		return fmt.Errorf("Quinn shutdown: %d", code)
	}
	return nil
}
func (l *quinnListener) Accept(ctx context.Context) (relaylistener.Conn, error) {
	for {
		if l.closed.Load() {
			return nil, errListenerClosed
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := l.api.accept(l.id, uint64(quinnContextQuantum/time.Millisecond))
		if id == 0 {
			continue
		}
		if id < 0 {
			if id == -1 {
				return nil, errListenerClosed
			}
			return nil, fmt.Errorf("Quinn accept: %d", id)
		}
		b := make([]byte, 256)
		n := l.api.remote(uint64(id), quinnPointer(b), uintptr(len(b)))
		if n < 0 {
			l.api.close(uint64(id))
			return nil, fmt.Errorf("Quinn peer address: %d", n)
		}
		remote, err := net.ResolveUDPAddr("udp", string(b[:n]))
		if err != nil {
			l.api.close(uint64(id))
			return nil, err
		}
		return &quinnConn{api: l.api, id: uint64(id), remote: remote}, nil
	}
}

type quinnConn struct {
	api    *quinnAPI
	id     uint64
	remote net.Addr
	closed atomic.Bool
}

func (c *quinnConn) Read(ctx context.Context, b []byte) (int, error) {
	return c.transfer(ctx, b, false)
}
func (c *quinnConn) Write(ctx context.Context, b []byte) (int, error) {
	return c.transfer(ctx, b, true)
}
func (c *quinnConn) transfer(ctx context.Context, b []byte, write bool) (int, error) {
	for {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		wait := quinnContextQuantum
		if deadline, ok := ctx.Deadline(); ok {
			wait = min(wait, time.Until(deadline))
			if wait <= 0 {
				return 0, context.DeadlineExceeded
			}
		}
		millis := max(uint64(wait/time.Millisecond), 1)
		var n int64
		if write {
			n = c.api.write(c.id, quinnPointer(b), uintptr(len(b)), millis)
		} else {
			n = c.api.read(c.id, quinnPointer(b), uintptr(len(b)), millis)
		}
		runtime.KeepAlive(b)
		if n >= 0 {
			return int(n), nil
		}
		if n == -2 {
			continue
		}
		if n == -1 {
			return 0, net.ErrClosed
		}
		return 0, fmt.Errorf("Quinn datagram operation: %d", n)
	}
}
func (c *quinnConn) RemoteAddr() net.Addr { return c.remote }
func (c *quinnConn) Protocol() string     { return "quic" }
func (c *quinnConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	if code := c.api.close(c.id); code != 0 {
		return fmt.Errorf("Quinn connection close: %d", code)
	}
	return nil
}

// QuinnSnapshot reports native counters when the experimental backend is loaded.
func QuinnSnapshot() ([]byte, error) {
	quinnLibraries.Lock()
	var api *quinnAPI
	for _, candidate := range quinnLibraries.entries {
		api = candidate
	}
	quinnLibraries.Unlock()
	if api == nil {
		return nil, nil
	}
	b := make([]byte, 128*1024)
	n := api.stats(quinnPointer(b), uintptr(len(b)))
	if n < 0 {
		return nil, fmt.Errorf("Quinn statistics: %d", n)
	}
	return b[:n], nil
}
