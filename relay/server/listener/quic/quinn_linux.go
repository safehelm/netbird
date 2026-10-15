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
	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
)

// EnvQuinnLibrary specifies the absolute path to the experimental native backend.
const EnvQuinnLibrary = "NB_RELAY_QUINN_LIBRARY"

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
	}{{"onv_quinn_abi_version", &version}, {"onv_quinn_listen", &api.listen}, {"onv_quinn_address", &api.address}, {"onv_quinn_accept", &api.accept}, {"onv_quinn_remote", &api.remote}, {"onv_quinn_read", &api.read}, {"onv_quinn_write", &api.write}, {"onv_quinn_close", &api.close}, {"onv_quinn_stop", &api.stop}, {"onv_quinn_stats", &api.stats}}
	for _, symbol := range symbols {
		address, err := purego.Dlsym(lib, symbol.name)
		if err != nil {
			_ = purego.Dlclose(lib)
			return nil, fmt.Errorf("Quinn symbol %s: %w", symbol.name, err)
		}
		purego.RegisterFunc(symbol.target, address)
	}
	if version() != 1 {
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
func quinnTLSBlob(address string, cfg *tls.Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("Quinn requires TLS certificates")
	}
	if cfg.GetCertificate != nil || cfg.GetConfigForClient != nil || cfg.VerifyConnection != nil || cfg.VerifyPeerCertificate != nil || cfg.ClientAuth != tls.NoClientCert || len(cfg.CurvePreferences) > 0 {
		return nil, fmt.Errorf("experimental Quinn backend requires static certificates and no custom TLS callbacks or client-auth policy")
	}
	if len(cfg.Certificates) != 1 || len(cfg.NextProtos) == 0 {
		return nil, fmt.Errorf("experimental Quinn backend requires one certificate chain and explicit ALPN")
	}
	if cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		return nil, fmt.Errorf("Quinn requires TLS 1.3")
	}
	key, err := x509.MarshalPKCS8PrivateKey(cfg.Certificates[0].PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Quinn TLS private key: %w", err)
	}
	defer clear(key)
	b := appendQuinnField(nil, []byte(address))
	for _, cert := range cfg.Certificates[0].Certificate {
		if len(cert) == 0 {
			return nil, fmt.Errorf("empty Quinn TLS certificate")
		}
		b = appendQuinnField(b, cert)
	}
	b = appendQuinnField(b, nil)
	b = appendQuinnField(b, key)
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
	return &quinnListener{api: api, id: id, addr: addr}, nil
}
func (l *quinnListener) Addr() net.Addr { return l.addr }
func (l *quinnListener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
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

func (c *quinnConn) Read(ctx context.Context, b []byte) (int, error)  { return c.transfer(ctx, b, false) }
func (c *quinnConn) Write(ctx context.Context, b []byte) (int, error) { return c.transfer(ctx, b, true) }
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
