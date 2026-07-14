//go:build linux && !android

package loopback

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.org/x/net/ipv6"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/bufsize"
	"github.com/netbirdio/netbird/client/iface/wgproxy/rawsocket"
	nbnet "github.com/netbirdio/netbird/client/net"
)

const (
	loopbackDevice = "lo"

	portRangeStart = 3128
	portRangeEnd   = portRangeStart + 100
)

// Proxy forwards packets between relayed connections and a local kernel
// WireGuard instance. Every relayed peer gets its own loopback address as its
// WireGuard endpoint, so a single socket serves all of them: the destination
// address of an incoming packet identifies the peer.
type Proxy struct {
	localWGListenPort int
	mtu               uint16
	proxyPort         int

	conn        *net.UDPConn
	packetConn  *ipv4.PacketConn
	loIndex     int
	rawConnIPv4 net.PacketConn
	rawConnIPv6 net.PacketConn

	relayedConnMutex sync.Mutex
	relayedConnStore map[netip.Addr]net.Conn
	addrs            allocator
	// batchConnIPv4/IPv6 wrap the raw sockets so the inject path can write a
	// whole batch of packets with one sendmmsg (WriteBatch) instead of one
	// WriteTo per packet. Non-nil whenever the matching raw socket is present.
	batchConnIPv4 *ipv4.PacketConn
	batchConnIPv6 *ipv6.PacketConn

	// batchRead drains several relayed packets from the local WireGuard socket
	// with one recvmmsg and forwards them back-to-back, cutting the per-packet
	// syscall and wakeup overhead on the hot send path. Gated by
	// NB_RELAY_BATCH_READ; the per-packet path stays the default.
	batchRead bool

	ctx       context.Context
	ctxCancel context.CancelFunc
}

// batchReadSize bounds how many packets are drained from the local WireGuard
// socket per recvmmsg when NB_RELAY_BATCH_READ is set.
const batchReadSize = 64

// NewProxy creates a proxy for the WireGuard instance listening on wgPort.
func NewProxy(wgPort int, mtu uint16) *Proxy {
	log.Debugf("instantiate loopback wg proxy")
	return &Proxy{
		localWGListenPort: wgPort,
		mtu:               mtu,
		relayedConnStore:  make(map[netip.Addr]net.Conn),
	}
}

// Listen opens the shared socket and starts forwarding WireGuard packets to the
// relayed connections.
func (p *Proxy) Listen() error {
	rawConnIPv4, err := rawsocket.PrepareSenderRawSocketIPv4()
	if err != nil {
		return fmt.Errorf("prepare IPv4 raw socket: %w", err)
	}
	p.rawConnIPv4 = rawConnIPv4
	p.batchConnIPv4 = ipv4.NewPacketConn(p.rawConnIPv4)

	p.rawConnIPv6, err = rawsocket.PrepareSenderRawSocketIPv6()
	if err != nil {
		log.Warnf("failed to prepare IPv6 raw socket, continuing with IPv4 only: %v", err)
	}
	if p.rawConnIPv6 != nil {
		p.batchConnIPv6 = ipv6.NewPacketConn(p.rawConnIPv6)
	}

	loopback, err := net.InterfaceByName(loopbackDevice)
	if err != nil {
		if freeErr := p.Free(); freeErr != nil {
			log.Errorf("failed to free the wgproxy: %s", freeErr)
		}
		return fmt.Errorf("look up %s: %w", loopbackDevice, err)
	}
	p.loIndex = loopback.Index

	if err := p.listen(); err != nil {
		if freeErr := p.Free(); freeErr != nil {
			log.Errorf("failed to free the wgproxy: %s", freeErr)
		}
		return err
	}

	p.ctx, p.ctxCancel = context.WithCancel(context.Background())

	p.batchRead = os.Getenv("NB_RELAY_BATCH_READ") == "true"
	go p.proxyToRemote()
	log.Infof("local wg proxy listening on %s:%d", addrRangePrefix, p.proxyPort)
	return nil
}

// listen binds the shared socket on the first free port of the range. The bind
// has to be a wildcard one to receive every peer address in the range, so it is
// restricted to the loopback device: without that the port would be reachable
// on every interface.
func (p *Proxy) listen() error {
	var lastErr error
	for port := portRangeStart; port <= portRangeEnd; port++ {
		err := p.listenOn(port)
		if err == nil {
			p.proxyPort = port
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("bind proxy port in range %d-%d: %w", portRangeStart, portRangeEnd, lastErr)
}

func (p *Proxy) listenOn(proxyPort int) error {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, loopbackDevice); err != nil {
					sockErr = fmt.Errorf("bind to %s: %w", loopbackDevice, err)
					return
				}
			}); err != nil {
				return fmt.Errorf("control socket: %w", err)
			}
			return sockErr
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", proxyPort))
	if err != nil {
		return fmt.Errorf("listen on :%d: %w", proxyPort, err)
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		if closeErr := conn.Close(); closeErr != nil {
			log.Errorf("failed to close proxy conn: %s", closeErr)
		}
		return fmt.Errorf("unexpected conn type %T", conn)
	}

	packetConn := ipv4.NewPacketConn(udpConn)
	// the destination address carries the peer identity, the interface index is
	// checked on receive as a second line of defense behind SO_BINDTODEVICE
	if err := packetConn.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
		if closeErr := udpConn.Close(); closeErr != nil {
			log.Errorf("failed to close proxy conn: %s", closeErr)
		}
		return fmt.Errorf("request destination address: %w", err)
	}

	p.conn = udpConn
	nbnet.SizeRelaySocketBuffers(p.conn)
	p.packetConn = packetConn
	return nil
}

// AddRelayedConn assigns an endpoint address to the relayed connection and
// returns the address WireGuard should send to, along with the key the
// connection is stored under.
func (p *Proxy) AddRelayedConn(relayedConn net.Conn) (*net.UDPAddr, netip.Addr, error) {
	addr, err := p.storeRelayedConn(relayedConn)
	if err != nil {
		return nil, netip.Addr{}, err
	}

	log.Infof("relayed conn added to wg proxy store: %s, endpoint address: %s", relayedConn.RemoteAddr(), addr)

	return &net.UDPAddr{
		IP:   addr.AsSlice(),
		Port: p.proxyPort,
	}, addr, nil
}

// Free releases the proxy resources. The relayed connections are left open.
func (p *Proxy) Free() error {
	log.Debugf("free up loopback wg proxy")
	if p.ctx != nil && p.ctx.Err() != nil {
		//nolint
		return nil
	}

	if p.ctxCancel != nil {
		p.ctxCancel()
	}

	var result *multierror.Error
	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if p.rawConnIPv4 != nil {
		if err := p.rawConnIPv4.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}

	if p.rawConnIPv6 != nil {
		if err := p.rawConnIPv6.Close(); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return nberrors.FormatErrorOrNil(result)
}

// proxyToRemote reads packets from the local WireGuard instance and forwards
// them to the relayed connection the destination address belongs to.
func (p *Proxy) proxyToRemote() {
	if p.batchRead {
		p.proxyToRemoteBatch()
		return
	}
	buf := make([]byte, p.mtu+bufsize.WGBufferOverhead)
	for p.ctx.Err() == nil {
		if err := p.readAndForwardPacket(buf); err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Errorf("failed to proxy packet to remote conn: %s", err)
		}
	}
}

// proxyToRemoteBatch drains up to batchReadSize packets from the local
// WireGuard socket with one recvmmsg, each with its control message, and
// forwards each as readAndForwardPacket does: the destination address names
// the relayed connection. Draining several packets a call spreads the read
// syscall and wakeup over the batch on the hot send path.
func (p *Proxy) proxyToRemoteBatch() {
	bufSize := int(p.mtu) + bufsize.WGBufferOverhead
	oobSize := len(ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface))
	msgs := make([]ipv4.Message, batchReadSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, bufSize)}
		msgs[i].OOB = make([]byte, oobSize)
	}
	var cm ipv4.ControlMessage
	for p.ctx.Err() == nil {
		n, err := p.packetConn.ReadBatch(msgs, 0)
		if err != nil {
			if p.ctx.Err() != nil {
				return
			}
			log.Errorf("failed to batch read UDP packets from WG: %s", err)
			continue
		}
		for i := 0; i < n; i++ {
			if err := cm.Parse(msgs[i].OOB[:msgs[i].NN]); err != nil {
				log.Tracef("dropping packet with an unreadable control message: %s", err)
				continue
			}
			if err := p.forwardPacket(msgs[i].Buffers[0][:msgs[i].N], &cm); err != nil {
				log.Errorf("failed to proxy packet to remote conn: %s", err)
			}
		}
	}
}

func (p *Proxy) readAndForwardPacket(buf []byte) error {
	n, cm, _, err := p.packetConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("read UDP packet from WG: %w", err)
	}
	return p.forwardPacket(buf[:n], cm)
}

// forwardPacket sends one packet WireGuard wrote to the proxy to the relayed
// connection its destination address belongs to.
func (p *Proxy) forwardPacket(payload []byte, cm *ipv4.ControlMessage) error {
	if cm == nil {
		return fmt.Errorf("no control message on packet")
	}

	if cm.IfIndex != p.loIndex {
		log.Tracef("dropping packet received on interface %d instead of %s", cm.IfIndex, loopbackDevice)
		return nil
	}

	dst, ok := netip.AddrFromSlice(cm.Dst.To4())
	if !ok || !inRange(dst) {
		log.Tracef("dropping packet for unexpected destination %s", cm.Dst)
		return nil
	}

	p.relayedConnMutex.Lock()
	conn, ok := p.relayedConnStore[dst]
	p.relayedConnMutex.Unlock()
	if !ok {
		if p.ctx.Err() == nil {
			log.Debugf("relayed conn not found by address because conn already has been closed: %s", dst)
		}
		return nil
	}

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("forward local WG packet (%s) to remote relayed conn: %w", dst, err)
	}
	return nil
}

func (p *Proxy) storeRelayedConn(relayedConn net.Conn) (netip.Addr, error) {
	p.relayedConnMutex.Lock()
	defer p.relayedConnMutex.Unlock()

	addr, err := p.addrs.next(func(a netip.Addr) bool {
		_, ok := p.relayedConnStore[a]
		return ok
	})
	if err != nil {
		return netip.Addr{}, err
	}

	p.relayedConnStore[addr] = relayedConn
	return addr, nil
}

// removeRelayedConn releases an endpoint address. It only removes the entry
// while it still belongs to relayedConn, so a late release cannot take an
// address away from the peer it was handed to next.
func (p *Proxy) removeRelayedConn(addr netip.Addr, relayedConn net.Conn) {
	p.relayedConnMutex.Lock()
	defer p.relayedConnMutex.Unlock()

	if stored, ok := p.relayedConnStore[addr]; !ok || stored != relayedConn {
		return
	}

	log.Debugf("remove relayed conn from store by address: %s", addr)
	delete(p.relayedConnStore, addr)
}
