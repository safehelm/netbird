package relay

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	// WebSocketURLPath is the path for the websocket relay connection
	WebSocketURLPath = "/relay"

	// QUICInitialPacketSize is the conservative initial QUIC packet size (bytes)
	// for unknown-path PMTU, per RFC 9000 §14: 1280 (IPv6 min MTU) − 40 (IPv6
	// header) − 8 (UDP header) = 1232. DPLPMTUD may probe larger sizes later.
	QUICInitialPacketSize = 1232

	// EnvQUICInitialPacketSize names the size a QUIC connection to or from the
	// relay starts at, in place of QUICInitialPacketSize (omnuv).
	//
	// Why one would: a relayed packet travels in one datagram, and a datagram
	// may be 37 bytes less than the connection's packet size. At 1232 that is
	// 1195, under a full packet of the overlay (its MTU, WireGuard's 32 and
	// the relay's header of 38: 1310 at an MTU of 1240), so nothing full-sized
	// passes until the library has found a larger size for the path. When it
	// does not find one, nothing full-sized passes for as long as the
	// connection lives. Started at 1347 or more, such a connection carries
	// them from its first packet. The price is a path whose own limit is
	// under the size named: QUIC does not connect over it at all.
	EnvQUICInitialPacketSize = "NB_RELAY_QUIC_INITIAL_PACKET"

	// The library refuses a start under 1200 and never sends over 1452.
	minQUICInitialPacketSize = 1200
	maxQUICInitialPacketSize = 1452
)

// InitialPacketSize is the size a QUIC connection starts at:
// EnvQUICInitialPacketSize when it names one the library can use, else
// QUICInitialPacketSize.
func InitialPacketSize() uint16 {
	v := os.Getenv(EnvQUICInitialPacketSize)
	if v == "" {
		return QUICInitialPacketSize
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < minQUICInitialPacketSize || n > maxQUICInitialPacketSize {
		log.Warnf("invalid %s value %q (%d to %d), using %d", EnvQUICInitialPacketSize, v, minQUICInitialPacketSize, maxQUICInitialPacketSize, QUICInitialPacketSize)
		return QUICInitialPacketSize
	}
	return uint16(n)
}
