package conntype

import (
	"fmt"
)

const (
	None  ConnPriority = 0
	Relay ConnPriority = 1
	// RelayUDP is the relay that forwards plain UDP (shared/relay/udp): above
	// the QUIC or WebSocket relay it is climbed to from, below any direct path.
	RelayUDP ConnPriority = 2
	ICETurn  ConnPriority = 3
	ICEP2P   ConnPriority = 4
)

type ConnPriority int

func (cp ConnPriority) String() string {
	switch cp {
	case None:
		return "None"
	case Relay:
		return "PriorityRelay"
	case RelayUDP:
		return "PriorityRelayUDP"
	case ICETurn:
		return "PriorityICETurn"
	case ICEP2P:
		return "PriorityICEP2P"
	default:
		return fmt.Sprintf("ConnPriority(%d)", cp)
	}
}
