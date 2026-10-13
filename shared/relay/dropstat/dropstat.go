// Package dropstat counts the relayed packets this process discards without
// saying so, and writes the counts to the log when they move. Measurement
// only (omnuv): it changes no behaviour.
package dropstat

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

// ChannelDrops counts messages freed because a peer's inbound channel was full.
var ChannelDrops atomic.Uint64

// WriteErrors counts transport messages the relay could not write to their peer.
var WriteErrors atomic.Uint64

// TooLarge counts the packets the client did not send because they are over
// what its connection to the relay carries in one datagram. Held to QUIC
// (NB_RELAY_TRANSPORT=quic) the client warns once a connection and drops
// every such packet after it.
var TooLarge atomic.Uint64

// counts reads every counter, in the order the line names them. The last is
// the one omnuv's build adds to quic-go's connection
// (deployment/netbird/quic-go-unprocessed-count.patch in omnuv): packets a
// connection discarded because its run loop had not taken the ones before.
func counts() [6]uint64 {
	return [6]uint64{ChannelDrops.Load(), quic.DiscardedDatagrams.Load(), quic.BlockedDatagramSends.Load(), WriteErrors.Load(), quic.DroppedUnprocessedPackets.Load(), TooLarge.Load()}
}

// line is what the log carries. A reader greps for a field by its name, so a
// new one goes at the end and none is renamed.
func line(c [6]uint64) string {
	return fmt.Sprintf("onv dropstat channel_drops=%d quic_rcv_discards=%d quic_send_waits=%d write_errors=%d quic_unprocessed_drops=%d too_large=%d", c[0], c[1], c[2], c[3], c[4], c[5])
}

func init() {
	go func() {
		var last [6]uint64
		for range time.Tick(2 * time.Second) {
			now := counts()
			if now != last {
				log.Info(line(now))
				last = now
			}
		}
	}()
}
