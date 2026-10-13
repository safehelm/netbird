// Package dropstat counts the relayed packets this process discards without
// saying so, and writes the counts to the log when they move (omnuv). It
// changes no behaviour. The QUIC counters are the two that omnuv's build adds
// to quic-go (deployment/netbird/quic-go-dropstat.patch in omnuv).
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

// QueueDrops counts transport messages the relay freed because their peer's
// write queue was full.
var QueueDrops atomic.Uint64

// WriteErrors counts transport messages the relay could not write to their peer.
var WriteErrors atomic.Uint64

// counts reads every counter, in the order the line names them. The last is
// the one omnuv's build adds to quic-go's connection
// (deployment/netbird/quic-go-unprocessed-count.patch in omnuv): packets a
// connection discarded because its run loop had not taken the ones before.
func counts() [6]uint64 {
	return [6]uint64{ChannelDrops.Load(), quic.DiscardedDatagrams.Load(), quic.BlockedDatagramSends.Load(), WriteErrors.Load(), QueueDrops.Load(), quic.DroppedUnprocessedPackets.Load()}
}

// line is what the log carries. A reader greps for a field by its name, so a
// new one goes at the end and none is renamed.
func line(c [6]uint64) string {
	return fmt.Sprintf("onv dropstat channel_drops=%d quic_rcv_discards=%d quic_send_waits=%d write_errors=%d queue_drops=%d quic_unprocessed_drops=%d", c[0], c[1], c[2], c[3], c[4], c[5])
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
