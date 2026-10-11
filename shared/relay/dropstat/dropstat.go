// Package dropstat counts the relayed packets this process discards without
// saying so, and writes the counts to the log when they move (omnuv). It
// changes no behaviour. The QUIC counters are the two that omnuv's build adds
// to quic-go (deployment/netbird/quic-go-dropstat.patch in omnuv).
package dropstat

import (
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

func init() {
	go func() {
		var last [5]uint64
		for range time.Tick(2 * time.Second) {
			now := [5]uint64{ChannelDrops.Load(), quic.DiscardedDatagrams.Load(), quic.BlockedDatagramSends.Load(), WriteErrors.Load(), QueueDrops.Load()}
			if now != last {
				log.Infof("onv dropstat channel_drops=%d quic_rcv_discards=%d quic_send_waits=%d write_errors=%d queue_drops=%d", now[0], now[1], now[2], now[3], now[4])
				last = now
			}
		}
	}()
}
