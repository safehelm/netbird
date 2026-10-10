// Package dropstat counts the relayed packets this process discards without
// saying so, and writes the counts to the log when they move. Measurement
// only (omnuv): it changes no behaviour.
package dropstat

import (
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"
)

// ChannelDrops counts messages freed because a peer's inbound channel was full.
var ChannelDrops atomic.Uint64

// WriteErrors counts transport messages the relay could not write to their peer.
var WriteErrors atomic.Uint64

func init() {
	go func() {
		var last [4]uint64
		for range time.Tick(2 * time.Second) {
			now := [4]uint64{ChannelDrops.Load(), quic.DiscardedDatagrams.Load(), quic.BlockedDatagramSends.Load(), WriteErrors.Load()}
			if now != last {
				log.Infof("onv dropstat channel_drops=%d quic_rcv_discards=%d quic_send_waits=%d write_errors=%d", now[0], now[1], now[2], now[3])
				last = now
			}
		}
	}()
}
