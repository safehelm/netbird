package dropstat

import (
	"strings"
	"testing"

	"github.com/quic-go/quic-go"
)

// The log line is read by name, field by field (omnuv's runbook and its
// bench): every counter is in it once, in the order counts() reads them, and
// the library's unprocessed-packet drops are the last.
func TestLineNamesEveryCounterInOrder(t *testing.T) {
	var c [6]uint64
	for i := range c {
		c[i] = uint64(i + 1)
	}
	got := line(c)
	want := "onv dropstat channel_drops=1 quic_rcv_discards=2 quic_send_waits=3 write_errors=4 queue_drops=5 quic_unprocessed_drops=6"
	if got != want {
		t.Fatalf("line:\n got %q\nwant %q", got, want)
	}
	if !strings.HasSuffix(got, " quic_unprocessed_drops=6") {
		t.Fatalf("the unprocessed-packet drops are not the last field: %q", got)
	}
}

// counts() reads the library's counter and not a copy: a packet the
// connection discards moves the line.
func TestCountsReadsTheLibrarysCounter(t *testing.T) {
	before := counts()[5]
	quic.DroppedUnprocessedPackets.Add(3)
	if after := counts()[5]; after != before+3 {
		t.Fatalf("quic_unprocessed_drops went from %d to %d, want %d", before, after, before+3)
	}
}
