package net

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// relayPaceEnv sets, in Mbit/s, the rate that the UDP socket carrying a QUIC connection
// to a relay is held to. Unset, empty or "0" leaves the socket as it is.
const relayPaceEnv = "NB_RELAY_PACE_MBIT"

// quicBatchedSendsEnv is the QUIC library's own switch for its batched sends (GSO).
const quicBatchedSendsEnv = "QUIC_GO_DISABLE_GSO"

// maxRelayPaceMbit keeps the rate, in bytes a second, within the int32 that setsockopt takes.
const maxRelayPaceMbit = 16000

// pacedRelaySendBuffer is the send buffer a paced relay socket is given, in bytes. A packet
// waiting its turn in the interface's queue still counts against its socket's send buffer,
// so with a buffer this small a burst waits in the socket, where the sender blocks, before
// it reaches the queue's own limit for one flow (100 packets in fq), where a packet is
// dropped and nothing says so. The kernel doubles the figure: 128 KiB, about 55 packets.
const pacedRelaySendBuffer = 64 << 10

// relayPaceBytes resolves the configured rate from the environment, in bytes a second.
func relayPaceBytes() int {
	v := os.Getenv(relayPaceEnv)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		log.Warnf("invalid %s value %q, the relay socket is not paced", relayPaceEnv, v)
		return 0
	}
	if n > maxRelayPaceMbit {
		log.Warnf("%s value %d is over what the kernel takes, using %d", relayPaceEnv, n, maxRelayPaceMbit)
		n = maxRelayPaceMbit
	}
	return int(n) * 1000 * 1000 / 8
}

// PrepareRelayPacing turns the QUIC library's batched sends off when the relay socket is to
// be paced and the environment does not say otherwise: the queue spaces what it is handed,
// and a batch is handed to it as one packet. It has to run before the library opens a socket.
func PrepareRelayPacing() {
	if relayPaceBytes() == 0 {
		return
	}
	if _, set := os.LookupEnv(quicBatchedSendsEnv); set {
		return
	}
	if err := os.Setenv(quicBatchedSendsEnv, "true"); err != nil {
		log.Warnf("failed to turn the QUIC library's batched sends off: %v", err)
	}
}

// PaceRelaySocket asks the kernel to space the packets this socket sends, at the rate set
// by NB_RELAY_PACE_MBIT. The QUIC library sends about two milliseconds of traffic at once,
// and a path with a slower link past the machine loses a part of a burst that long: counted
// on a 1 Gbit/s line behind a 10 Gbit/s card, 17 to 26 packets in ten seconds unspaced and
// none spaced, the tunnelled TCP stream a fifth faster. The spacing is the interface's
// queue's to do, and only fq does it by a socket's rate; under any other queue the option
// is taken and changes nothing. Only Linux has the option.
func PaceRelaySocket(conn any) {
	rate := relayPaceBytes()
	if rate == 0 {
		return
	}
	setSocketPacing(conn, rate)
}

// BoundPacedRelaySocket holds a paced relay socket's send buffer to pacedRelaySendBuffer.
// It has to run after the QUIC library has opened its connection on the socket: the
// library raises the send buffer itself when it is handed one. Without pacing asked it
// does nothing.
func BoundPacedRelaySocket(conn any) {
	if relayPaceBytes() == 0 {
		return
	}
	setSocketSendBuffer(conn, pacedRelaySendBuffer)
}
