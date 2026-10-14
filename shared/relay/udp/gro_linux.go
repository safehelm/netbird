//go:build linux

package udp

import (
	"encoding/binary"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// enableGRO asks the kernel to hand this socket a run of datagrams of one
// size from one source as one buffer, with the size in a control message
// (UDP_GRO). The receiving core then does one pass and one system call for
// many packets, where it did one each.
func enableGRO(pc net.PacketConn) bool {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil {
		return false
	}
	return serr == nil
}

// groSize is the size of each datagram of a coalesced buffer, from its
// control message; 0 when the buffer is one datagram.
func groSize(oob []byte) int {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_UDP && m.Header.Type == unix.UDP_GRO && len(m.Data) >= 4 {
			return int(binary.NativeEndian.Uint32(m.Data[:4]))
		}
	}
	return 0
}

// groOOB is room for the one control message.
const groOOB = 64
