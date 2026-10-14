//go:build !linux

package udp

import "net"

func enableGRO(net.PacketConn) bool { return false }

func groSize([]byte) int { return 0 }

const groOOB = 0
