//go:build linux

package net

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func setSocketPacing(conn any, bytesPerSec int) {
	rc, ok := conn.(rawConnProvider)
	if !ok {
		log.Warnf("relay socket pacing skipped: %T has no raw connection", conn)
		return
	}
	raw, err := rc.SyscallConn()
	if err != nil {
		log.Warnf("relay socket pacing skipped: get raw conn: %v", err)
		return
	}
	if err := setSockoptInt(raw, unix.SO_MAX_PACING_RATE, bytesPerSec); err != nil {
		log.Warnf("failed to pace the relay socket at %d bytes/s: %v", bytesPerSec, err)
		return
	}
	got, err := getSockoptInt(raw, unix.SO_MAX_PACING_RATE)
	if err != nil {
		log.Warnf("failed to read the relay socket's pacing rate back: %v", err)
		return
	}
	log.Infof("relay socket paced at %d bytes/s (the kernel reports %d)", bytesPerSec, got)
}

func setSocketSendBuffer(conn any, size int) {
	rc, ok := conn.(rawConnProvider)
	if !ok {
		log.Warnf("paced relay socket's send buffer not set: %T has no raw connection", conn)
		return
	}
	raw, err := rc.SyscallConn()
	if err != nil {
		log.Warnf("paced relay socket's send buffer not set: get raw conn: %v", err)
		return
	}
	before, _ := getSockoptInt(raw, unix.SO_SNDBUF)
	if err := setSockoptInt(raw, unix.SO_SNDBUF, size); err != nil {
		log.Warnf("failed to set the paced relay socket's send buffer to %d bytes: %v", size, err)
		return
	}
	after, err := getSockoptInt(raw, unix.SO_SNDBUF)
	if err != nil {
		log.Warnf("failed to read the paced relay socket's send buffer back: %v", err)
		return
	}
	log.Infof("paced relay socket's send buffer set from %d to %d bytes (kernel-reported)", before, after)
}
