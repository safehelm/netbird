//go:build !linux || (!amd64 && !arm64)

package quic

import (
	"crypto/tls"
	"fmt"
)

func newQuinnListener(_ string, _ *tls.Config) (sessionListener, error) {
	return nil, fmt.Errorf("experimental Quinn backend requires Linux amd64 or arm64")
}

// QuinnSnapshot reports no native backend on unsupported platforms.
func QuinnSnapshot() ([]byte, error) { return nil, nil }
