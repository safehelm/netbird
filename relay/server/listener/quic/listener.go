package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/protocol"
	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
	nbRelay "github.com/netbirdio/netbird/shared/relay"
)

const Proto protocol.Protocol = "quic"

// EnvQUICBackend selects the experimental relay-only QUIC implementation.
const EnvQUICBackend = "NB_RELAY_QUIC_BACKEND"

var errListenerClosed = errors.New("QUIC listener closed")

type sessionListener interface {
	Accept(context.Context) (relaylistener.Conn, error)
	Addr() net.Addr
	Close() error
}

type goSessionListener struct{ *quic.Listener }

func (l *goSessionListener) Accept(ctx context.Context) (relaylistener.Conn, error) {
	c, err := l.Listener.Accept(ctx)
	if errors.Is(err, quic.ErrServerClosed) {
		return nil, errListenerClosed
	}
	if err != nil {
		return nil, err
	}
	return NewConn(c), nil
}

type Listener struct {
	// Address is the address to listen on
	Address string
	// TLSConfig is the TLS configuration for the server
	TLSConfig *tls.Config

	listener sessionListener
}

func (l *Listener) Bind() error {
	backend := os.Getenv(EnvQUICBackend)
	if backend == "quinn" {
		listener, err := newQuinnListener(l.Address, l.TLSConfig)
		if err != nil {
			return err
		}
		l.listener = listener
		log.Infof("Quinn QUIC server listening on address: %s", listener.Addr())
		return nil
	}
	if backend != "" && backend != "quic-go" {
		return fmt.Errorf("unknown relay QUIC backend %q", backend)
	}

	quicCfg := &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: nbRelay.QUICInitialPacketSize,
	}
	listener, err := quic.ListenAddr(l.Address, l.TLSConfig, quicCfg)
	if err != nil {
		return err
	}

	l.listener = &goSessionListener{Listener: listener}
	log.Infof("QUIC server listening on address: %s", l.Address)
	return nil
}

func (l *Listener) Serve(acceptFn func(conn relaylistener.Conn)) error {
	if l.listener == nil {
		return errors.New("listener is not bound")
	}

	for {
		session, err := l.listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, errListenerClosed) {
				return nil
			}

			log.Errorf("Failed to accept QUIC session: %v", err)
			continue
		}

		log.Infof("QUIC client connected from: %s", session.RemoteAddr())
		conn := session
		// Run the accept handler (which performs the pre-auth handshake) in its
		// own goroutine so a slow or stalled handshake cannot block accepting
		// further connections.
		go acceptFn(conn)
	}
}

func (l *Listener) Protocol() protocol.Protocol {
	return Proto
}

func (l *Listener) Shutdown(ctx context.Context) error {
	if l.listener == nil {
		return nil
	}

	log.Infof("stopping QUIC listener")
	if err := l.listener.Close(); err != nil {
		return fmt.Errorf("listener shutdown failed: %v", err)
	}
	log.Infof("QUIC listener stopped")
	return nil
}
