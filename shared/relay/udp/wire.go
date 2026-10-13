// Package udp is the client's half of a relay that forwards WireGuard packets
// as plain UDP: Tailscale's net/udprelay server, run as onv-udp-relay.
//
// The wire format is that server's, written here against it and not imported:
// Tailscale's module asks a newer Go than this one builds with. What is
// Tailscale's is the Geneve header and the three bind messages; the ping and
// the pong two peers send each other through the relay are ours, since both
// ends are this package.
package udp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

const (
	// GeneveLen is what the relay's header adds to every packet.
	GeneveLen = 8

	protoDisco     uint16 = 0x7A11
	protoWireGuard uint16 = 0x7A12

	keyLen   = 32
	nonceLen = 24

	typePing      byte = 0x01
	typePong      byte = 0x02
	typeBind      byte = 0x04
	typeChallenge byte = 0x05
	typeAnswer    byte = 0x06

	challengeLen = 32
	// A bind message's body: VNI, generation, the other peer's key, challenge.
	bindBodyLen = 4 + 4 + keyLen + challengeLen
	pingIDLen   = 12
)

// magic opens every discovery message: "TS" and U+1F4AC.
var magic = [6]byte{0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac}

const sealedHeaderLen = len(magic) + keyLen

var errShort = errors.New("short packet")

// putGeneve writes the 8-byte header. control is set only on the three bind
// messages, which the relay answers itself; everything else it forwards.
func putGeneve(b []byte, vni uint32, proto uint16, control bool) {
	b[0] = 0
	b[1] = 0
	if control {
		b[1] = 0x80
	}
	binary.BigEndian.PutUint16(b[2:], proto)
	binary.BigEndian.PutUint32(b[4:], vni<<8)
}

func parseGeneve(b []byte) (vni uint32, proto uint16, control bool, err error) {
	if len(b) < GeneveLen {
		return 0, 0, false, errShort
	}
	if b[0]>>6 != 0 {
		return 0, 0, false, errors.New("unknown Geneve version")
	}
	return binary.BigEndian.Uint32(b[4:]) >> 8, binary.BigEndian.Uint16(b[2:]), b[1]&0x80 != 0, nil
}

// Key is a relay key: a Curve25519 pair made at start and never written. Not
// the WireGuard key.
type Key struct {
	private [keyLen]byte
	public  [keyLen]byte
}

// NewKey makes a relay key.
func NewKey() (*Key, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{private: *priv, public: *pub}, nil
}

// Public is the half given to the peer and to the relay.
func (k *Key) Public() [keyLen]byte { return k.public }

func (k *Key) shared(peer [keyLen]byte) *[keyLen]byte {
	var s [keyLen]byte
	box.Precompute(&s, &peer, &k.private)
	return &s
}

// seal appends, after hdr, a discovery message from sender: the magic, the
// sender's public key, a nonce, and the box holding body.
func seal(hdr []byte, sender [keyLen]byte, shared *[keyLen]byte, body []byte) ([]byte, error) {
	out := append(hdr, magic[:]...)
	out = append(out, sender[:]...)
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	out = append(out, nonce[:]...)
	return box.SealAfterPrecomputation(out, body, &nonce, shared), nil
}

// open undoes seal for a message that must come from want.
func open(msg []byte, want [keyLen]byte, shared *[keyLen]byte) ([]byte, bool) {
	if len(msg) < sealedHeaderLen+nonceLen+box.Overhead {
		return nil, false
	}
	if [6]byte(msg[:len(magic)]) != magic || [keyLen]byte(msg[len(magic):sealedHeaderLen]) != want {
		return nil, false
	}
	nonce := [nonceLen]byte(msg[sealedHeaderLen : sealedHeaderLen+nonceLen])
	return box.OpenAfterPrecomputation(nil, msg[sealedHeaderLen+nonceLen:], &nonce, shared)
}

// bindBody is the body the three bind messages share. In a bind the challenge
// is zero and only pads; the relay sets it and an answer echoes it.
type bindBody struct {
	vni        uint32
	generation uint32
	remote     [keyLen]byte
	challenge  [challengeLen]byte
}

func (m *bindBody) marshal(typ byte) []byte {
	b := make([]byte, 2+bindBodyLen)
	b[0], b[1] = typ, 0
	binary.BigEndian.PutUint32(b[2:], m.vni)
	binary.BigEndian.PutUint32(b[6:], m.generation)
	copy(b[10:], m.remote[:])
	copy(b[10+keyLen:], m.challenge[:])
	return b
}

func parseBind(b []byte) (typ byte, m bindBody, err error) {
	if len(b) < 2+bindBodyLen {
		return 0, m, errShort
	}
	m.vni = binary.BigEndian.Uint32(b[2:])
	m.generation = binary.BigEndian.Uint32(b[6:])
	copy(m.remote[:], b[10:])
	copy(m.challenge[:], b[10+keyLen:])
	return b[0], m, nil
}

func marshalPing(typ byte, id [pingIDLen]byte) []byte {
	b := make([]byte, 2+pingIDLen)
	b[0] = typ
	copy(b[2:], id[:])
	return b
}

func parsePing(b []byte) (typ byte, id [pingIDLen]byte, err error) {
	if len(b) < 2+pingIDLen {
		return 0, id, errShort
	}
	copy(id[:], b[2:])
	return b[0], id, nil
}
