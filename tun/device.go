package tun

import (
	"context"
	"net/netip"
)

type Device interface {
	Open(context.Context, Config) error
	Start(context.Context) error
	Close(context.Context) error
	Read(context.Context) (Packet, error)
	Write(context.Context, Packet) error
	Name() (string, error)
}

type Protocol string

const (
	ProtocolIP  Protocol = "ip"
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

type Packet struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Protocol    Protocol
	Payload     []byte
}

func RawPacket(payload []byte) Packet {
	return Packet{Protocol: ProtocolIP, Payload: payload}
}

type Config struct {
	Name         string
	MTU          int
	Inet4Address []netip.Prefix
	Inet6Address []netip.Prefix
	Stack        Stack
	WindowsDLL   string
	DisableSetup bool
}

type Stack string

const (
	StackSystem Stack = "system"
	StackGVisor Stack = "gvisor"
	StackMixed  Stack = "mixed"
)

func Defaults(config Config) Config {
	if config.MTU == 0 {
		config.MTU = 9000
	}
	if config.Stack == "" {
		config.Stack = StackMixed
	}
	return config
}
