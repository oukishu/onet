package tunnel

import (
	"context"
	"net/netip"
	"runtime"
)

// Device represents an abstract interface for a TUN virtual network device.
// The calling sequence should be: Open → Start → (Read/Write) → Close.
type Device interface {
	// Open initializes and opens the underlying TUN device based on the configuration.
	Open(ctx context.Context, config Config) error
	// Start activates the device (configuring addresses, MTU, etc.) so it can send and receive data.
	Start(ctx context.Context) error
	// Close releases all resources occupied by the device.
	Close(ctx context.Context) error
	// Read reads an IP packet from the device, blocking until data is available or ctx times out/is canceled.
	Read(ctx context.Context) (Packet, error)
	// Write writes an IP packet to the device.
	Write(ctx context.Context, packet Packet) error
	// Name returns the system name of the underlying network interface (e.g., "tun0", "utun3").
	Name() (string, error)
}

// ─────────────────────────────────────────────
// Protocol
// ─────────────────────────────────────────────

// Protocol describes the network layer protocol used by the packet.
type Protocol string

const (
	ProtocolIP  Protocol = "ip"
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

// ─────────────────────────────────────────────
// Packet
// ─────────────────────────────────────────────

// Packet represents a network packet sent or received via the TUN device.
type Packet struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Protocol    Protocol
	Payload     []byte
}

// RawPacket constructs an IP protocol packet using raw bytes.
func RawPacket(payload []byte) Packet {
	return Packet{Protocol: ProtocolIP, Payload: payload}
}

// ─────────────────────────────────────────────
// Stack
// ─────────────────────────────────────────────

// Stack specifies the network protocol stack implementation used by the TUN device.
type Stack string

const (
	// StackSystem uses the host operating system's kernel protocol stack.
	StackSystem Stack = "system"
	// StackGVisor uses the gVisor user-space protocol stack.
	StackGVisor Stack = "gvisor"
	// StackMixed represents a mixed mode: TCP goes through the system stack, UDP goes through the gVisor stack.
	StackMixed Stack = "mixed"
)

// ─────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────

// Config contains all the parameters required to create a TUN device.
type Config struct {
	// Name is the desired name to assign to the interface.
	// If left empty, Defaults will populate a suitable default value based on the platform.
	Name string

	// MTU is the Maximum Transmission Unit (in bytes) for the interface. 0 means use the default value (9000).
	MTU int

	// Inet4Address / Inet6Address are the lists of IPv4/IPv6 prefixes assigned to the interface.
	Inet4Address []netip.Prefix
	Inet6Address []netip.Prefix

	// Stack specifies the protocol stack implementation; if left empty, Defaults will populate it with StackMixed.
	Stack Stack

	// WindowsDLL is the path to wintun.dll on Windows platforms; if left empty, it is searched from standard paths.
	WindowsDLL string

	// DisableSetup, when true, skips the address/routing configuration during the Start phase.
	// This is suitable for scenarios where an external program manages the network configuration.
	DisableSetup bool
}

// Defaults assigns reasonable default values to unpopulated fields and returns a new Config.
func Defaults(config Config) Config {
	if config.MTU == 0 {
		config.MTU = 9000
	}
	if config.Stack == "" {
		config.Stack = StackMixed
	}
	if config.Name == "" {
		config.Name = defaultName()
	}
	return config
}

// defaultName returns a suitable interface name template based on the current operating system.
func defaultName() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun"
	case "windows":
		return "tun0"
	default:
		// Linux / Android: "tun%d" tells the kernel to automatically select an available index number.
		return "tun%d"
	}
}