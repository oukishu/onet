//go:build darwin

package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ─────────────────────────────────────────────
// Darwin System Constants (from netinet6/in6_var.h, nd6.h)
// ─────────────────────────────────────────────

const (
	siocaifaddrIN6  = 2155899162 // SIOCAIFADDR_IN6
	in6IffNodad     = 0x0020     // IN6_IFF_NODAD
	in6IffSecured   = 0x0400     // IN6_IFF_SECURED
	nd6InfiniteLife = 0xFFFFFFFF // ND6_INFINITE_LIFETIME
	utunControlName = "com.apple.net.utun_control"
)

// ─────────────────────────────────────────────
// ioctl Structs
// ─────────────────────────────────────────────

type ifAliasReq struct {
	Name    [unix.IFNAMSIZ]byte
	Addr    unix.RawSockaddrInet4
	Dstaddr unix.RawSockaddrInet4
	Mask    unix.RawSockaddrInet4
}

type ifAliasReq6 struct {
	Name     [16]byte
	Addr     unix.RawSockaddrInet6
	Dstaddr  unix.RawSockaddrInet6
	Mask     unix.RawSockaddrInet6
	Flags    uint32
	Lifetime addrLifetime6
}

type addrLifetime6 struct {
	Expire    float64
	Preferred float64
	Vltime    uint32
	Pltime    uint32
}

// ─────────────────────────────────────────────
// darwinDriver
// ─────────────────────────────────────────────

type darwinDriver struct {
	name string
	file *os.File
}

// openPlatform opens a utun device via a SYSPROTO_CONTROL socket.
// config.Name must comply with the "utun<N>" format.
func openPlatform(config Config) (platformDriver, error) {
	var ifIndex int
	if _, err := fmt.Sscanf(config.Name, "utun%d", &ifIndex); err != nil {
		return nil, fmt.Errorf("tun: invalid darwin interface name %q (expected utunN)", config.Name)
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
	if err != nil {
		return nil, fmt.Errorf("tun: socket: %w", err)
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	if err = unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("IoctlCtlInfo", err)
	}

	if err = unix.Connect(fd, &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: uint32(ifIndex) + 1,
	}); err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("connect", err)
	}

	name := fmt.Sprintf("utun%d", ifIndex)
	return &darwinDriver{
		name: name,
		file: os.NewFile(uintptr(fd), name),
	}, nil
}

func (d *darwinDriver) Start() error   { return nil }
func (d *darwinDriver) Close() error   { return d.file.Close() }
func (d *darwinDriver) Name() string   { return d.name }
func (d *darwinDriver) File() *os.File { return d.file }

// Configure sets the MTU and adds IPv4/IPv6 addresses via ioctl.
func (d *darwinDriver) Configure(config Config) error {
	// ── MTU ──
	if err := withSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(sfd int) error {
		var ifr unix.IfreqMTU
		copy(ifr.Name[:], d.name)
		ifr.MTU = int32(config.MTU)
		return unix.IoctlSetIfreqMTU(sfd, &ifr)
	}); err != nil {
		return os.NewSyscallError("IoctlSetIfreqMTU", err)
	}

	// ── IPv4 Addresses ──
	for _, prefix := range config.Inet4Address {
		maskIP := net.IP(net.CIDRMask(prefix.Bits(), 32))
		req := ifAliasReq{
			Addr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   prefix.Addr().As4(),
			},
			Dstaddr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   prefix.Addr().As4(),
			},
			Mask: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   netip.MustParseAddr(maskIP.String()).As4(),
			},
		}
		copy(req.Name[:], d.name)
		if err := withSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(sfd int) error {
			_, _, errno := unix.Syscall(
				syscall.SYS_IOCTL,
				uintptr(sfd),
				uintptr(unix.SIOCAIFADDR),
				uintptr(unsafe.Pointer(&req)),
			)
			if errno != 0 {
				return os.NewSyscallError("SIOCAIFADDR", errno)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	// ── IPv6 Addresses ──
	for _, prefix := range config.Inet6Address {
		maskIP := net.IP(net.CIDRMask(prefix.Bits(), 128))
		req6 := ifAliasReq6{
			Addr: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   prefix.Addr().As16(),
			},
			Mask: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   netip.MustParseAddr(maskIP.String()).As16(),
			},
			Flags: in6IffNodad | in6IffSecured,
			Lifetime: addrLifetime6{
				Vltime: nd6InfiniteLife,
				Pltime: nd6InfiniteLife,
			},
		}
		// Point-to-point prefixes (/128) require setting a destination address.
		if prefix.Bits() == 128 {
			req6.Dstaddr = unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   prefix.Addr().Next().As16(),
			}
		}
		copy(req6.Name[:], d.name)
		if err := withSocket(unix.AF_INET6, unix.SOCK_DGRAM, 0, func(sfd int) error {
			_, _, errno := unix.Syscall(
				syscall.SYS_IOCTL,
				uintptr(sfd),
				uintptr(siocaifaddrIN6),
				uintptr(unsafe.Pointer(&req6)),
			)
			if errno != 0 {
				return os.NewSyscallError("SIOCAIFADDR_IN6", errno)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	return nil
}

// Read reads a packet from utun and strips the 4-byte protocol family header from the beginning.
func (d *darwinDriver) Read(ctx context.Context) (Packet, error) {
	pkt, err := readRaw(ctx, d.file)
	if err != nil {
		return Packet{}, err
	}
	if len(pkt.Payload) >= 4 {
		pkt.Payload = pkt.Payload[4:]
	}
	return pkt, nil
}

// Write inserts a 4-byte AF header in front of the Payload, then writes it to utun.
func (d *darwinDriver) Write(ctx context.Context, packet Packet) error {
	hdr := make([]byte, 4)
	if len(packet.Payload) > 0 && packet.Payload[0]>>4 == 6 {
		binary.BigEndian.PutUint32(hdr, syscall.AF_INET6)
	} else {
		binary.BigEndian.PutUint32(hdr, syscall.AF_INET)
	}
	packet.Payload = append(hdr, packet.Payload...)
	return writeRaw(ctx, d.file, packet)
}

// withSocket creates a temporary socket, executes the block, and then closes the socket.
func withSocket(domain, typ, proto int, block func(fd int) error) error {
	fd, err := unix.Socket(domain, typ, proto)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return block(fd)
}
