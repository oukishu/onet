//go:build darwin

package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"github.com/oukishu/onet/tunnel"
	"golang.org/x/sys/unix"
)

const (
	SIOCAIFADDR_IN6       = 2155899162 // netinet6/in6_var.h
	IN6_IFF_NODAD         = 0x0020     // netinet6/in6_var.h
	IN6_IFF_SECURED       = 0x0400     // netinet6/in6_var.h
	ND6_INFINITE_LIFETIME = 0xFFFFFFFF // netinet6/nd6.h
)

const utunControlName = "com.apple.net.utun_control"

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

type darwinDriver struct {
	name string
	file *os.File
}

func openPlatform(_ context.Context, config tunnel.Config) (platformDriver, error) {
	ifIndex := -1
	if _, err := fmt.Sscanf(config.Name, "utun%d", &ifIndex); err != nil {
		return nil, fmt.Errorf("bad tun name: %s", config.Name)
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
	if err != nil {
		return nil, err
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
		return nil, os.NewSyscallError("Connect", err)
	}

	name := fmt.Sprintf("utun%d", ifIndex)
	file := os.NewFile(uintptr(fd), name)
	return &darwinDriver{name: name, file: file}, nil
}

func (d *darwinDriver) Start() error   { return nil }
func (d *darwinDriver) Close() error   { return d.file.Close() }
func (d *darwinDriver) Name() string   { return d.name }
func (d *darwinDriver) File() *os.File { return d.file }

func (d *darwinDriver) Configure(config tunnel.Config) error {
	fd := int(d.file.Fd())

	// Set MTU
	err := useSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(socketFd int) error {
		var ifr unix.IfreqMTU
		copy(ifr.Name[:], d.name)
		ifr.MTU = int32(config.MTU)
		return unix.IoctlSetIfreqMTU(socketFd, &ifr)
	})
	if err != nil {
		return os.NewSyscallError("IoctlSetIfreqMTU", err)
	}

	_ = fd // fd used implicitly via d.file for name resolution above

	// Configure IPv4 addresses
	for _, address := range config.Inet4Address {
		ifReq := ifAliasReq{
			Addr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   address.Addr().As4(),
			},
			Dstaddr: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   address.Addr().As4(),
			},
			Mask: unix.RawSockaddrInet4{
				Len:    unix.SizeofSockaddrInet4,
				Family: unix.AF_INET,
				Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(address.Bits(), 32)).String()).As4(),
			},
		}
		copy(ifReq.Name[:], d.name)
		err = useSocket(unix.AF_INET, unix.SOCK_DGRAM, 0, func(socketFd int) error {
			if _, _, errno := unix.Syscall(
				syscall.SYS_IOCTL,
				uintptr(socketFd),
				uintptr(unix.SIOCAIFADDR),
				uintptr(unsafe.Pointer(&ifReq)),
			); errno != 0 {
				return os.NewSyscallError("SIOCAIFADDR", errno)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Configure IPv6 addresses
	for _, address := range config.Inet6Address {
		ifReq6 := ifAliasReq6{
			Addr: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   address.Addr().As16(),
			},
			Mask: unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   netip.MustParseAddr(net.IP(net.CIDRMask(address.Bits(), 128)).String()).As16(),
			},
			Flags: IN6_IFF_NODAD | IN6_IFF_SECURED,
			Lifetime: addrLifetime6{
				Vltime: ND6_INFINITE_LIFETIME,
				Pltime: ND6_INFINITE_LIFETIME,
			},
		}
		if address.Bits() == 128 {
			ifReq6.Dstaddr = unix.RawSockaddrInet6{
				Len:    unix.SizeofSockaddrInet6,
				Family: unix.AF_INET6,
				Addr:   address.Addr().Next().As16(),
			}
		}
		copy(ifReq6.Name[:], d.name)
		err = useSocket(unix.AF_INET6, unix.SOCK_DGRAM, 0, func(socketFd int) error {
			if _, _, errno := unix.Syscall(
				syscall.SYS_IOCTL,
				uintptr(socketFd),
				uintptr(SIOCAIFADDR_IN6),
				uintptr(unsafe.Pointer(&ifReq6)),
			); errno != 0 {
				return os.NewSyscallError("SIOCAIFADDR_IN6", errno)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *darwinDriver) Read(ctx context.Context) (tunnel.Packet, error) {
	packet, err := readRaw(ctx, d.file)
	if err != nil {
		return tunnel.Packet{}, err
	}
	if len(packet.Payload) >= 4 {
		packet.Payload = packet.Payload[4:]
	}
	return packet, nil
}

func (d *darwinDriver) Write(ctx context.Context, packet tunnel.Packet) error {
	family := make([]byte, 4)
	if len(packet.Payload) > 0 && packet.Payload[0]>>4 == 6 {
		binary.BigEndian.PutUint32(family, syscall.AF_INET6)
	} else {
		binary.BigEndian.PutUint32(family, syscall.AF_INET)
	}
	packet.Payload = append(family, packet.Payload...)
	return writeRaw(ctx, d.file, packet)
}

func useSocket(domain, typ, proto int, block func(socketFd int) error) error {
	socketFd, err := unix.Socket(domain, typ, proto)
	if err != nil {
		return err
	}
	defer unix.Close(socketFd)
	return block(socketFd)
}
