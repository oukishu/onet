//go:build darwin

package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/oukishu/onet/tun"
)

const (
	darwinAFSystem        = 32
	darwinAFSysControl    = 2
	darwinSysProtoControl = 2
	darwinCtlIOCGInfo     = 0xc0644e03
)

type darwinDriver struct {
	name string
	file *os.File
}

type ctlInfo struct {
	id   uint32
	name [96]byte
}

type sockaddrCtl struct {
	len      uint8
	family   uint8
	sysaddr  uint16
	id       uint32
	unit     uint32
	reserved [5]uint32
}

func openPlatform(_ context.Context, config tun.Config) (platformDriver, error) {
	fd, err := syscall.Socket(darwinAFSystem, syscall.SOCK_DGRAM, darwinSysProtoControl)
	if err != nil {
		return nil, err
	}
	info := ctlInfo{}
	copy(info.name[:], "com.apple.net.utun_control")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(darwinCtlIOCGInfo), uintptr(unsafe.Pointer(&info))); errno != 0 {
		_ = syscall.Close(fd)
		return nil, errno
	}
	unit, name := darwinUnit(config.Name)
	addr := sockaddrCtl{
		len:     uint8(unsafe.Sizeof(sockaddrCtl{})),
		family:  darwinAFSystem,
		sysaddr: darwinAFSysControl,
		id:      info.id,
		unit:    unit,
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), uintptr(addr.len)); errno != 0 {
		_ = syscall.Close(fd)
		return nil, errno
	}
	file := os.NewFile(uintptr(fd), name)
	return &darwinDriver{name: name, file: file}, nil
}

func (d *darwinDriver) Start() error   { return nil }
func (d *darwinDriver) Close() error   { return d.file.Close() }
func (d *darwinDriver) Name() string   { return d.name }
func (d *darwinDriver) File() *os.File { return d.file }
func (d *darwinDriver) Configure(config tun.Config) error {
	if err := exec.Command("ifconfig", d.name, "mtu", strconv.Itoa(config.MTU), "up").Run(); err != nil {
		return err
	}
	for _, address := range config.Inet4Address {
		addr, mask := ipv4Ifconfig(address)
		if err := exec.Command("ifconfig", d.name, "inet", addr, addr, "netmask", mask).Run(); err != nil {
			return err
		}
	}
	for _, address := range config.Inet6Address {
		if err := exec.Command("ifconfig", d.name, "inet6", address.String(), "prefixlen", strconv.Itoa(address.Bits())).Run(); err != nil {
			return err
		}
	}
	return nil
}

func (d *darwinDriver) Read(ctx context.Context) (tun.Packet, error) {
	packet, err := readRaw(ctx, d.file)
	if err != nil {
		return tun.Packet{}, err
	}
	if len(packet.Payload) >= 4 {
		packet.Payload = packet.Payload[4:]
	}
	return packet, nil
}

func (d *darwinDriver) Write(ctx context.Context, packet tun.Packet) error {
	family := make([]byte, 4)
	if len(packet.Payload) > 0 && packet.Payload[0]>>4 == 6 {
		binary.BigEndian.PutUint32(family, syscall.AF_INET6)
	} else {
		binary.BigEndian.PutUint32(family, syscall.AF_INET)
	}
	packet.Payload = append(family, packet.Payload...)
	return writeRaw(ctx, d.file, packet)
}

func darwinUnit(name string) (uint32, string) {
	if !strings.HasPrefix(name, "utun") {
		return 0, "utun"
	}
	n, err := strconv.Atoi(strings.TrimPrefix(name, "utun"))
	if err != nil || n < 0 {
		return 0, "utun"
	}
	return uint32(n + 1), fmt.Sprintf("utun%d", n)
}

func ipv4Ifconfig(prefix netip.Prefix) (string, string) {
	addr := prefix.Addr().String()
	mask := uint32(0xffffffff) << uint(32-prefix.Bits())
	return addr, fmt.Sprintf("0x%08x", mask)
}
