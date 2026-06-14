//go:build linux

package native

import (
	"context"
	"errors"
	"os"

	"github.com/oukishu/netlink"
	"github.com/oukishu/onet/tunnel"

	"golang.org/x/sys/unix"
)

// controlPath is the path to the TUN control device.
// On Android it lives at /dev/tun; on standard Linux at /dev/net/tunnel.
var controlPath string

func init() {
	const defaultTunPath = "/dev/net/tun"
	const androidTunPath = "/dev/tun"
	if _, err := os.Stat(androidTunPath); err == nil {
		controlPath = androidTunPath
	} else {
		controlPath = defaultTunPath
	}
}

type linuxDriver struct {
	name string
	fd   int
	file *os.File
}

func openPlatform(_ context.Context, config tunnel.Config) (platformDriver, error) {
	name := config.Name
	if name == "" {
		name = "tun%d"
	}

	fd, err := unix.Open(controlPath, unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))

	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, err
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// Re-read the actual interface name assigned by the kernel
	// (important when name contained "%d").
	nameIfr, err := unix.NewIfreq("") // dummy, will be filled by TUNGETIFF
	if err == nil {
		if ioctlErr := unix.IoctlIfreq(fd, unix.TUNGETIFF, nameIfr); ioctlErr == nil {
			name = nameIfr.Name()
		}
	}

	return &linuxDriver{
		name: name,
		fd:   fd,
		file: os.NewFile(uintptr(fd), "tun"),
	}, nil
}

func (d *linuxDriver) Start() error { return nil }

func (d *linuxDriver) Close() error {
	return d.file.Close()
}

func (d *linuxDriver) Name() string { return d.name }

func (d *linuxDriver) File() *os.File { return d.file }

func (d *linuxDriver) Configure(config tunnel.Config) error {
	tunLink, err := netlink.LinkByName(d.name)
	if err != nil {
		return err
	}

	if err = netlink.LinkSetMTU(tunLink, config.MTU); err != nil && !errors.Is(err, unix.EPERM) {
		return err
	}

	if err = netlink.LinkSetUp(tunLink); err != nil {
		return err
	}

	for _, address := range config.Inet4Address {
		addr, err := netlink.ParseAddr(address.String())
		if err != nil {
			return err
		}
		if err = netlink.AddrAdd(tunLink, addr); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}

	for _, address := range config.Inet6Address {
		addr, err := netlink.ParseAddr(address.String())
		if err != nil {
			return err
		}
		if err = netlink.AddrAdd(tunLink, addr); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}

	return nil
}

func (d *linuxDriver) Read(ctx context.Context) (tunnel.Packet, error) {
	return readRaw(ctx, d.file)
}

func (d *linuxDriver) Write(ctx context.Context, packet tunnel.Packet) error {
	return writeRaw(ctx, d.file, packet)
}
