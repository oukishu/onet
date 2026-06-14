//go:build linux

package tunnel

import (
	"context"
	"errors"
	"os"

	"github.com/oukishu/netlink"

	"golang.org/x/sys/unix"
)

// controlPath is the path to the TUN control device.
// On Android it lives at /dev/tun; on standard Linux at /dev/net/tun.
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

// openPlatform opens the TUN device using the Linux clone device.
func openPlatform(_ context.Context, config Config) (platformDriver, error) {
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
	// (important when the name contains "%d").
	nameIfr, err := unix.NewIfreq("") // Dummy, will be filled by TUNGETIFF
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

// Configure sets up the interface's MTU, links it up, and assigns IP addresses via netlink.
func (d *linuxDriver) Configure(config Config) error {
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

// Read reads a raw packet from the Linux TUN device.
func (d *linuxDriver) Read(ctx context.Context) (Packet, error) {
	return readRaw(ctx, d.file)
}

// Write writes a raw packet to the Linux TUN device.
func (d *linuxDriver) Write(ctx context.Context, packet Packet) error {
	return writeRaw(ctx, d.file, packet)
}