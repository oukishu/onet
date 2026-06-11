//go:build linux

package native

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"unsafe"

	"github.com/oukishu/onet/tun"

	"golang.org/x/sys/unix"
)

const (
	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunSetIFF = 0x400454ca
)

type linuxDriver struct {
	name string
	file *os.File
}

type ifreq struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_pad  [64 - unix.IFNAMSIZ - 2]byte
}

func openPlatform(_ context.Context, config tun.Config) (platformDriver, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	request := ifreq{flags: iffTUN | iffNoPI}
	name := config.Name
	if name == "" {
		name = "tun%d"
	}
	copy(request.name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&request)))
	if errno != 0 {
		_ = file.Close()
		return nil, errno
	}
	return &linuxDriver{name: cString(request.name[:]), file: file}, nil
}

func (d *linuxDriver) Start() error   { return nil }
func (d *linuxDriver) Close() error   { return d.file.Close() }
func (d *linuxDriver) Name() string   { return d.name }
func (d *linuxDriver) File() *os.File { return d.file }
func (d *linuxDriver) Configure(config tun.Config) error {
	if err := exec.Command("ip", "link", "set", "dev", d.name, "mtu", strconv.Itoa(config.MTU), "up").Run(); err != nil {
		return err
	}
	for _, address := range config.Inet4Address {
		if err := exec.Command("ip", "addr", "add", address.String(), "dev", d.name).Run(); err != nil {
			return err
		}
	}
	for _, address := range config.Inet6Address {
		if err := exec.Command("ip", "-6", "addr", "add", address.String(), "dev", d.name).Run(); err != nil {
			return err
		}
	}
	return nil
}

func (d *linuxDriver) Read(ctx context.Context) (tun.Packet, error) {
	return readRaw(ctx, d.file)
}

func (d *linuxDriver) Write(ctx context.Context, packet tun.Packet) error {
	return writeRaw(ctx, d.file, packet)
}

func cString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
