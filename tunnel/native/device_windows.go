//go:build windows

package native

import (
	"context"
	"errors"

	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"time"
	"unsafe"

	"github.com/oukishu/onet/tun"

	"golang.org/x/sys/windows"
)

type windowsDriver struct {
	name           string
	dll            *windows.LazyDLL
	adapter        uintptr
	session        uintptr
	closeAdapter   *windows.LazyProc
	endSession     *windows.LazyProc
	receivePacket  *windows.LazyProc
	releasePacket  *windows.LazyProc
	allocatePacket *windows.LazyProc
	sendPacket     *windows.LazyProc
}

func openPlatform(_ context.Context, config tun.Config) (platformDriver, error) {
	dllName := config.WindowsDLL
	if dllName == "" {
		dllName = "wintun.dll"
	}
	name := config.Name
	if name == "" {
		name = "tun0"
	}
	dll := windows.NewLazyDLL(dllName)
	createAdapter := dll.NewProc("WintunCreateAdapter")
	startSession := dll.NewProc("WintunStartSession")
	driver := &windowsDriver{
		name:           name,
		dll:            dll,
		closeAdapter:   dll.NewProc("WintunCloseAdapter"),
		endSession:     dll.NewProc("WintunEndSession"),
		receivePacket:  dll.NewProc("WintunReceivePacket"),
		releasePacket:  dll.NewProc("WintunReleaseReceivePacket"),
		allocatePacket: dll.NewProc("WintunAllocateSendPacket"),
		sendPacket:     dll.NewProc("WintunSendPacket"),
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	typePtr, err := windows.UTF16PtrFromString("ModularTun")
	if err != nil {
		return nil, err
	}
	adapter, _, errno := createAdapter.Call(uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(typePtr)), 0)
	if adapter == 0 {
		if errno != windows.ERROR_SUCCESS {
			return nil, errno
		}
		return nil, errors.New("WintunCreateAdapter returned nil adapter")
	}
	driver.adapter = adapter
	session, _, errno := startSession.Call(adapter, 0x400000)
	if session == 0 {
		driver.closeAdapter.Call(adapter)
		if errno != windows.ERROR_SUCCESS {
			return nil, errno
		}
		return nil, errors.New("WintunStartSession returned nil session")
	}
	driver.session = session
	return driver, nil
}

func (d *windowsDriver) Start() error   { return nil }
func (d *windowsDriver) Name() string   { return d.name }
func (d *windowsDriver) File() *os.File { return nil }
func (d *windowsDriver) Configure(config tun.Config) error {
	if err := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", d.name, "mtu="+strconv.Itoa(config.MTU), "store=active").Run(); err != nil {
		return err
	}
	for _, address := range config.Inet4Address {
		addr, mask := windowsIPv4(address)
		if err := exec.Command("netsh", "interface", "ipv4", "add", "address", "name="+d.name, "address="+addr, "mask="+mask).Run(); err != nil {
			return err
		}
	}
	for _, address := range config.Inet6Address {
		if err := exec.Command("netsh", "interface", "ipv6", "add", "address", "interface="+d.name, "address="+address.String()).Run(); err != nil {
			return err
		}
	}
	return nil
}

func (d *windowsDriver) Close() error {
	if d.session != 0 {
		d.endSession.Call(d.session)
		d.session = 0
	}
	if d.adapter != 0 {
		d.closeAdapter.Call(d.adapter)
		d.adapter = 0
	}
	return nil
}

func (d *windowsDriver) Read(ctx context.Context) (tun.Packet, error) {
	for {
		select {
		case <-ctx.Done():
			return tun.Packet{}, ctx.Err()
		default:
		}
		var size uint32
		packet, _, errno := d.receivePacket.Call(d.session, uintptr(unsafe.Pointer(&size)))
		if packet != 0 {
			bytes := unsafe.Slice((*byte)(unsafe.Pointer(packet)), size)
			payload := append([]byte(nil), bytes...)
			d.releasePacket.Call(d.session, packet)
			return tun.RawPacket(payload), nil
		}
		if errno != windows.ERROR_NO_MORE_ITEMS && errno != windows.ERROR_SUCCESS {
			return tun.Packet{}, errno
		}
		time.Sleep(time.Millisecond * 10)
	}
}

func (d *windowsDriver) Write(ctx context.Context, packet tun.Packet) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	ptr, _, errno := d.allocatePacket.Call(d.session, uintptr(uint32(len(packet.Payload))))
	if ptr == 0 {
		if errno != windows.ERROR_SUCCESS {
			return errno
		}
		return errors.New("WintunAllocateSendPacket returned nil packet")
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(packet.Payload))
	copy(dst, packet.Payload)
	d.sendPacket.Call(d.session, ptr)
	return nil
}

func windowsIPv4(prefix netip.Prefix) (string, string) {
	mask := uint32(0xffffffff) << uint(32-prefix.Bits())
	return prefix.Addr().String(), dottedIPv4(mask)
}

func dottedIPv4(mask uint32) string {
	return strconv.Itoa(int(mask>>24&0xff)) + "." +
		strconv.Itoa(int(mask>>16&0xff)) + "." +
		strconv.Itoa(int(mask>>8&0xff)) + "." +
		strconv.Itoa(int(mask&0xff))
}
