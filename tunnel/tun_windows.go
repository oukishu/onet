//go:build windows

package tunnel

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/oukishu/onet/internal/winipcfg"
	"github.com/oukishu/onet/internal/wintun"
	"golang.org/x/sys/windows"
)

const (
	ringBufferSize             = 0x800000 // 8 MiB, aligned with the reference implementation
	rateMeasurementGranularity = uint64((time.Second / 2) / time.Nanosecond)
	spinloopRateThreshold      = 800000000 / 8                                   // 800 Mbps
	spinloopDuration           = uint64(time.Millisecond / 80 / time.Nanosecond) // ~1 Gbps
)

// TunnelType specifies the device type string for the Wintun adapter.
var TunnelType = "Tunnel"

type windowsDriver struct {
	name      string
	adapter   *wintun.Adapter
	session   wintun.Session
	readEvent windows.Handle
	rate      rateJuggler
	running   sync.WaitGroup
	closeOnce sync.Once
	closed    atomic.Int32
}

// openPlatform initializes and opens the Wintun adapter pool on Windows.
// It automatically falls back to opening an existing adapter if the creation returns an existential conflict.
func openPlatform(_ context.Context, config Config) (platformDriver, error) {
	name := config.Name
	if name == "" {
		name = "tun0"
	}
	var targetDir string
	if config.WindowsDLL != "" {
		if filepath.Ext(config.WindowsDLL) == ".dll" {
			targetDir = filepath.Dir(config.WindowsDLL)
		} else {
			targetDir = config.WindowsDLL
		}
		wintun.SetLibraryDir(targetDir)
	}

	guid := generateGUIDByDeviceName(name)
	adapter, err := wintun.CreateAdapter(name, TunnelType, guid)
	if err != nil {
		// If the adapter already exists, attempt to open the existing instance
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create adapter: %w", err)
		}
		createErr := err
		adapter, err = wintun.OpenAdapter(name)
		if err != nil {
			return nil, fmt.Errorf("create adapter: %w; open existing adapter: %w", createErr, err)
		}
	}

	session, err := adapter.StartSession(ringBufferSize)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session: %w", err)
	}

	readEvent := session.ReadWaitEvent()
	if readEvent == 0 {
		session.End()
		adapter.Close()
		return nil, errors.New("WintunGetReadWaitEvent returned invalid handle")
	}

	return &windowsDriver{
		name:      name,
		adapter:   adapter,
		session:   session,
		readEvent: readEvent,
	}, nil
}

func (d *windowsDriver) Start() error   { return nil }
func (d *windowsDriver) Name() string   { return d.name }
func (d *windowsDriver) File() *os.File { return nil }

// Configure sets up IP addresses, flushes, drops DNS registration leaks, and applies interface configurations.
func (d *windowsDriver) Configure(config Config) error {
	luid := winipcfg.LUID(d.adapter.LUID())

	// Configure by address family separately to ensure IPv4/IPv6 are added after their respective flushes
	if len(config.Inet4Address) > 0 {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET), config.Inet4Address)
		if err != nil {
			return fmt.Errorf("set ipv4 address: %w", err)
		}
	}
	if len(config.Inet6Address) > 0 {
		err := luid.SetIPAddressesForFamily(winipcfg.AddressFamily(windows.AF_INET6), config.Inet6Address)
		if err != nil {
			return fmt.Errorf("set ipv6 address: %w", err)
		}
	}

	// Disable DNS registration to avoid leaks
	if len(config.Inet4Address) > 0 || len(config.Inet6Address) > 0 {
		_ = luid.DisableDNSRegistration()
	}

	// Configure IPv4 interface parameters (MTU, Router Discovery, DAD)
	if len(config.Inet4Address) > 0 {
		inetIf, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET))
		if err != nil {
			return fmt.Errorf("get ipv4 interface: %w", err)
		}
		inetIf.ForwardingEnabled = true
		inetIf.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inetIf.DadTransmits = 0
		inetIf.ManagedAddressConfigurationSupported = false
		inetIf.OtherStatefulConfigurationSupported = false
		if config.MTU > 0 {
			inetIf.NLMTU = uint32(config.MTU)
		}
		if err = inetIf.Set(); err != nil {
			return fmt.Errorf("set ipv4 options: %w", err)
		}
	}

	// Configure IPv6 interface parameters
	if len(config.Inet6Address) > 0 {
		inet6If, err := luid.IPInterface(winipcfg.AddressFamily(windows.AF_INET6))
		if err != nil {
			return fmt.Errorf("get ipv6 interface: %w", err)
		}
		inet6If.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		inet6If.DadTransmits = 0
		inet6If.ManagedAddressConfigurationSupported = false
		inet6If.OtherStatefulConfigurationSupported = false
		if config.MTU > 0 {
			inet6If.NLMTU = uint32(config.MTU)
		}
		if err = inet6If.Set(); err != nil {
			return fmt.Errorf("set ipv6 options: %w", err)
		}
	}

	return nil
}

// Close teardowns the driver session and unblocks pending read routines.
func (d *windowsDriver) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(1)
		// Wake up all Read goroutines blocked on WaitForSingleObject
		windows.SetEvent(d.readEvent)
		d.running.Wait()
		d.session.End()
		d.adapter.Close()
	})
	return nil
}

// Read extracts a packet payload from the ring buffer, dynamically utilizing adaptive spinloops under high loads.
func (d *windowsDriver) Read(ctx context.Context) (Packet, error) {
	d.running.Add(1)
	defer d.running.Done()

retry:
	if d.closed.Load() == 1 {
		return Packet{}, os.ErrClosed
	}

	start := nanotime()
	shouldSpin := d.rate.current.Load() >= spinloopRateThreshold &&
		uint64(start-d.rate.nextStartTime.Load()) <= rateMeasurementGranularity*2

	for {
		if d.closed.Load() == 1 {
			return Packet{}, os.ErrClosed
		}

		// Prioritize checking context to avoid creating extra goroutines in the fast path
		select {
		case <-ctx.Done():
			return Packet{}, ctx.Err()
		default:
		}

		packet, err := d.session.ReceivePacket()
		switch err {
		case nil:
			payload := append([]byte(nil), packet...)
			d.session.ReleaseReceivePacket(packet)
			d.rate.update(uint64(len(payload)))
			return RawPacket(payload), nil
		case windows.ERROR_NO_MORE_ITEMS:
			if !shouldSpin || uint64(nanotime()-start) >= spinloopDuration {
				windows.WaitForSingleObject(d.readEvent, windows.INFINITE)
				goto retry
			}
			procyield(1)
			continue
		case windows.ERROR_HANDLE_EOF:
			return Packet{}, os.ErrClosed
		case windows.ERROR_INVALID_DATA:
			return Packet{}, errors.New("receive ring corrupt")
		}
		return Packet{}, fmt.Errorf("read failed: %w", err)
	}
}

// Write allocates space inside the ring buffer and writes out a packet payload.
func (d *windowsDriver) Write(ctx context.Context, packet Packet) error {
	d.running.Add(1)
	defer d.running.Done()

	if d.closed.Load() == 1 {
		return os.ErrClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	payload := packet.Payload
	d.rate.update(uint64(len(payload)))

	buf, err := d.session.AllocateSendPacket(len(payload))
	if err == nil {
		copy(buf, payload)
		d.session.SendPacket(buf)
		return nil
	}
	switch err {
	case windows.ERROR_HANDLE_EOF:
		return os.ErrClosed
	case windows.ERROR_BUFFER_OVERFLOW:
		return nil // Drop packets proactively when the ring buffer is full, consistent with the reference implementation
	}
	return fmt.Errorf("write failed: %w", err)
}

// generateGUIDByDeviceName generates a deterministic GUID based on the device name,
// keeping the algorithm consistent with the reference implementation (tun_windows.go).
func generateGUIDByDeviceName(name string) *windows.GUID {
	hash := md5.New()
	hash.Write([]byte("wintun"))
	hash.Write([]byte(name))
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0]))
}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

// rateJuggler measures throughput using a lock-free, double-window sliding average
// to decide whether to activate the spinloop path.
type rateJuggler struct {
	current       atomic.Uint64
	nextByteCount atomic.Uint64
	nextStartTime atomic.Int64
	changing      atomic.Int32
}

func (r *rateJuggler) update(packetLen uint64) {
	now := nanotime()
	total := r.nextByteCount.Add(packetLen)
	period := uint64(now - r.nextStartTime.Load())
	if period >= rateMeasurementGranularity {
		if !r.changing.CompareAndSwap(0, 1) {
			return
		}
		r.nextStartTime.Store(now)
		r.current.Store(total * uint64(time.Second/time.Nanosecond) / period)
		r.nextByteCount.Store(0)
		r.changing.Store(0)
	}
}
