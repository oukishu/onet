package tunnel

import (
	"context"
	"errors"
	"os"
	"sync"
)

// NativeDevice is the unified cross-platform implementation of a TUN device, implementing the Device interface.
// It abstracts away platform differences through the platformDriver interface.
// All exported methods are protected by a mutex, making them safe for concurrent use.
type NativeDevice struct {
	mu     sync.Mutex
	name   string
	config Config
	file   *os.File
	driver platformDriver
}

// NewNativeDevice returns an unopened NativeDevice instance.
// Open must be called first, followed by Start, before using the device.
func NewNativeDevice() *NativeDevice {
	return &NativeDevice{}
}

// Open opens the TUN device on the current platform based on the config.
// It returns an error if the device is already open; the config is saved after being normalized by Defaults.
func (d *NativeDevice) Open(ctx context.Context, config Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.driver != nil {
		return errors.New("tun: device is already open")
	}

	normalized := Defaults(config)
	drv, err := openPlatform(ctx, normalized)
	if err != nil {
		return err
	}

	d.name = drv.Name()
	d.config = normalized
	d.file = drv.File()
	d.driver = drv
	return nil
}

// Start activates the device; if config.DisableSetup is false, it also calls
// driver.Configure to complete IP address and MTU configurations.
func (d *NativeDevice) Start(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.driver == nil {
		return errors.New("tun: device is not open")
	}
	if err := d.driver.Start(); err != nil {
		return err
	}
	if !d.config.DisableSetup {
		return d.driver.Configure(d.config)
	}
	return nil
}

// Close shuts down the underlying driver and resets all internal states (idempotent).
func (d *NativeDevice) Close(_ context.Context) error {
	d.mu.Lock()
	drv := d.driver
	d.driver = nil
	d.file = nil
	d.name = ""
	d.config = Config{}
	d.mu.Unlock()

	if drv == nil {
		return nil
	}
	return drv.Close()
}

// Read reads an IP packet from the device, blocking until data is available or ctx is canceled.
func (d *NativeDevice) Read(ctx context.Context) (Packet, error) {
	d.mu.Lock()
	drv := d.driver
	d.mu.Unlock()

	if drv == nil {
		return Packet{}, errors.New("tun: device is not open")
	}
	return drv.Read(ctx)
}

// Write writes an IP packet to the device.
func (d *NativeDevice) Write(ctx context.Context, packet Packet) error {
	d.mu.Lock()
	drv := d.driver
	d.mu.Unlock()

	if drv == nil {
		return errors.New("tun: device is not open")
	}
	return drv.Write(ctx, packet)
}

// Name returns the system name of the underlying network interface. It returns an error if the device is not open.
func (d *NativeDevice) Name() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.driver == nil {
		return "", errors.New("tun: device is not open")
	}
	return d.name, nil
}

// ─────────────────────────────────────────────
// platformDriver (Internal Platform Interface)
// ─────────────────────────────────────────────

// platformDriver is returned by the openPlatform function of each platform.
// Each platform provides its specific implementation in separate device_<os>.go files.
type platformDriver interface {
	Start() error
	Close() error
	Read(ctx context.Context) (Packet, error)
	Write(ctx context.Context, packet Packet) error
	Name() string
	File() *os.File
	Configure(config Config) error
}
