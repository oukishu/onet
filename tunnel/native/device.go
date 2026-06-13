package native

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/oukishu/onet/tun"
)

type Device struct {
	mu     sync.Mutex
	name   string
	config tun.Config
	file   *os.File
	driver platformDriver
}

func New() *Device {
	return &Device{}
}

func (d *Device) Open(ctx context.Context, config tun.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.driver != nil {
		return errors.New("tun device is already open")
	}
	driver, err := openPlatform(ctx, tun.Defaults(config))
	if err != nil {
		return err
	}
	d.name = driver.Name()
	d.config = tun.Defaults(config)
	d.file = driver.File()
	d.driver = driver
	return nil
}

func (d *Device) Start(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.driver == nil {
		return errors.New("tun device is not open")
	}
	if err := d.driver.Start(); err != nil {
		return err
	}
	if !d.config.DisableSetup {
		return d.driver.Configure(d.config)
	}
	return nil
}

func (d *Device) Close(context.Context) error {
	d.mu.Lock()
	driver := d.driver
	d.driver = nil
	d.file = nil
	d.name = ""
	d.config = tun.Config{}
	d.mu.Unlock()
	if driver == nil {
		return nil
	}
	return driver.Close()
}

func (d *Device) Read(ctx context.Context) (tun.Packet, error) {
	d.mu.Lock()
	driver := d.driver
	d.mu.Unlock()
	if driver == nil {
		return tun.Packet{}, errors.New("tun device is not open")
	}
	return driver.Read(ctx)
}

func (d *Device) Write(ctx context.Context, packet tun.Packet) error {
	d.mu.Lock()
	driver := d.driver
	d.mu.Unlock()
	if driver == nil {
		return errors.New("tun device is not open")
	}
	return driver.Write(ctx, packet)
}

func (d *Device) Name() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.driver == nil {
		return "", errors.New("tun device is not open")
	}
	return d.name, nil
}

type platformDriver interface {
	Start() error
	Close() error
	Read(context.Context) (tun.Packet, error)
	Write(context.Context, tun.Packet) error
	Name() string
	File() *os.File
	Configure(tun.Config) error
}
