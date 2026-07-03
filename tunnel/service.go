package tunnel

import (
	"context"
	"errors"
)

// Service wraps a Device into a higher-level lifecycle management object.
// It holds a copy of the configuration normalized by Defaults and delegates all operations to the underlying Device.
type Service struct {
	config Config
	device Device
}

// New creates a new Service.
// The device parameter must not be nil; the config will be normalized by Defaults before being saved.
func New(config Config, device Device) (*Service, error) {
	if device == nil {
		return nil, errors.New("tun: device must not be nil")
	}
	return &Service{
		config: Defaults(config),
		device: device,
	}, nil
}

// Open opens the underlying TUN device and should be called before Start.
func (s *Service) Open(ctx context.Context) error {
	return s.device.Open(ctx, s.config)
}

// Start activates the device (configuring addresses, routing, etc.) and should be called after a successful Open.
func (s *Service) Start(ctx context.Context) error {
	return s.device.Start(ctx)
}

// Close closes the device and releases all associated resources.
func (s *Service) Close(ctx context.Context) error {
	return s.device.Close(ctx)
}

// Read reads an IP packet from the device, blocking until data is available or ctx times out/is canceled.
func (s *Service) Read(ctx context.Context) (Packet, error) {
	return s.device.Read(ctx)
}

// Write sends an IP packet to the device.
func (s *Service) Write(ctx context.Context, packet Packet) error {
	return s.device.Write(ctx, packet)
}

// Config returns a copy of the normalized configuration.
func (s *Service) Config() Config {
	return s.config
}

// Name returns the system name of the underlying network interface.
func (s *Service) Name() (string, error) {
	return s.device.Name()
}
