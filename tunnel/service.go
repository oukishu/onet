package tunnel

import (
	"context"
	"errors"
)

type Service struct {
	config Config
	device Device
}

func New(config Config, device Device) (*Service, error) {
	if device == nil {
		return nil, errors.New("tun device is nil")
	}
	return &Service{config: Defaults(config), device: device}, nil
}

func (s *Service) Open(ctx context.Context) error {
	return s.device.Open(ctx, s.config)
}

func (s *Service) Start(ctx context.Context) error {
	return s.device.Start(ctx)
}

func (s *Service) Close(ctx context.Context) error {
	return s.device.Close(ctx)
}

func (s *Service) Read(ctx context.Context) (Packet, error) {
	return s.device.Read(ctx)
}

func (s *Service) Write(ctx context.Context, packet Packet) error {
	return s.device.Write(ctx, packet)
}

func (s *Service) Config() Config {
	return s.config
}

func (s *Service) Name() (string, error) {
	return s.device.Name()
}
