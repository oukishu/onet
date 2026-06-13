package tunnel

import (
	"context"
	"testing"
)

func TestNewAppliesDefaults(t *testing.T) {
	svc, err := New(Config{}, noopDevice{})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Config().MTU != 9000 || svc.Config().Stack != StackMixed {
		t.Fatalf("unexpected defaults: %+v", svc.Config())
	}
}

type noopDevice struct{}

func (noopDevice) Open(context.Context, Config) error { return nil }
func (noopDevice) Start(context.Context) error        { return nil }
func (noopDevice) Close(context.Context) error        { return nil }
func (noopDevice) Read(context.Context) (Packet, error) {
	return Packet{}, nil
}
func (noopDevice) Write(context.Context, Packet) error { return nil }
func (noopDevice) Name() (string, error)               { return "tun0", nil }
