package monitor

import (
	"errors"

	"github.com/oukishu/internal/list"
)

var ErrNoRoute = errors.New("no route to internet")

type (
	NetworkUpdateCallback          = func()
	DefaultInterfaceUpdateCallback = func(defaultInterface *Interface, flags int)
)

type NetworkUpdateMonitor interface {
	Start() error
	Close() error
	RegisterCallback(callback NetworkUpdateCallback) *list.Element[NetworkUpdateCallback]
	UnregisterCallback(element *list.Element[NetworkUpdateCallback])
}

type DefaultInterfaceMonitor interface {
	Start() error
	Close() error
	DefaultInterface() *Interface
	RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback]
	UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback])
	RegisterMyInterface(interfaceName string)
	MyInterfaces() []string
}

type DefaultInterfaceMonitorOptions struct {
	InterfaceFinder       InterfaceFinder
	UnderNetworkExtension bool
}
