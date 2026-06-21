package monitor

import (
	"errors"

	"github.com/oukishu/internal/list"
	"github.com/oukishu/internal/netif"
)

var ErrNoRoute = errors.New("no route to internet")

type (
	NetworkUpdateCallback          = func()
	DefaultInterfaceUpdateCallback = func(defaultInterface *netif.Interface, flags int)
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
	DefaultInterface() *netif.Interface
	RegisterCallback(callback DefaultInterfaceUpdateCallback) *list.Element[DefaultInterfaceUpdateCallback]
	UnregisterCallback(element *list.Element[DefaultInterfaceUpdateCallback])
	RegisterMyInterface(interfaceName string)
	MyInterfaces() []string
}

type DefaultInterfaceMonitorOptions struct {
	InterfaceFinder       netif.InterfaceFinder
	UnderNetworkExtension bool
}
