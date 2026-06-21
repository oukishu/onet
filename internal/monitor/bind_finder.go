package monitor

import (
	"bytes"
	"net"
	"net/netip"
	"slices"
	"unsafe"

	"github.com/oukishu/internal/metadata"
)

type InterfaceFinder interface {
	Update() error
	Interfaces() []Interface
	ByName(name string) (*Interface, error)
	ByIndex(index int) (*Interface, error)
	ByAddr(addr netip.Addr) (*Interface, error)
}

type Interface struct {
	Index        int
	MTU          int
	Name         string
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
	Addresses    []netip.Prefix
}

func (i Interface) Equals(other Interface) bool {
	return i.Index == other.Index &&
		i.MTU == other.MTU &&
		i.Name == other.Name &&
		bytes.Equal(i.HardwareAddr, other.HardwareAddr) &&
		i.Flags == other.Flags &&
		slices.Equal(i.Addresses, other.Addresses)
}

func (i Interface) NetInterface() net.Interface {
	return *(*net.Interface)(unsafe.Pointer(&i))
}

func InterfaceFromNet(iif net.Interface) (Interface, error) {
	ifAddrs, err := iif.Addrs()
	if err != nil {
		return Interface{}, err
	}

	prefixes := make([]netip.Prefix, 0, len(ifAddrs))
	for _, addr := range ifAddrs {
		prefixes = append(prefixes, metadata.PrefixFromNet(addr))
	}

	return InterfaceFromNetAddrs(iif, prefixes), nil
}

func InterfaceFromNetAddrs(iif net.Interface, addresses []netip.Prefix) Interface {
	return Interface{
		Index:        iif.Index,
		MTU:          iif.MTU,
		Name:         iif.Name,
		HardwareAddr: iif.HardwareAddr,
		Flags:        iif.Flags,
		Addresses:    addresses,
	}
}
