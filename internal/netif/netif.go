package netif

import (
	"bytes"
	"net"
	"net/netip"
	"slices"
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
	return net.Interface{
		Index:        i.Index,
		MTU:          i.MTU,
		Name:         i.Name,
		HardwareAddr: i.HardwareAddr,
		Flags:        i.Flags,
	}
}

func InterfaceFromNet(iif net.Interface) (Interface, error) {
	ifAddrs, err := iif.Addrs()
	if err != nil {
		return Interface{}, err
	}

	prefixes := make([]netip.Prefix, 0, len(ifAddrs))
	for _, netAddr := range ifAddrs {
		if ipNet, ok := netAddr.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipNet.IP); ok {
				bits, _ := ipNet.Mask.Size()
				prefix := netip.PrefixFrom(ip.Unmap(), bits)
				prefixes = append(prefixes, prefix)
			}
		}
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
