//go:build !(linux || windows || darwin)

package monitor

import (
	"os"
)

func NewNetworkUpdateMonitor(logger Logger) (NetworkUpdateMonitor, error) {
	return nil, os.ErrInvalid
}

func NewDefaultInterfaceMonitor(networkMonitor NetworkUpdateMonitor, logger Logger, options DefaultInterfaceMonitorOptions) (DefaultInterfaceMonitor, error) {
	return nil, os.ErrInvalid
}
