//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"crypto/sha1"
	"log"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type loggerLevel int

const (
	logInfo loggerLevel = iota
	logWarn
	logErr
)

const AdapterNameMax = 128

type Adapter struct {
	handle uintptr
}

var (
	modwintun                         = newLazyDLL("wintun.dll", setupLogger)
	procWintunCreateAdapter           = modwintun.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter             = modwintun.NewProc("WintunOpenAdapter")
	procWintunCloseAdapter            = modwintun.NewProc("WintunCloseAdapter")
	procWintunDeleteDriver            = modwintun.NewProc("WintunDeleteDriver")
	procWintunGetAdapterLUID          = modwintun.NewProc("WintunGetAdapterLUID")
	procWintunGetRunningDriverVersion = modwintun.NewProc("WintunGetRunningDriverVersion")
)

type TimestampedWriter interface {
	WriteWithTimestamp(p []byte, ts int64) (n int, err error)
}

func logMessage(level loggerLevel, timestamp uint64, msg *uint16) int {
	if tw, ok := log.Default().Writer().(TimestampedWriter); ok {
		tw.WriteWithTimestamp([]byte(log.Default().Prefix()+windows.UTF16PtrToString(msg)), (int64(timestamp)-116444736000000000)*100)
	} else {
		log.Println(windows.UTF16PtrToString(msg))
	}
	return 0
}

func setupLogger(dll *lazyDLL) {
	var callback uintptr
	if runtime.GOARCH == "386" {
		callback = windows.NewCallback(func(level loggerLevel, timestampLow, timestampHigh uint32, msg *uint16) int {
			return logMessage(level, uint64(timestampHigh)<<32|uint64(timestampLow), msg)
		})
	} else if runtime.GOARCH == "arm" {
		callback = windows.NewCallback(func(level loggerLevel, _, timestampLow, timestampHigh uint32, msg *uint16) int {
			return logMessage(level, uint64(timestampHigh)<<32|uint64(timestampLow), msg)
		})
	} else if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		callback = windows.NewCallback(logMessage)
	}
	syscall.SyscallN(dll.NewProc("WintunSetLogger").Addr(), callback)
}

func closeAdapter(wintun *Adapter) {
	syscall.SyscallN(procWintunCloseAdapter.Addr(), wintun.handle)
}

// CreateAdapter creates a Wintun adapter. name is the cosmetic name of the adapter.
// tunnelType represents the type of adapter and should be "Wintun". requestedGUID is
// the GUID of the created network adapter, which then influences NLA generation
// deterministically. If it is set to nil, the GUID is chosen by the system at random,
// and hence a new NLA entry is created for each new adapter.
func CreateAdapter(name string, tunnelType string, requestedGUID *windows.GUID) (wintun *Adapter, err error) {
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	var tunnelType16 *uint16
	tunnelType16, err = windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return
	}
	if err := procWintunCreateAdapter.Find(); err != nil {
		return nil, err
	}
	r0, _, e1 := syscall.SyscallN(procWintunCreateAdapter.Addr(), uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(tunnelType16)), uintptr(unsafe.Pointer(requestedGUID)))
	if r0 == 0 {
		err = e1
		return
	}
	wintun = &Adapter{handle: r0}
	runtime.SetFinalizer(wintun, closeAdapter)
	return
}

// OpenAdapter opens an existing Wintun adapter by name.
func OpenAdapter(name string) (wintun *Adapter, err error) {
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	if err := procWintunOpenAdapter.Find(); err != nil {
		return nil, err
	}
	r0, _, e1 := syscall.SyscallN(procWintunOpenAdapter.Addr(), uintptr(unsafe.Pointer(name16)))
	if r0 == 0 {
		err = e1
		return
	}
	wintun = &Adapter{handle: r0}
	runtime.SetFinalizer(wintun, closeAdapter)
	return
}

// Close closes a Wintun adapter.
func (wintun *Adapter) Close() (err error) {
	if err := procWintunCloseAdapter.Find(); err != nil {
		return err
	}
	runtime.SetFinalizer(wintun, nil)
	r1, _, e1 := syscall.SyscallN(procWintunCloseAdapter.Addr(), wintun.handle)
	if r1 == 0 {
		err = e1
	}
	return
}

// Uninstall removes the driver from the system if no drivers are currently in use.
func Uninstall() (err error) {
	if err := procWintunDeleteDriver.Find(); err != nil {
		return err
	}
	r1, _, e1 := syscall.SyscallN(procWintunDeleteDriver.Addr())
	if r1 == 0 {
		err = e1
	}
	return
}

// RunningVersion returns the version of the loaded driver.
func RunningVersion() (version uint32, err error) {
	if err := procWintunGetRunningDriverVersion.Find(); err != nil {
		return 0, err
	}
	r0, _, e1 := syscall.SyscallN(procWintunGetRunningDriverVersion.Addr())
	version = uint32(r0)
	if version == 0 {
		err = e1
	}
	return
}

// LUID returns the LUID of the adapter.
func (wintun *Adapter) LUID() (luid uint64) {
	syscall.SyscallN(procWintunGetAdapterLUID.Addr(), uintptr(wintun.handle), uintptr(unsafe.Pointer(&luid)))
	return
}

func GenerateGUIDFromName(name string) *windows.GUID {
	hash := sha1.Sum([]byte(name))

	guid := windows.GUID{
		Data1: uint32(hash[0]) | uint32(hash[1])<<8 | uint32(hash[2])<<16 | uint32(hash[3])<<24,
		Data2: uint16(hash[4]) | uint16(hash[5])<<8,
		Data3: uint16(hash[6]) | uint16(hash[7])<<8,
		Data4: [8]byte{hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]},
	}

	guid.Data3 = (guid.Data3 & 0x0FFF) | 0x5000
	guid.Data4[0] = (guid.Data4[0] & 0x3F) | 0x80

	return &guid
}
