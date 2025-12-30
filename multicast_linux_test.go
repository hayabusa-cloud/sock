// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"testing"
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/sock"
	"code.hybscloud.com/zcall"
)

func TestIPMreqSize(t *testing.T) {
	var mreq sock.IPMreq
	if unsafe.Sizeof(mreq) != 8 {
		t.Errorf("IPMreq size: got %d, want 8", unsafe.Sizeof(mreq))
	}
}

func TestIPMreqnSize(t *testing.T) {
	var mreq sock.IPMreqn
	if unsafe.Sizeof(mreq) != 12 {
		t.Errorf("IPMreqn size: got %d, want 12", unsafe.Sizeof(mreq))
	}
}

func TestIPv6MreqSize(t *testing.T) {
	var mreq sock.IPv6Mreq
	if unsafe.Sizeof(mreq) != 20 {
		t.Errorf("IPv6Mreq size: got %d, want 20", unsafe.Sizeof(mreq))
	}
}

func TestMulticastTTL(t *testing.T) {
	// Create UDP socket
	fd, errno := zcall.Socket(zcall.AF_INET, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Set multicast TTL
	err := sock.SetMulticastTTL(&ioFD, 5)
	if err != nil {
		t.Fatalf("SetMulticastTTL failed: %v", err)
	}

	// Get multicast TTL
	ttl, err := sock.GetMulticastTTL(&ioFD)
	if err != nil {
		t.Fatalf("GetMulticastTTL failed: %v", err)
	}
	if ttl != 5 {
		t.Errorf("TTL: got %d, want 5", ttl)
	}
}

func TestMulticastLoop(t *testing.T) {
	// Create UDP socket
	fd, errno := zcall.Socket(zcall.AF_INET, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Disable multicast loop
	err := sock.SetMulticastLoop(&ioFD, false)
	if err != nil {
		t.Fatalf("SetMulticastLoop failed: %v", err)
	}

	// Check it's disabled
	loop, err := sock.GetMulticastLoop(&ioFD)
	if err != nil {
		t.Fatalf("GetMulticastLoop failed: %v", err)
	}
	if loop {
		t.Error("Multicast loop should be disabled")
	}

	// Enable it again
	err = sock.SetMulticastLoop(&ioFD, true)
	if err != nil {
		t.Fatalf("SetMulticastLoop failed: %v", err)
	}

	loop, err = sock.GetMulticastLoop(&ioFD)
	if err != nil {
		t.Fatalf("GetMulticastLoop failed: %v", err)
	}
	if !loop {
		t.Error("Multicast loop should be enabled")
	}
}

func TestMulticast6Hops(t *testing.T) {
	// Create UDP6 socket
	fd, errno := zcall.Socket(zcall.AF_INET6, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Set multicast hops
	err := sock.SetMulticast6Hops(&ioFD, 3)
	if err != nil {
		t.Fatalf("SetMulticast6Hops failed: %v", err)
	}

	// Get multicast hops
	hops, err := sock.GetMulticast6Hops(&ioFD)
	if err != nil {
		t.Fatalf("GetMulticast6Hops failed: %v", err)
	}
	if hops != 3 {
		t.Errorf("Hops: got %d, want 3", hops)
	}
}

func TestMulticast6Loop(t *testing.T) {
	// Create UDP6 socket
	fd, errno := zcall.Socket(zcall.AF_INET6, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Disable multicast loop
	err := sock.SetMulticast6Loop(&ioFD, false)
	if err != nil {
		t.Fatalf("SetMulticast6Loop failed: %v", err)
	}

	// Check it's disabled
	loop, err := sock.GetMulticast6Loop(&ioFD)
	if err != nil {
		t.Fatalf("GetMulticast6Loop failed: %v", err)
	}
	if loop {
		t.Error("Multicast6 loop should be disabled")
	}
}

func TestMulticast6Interface(t *testing.T) {
	// Create UDP6 socket
	fd, errno := zcall.Socket(zcall.AF_INET6, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Get default interface (should be 0)
	ifindex, err := sock.GetMulticast6Interface(&ioFD)
	if err != nil {
		t.Fatalf("GetMulticast6Interface failed: %v", err)
	}
	// Default is typically 0
	if ifindex != 0 {
		t.Logf("Default multicast interface: %d", ifindex)
	}
}

func TestJoinLeaveMulticast4(t *testing.T) {
	// Create UDP socket
	fd, errno := zcall.Socket(zcall.AF_INET, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Enable SO_REUSEADDR
	err := sock.SetReuseAddr(&ioFD, true)
	if err != nil {
		t.Fatalf("SetReuseAddr failed: %v", err)
	}

	// Join multicast group 224.0.0.1 (all-hosts)
	mcastAddr := [4]byte{224, 0, 0, 1}
	ifAddr := [4]byte{0, 0, 0, 0} // Any interface
	err = sock.JoinMulticast4(&ioFD, mcastAddr, ifAddr)
	if err != nil {
		t.Fatalf("JoinMulticast4 failed: %v", err)
	}

	// Leave the group
	err = sock.LeaveMulticast4(&ioFD, mcastAddr, ifAddr)
	if err != nil {
		t.Fatalf("LeaveMulticast4 failed: %v", err)
	}
}

func TestJoinLeaveMulticast6(t *testing.T) {
	// Create UDP6 socket
	fd, errno := zcall.Socket(zcall.AF_INET6, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Enable SO_REUSEADDR
	err := sock.SetReuseAddr(&ioFD, true)
	if err != nil {
		t.Fatalf("SetReuseAddr failed: %v", err)
	}

	// Join multicast group ff02::1 (all-nodes link-local)
	mcastAddr := [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	err = sock.JoinMulticast6(&ioFD, mcastAddr, 0)
	if err != nil {
		t.Fatalf("JoinMulticast6 failed: %v", err)
	}

	// Leave the group
	err = sock.LeaveMulticast6(&ioFD, mcastAddr, 0)
	if err != nil {
		t.Fatalf("LeaveMulticast6 failed: %v", err)
	}
}

func TestSetMulticastInterface(t *testing.T) {
	// Create UDP socket
	fd, errno := zcall.Socket(zcall.AF_INET, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Set multicast interface by address (INADDR_ANY)
	ifAddr := [4]byte{0, 0, 0, 0}
	err := sock.SetMulticastInterface(&ioFD, ifAddr)
	if err != nil {
		t.Fatalf("SetMulticastInterface failed: %v", err)
	}
}

func TestSetMulticast6Interface(t *testing.T) {
	// Create UDP6 socket
	fd, errno := zcall.Socket(zcall.AF_INET6, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if errno != 0 {
		t.Fatalf("Socket failed: %v", zcall.Errno(errno))
	}
	ioFD := iofd.NewFD(int(fd))
	defer ioFD.Close()

	// Set multicast interface by index (0 = default)
	err := sock.SetMulticast6Interface(&ioFD, 0)
	if err != nil {
		t.Fatalf("SetMulticast6Interface failed: %v", err)
	}
}
