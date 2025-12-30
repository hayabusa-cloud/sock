// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// IPv4 multicast socket options.
const (
	IP_MULTICAST_IF    = 32
	IP_MULTICAST_TTL   = 33
	IP_MULTICAST_LOOP  = 34
	IP_ADD_MEMBERSHIP  = 35
	IP_DROP_MEMBERSHIP = 36
)

// IPv6 multicast socket options.
const (
	IPV6_MULTICAST_IF    = 17
	IPV6_MULTICAST_HOPS  = 18
	IPV6_MULTICAST_LOOP  = 19
	IPV6_ADD_MEMBERSHIP  = 20
	IPV6_DROP_MEMBERSHIP = 21
	IPV6_MULTICAST_ALL   = 29
)

// IPMreq is the IPv4 multicast group request structure.
// Matches struct ip_mreq in Linux.
type IPMreq struct {
	Multiaddr [4]byte // Multicast group address
	Interface [4]byte // Local interface address
}

// IPMreqn is the IPv4 multicast group request structure with interface index.
// Matches struct ip_mreqn in Linux.
type IPMreqn struct {
	Multiaddr [4]byte // Multicast group address
	Address   [4]byte // Local interface address
	Ifindex   int32   // Interface index
}

// IPv6Mreq is the IPv6 multicast group request structure.
// Matches struct ipv6_mreq in Linux.
type IPv6Mreq struct {
	Multiaddr [16]byte // IPv6 multicast address
	Ifindex   int32    // Interface index
}

// JoinMulticast4 joins an IPv4 multicast group.
// mcastAddr is the multicast group address (e.g., 224.0.0.1).
// ifAddr is the local interface address to use (0.0.0.0 for default).
func JoinMulticast4(fd *iofd.FD, mcastAddr, ifAddr [4]byte) error {
	mreq := IPMreq{
		Multiaddr: mcastAddr,
		Interface: ifAddr,
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_ADD_MEMBERSHIP),
		unsafe.Pointer(&mreq),
		unsafe.Sizeof(mreq),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// JoinMulticast4n joins an IPv4 multicast group using interface index.
// ifindex of 0 uses the default interface.
func JoinMulticast4n(fd *iofd.FD, mcastAddr [4]byte, ifindex int) error {
	mreq := IPMreqn{
		Multiaddr: mcastAddr,
		Ifindex:   int32(ifindex),
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_ADD_MEMBERSHIP),
		unsafe.Pointer(&mreq),
		unsafe.Sizeof(mreq),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// LeaveMulticast4 leaves an IPv4 multicast group.
func LeaveMulticast4(fd *iofd.FD, mcastAddr, ifAddr [4]byte) error {
	mreq := IPMreq{
		Multiaddr: mcastAddr,
		Interface: ifAddr,
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_DROP_MEMBERSHIP),
		unsafe.Pointer(&mreq),
		unsafe.Sizeof(mreq),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// LeaveMulticast4n leaves an IPv4 multicast group using interface index.
func LeaveMulticast4n(fd *iofd.FD, mcastAddr [4]byte, ifindex int) error {
	mreq := IPMreqn{
		Multiaddr: mcastAddr,
		Ifindex:   int32(ifindex),
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_DROP_MEMBERSHIP),
		unsafe.Pointer(&mreq),
		unsafe.Sizeof(mreq),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// JoinMulticast6 joins an IPv6 multicast group.
// ifindex of 0 uses the default interface.
func JoinMulticast6(fd *iofd.FD, mcastAddr [16]byte, ifindex int) error {
	mreq := IPv6Mreq{
		Multiaddr: mcastAddr,
		Ifindex:   int32(ifindex),
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_ADD_MEMBERSHIP),
		unsafe.Pointer(&mreq),
		unsafe.Sizeof(mreq),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// LeaveMulticast6 leaves an IPv6 multicast group.
func LeaveMulticast6(fd *iofd.FD, mcastAddr [16]byte, ifindex int) error {
	mreq := IPv6Mreq{
		Multiaddr: mcastAddr,
		Ifindex:   int32(ifindex),
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_DROP_MEMBERSHIP),
		unsafe.Pointer(&mreq),
		unsafe.Sizeof(mreq),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// SetMulticastTTL sets the IPv4 multicast TTL (time-to-live).
// TTL of 1 means packets stay on local network only.
func SetMulticastTTL(fd *iofd.FD, ttl int) error {
	v := uint8(ttl)
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_MULTICAST_TTL),
		unsafe.Pointer(&v),
		unsafe.Sizeof(v),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// GetMulticastTTL returns the current IPv4 multicast TTL.
func GetMulticastTTL(fd *iofd.FD) (int, error) {
	var v uint8
	vlen := uint32(unsafe.Sizeof(v))
	errno := zcall.Getsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_MULTICAST_TTL),
		unsafe.Pointer(&v),
		unsafe.Pointer(&vlen),
	)
	if errno != 0 {
		return 0, errFromErrno(errno)
	}
	return int(v), nil
}

// SetMulticast6Hops sets the IPv6 multicast hop limit.
// A value of 1 means packets stay on local network only.
// A value of -1 uses the system default.
func SetMulticast6Hops(fd *iofd.FD, hops int) error {
	v := int32(hops)
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_MULTICAST_HOPS),
		unsafe.Pointer(&v),
		unsafe.Sizeof(v),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// GetMulticast6Hops returns the current IPv6 multicast hop limit.
func GetMulticast6Hops(fd *iofd.FD) (int, error) {
	var v int32
	vlen := uint32(unsafe.Sizeof(v))
	errno := zcall.Getsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_MULTICAST_HOPS),
		unsafe.Pointer(&v),
		unsafe.Pointer(&vlen),
	)
	if errno != 0 {
		return 0, errFromErrno(errno)
	}
	return int(v), nil
}

// SetMulticastLoop enables or disables IPv4 multicast loopback.
// When enabled, multicast packets are looped back to local sockets.
func SetMulticastLoop(fd *iofd.FD, enable bool) error {
	var v uint8
	if enable {
		v = 1
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_MULTICAST_LOOP),
		unsafe.Pointer(&v),
		unsafe.Sizeof(v),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// GetMulticastLoop returns whether IPv4 multicast loopback is enabled.
func GetMulticastLoop(fd *iofd.FD) (bool, error) {
	var v uint8
	vlen := uint32(unsafe.Sizeof(v))
	errno := zcall.Getsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_MULTICAST_LOOP),
		unsafe.Pointer(&v),
		unsafe.Pointer(&vlen),
	)
	if errno != 0 {
		return false, errFromErrno(errno)
	}
	return v != 0, nil
}

// SetMulticast6Loop enables or disables IPv6 multicast loopback.
func SetMulticast6Loop(fd *iofd.FD, enable bool) error {
	v := int32(0)
	if enable {
		v = 1
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_MULTICAST_LOOP),
		unsafe.Pointer(&v),
		unsafe.Sizeof(v),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// GetMulticast6Loop returns whether IPv6 multicast loopback is enabled.
func GetMulticast6Loop(fd *iofd.FD) (bool, error) {
	var v int32
	vlen := uint32(unsafe.Sizeof(v))
	errno := zcall.Getsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_MULTICAST_LOOP),
		unsafe.Pointer(&v),
		unsafe.Pointer(&vlen),
	)
	if errno != 0 {
		return false, errFromErrno(errno)
	}
	return v != 0, nil
}

// SetMulticastInterface sets the IPv4 multicast output interface by address.
func SetMulticastInterface(fd *iofd.FD, ifAddr [4]byte) error {
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_MULTICAST_IF),
		unsafe.Pointer(&ifAddr),
		unsafe.Sizeof(ifAddr),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// SetMulticastInterfaceByIndex sets the IPv4 multicast output interface by index.
func SetMulticastInterfaceByIndex(fd *iofd.FD, ifindex int) error {
	mreq := IPMreqn{
		Ifindex: int32(ifindex),
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IP),
		uintptr(IP_MULTICAST_IF),
		unsafe.Pointer(&mreq),
		unsafe.Sizeof(mreq),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// SetMulticast6Interface sets the IPv6 multicast output interface.
func SetMulticast6Interface(fd *iofd.FD, ifindex int) error {
	v := int32(ifindex)
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_MULTICAST_IF),
		unsafe.Pointer(&v),
		unsafe.Sizeof(v),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// GetMulticast6Interface returns the current IPv6 multicast output interface.
func GetMulticast6Interface(fd *iofd.FD) (int, error) {
	var v int32
	vlen := uint32(unsafe.Sizeof(v))
	errno := zcall.Getsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_MULTICAST_IF),
		unsafe.Pointer(&v),
		unsafe.Pointer(&vlen),
	)
	if errno != 0 {
		return 0, errFromErrno(errno)
	}
	return int(v), nil
}

// SetMulticast6All enables or disables receiving all multicast packets.
// When disabled, only packets to joined groups are received.
func SetMulticast6All(fd *iofd.FD, enable bool) error {
	v := int32(0)
	if enable {
		v = 1
	}
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.IPPROTO_IPV6),
		uintptr(IPV6_MULTICAST_ALL),
		unsafe.Pointer(&v),
		unsafe.Sizeof(v),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}
