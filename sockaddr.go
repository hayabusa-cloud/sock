// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock

import (
	"math/bits"
	"net"
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// Sockaddr encodes to raw kernel format without allocation.
type Sockaddr interface {
	Raw() (unsafe.Pointer, uint32)
	Family() uint16
}

// SockaddrInet4 is a zero-allocation IPv4 socket address.
type SockaddrInet4 struct {
	raw RawSockaddrInet4
}

// NewSockaddrInet4 creates a new IPv4 socket address.
func NewSockaddrInet4(addr [4]byte, port uint16) *SockaddrInet4 {
	sa := &SockaddrInet4{}
	initRawSockaddrInet4(&sa.raw, AF_INET)
	sa.raw.Port = htons(port)
	sa.raw.Addr = addr
	return sa
}

//go:nosplit
func (sa *SockaddrInet4) Raw() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet4
}

//go:nosplit
func (sa *SockaddrInet4) Family() uint16 { return AF_INET }

//go:nosplit
func (sa *SockaddrInet4) Addr() [4]byte { return sa.raw.Addr }

//go:nosplit
func (sa *SockaddrInet4) Port() uint16 { return ntohs(sa.raw.Port) }

//go:nosplit
func (sa *SockaddrInet4) SetAddr(addr [4]byte) { sa.raw.Addr = addr }

//go:nosplit
func (sa *SockaddrInet4) SetPort(port uint16) { sa.raw.Port = htons(port) }

// SockaddrInet6 is a zero-allocation IPv6 socket address.
type SockaddrInet6 struct {
	raw RawSockaddrInet6
}

// NewSockaddrInet6 creates a new IPv6 socket address.
func NewSockaddrInet6(addr [16]byte, port uint16, zone uint32) *SockaddrInet6 {
	sa := &SockaddrInet6{}
	initRawSockaddrInet6(&sa.raw, AF_INET6)
	sa.raw.Port = htons(port)
	sa.raw.Addr = addr
	sa.raw.ScopeID = zone
	return sa
}

//go:nosplit
func (sa *SockaddrInet6) Raw() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet6
}

//go:nosplit
func (sa *SockaddrInet6) Family() uint16 { return AF_INET6 }

//go:nosplit
func (sa *SockaddrInet6) Addr() [16]byte { return sa.raw.Addr }

//go:nosplit
func (sa *SockaddrInet6) Port() uint16 { return ntohs(sa.raw.Port) }

//go:nosplit
func (sa *SockaddrInet6) ScopeID() uint32 { return sa.raw.ScopeID }

//go:nosplit
func (sa *SockaddrInet6) SetAddr(addr [16]byte) { sa.raw.Addr = addr }

//go:nosplit
func (sa *SockaddrInet6) SetPort(port uint16) { sa.raw.Port = htons(port) }

//go:nosplit
func (sa *SockaddrInet6) SetScopeID(id uint32) { sa.raw.ScopeID = id }

// SockaddrUnix is a zero-allocation Unix domain socket address.
type SockaddrUnix struct {
	raw    RawSockaddrUnix
	length uint32
}

// NewSockaddrUnix creates a new Unix domain socket address.
func NewSockaddrUnix(path string) *SockaddrUnix {
	sa := &SockaddrUnix{}
	initRawSockaddrUnix(&sa.raw, AF_UNIX)
	n := copy(sa.raw.Path[:], path)
	if n < len(sa.raw.Path) {
		sa.raw.Path[n] = 0
		sa.length = uint32(2 + n + 1) // Family + path + NUL terminator
	} else {
		sa.length = uint32(2 + n) // Family + path (no room for NUL)
	}
	return sa
}

//go:nosplit
func (sa *SockaddrUnix) Raw() (unsafe.Pointer, uint32) {
	return unsafe.Pointer(&sa.raw), sa.length
}

//go:nosplit
func (sa *SockaddrUnix) Family() uint16 { return AF_UNIX }

func (sa *SockaddrUnix) Path() string {
	if sa.length < 2 {
		// Fallback for zero-initialized struct: search for NUL
		for i, b := range sa.raw.Path {
			if b == 0 {
				return string(sa.raw.Path[:i])
			}
		}
		return ""
	}

	// Calculate path length from stored length field
	// length = 2 (family) + path_bytes [+ NUL if present]
	pathLen := int(sa.length) - 2
	if pathLen <= 0 {
		return ""
	}
	if pathLen > len(sa.raw.Path) {
		pathLen = len(sa.raw.Path)
	}

	// Check for abstract socket (starts with NUL and has content after)
	// Abstract sockets have path[0] == 0 with additional bytes
	// Empty path case: pathLen == 1 and path[0] == 0 means empty pathname
	if sa.raw.Path[0] == 0 && pathLen > 1 {
		return string(sa.raw.Path[:pathLen])
	}

	// Pathname socket: stop at NUL terminator
	for i := range pathLen {
		if sa.raw.Path[i] == 0 {
			return string(sa.raw.Path[:i])
		}
	}
	return string(sa.raw.Path[:pathLen])
}

func (sa *SockaddrUnix) SetPath(path string) {
	for i := range sa.raw.Path {
		sa.raw.Path[i] = 0
	}
	n := copy(sa.raw.Path[:], path)
	if n < len(sa.raw.Path) {
		sa.length = uint32(2 + n + 1) // Family + path + NUL terminator
	} else {
		sa.length = uint32(2 + n) // Family + path (no room for NUL)
	}
}

// Address conversion functions.

// TCPAddrToSockaddr converts a *net.TCPAddr to a Sockaddr.
func TCPAddrToSockaddr(addr *net.TCPAddr) Sockaddr {
	if addr == nil {
		return nil
	}
	if ip4 := addr.IP.To4(); ip4 != nil {
		sa := &SockaddrInet4{}
		initRawSockaddrInet4(&sa.raw, AF_INET)
		sa.raw.Port = htons(uint16(addr.Port))
		copy(sa.raw.Addr[:], ip4)
		return sa
	}
	if ip6 := addr.IP.To16(); ip6 != nil {
		sa := &SockaddrInet6{}
		initRawSockaddrInet6(&sa.raw, AF_INET6)
		sa.raw.Port = htons(uint16(addr.Port))
		copy(sa.raw.Addr[:], ip6)
		if addr.Zone != "" {
			sa.raw.ScopeID = zoneToScopeID(addr.Zone)
		}
		return sa
	}
	return nil
}

// UDPAddrToSockaddr converts a *net.UDPAddr to a Sockaddr.
func UDPAddrToSockaddr(addr *net.UDPAddr) Sockaddr {
	if addr == nil {
		return nil
	}
	if ip4 := addr.IP.To4(); ip4 != nil {
		sa := &SockaddrInet4{}
		initRawSockaddrInet4(&sa.raw, AF_INET)
		sa.raw.Port = htons(uint16(addr.Port))
		copy(sa.raw.Addr[:], ip4)
		return sa
	}
	if ip6 := addr.IP.To16(); ip6 != nil {
		sa := &SockaddrInet6{}
		initRawSockaddrInet6(&sa.raw, AF_INET6)
		sa.raw.Port = htons(uint16(addr.Port))
		copy(sa.raw.Addr[:], ip6)
		if addr.Zone != "" {
			sa.raw.ScopeID = zoneToScopeID(addr.Zone)
		}
		return sa
	}
	return nil
}

// UnixAddrToSockaddr converts a *net.UnixAddr to a Sockaddr.
func UnixAddrToSockaddr(addr *net.UnixAddr) Sockaddr {
	if addr == nil {
		return nil
	}
	return NewSockaddrUnix(addr.Name)
}

// SockaddrToTCPAddr converts a Sockaddr to a *net.TCPAddr.
func SockaddrToTCPAddr(sa Sockaddr) *net.TCPAddr {
	if sa == nil {
		return nil
	}
	switch s := sa.(type) {
	case *SockaddrInet4:
		return &net.TCPAddr{IP: net.IP(s.raw.Addr[:]), Port: int(ntohs(s.raw.Port))}
	case *SockaddrInet6:
		return &net.TCPAddr{IP: net.IP(s.raw.Addr[:]), Port: int(ntohs(s.raw.Port)), Zone: scopeIDToZone(s.raw.ScopeID)}
	}
	return nil
}

// SockaddrToUDPAddr converts a Sockaddr to a *net.UDPAddr.
func SockaddrToUDPAddr(sa Sockaddr) *net.UDPAddr {
	if sa == nil {
		return nil
	}
	switch s := sa.(type) {
	case *SockaddrInet4:
		return &net.UDPAddr{IP: net.IP(s.raw.Addr[:]), Port: int(ntohs(s.raw.Port))}
	case *SockaddrInet6:
		return &net.UDPAddr{IP: net.IP(s.raw.Addr[:]), Port: int(ntohs(s.raw.Port)), Zone: scopeIDToZone(s.raw.ScopeID)}
	}
	return nil
}

// SockaddrToUnixAddr converts a Sockaddr to a *net.UnixAddr.
func SockaddrToUnixAddr(sa Sockaddr, network string) *net.UnixAddr {
	if sa == nil {
		return nil
	}
	if s, ok := sa.(*SockaddrUnix); ok {
		return &net.UnixAddr{Name: s.Path(), Net: network}
	}
	return nil
}

// DecodeSockaddr decodes a raw sockaddr into a Sockaddr.
// For Unix sockets, addrlen from the kernel is required to correctly handle
// abstract sockets (which start with NUL byte). For IPv4/IPv6, addrlen is ignored.
func DecodeSockaddr(raw *RawSockaddrAny, addrlen uint32) Sockaddr {
	if raw == nil {
		return nil
	}
	family := getRawFamily(raw)
	switch family {
	case AF_INET:
		sa := &SockaddrInet4{}
		sa.raw = *(*RawSockaddrInet4)(unsafe.Pointer(raw))
		return sa
	case AF_INET6:
		sa := &SockaddrInet6{}
		sa.raw = *(*RawSockaddrInet6)(unsafe.Pointer(raw))
		return sa
	case AF_UNIX:
		sa := &SockaddrUnix{}
		sa.raw = *(*RawSockaddrUnix)(unsafe.Pointer(raw))
		// Use kernel-provided addrlen for correct abstract socket handling
		sa.length = addrlen
		return sa
	}
	return nil
}

// Byte order conversion.
// Network byte order is big-endian. These functions convert between host and
// network byte order using math/bits for optimal codegen (single instruction
// on most architectures). The nativeIsLittleEndian constant is defined in
// endian_le.go / endian_be.go based on build tags.

func htons(v uint16) uint16 {
	if nativeIsLittleEndian {
		return bits.ReverseBytes16(v)
	}
	return v
}

func ntohs(v uint16) uint16 {
	if nativeIsLittleEndian {
		return bits.ReverseBytes16(v)
	}
	return v
}

func htonl(v uint32) uint32 {
	if nativeIsLittleEndian {
		return bits.ReverseBytes32(v)
	}
	return v
}

func ntohl(v uint32) uint32 {
	if nativeIsLittleEndian {
		return bits.ReverseBytes32(v)
	}
	return v
}

func zoneToScopeID(zone string) uint32 {
	if zone == "" {
		return 0
	}
	var id uint32
	for _, c := range zone {
		if c < '0' || c > '9' {
			return 0
		}
		id = id*10 + uint32(c-'0')
	}
	return id
}

func scopeIDToZone(id uint32) string {
	if id == 0 {
		return ""
	}
	var buf [10]byte
	n := len(buf)
	for id > 0 {
		n--
		buf[n] = byte('0' + id%10)
		id /= 10
	}
	return string(buf[n:])
}

// GetSockname retrieves the local address of a socket.
func GetSockname(fd *iofd.FD) (Sockaddr, error) {
	raw := fd.Raw()
	if raw < 0 {
		return nil, ErrClosed
	}
	var rsa RawSockaddrAny
	addrlen := uint32(SizeofSockaddrAny)
	errno := zcall.Getsockname(uintptr(raw), unsafe.Pointer(&rsa), unsafe.Pointer(&addrlen))
	if errno != 0 {
		return nil, errFromErrno(errno)
	}
	return DecodeSockaddr(&rsa, addrlen), nil
}

// GetPeername retrieves the remote address of a connected socket.
func GetPeername(fd *iofd.FD) (Sockaddr, error) {
	raw := fd.Raw()
	if raw < 0 {
		return nil, ErrClosed
	}
	var rsa RawSockaddrAny
	addrlen := uint32(SizeofSockaddrAny)
	errno := zcall.Getpeername(uintptr(raw), unsafe.Pointer(&rsa), unsafe.Pointer(&addrlen))
	if errno != 0 {
		return nil, errFromErrno(errno)
	}
	return DecodeSockaddr(&rsa, addrlen), nil
}
