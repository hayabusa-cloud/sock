// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"unsafe"

	"code.hybscloud.com/zcall"
)

// Raw socket address structures matching Linux kernel layout.
// Linux uses sa_family (uint16) at offset 0, without sa_len.

// RawSockaddr is the base socket address structure (struct sockaddr).
type RawSockaddr struct {
	Family uint16
	Data   [14]byte
}

// RawSockaddrInet4 is the raw IPv4 socket address (struct sockaddr_in).
// Size: 16 bytes.
type RawSockaddrInet4 struct {
	Family uint16
	Port   uint16 // Network byte order (big-endian)
	Addr   [4]byte
	Zero   [8]byte
}

// RawSockaddrInet6 is the raw IPv6 socket address (struct sockaddr_in6).
// Size: 28 bytes.
type RawSockaddrInet6 struct {
	Family   uint16
	Port     uint16 // Network byte order (big-endian)
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// RawSockaddrUnix is the raw Unix domain socket address (struct sockaddr_un).
// Size: 110 bytes.
type RawSockaddrUnix struct {
	Family uint16
	Path   [108]byte
}

// RawSockaddrAny is a raw socket address that can hold any address type.
// Size matches sockaddr_storage (128 bytes).
type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [112]byte // 128 - sizeof(RawSockaddr) = 128 - 16 = 112
}

// Size constants for socket address structures.
const (
	SizeofSockaddrInet4 = 16
	SizeofSockaddrInet6 = 28
	SizeofSockaddrUnix  = 110
	SizeofSockaddrAny   = 128
)

// Compile-time size assertions to match Linux kernel structures.
var (
	_ [SizeofSockaddrInet4]byte = [unsafe.Sizeof(RawSockaddrInet4{})]byte{}
	_ [SizeofSockaddrInet6]byte = [unsafe.Sizeof(RawSockaddrInet6{})]byte{}
	_ [SizeofSockaddrUnix]byte  = [unsafe.Sizeof(RawSockaddrUnix{})]byte{}
	_ [SizeofSockaddrAny]byte   = [unsafe.Sizeof(RawSockaddrAny{})]byte{}
)

// Address family constants - aliases to zcall for convenience.
const (
	AF_UNSPEC = zcall.AF_UNIX - zcall.AF_UNIX // 0
	AF_UNIX   = zcall.AF_UNIX
	AF_LOCAL  = zcall.AF_LOCAL
	AF_INET   = zcall.AF_INET
	AF_INET6  = zcall.AF_INET6
)

// initRawSockaddrInet4 initializes a RawSockaddrInet4 with the given family.
func initRawSockaddrInet4(raw *RawSockaddrInet4, family uint16) {
	raw.Family = family
}

// initRawSockaddrInet6 initializes a RawSockaddrInet6 with the given family.
func initRawSockaddrInet6(raw *RawSockaddrInet6, family uint16) {
	raw.Family = family
}

// initRawSockaddrUnix initializes a RawSockaddrUnix with the given family.
func initRawSockaddrUnix(raw *RawSockaddrUnix, family uint16) {
	raw.Family = family
}

// getRawFamily extracts the address family from a RawSockaddrAny.
func getRawFamily(raw *RawSockaddrAny) uint16 {
	return raw.Addr.Family
}
