// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build freebsd || darwin

package sock

import "code.hybscloud.com/zcall"

// Raw socket address structures matching BSD/Darwin kernel layout.
// BSD/Darwin uses sa_len (uint8) at offset 0, followed by sa_family (uint8).

// RawSockaddr is the base socket address structure (struct sockaddr).
type RawSockaddr struct {
	Len    uint8
	Family uint8
	Data   [14]byte
}

// RawSockaddrInet4 is the raw IPv4 socket address (struct sockaddr_in).
// Size: 16 bytes.
type RawSockaddrInet4 struct {
	Len    uint8
	Family uint8
	Port   uint16 // Network byte order (big-endian)
	Addr   [4]byte
	Zero   [8]byte
}

// RawSockaddrInet6 is the raw IPv6 socket address (struct sockaddr_in6).
// Size: 28 bytes.
type RawSockaddrInet6 struct {
	Len      uint8
	Family   uint8
	Port     uint16 // Network byte order (big-endian)
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// RawSockaddrUnix is the raw Unix domain socket address (struct sockaddr_un).
// Size: 106 bytes on BSD/Darwin (shorter path than Linux).
type RawSockaddrUnix struct {
	Len    uint8
	Family uint8
	Path   [104]byte
}

// RawSockaddrAny is a raw socket address that can hold any address type.
// Size matches sockaddr_storage (128 bytes).
type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [112]byte
}

// Size constants for socket address structures.
const (
	SizeofSockaddrInet4 = 16
	SizeofSockaddrInet6 = 28
	SizeofSockaddrUnix  = 106
	SizeofSockaddrAny   = 128
)

// Address family constants - aliases to zcall for convenience.
const (
	AF_UNSPEC = 0
	AF_UNIX   = zcall.AF_UNIX
	AF_LOCAL  = zcall.AF_UNIX
	AF_INET   = zcall.AF_INET
	AF_INET6  = zcall.AF_INET6
)

// initRawSockaddrInet4 initializes a RawSockaddrInet4 with the given family.
// On BSD/Darwin, this also sets the sa_len field.
func initRawSockaddrInet4(raw *RawSockaddrInet4, family uint16) {
	raw.Len = SizeofSockaddrInet4
	raw.Family = uint8(family)
}

// initRawSockaddrInet6 initializes a RawSockaddrInet6 with the given family.
// On BSD/Darwin, this also sets the sa_len field.
func initRawSockaddrInet6(raw *RawSockaddrInet6, family uint16) {
	raw.Len = SizeofSockaddrInet6
	raw.Family = uint8(family)
}

// initRawSockaddrUnix initializes a RawSockaddrUnix with the given family.
// On BSD/Darwin, this also sets the sa_len field.
func initRawSockaddrUnix(raw *RawSockaddrUnix, family uint16) {
	raw.Len = SizeofSockaddrUnix
	raw.Family = uint8(family)
}

// getRawFamily extracts the address family from a RawSockaddrAny.
// On BSD/Darwin, the family is at offset 1 (after sa_len).
func getRawFamily(raw *RawSockaddrAny) uint16 {
	return uint16(raw.Addr.Family)
}
