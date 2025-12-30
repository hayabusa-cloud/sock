// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock

import (
	"code.hybscloud.com/zcall"
)

// UnderlyingProtocol represents the socket type / underlying protocol.
// It corresponds to the SOCK_* constants.
type UnderlyingProtocol int

// Socket type constants matching SOCK_* values.
// These values are consistent across Unix platforms.
const (
	UnderlyingProtocolStream    UnderlyingProtocol = 1 // SOCK_STREAM - TCP, Unix stream
	UnderlyingProtocolDgram     UnderlyingProtocol = 2 // SOCK_DGRAM - UDP, Unix datagram
	UnderlyingProtocolRaw       UnderlyingProtocol = 3 // SOCK_RAW - Raw sockets
	UnderlyingProtocolSeqPacket UnderlyingProtocol = 5 // SOCK_SEQPACKET - SCTP, Unix seqpacket
)

// Socket type constants (SOCK_*) - aliased from zcall for platform compatibility.
const (
	SOCK_STREAM    = zcall.SOCK_STREAM
	SOCK_DGRAM     = zcall.SOCK_DGRAM
	SOCK_RAW       = zcall.SOCK_RAW
	SOCK_SEQPACKET = zcall.SOCK_SEQPACKET
	SOCK_NONBLOCK  = zcall.SOCK_NONBLOCK
	SOCK_CLOEXEC   = zcall.SOCK_CLOEXEC
)

// Protocol constants (IPPROTO_*) - aliased from zcall for platform compatibility.
const (
	IPPROTO_IP     = zcall.IPPROTO_IP
	IPPROTO_ICMP   = zcall.IPPROTO_ICMP
	IPPROTO_TCP    = zcall.IPPROTO_TCP
	IPPROTO_UDP    = zcall.IPPROTO_UDP
	IPPROTO_IPV6   = zcall.IPPROTO_IPV6
	IPPROTO_ICMPV6 = 58 // Consistent across platforms
	IPPROTO_RAW    = zcall.IPPROTO_RAW
)

// Socket option levels (SOL_*) - aliased from zcall for platform compatibility.
const (
	SOL_SOCKET = zcall.SOL_SOCKET
	SOL_IP     = zcall.SOL_IP
	SOL_TCP    = zcall.SOL_TCP
	SOL_UDP    = zcall.SOL_UDP
	SOL_IPV6   = zcall.SOL_IPV6
)

// Socket options (SO_*) - aliased from zcall for platform compatibility.
const (
	SO_REUSEADDR = zcall.SO_REUSEADDR
	SO_REUSEPORT = zcall.SO_REUSEPORT
	SO_KEEPALIVE = zcall.SO_KEEPALIVE
	SO_BROADCAST = zcall.SO_BROADCAST
	SO_SNDBUF    = zcall.SO_SNDBUF
	SO_RCVBUF    = zcall.SO_RCVBUF
	SO_ERROR     = zcall.SO_ERROR
	SO_TYPE      = zcall.SO_TYPE
	SO_LINGER    = zcall.SO_LINGER
	SO_RCVTIMEO  = zcall.SO_RCVTIMEO
	SO_SNDTIMEO  = zcall.SO_SNDTIMEO
)

// TCP options (TCP_*) - aliased from zcall for platform compatibility.
const (
	TCP_NODELAY   = zcall.TCP_NODELAY
	TCP_KEEPINTVL = zcall.TCP_KEEPINTVL
	TCP_KEEPCNT   = zcall.TCP_KEEPCNT
)

// Shutdown constants (SHUT_*) - aliased from zcall for platform compatibility.
const (
	SHUT_RD   = zcall.SHUT_RD
	SHUT_WR   = zcall.SHUT_WR
	SHUT_RDWR = zcall.SHUT_RDWR
)

// Message flags (MSG_*) - aliased from zcall for platform compatibility.
const (
	MSG_OOB       = zcall.MSG_OOB
	MSG_PEEK      = zcall.MSG_PEEK
	MSG_DONTROUTE = zcall.MSG_DONTROUTE
	MSG_TRUNC     = zcall.MSG_TRUNC
	MSG_DONTWAIT  = zcall.MSG_DONTWAIT
	MSG_WAITALL   = zcall.MSG_WAITALL
)

// File descriptor flags - aliased from zcall for platform compatibility.
const (
	O_RDONLY   = zcall.O_RDONLY
	O_WRONLY   = zcall.O_WRONLY
	O_RDWR     = zcall.O_RDWR
	O_NONBLOCK = zcall.O_NONBLOCK
	O_CLOEXEC  = zcall.O_CLOEXEC
)

// Default backlog for listen().
const DefaultBacklog = 511
