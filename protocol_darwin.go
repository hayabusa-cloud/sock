// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build darwin

package sock

// Darwin-specific protocol constants.

// Darwin-specific IPPROTO constants.
const (
	IPPROTO_SCTP    = 132
	IPPROTO_UDPLITE = 136
)

// Darwin-specific socket options (SO_*).
const (
	SO_DEBUG     = 0x0001
	SO_DONTROUTE = 0x0010
	SO_OOBINLINE = 0x0100
	SO_ZEROCOPY  = 0 // Not available on Darwin
)

// Darwin-specific TCP options (TCP_*).
const (
	TCP_MAXSEG        = 0x02
	TCP_CORK          = 0    // Not available on Darwin
	TCP_KEEPIDLE      = 0x10 // TCP_KEEPALIVE on Darwin
	TCP_SYNCNT        = 0    // Not available on Darwin
	TCP_LINGER2       = 0    // Not available on Darwin
	TCP_DEFER_ACCEPT  = 0    // Not available on Darwin
	TCP_WINDOW_CLAMP  = 0    // Not available on Darwin
	TCP_QUICKACK      = 0    // Not available on Darwin
	TCP_CONGESTION    = 0    // Not available on Darwin
	TCP_FASTOPEN      = 0    // Not available on Darwin
	TCP_NOTSENT_LOWAT = 0x201
)

// Darwin-specific IPv6 options (IPV6_*).
const (
	IPV6_V6ONLY = 27
)

// Darwin-specific message flags (MSG_*).
const (
	MSG_CTRUNC       = 0x20
	MSG_EOR          = 0x8
	MSG_NOSIGNAL     = 0x80000 // Not directly available, use SO_NOSIGPIPE
	MSG_MORE         = 0       // Not available on Darwin
	MSG_WAITFORONE   = 0       // Not available on Darwin
	MSG_FASTOPEN     = 0       // Not available on Darwin
	MSG_CMSG_CLOEXEC = 0       // Not available on Darwin
	MSG_ZEROCOPY     = 0       // Not available on Darwin
)

// Darwin-specific poll event constants.
const (
	POLLIN   = 0x0001
	POLLPRI  = 0x0002
	POLLOUT  = 0x0004
	POLLERR  = 0x0008
	POLLHUP  = 0x0010
	POLLNVAL = 0x0020
)

// Darwin-specific file descriptor flags.
const (
	O_CREAT  = 0x0200
	O_EXCL   = 0x0800
	O_NOCTTY = 0x20000
	O_TRUNC  = 0x0400
	O_APPEND = 0x0008
	O_SYNC   = 0x0080
	O_DIRECT = 0 // Not available on Darwin
)
