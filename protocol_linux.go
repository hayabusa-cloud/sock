// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import "code.hybscloud.com/zcall"

// Linux-specific protocol constants.
// These constants are only available on Linux and should not be used
// in cross-platform code.

// Linux-specific IPPROTO constants.
const (
	IPPROTO_SCTP    = zcall.IPPROTO_SCTP
	IPPROTO_UDPLITE = 136
)

// Linux-specific socket options (SO_*).
const (
	SO_DEBUG        = zcall.SO_DEBUG
	SO_DONTROUTE    = zcall.SO_DONTROUTE
	SO_OOBINLINE    = zcall.SO_OOBINLINE
	SO_INCOMING_CPU = zcall.SO_INCOMING_CPU
	SO_ZEROCOPY     = zcall.SO_ZEROCOPY
	SO_BUSY_POLL    = zcall.SO_BUSY_POLL
)

// Linux-specific TCP options (TCP_*).
const (
	TCP_MAXSEG        = zcall.TCP_MAXSEG
	TCP_CORK          = zcall.TCP_CORK
	TCP_KEEPIDLE      = zcall.TCP_KEEPIDLE
	TCP_SYNCNT        = zcall.TCP_SYNCNT
	TCP_LINGER2       = zcall.TCP_LINGER2
	TCP_DEFER_ACCEPT  = zcall.TCP_DEFER_ACCEPT
	TCP_WINDOW_CLAMP  = zcall.TCP_WINDOW_CLAMP
	TCP_INFO          = zcall.TCP_INFO
	TCP_QUICKACK      = zcall.TCP_QUICKACK
	TCP_CONGESTION    = zcall.TCP_CONGESTION
	TCP_USER_TIMEOUT  = zcall.TCP_USER_TIMEOUT
	TCP_FASTOPEN      = zcall.TCP_FASTOPEN
	TCP_NOTSENT_LOWAT = zcall.TCP_NOTSENT_LOWAT
)

// Linux-specific UDP options (UDP_*).
const (
	UDP_SEGMENT = zcall.UDP_SEGMENT
	UDP_GRO     = zcall.UDP_GRO
)

// Linux-specific IP options (IP_*).
const (
	IP_TRANSPARENT = zcall.IP_TRANSPARENT
)

// Linux-specific IPv6 options (IPV6_*).
const (
	IPV6_V6ONLY = zcall.IPV6_V6ONLY
)

// Linux-specific message flags (MSG_*).
const (
	MSG_CTRUNC       = zcall.MSG_CTRUNC
	MSG_EOR          = zcall.MSG_EOR
	MSG_NOSIGNAL     = zcall.MSG_NOSIGNAL
	MSG_MORE         = zcall.MSG_MORE
	MSG_WAITFORONE   = zcall.MSG_WAITFORONE
	MSG_FASTOPEN     = zcall.MSG_FASTOPEN
	MSG_CMSG_CLOEXEC = zcall.MSG_CMSG_CLOEXEC
	MSG_ZEROCOPY     = zcall.MSG_ZEROCOPY
)

// Linux-specific poll event constants.
const (
	POLLIN   = zcall.POLLIN
	POLLPRI  = zcall.POLLPRI
	POLLOUT  = zcall.POLLOUT
	POLLERR  = zcall.POLLERR
	POLLHUP  = zcall.POLLHUP
	POLLNVAL = zcall.POLLNVAL
)

// Linux-specific file descriptor flags.
const (
	O_CREAT  = zcall.O_CREAT
	O_EXCL   = zcall.O_EXCL
	O_NOCTTY = zcall.O_NOCTTY
	O_TRUNC  = zcall.O_TRUNC
	O_APPEND = zcall.O_APPEND
	O_SYNC   = zcall.O_SYNC
	O_DIRECT = zcall.O_DIRECT
)
