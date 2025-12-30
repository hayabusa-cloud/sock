// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build freebsd

package sock

import "code.hybscloud.com/zcall"

// FreeBSD-specific protocol constants.

// FreeBSD-specific socket options (SO_*).
const (
	SO_DEBUG     = zcall.SO_DEBUG
	SO_DONTROUTE = zcall.SO_DONTROUTE
	SO_OOBINLINE = zcall.SO_OOBINLINE
	SO_ZEROCOPY  = zcall.SO_ZEROCOPY // Always 0 on FreeBSD
)

// FreeBSD-specific TCP options (TCP_*).
const (
	TCP_MAXSEG   = zcall.TCP_MAXSEG
	TCP_NOPUSH   = zcall.TCP_NOPUSH
	TCP_KEEPIDLE = zcall.TCP_KEEPIDLE
)

// FreeBSD-specific IPv6 options (IPV6_*).
const (
	IPV6_V6ONLY = 27 // FreeBSD value
)

// FreeBSD-specific message flags (MSG_*).
const (
	MSG_CTRUNC   = zcall.MSG_CTRUNC
	MSG_EOR      = zcall.MSG_EOR
	MSG_NOSIGNAL = zcall.MSG_NOSIGNAL
	MSG_EOF      = zcall.MSG_EOF
	MSG_ZEROCOPY = zcall.MSG_ZEROCOPY // Always 0 on FreeBSD
)

// FreeBSD-specific file descriptor flags.
const (
	O_CREAT  = zcall.O_CREAT
	O_EXCL   = zcall.O_EXCL
	O_TRUNC  = zcall.O_TRUNC
	O_APPEND = zcall.O_APPEND
)
