// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock

import (
	"errors"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/iox"
	"code.hybscloud.com/zcall"
)

// ErrClosed indicates the socket or file descriptor has been closed.
// Reused from iofd for semantic consistency across the ecosystem.
var ErrClosed = iofd.ErrClosed

// Socket-specific errors for network operations.
//
// These errors map from Linux kernel errno values to semantic Go errors.
// Use errors.Is() to check for specific error conditions:
//
//	if errors.Is(err, sock.ErrConnectionRefused) {
//	    // Handle connection refused
//	}
var (
	// ErrAddressInUse indicates the address is already bound (EADDRINUSE).
	// Common when restarting a server without SO_REUSEADDR.
	ErrAddressInUse = errors.New("sock: address in use")

	// ErrAddressNotAvailable indicates the requested address is not available (EADDRNOTAVAIL).
	// Occurs when binding to a non-local IP or invalid interface.
	ErrAddressNotAvailable = errors.New("sock: address not available")

	// ErrConnectionRefused indicates the target actively refused the connection (ECONNREFUSED).
	// No service is listening on the specified port.
	ErrConnectionRefused = errors.New("sock: connection refused")

	// ErrConnectionReset indicates the connection was reset by the peer (ECONNRESET, ECONNABORTED, EPIPE).
	// The remote end closed the connection unexpectedly.
	ErrConnectionReset = errors.New("sock: connection reset")

	// ErrNotConnected indicates the socket is not connected (ENOTCONN, EDESTADDRREQ).
	// Returned when calling Read/Write on an unconnected socket without an address.
	ErrNotConnected = errors.New("sock: not connected")

	// ErrTimedOut indicates the operation exceeded its deadline (ETIMEDOUT).
	// Returned by adaptive I/O when the deadline set via SetDeadline is exceeded.
	ErrTimedOut = errors.New("sock: timed out")

	// ErrNetworkUnreachable indicates the network is unreachable (ENETUNREACH, ENETDOWN).
	// No route exists to the destination network.
	ErrNetworkUnreachable = errors.New("sock: network unreachable")

	// ErrHostUnreachable indicates the host is unreachable (EHOSTUNREACH).
	// The specific host cannot be reached, even though the network is reachable.
	ErrHostUnreachable = errors.New("sock: host unreachable")

	// ErrMessageTooLarge indicates the message is too large for the transport (EMSGSIZE).
	// For UDP, this means the datagram exceeds the MTU.
	ErrMessageTooLarge = errors.New("sock: message too large")

	// ErrProtocolNotSupported indicates the protocol is not supported (EPROTONOSUPPORT).
	// For example, SCTP on systems without kernel SCTP support.
	ErrProtocolNotSupported = errors.New("sock: protocol not supported")

	// ErrAddressFamilyNotSupported indicates the address family is not supported (EAFNOSUPPORT).
	// For example, IPv6 on systems without IPv6 support.
	ErrAddressFamilyNotSupported = errors.New("sock: address family not supported")
)

// Errno constants for common error codes.
// These are aliased from zcall for cross-platform compatibility.
const (
	EAGAIN          = uintptr(zcall.EAGAIN)
	EWOULDBLOCK     = uintptr(zcall.EWOULDBLOCK)
	EBADF           = uintptr(zcall.EBADF)
	EINVAL          = uintptr(zcall.EINVAL)
	EINTR           = uintptr(zcall.EINTR)
	ENOMEM          = uintptr(zcall.ENOMEM)
	EACCES          = uintptr(zcall.EACCES)
	EPERM           = uintptr(zcall.EPERM)
	EADDRINUSE      = uintptr(zcall.EADDRINUSE)
	EADDRNOTAVAIL   = uintptr(zcall.EADDRNOTAVAIL)
	ECONNREFUSED    = uintptr(zcall.ECONNREFUSED)
	ECONNRESET      = uintptr(zcall.ECONNRESET)
	ENOTCONN        = uintptr(zcall.ENOTCONN)
	EDESTADDRREQ    = uintptr(zcall.EDESTADDRREQ)
	EMSGSIZE        = uintptr(zcall.EMSGSIZE)
	ETIMEDOUT       = uintptr(zcall.ETIMEDOUT)
	ENETDOWN        = uintptr(zcall.ENETDOWN)
	ENETUNREACH     = uintptr(zcall.ENETUNREACH)
	EHOSTUNREACH    = uintptr(zcall.EHOSTUNREACH)
	ESHUTDOWN       = uintptr(zcall.ESHUTDOWN)
	EINPROGRESS     = uintptr(zcall.EINPROGRESS)
	ECONNABORTED    = uintptr(zcall.ECONNABORTED)
	EALREADY        = uintptr(zcall.EALREADY)
	EISCONN         = uintptr(zcall.EISCONN)
	EPIPE           = uintptr(zcall.EPIPE)
	ENOBUFS         = uintptr(zcall.ENOBUFS)
	EAFNOSUPPORT    = uintptr(zcall.EAFNOSUPPORT)
	EPROTONOSUPPORT = uintptr(zcall.EPROTONOSUPPORT)
)

// errFromErrno converts a zcall errno to a semantic error.
// Error mapping follows the layered semantics:
//   - iox: control flow (EAGAIN → ErrWouldBlock)
//   - iofd: common fd errors (EBADF, EINTR, EINVAL, ENOMEM, EPERM)
//   - sock: socket-specific errors (connection, address, network, protocol)
func errFromErrno(errno uintptr) error {
	if errno == 0 {
		return nil
	}
	switch errno {
	// iox semantic: would block
	case EAGAIN:
		return iox.ErrWouldBlock
	// iofd common errors
	case EBADF:
		return ErrClosed
	case EINVAL:
		return ErrInvalidParam
	case EINTR:
		return ErrInterrupted
	case ENOMEM, ENOBUFS:
		return ErrNoMemory
	case EACCES, EPERM:
		return ErrPermission
	// sock: connection errors
	case ECONNREFUSED:
		return ErrConnectionRefused
	case ECONNRESET, ECONNABORTED, EPIPE, ESHUTDOWN:
		return ErrConnectionReset
	case ENOTCONN, EDESTADDRREQ:
		return ErrNotConnected
	case EINPROGRESS, EALREADY:
		return ErrInProgress
	case EISCONN:
		return nil // Already connected is success for non-blocking connect
	// sock: address errors
	case EADDRINUSE:
		return ErrAddressInUse
	case EADDRNOTAVAIL:
		return ErrAddressNotAvailable
	// sock: network errors
	case ETIMEDOUT:
		return ErrTimedOut
	case ENETDOWN, ENETUNREACH:
		return ErrNetworkUnreachable
	case EHOSTUNREACH:
		return ErrHostUnreachable
	// sock: protocol/message errors
	case EMSGSIZE:
		return ErrMessageTooLarge
	case EAFNOSUPPORT:
		return ErrAddressFamilyNotSupported
	case EPROTONOSUPPORT:
		return ErrProtocolNotSupported
	default:
		return zcall.Errno(errno)
	}
}
