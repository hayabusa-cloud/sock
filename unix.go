// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock

import (
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"code.hybscloud.com/zcall"
)

// UnixSocket represents a Unix domain socket.
type UnixSocket struct {
	*NetSocket
}

// NewUnixStreamSocket creates a new Unix stream socket (SOCK_STREAM).
func NewUnixStreamSocket() (*UnixSocket, error) {
	sock, err := NewNetSocket(zcall.AF_UNIX, zcall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	return &UnixSocket{NetSocket: sock}, nil
}

// NewUnixDatagramSocket creates a new Unix datagram socket (SOCK_DGRAM).
func NewUnixDatagramSocket() (*UnixSocket, error) {
	sock, err := NewNetSocket(zcall.AF_UNIX, zcall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	return &UnixSocket{NetSocket: sock}, nil
}

// NewUnixSeqpacketSocket creates a new Unix seqpacket socket (SOCK_SEQPACKET).
func NewUnixSeqpacketSocket() (*UnixSocket, error) {
	sock, err := NewNetSocket(zcall.AF_UNIX, SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, err
	}
	return &UnixSocket{NetSocket: sock}, nil
}

// Protocol returns the socket protocol.
func (s *UnixSocket) Protocol() UnderlyingProtocol {
	switch s.typ & 0xF { // Mask off flags
	case SOCK_STREAM:
		return UnderlyingProtocolStream
	case SOCK_DGRAM:
		return UnderlyingProtocolDgram
	case SOCK_SEQPACKET:
		return UnderlyingProtocolSeqPacket
	default:
		return UnderlyingProtocolStream
	}
}

func unixSocketNetwork(typ int) string {
	switch typ & 0xF {
	case SOCK_STREAM:
		return "unix"
	case SOCK_DGRAM:
		return "unixgram"
	case SOCK_SEQPACKET:
		return "unixpacket"
	default:
		return "unix"
	}
}

// UnixAddr represents a Unix domain socket address.
type UnixAddr = net.UnixAddr

// UnixConn represents a Unix domain socket connection with adaptive I/O.
// By default, Read/Write/ReadFrom/WriteTo are non-blocking and return iox.ErrWouldBlock.
// When a deadline is set, operations will retry with backoff until success or timeout.
type UnixConn struct {
	*UnixSocket
	laddr    *UnixAddr
	raddr    *UnixAddr
	deadline deadlineState
}

// LocalAddr returns the local address.
//
//go:nosplit
func (c *UnixConn) LocalAddr() Addr { return c.laddr }

// RemoteAddr returns the remote address.
//
//go:nosplit
func (c *UnixConn) RemoteAddr() Addr { return c.raddr }

// SetDeadline sets both read and write deadlines.
// A zero value disables the deadline (pure non-blocking mode).
func (c *UnixConn) SetDeadline(t time.Time) error {
	c.deadline.setDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline.
// A zero value disables the deadline (pure non-blocking mode).
func (c *UnixConn) SetReadDeadline(t time.Time) error {
	c.deadline.setReadDeadline(t)
	return nil
}

// SetWriteDeadline sets the write deadline.
// A zero value disables the deadline (pure non-blocking mode).
func (c *UnixConn) SetWriteDeadline(t time.Time) error {
	c.deadline.setWriteDeadline(t)
	return nil
}

// Read reads data from the connection with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if not ready.
// For stream sockets (SOCK_STREAM), returns io.EOF on connection close.
// For datagram and seqpacket sockets, an empty p discards one queued message.
// Receiving an empty message returns (0, nil).
func (c *UnixConn) Read(p []byte) (int, error) {
	n, err := adaptiveRead(func() (int, error) {
		return c.NetSocket.Read(p)
	}, &c.deadline)
	// Convert (0, nil) to (0, io.EOF) for stream protocols
	if n == 0 && err == nil && c.Protocol() == UnderlyingProtocolStream {
		return 0, io.EOF
	}
	return n, err
}

// Write writes data to the connection with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if not ready.
// On datagram and seqpacket sockets, an empty p sends an empty message.
func (c *UnixConn) Write(p []byte) (int, error) {
	return adaptiveWrite(func() (int, error) {
		return c.NetSocket.Write(p)
	}, &c.deadline)
}

// ReadFrom reads a datagram and returns the sender's address with adaptive I/O.
// A datagram from an unnamed sender has a nil source address.
// For unconnected sockets. If no deadline is set, returns immediately with iox.ErrWouldBlock.
func (c *UnixConn) ReadFrom(buf []byte) (int, Addr, error) {
	var addr *UnixAddr
	n, err := adaptiveRead(func() (int, error) {
		var rsa RawSockaddrAny
		rsaLen := uint32(SizeofSockaddrAny)
		n, err := c.recvFrom(buf, unsafe.Pointer(&rsa), &rsaLen)
		if err != nil {
			return 0, err
		}
		addr = decodeUnixAddr(&rsa, rsaLen, unixSocketNetwork(c.typ))
		return n, nil
	}, &c.deadline)
	if addr == nil || addr.Name == "" {
		return n, nil, err
	}
	return n, addr, err
}

// WriteTo writes a datagram to the specified address with adaptive I/O.
// For unconnected sockets. If no deadline is set, returns immediately with iox.ErrWouldBlock.
func (c *UnixConn) WriteTo(buf []byte, addr Addr) (int, error) {
	unixAddr, ok := addr.(*UnixAddr)
	if !ok {
		return 0, ErrInvalidParam
	}
	return adaptiveWrite(func() (int, error) {
		raw := c.fd.Raw()
		if raw < 0 {
			return 0, ErrClosed
		}
		if unixAddr.Net != unixSocketNetwork(c.typ) {
			return 0, ErrAddressFamilyNotSupported
		}
		sa := unixAddrToSockaddr(unixAddr)
		ptr, length := sa.Raw()
		return socketIOResult(zcall.Sendto(uintptr(raw), buf, 0, ptr, uintptr(length)))
	}, &c.deadline)
}

// SyscallConn returns a raw handle that borrows c's descriptor.
// Keep c open through each Control, Read, or Write call. Use the descriptor
// number passed to a callback only within that callback.
func (c *UnixConn) SyscallConn() (syscall.RawConn, error) {
	if c.fd.Raw() < 0 {
		return nil, ErrClosed
	}
	return newRawConn(c.fd), nil
}

// UnixListener represents a Unix domain socket listener with adaptive Accept support.
// By default, Accept is non-blocking and returns iox.ErrWouldBlock immediately.
// When a deadline is set via SetDeadline, Accept will retry with backoff
// until a connection arrives or the deadline is exceeded.
type UnixListener struct {
	*UnixSocket
	laddr    *UnixAddr
	deadline atomic.Int64 // Unix nano timestamp, 0 = no deadline
}

// SetDeadline sets the deadline for Accept operations.
// A zero value disables the deadline (pure non-blocking mode).
func (l *UnixListener) SetDeadline(t time.Time) error {
	if t.IsZero() {
		l.deadline.Store(0)
	} else {
		l.deadline.Store(t.UnixNano())
	}
	return nil
}

// Accept accepts an incoming connection with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if no connection pending.
// If a deadline is set, retries with backoff until success or deadline exceeded.
func (l *UnixListener) Accept() (*UnixConn, error) {
	return adaptiveAccept(func() (*UnixConn, error) {
		sock, rawAddr, addrlen, err := l.NetSocket.Accept()
		if err != nil {
			return nil, err
		}
		raddr := decodeUnixAddr(rawAddr, addrlen, unixSocketNetwork(sock.typ))
		conn := &UnixConn{
			UnixSocket: &UnixSocket{NetSocket: sock},
			laddr:      l.laddr,
			raddr:      raddr,
		}
		return conn, nil
	}, l.deadline.Load())
}

// AcceptSocket accepts and returns the underlying Socket interface.
func (l *UnixListener) AcceptSocket() (Socket, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Addr returns the listener's local address.
//
//go:nosplit
func (l *UnixListener) Addr() Addr { return l.laddr }

// ListenUnix creates a Unix domain socket listener.
// network must be "unix" or "unixpacket". Use ListenUnixgram for "unixgram".
func ListenUnix(network string, laddr *UnixAddr) (*UnixListener, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	var sock *UnixSocket
	var err error
	switch network {
	case "unix":
		sock, err = NewUnixStreamSocket()
	case "unixpacket":
		sock, err = NewUnixSeqpacketSocket()
	default:
		return nil, UnknownNetworkError(network)
	}
	if err != nil {
		return nil, err
	}
	sa := unixAddrToSockaddr(laddr)
	if err := sock.Bind(sa); err != nil {
		sock.Close()
		return nil, err
	}
	if network == "unix" || network == "unixpacket" {
		if err := sock.Listen(DefaultBacklog); err != nil {
			sock.Close()
			return nil, err
		}
	}
	actualLaddr := laddr
	if laddr.Name == "" {
		if sa, err := GetSockname(sock.fd); err == nil {
			if unixSa := SockaddrToUnixAddr(sa, network); unixSa != nil {
				actualLaddr = unixSa
			}
		}
	}
	return &UnixListener{UnixSocket: sock, laddr: actualLaddr}, nil
}

// ListenUnixgram creates a Unix datagram socket bound to laddr.
func ListenUnixgram(network string, laddr *UnixAddr) (*UnixConn, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	if network != "unixgram" {
		return nil, UnknownNetworkError(network)
	}
	sock, err := NewUnixDatagramSocket()
	if err != nil {
		return nil, err
	}
	sa := unixAddrToSockaddr(laddr)
	if err := sock.Bind(sa); err != nil {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if laddr.Name == "" {
		if sa, err := GetSockname(sock.fd); err == nil {
			if unixSa := SockaddrToUnixAddr(sa, network); unixSa != nil {
				actualLaddr = unixSa
			}
		}
	}
	return &UnixConn{UnixSocket: sock, laddr: actualLaddr, raddr: nil}, nil
}

// DialUnix starts a non-blocking connection on "unix", "unixgram", or "unixpacket".
// If the kernel starts an asynchronous connect, the handshake may still be
// in progress on return. On Linux, a full stream or sequenced-packet accept
// queue makes DialUnix return (nil, iox.ErrWouldBlock). Retry the dial after
// the listener accepts a connection. To keep a local pathname bound across
// retries, bind a UnixSocket and retry Connect on that socket.
func DialUnix(network string, laddr, raddr *UnixAddr) (*UnixConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	var sock *UnixSocket
	var err error
	switch network {
	case "unix":
		sock, err = NewUnixStreamSocket()
	case "unixgram":
		sock, err = NewUnixDatagramSocket()
	case "unixpacket":
		sock, err = NewUnixSeqpacketSocket()
	default:
		return nil, UnknownNetworkError(network)
	}
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		sa := unixAddrToSockaddr(laddr)
		if err := sock.Bind(sa); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := unixAddrToSockaddr(raddr)
	if err := sock.Connect(sa); err != nil && err != ErrInProgress {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if laddr != nil && laddr.Name == "" {
		if sa, err := GetSockname(sock.fd); err == nil {
			if unixSa := SockaddrToUnixAddr(sa, network); unixSa != nil {
				actualLaddr = unixSa
			}
		}
	}
	return &UnixConn{UnixSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// UnixConnPair creates a pair of connected Unix domain sockets.
// network must be "unix", "unixgram", or "unixpacket".
func UnixConnPair(network string) ([2]*UnixConn, error) {
	var typ int
	switch network {
	case "unix":
		typ = SOCK_STREAM
	case "unixgram":
		typ = SOCK_DGRAM
	case "unixpacket":
		typ = SOCK_SEQPACKET
	default:
		return [2]*UnixConn{}, UnknownNetworkError(network)
	}
	socks, err := NetSocketPair(zcall.AF_UNIX, typ, 0)
	if err != nil {
		return [2]*UnixConn{}, err
	}
	return [2]*UnixConn{
		{UnixSocket: &UnixSocket{NetSocket: socks[0]}},
		{UnixSocket: &UnixSocket{NetSocket: socks[1]}},
	}, nil
}

// Helper functions

func unixAddrToSockaddr(addr *UnixAddr) *SockaddrUnix {
	return NewSockaddrUnix(addr.Name)
}

func decodeUnixAddr(raw *RawSockaddrAny, addrlen uint32, network string) *UnixAddr {
	if raw == nil || raw.Addr.Family != AF_UNIX {
		return nil
	}
	su := (*RawSockaddrUnix)(unsafe.Pointer(raw))
	return &UnixAddr{Name: unixSockaddrPath(su, addrlen), Net: network}
}

// Compile-time interface assertions
var (
	_ Socket     = (*UnixSocket)(nil)
	_ Socket     = (*UnixConn)(nil)
	_ Conn       = (*UnixConn)(nil)
	_ PacketConn = (*UnixConn)(nil)
)
