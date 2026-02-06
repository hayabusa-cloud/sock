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
// For stream sockets (SOCK_STREAM, SOCK_SEQPACKET), returns io.EOF on connection close.
// For datagram sockets (SOCK_DGRAM), (0, nil) indicates an empty datagram.
func (c *UnixConn) Read(p []byte) (int, error) {
	n, err := adaptiveRead(func() (int, error) {
		return c.fd.Read(p)
	}, &c.deadline)
	// Convert (0, nil) to (0, io.EOF) for stream protocols
	if n == 0 && err == nil && c.Protocol() != UnderlyingProtocolDgram {
		return 0, io.EOF
	}
	return n, err
}

// Write writes data to the connection with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if not ready.
func (c *UnixConn) Write(p []byte) (int, error) {
	return adaptiveWrite(func() (int, error) {
		return c.fd.Write(p)
	}, &c.deadline)
}

// ReadFrom reads a datagram and returns the sender's address with adaptive I/O.
// For unconnected sockets. If no deadline is set, returns immediately with iox.ErrWouldBlock.
func (c *UnixConn) ReadFrom(buf []byte) (int, Addr, error) {
	var n int
	var addr *UnixAddr
	var err error

	n, err = adaptiveRead(func() (int, error) {
		raw := c.fd.Raw()
		if raw < 0 {
			return 0, ErrClosed
		}
		var rsa RawSockaddrAny
		rsaLen := uint32(SizeofSockaddrAny)
		rn, errno := zcall.Recvfrom(
			uintptr(raw),
			buf,
			0,
			unsafe.Pointer(&rsa),
			unsafe.Pointer(&rsaLen),
		)
		if errno != 0 {
			return int(rn), errFromErrno(errno)
		}
		addr = decodeUnixAddr(&rsa)
		return int(rn), nil
	}, &c.deadline)

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
		sa := unixAddrToSockaddr(unixAddr)
		ptr, length := sa.Raw()
		n, errno := zcall.Sendto(uintptr(raw), buf, 0, ptr, uintptr(length))
		if errno != 0 {
			return int(n), errFromErrno(errno)
		}
		return int(n), nil
	}, &c.deadline)
}

// SyscallConn returns a raw network connection for direct syscall access.
// This implements the syscall.Conn interface.
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
		sock, rawAddr, err := l.NetSocket.Accept()
		if err != nil {
			return nil, err
		}
		raddr := decodeUnixAddr(rawAddr)
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
// network must be "unix", "unixgram", or "unixpacket".
func ListenUnix(network string, laddr *UnixAddr) (*UnixListener, error) {
	if laddr == nil {
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
	return &UnixListener{UnixSocket: sock, laddr: laddr}, nil
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
	return &UnixConn{UnixSocket: sock, laddr: laddr, raddr: nil}, nil
}

// DialUnix initiates a non-blocking connection to a Unix domain socket.
//
// Unlike blocking dialers, this function returns immediately once the connection
// attempt starts. The handshake may still be in progress when this function
// returns (ErrInProgress is silently ignored).
//
// network must be "unix", "unixgram", or "unixpacket".
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
	return &UnixConn{UnixSocket: sock, laddr: laddr, raddr: raddr}, nil
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

func decodeUnixAddr(raw *RawSockaddrAny) *UnixAddr {
	if raw == nil || raw.Addr.Family != AF_UNIX {
		return nil
	}
	su := (*RawSockaddrUnix)(unsafe.Pointer(raw))
	// Find NUL terminator
	var path string
	for i, b := range su.Path {
		if b == 0 {
			path = string(su.Path[:i])
			break
		}
	}
	if path == "" && su.Path[0] != 0 {
		path = string(su.Path[:])
	}
	return &UnixAddr{Name: path, Net: "unix"}
}

// Compile-time interface assertions
var (
	_ Socket     = (*UnixSocket)(nil)
	_ Socket     = (*UnixConn)(nil)
	_ Conn       = (*UnixConn)(nil)
	_ PacketConn = (*UnixConn)(nil)
)
