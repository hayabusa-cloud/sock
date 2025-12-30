// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// SCTPSocket represents an SCTP socket with SOCK_SEQPACKET semantics.
// SCTP provides reliable, message-oriented transport with multi-streaming.
type SCTPSocket struct {
	*NetSocket
}

// NewSCTPSocket4 creates a new IPv4 SCTP socket.
func NewSCTPSocket4() (*SCTPSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET, zcall.SOCK_SEQPACKET, IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}
	if err := applySCTPDefaults(sock.fd); err != nil {
		sock.Close()
		return nil, err
	}
	return &SCTPSocket{NetSocket: sock}, nil
}

// NewSCTPSocket6 creates a new IPv6 SCTP socket.
func NewSCTPSocket6() (*SCTPSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET6, zcall.SOCK_SEQPACKET, IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}
	if err := applySCTPDefaults(sock.fd); err != nil {
		sock.Close()
		return nil, err
	}
	return &SCTPSocket{NetSocket: sock}, nil
}

// NewSCTPStreamSocket4 creates a new IPv4 SCTP stream socket.
func NewSCTPStreamSocket4() (*SCTPSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET, zcall.SOCK_STREAM, IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}
	if err := applySCTPDefaults(sock.fd); err != nil {
		sock.Close()
		return nil, err
	}
	return &SCTPSocket{NetSocket: sock}, nil
}

// NewSCTPStreamSocket6 creates a new IPv6 SCTP stream socket.
func NewSCTPStreamSocket6() (*SCTPSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET6, zcall.SOCK_STREAM, IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}
	if err := applySCTPDefaults(sock.fd); err != nil {
		sock.Close()
		return nil, err
	}
	return &SCTPSocket{NetSocket: sock}, nil
}

// applySCTPDefaults sets socket options for SCTP.
func applySCTPDefaults(fd *iofd.FD) error {
	if err := SetReuseAddr(fd, true); err != nil {
		return err
	}
	if err := SetReusePort(fd, true); err != nil {
		return err
	}
	return nil
}

// Protocol returns the socket type (SOCK_STREAM or SOCK_SEQPACKET).
func (s *SCTPSocket) Protocol() UnderlyingProtocol {
	switch s.typ & 0xF { // Mask off flags
	case SOCK_STREAM:
		return UnderlyingProtocolStream
	case SOCK_SEQPACKET:
		return UnderlyingProtocolSeqPacket
	default:
		return UnderlyingProtocolSeqPacket
	}
}

// SCTPConn represents an SCTP connection with adaptive I/O support.
// By default, Read/Write are non-blocking and return iox.ErrWouldBlock immediately.
// When a deadline is set via SetDeadline/SetReadDeadline/SetWriteDeadline,
// operations will retry with backoff until success or deadline exceeded.
type SCTPConn struct {
	*SCTPSocket
	laddr    *SCTPAddr
	raddr    *SCTPAddr
	deadline deadlineState
}

// LocalAddr returns the local address.
//
//go:nosplit
func (c *SCTPConn) LocalAddr() Addr { return c.laddr }

// RemoteAddr returns the remote address.
//
//go:nosplit
func (c *SCTPConn) RemoteAddr() Addr { return c.raddr }

// SetDeadline sets both read and write deadlines.
// A zero value disables the deadline (pure non-blocking mode).
// When a deadline is set, Read/Write will retry with backoff until
// success or deadline exceeded (returns ErrTimedOut).
func (c *SCTPConn) SetDeadline(t time.Time) error {
	c.deadline.setDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline.
// A zero value disables the deadline (pure non-blocking mode).
func (c *SCTPConn) SetReadDeadline(t time.Time) error {
	c.deadline.setReadDeadline(t)
	return nil
}

// SetWriteDeadline sets the write deadline.
// A zero value disables the deadline (pure non-blocking mode).
func (c *SCTPConn) SetWriteDeadline(t time.Time) error {
	c.deadline.setWriteDeadline(t)
	return nil
}

// Read reads data from the connection with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if not ready.
// If a deadline is set, retries with backoff until success or deadline exceeded.
// Returns io.EOF when the connection is closed.
func (c *SCTPConn) Read(p []byte) (int, error) {
	n, err := adaptiveRead(func() (int, error) {
		return c.fd.Read(p)
	}, &c.deadline)
	if n == 0 && err == nil {
		return 0, io.EOF // Connection closed
	}
	return n, err
}

// Write writes data to the connection with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if not ready.
// If a deadline is set, retries with backoff until success or deadline exceeded.
func (c *SCTPConn) Write(p []byte) (int, error) {
	return adaptiveWrite(func() (int, error) {
		return c.fd.Write(p)
	}, &c.deadline)
}

// SyscallConn returns a raw network connection for direct syscall access.
// This implements the syscall.Conn interface.
func (c *SCTPConn) SyscallConn() (syscall.RawConn, error) {
	if c.fd.Raw() < 0 {
		return nil, ErrClosed
	}
	return newRawConn(c.fd), nil
}

// SCTPListener represents an SCTP listener socket with adaptive Accept support.
// By default, Accept is non-blocking and returns iox.ErrWouldBlock immediately.
// When a deadline is set via SetDeadline, Accept will retry with backoff
// until an association arrives or the deadline is exceeded.
type SCTPListener struct {
	*SCTPSocket
	laddr    *SCTPAddr
	deadline atomic.Int64 // Unix nano timestamp, 0 = no deadline
}

// SetDeadline sets the deadline for Accept operations.
// A zero value disables the deadline (pure non-blocking mode).
func (l *SCTPListener) SetDeadline(t time.Time) error {
	if t.IsZero() {
		l.deadline.Store(0)
	} else {
		l.deadline.Store(t.UnixNano())
	}
	return nil
}

// Accept accepts an incoming SCTP association with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if no association pending.
// If a deadline is set, retries with backoff until success or deadline exceeded.
func (l *SCTPListener) Accept() (*SCTPConn, error) {
	return adaptiveAccept(func() (*SCTPConn, error) {
		sock, rawAddr, err := l.NetSocket.Accept()
		if err != nil {
			return nil, err
		}
		raddr := decodeSCTPAddr(rawAddr)
		conn := &SCTPConn{
			SCTPSocket: &SCTPSocket{NetSocket: sock},
			laddr:      l.laddr,
			raddr:      raddr,
		}
		return conn, nil
	}, l.deadline.Load())
}

// AcceptSocket accepts and returns the underlying Socket interface.
func (l *SCTPListener) AcceptSocket() (Socket, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Addr returns the listener's local address.
//
//go:nosplit
func (l *SCTPListener) Addr() Addr { return l.laddr }

// SCTPDialer provides SCTP connection with configurable timeout.
// By default (zero Timeout), Dial is non-blocking and returns immediately.
// When Timeout is set, Dial retries with backoff until connected or timeout exceeded.
type SCTPDialer struct {
	Timeout time.Duration
}

// SetDialTimeout sets the connection timeout.
// Zero disables the timeout (pure non-blocking mode).
func (d *SCTPDialer) SetDialTimeout(timeout time.Duration) {
	d.Timeout = timeout
}

// Dial4 connects to an IPv4 SCTP address.
// If Timeout is zero, returns immediately (non-blocking, may return ErrInProgress).
// If Timeout is set, retries with backoff until connected or ErrTimedOut.
func (d *SCTPDialer) Dial4(laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewSCTPSocket4()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		sa := sctpAddrToSockaddr4(laddr)
		if err := sock.Bind(sa); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := sctpAddrToSockaddr4(raddr)
	err = adaptiveConnect(sock.NetSocket, sa, d.Timeout)
	if err != nil {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet4, ok := sa.(*SockaddrInet4); ok {
				addr := inet4.Addr()
				actualLaddr = &SCTPAddr{IP: net.IP(addr[:]), Port: int(inet4.Port())}
			}
		}
	}
	return &SCTPConn{SCTPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// Dial6 connects to an IPv6 SCTP address.
// If Timeout is zero, returns immediately (non-blocking, may return ErrInProgress).
// If Timeout is set, retries with backoff until connected or ErrTimedOut.
func (d *SCTPDialer) Dial6(laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewSCTPSocket6()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		sa := sctpAddrToSockaddr6(laddr)
		if err := sock.Bind(sa); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := sctpAddrToSockaddr6(raddr)
	err = adaptiveConnect(sock.NetSocket, sa, d.Timeout)
	if err != nil {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet6, ok := sa.(*SockaddrInet6); ok {
				addr := inet6.Addr()
				actualLaddr = &SCTPAddr{IP: net.IP(addr[:]), Port: int(inet6.Port())}
			}
		}
	}
	return &SCTPConn{SCTPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// Dial connects to an SCTP address, auto-detecting IPv4/IPv6.
// If Timeout is zero, returns immediately (non-blocking, may return ErrInProgress).
// If Timeout is set, retries with backoff until connected or ErrTimedOut.
func (d *SCTPDialer) Dial(network string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	family := networkIPFamily(network, raddr.IP)
	if family == NetworkIPv4 {
		return d.Dial4(laddr, raddr)
	}
	return d.Dial6(laddr, raddr)
}

// ListenSCTP4 creates an SCTP listener on an IPv4 address.
func ListenSCTP4(laddr *SCTPAddr) (*SCTPListener, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewSCTPSocket4()
	if err != nil {
		return nil, err
	}
	sa := sctpAddrToSockaddr4(laddr)
	if err := sock.Bind(sa); err != nil {
		sock.Close()
		return nil, err
	}
	if err := sock.Listen(DefaultBacklog); err != nil {
		sock.Close()
		return nil, err
	}
	// Query actual bound address (handles port 0 → ephemeral port)
	actualLaddr := laddr
	if sa, err := GetSockname(sock.fd); err == nil {
		if inet4, ok := sa.(*SockaddrInet4); ok {
			addr := inet4.Addr()
			actualLaddr = &SCTPAddr{IP: net.IP(addr[:]), Port: int(inet4.Port())}
		}
	}
	return &SCTPListener{SCTPSocket: sock, laddr: actualLaddr}, nil
}

// ListenSCTP6 creates an SCTP listener on an IPv6 address.
func ListenSCTP6(laddr *SCTPAddr) (*SCTPListener, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewSCTPSocket6()
	if err != nil {
		return nil, err
	}
	sa := sctpAddrToSockaddr6(laddr)
	if err := sock.Bind(sa); err != nil {
		sock.Close()
		return nil, err
	}
	if err := sock.Listen(DefaultBacklog); err != nil {
		sock.Close()
		return nil, err
	}
	// Query actual bound address (handles port 0 → ephemeral port)
	actualLaddr := laddr
	if sa, err := GetSockname(sock.fd); err == nil {
		if inet6, ok := sa.(*SockaddrInet6); ok {
			addr := inet6.Addr()
			actualLaddr = &SCTPAddr{IP: net.IP(addr[:]), Port: int(inet6.Port()), Zone: scopeIDToZone(inet6.ScopeID())}
		}
	}
	return &SCTPListener{SCTPSocket: sock, laddr: actualLaddr}, nil
}

// ListenSCTP creates an SCTP listener, auto-detecting IPv4/IPv6.
func ListenSCTP(network string, laddr *SCTPAddr) (*SCTPListener, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	family := networkIPFamily(network, laddr.IP)
	if family == NetworkIPv4 {
		return ListenSCTP4(laddr)
	}
	return ListenSCTP6(laddr)
}

// DialSCTP4 initiates a non-blocking SCTP connection to an IPv4 address.
//
// Unlike blocking dialers, this function returns immediately once the connection
// attempt starts. The SCTP handshake may still be in progress when this
// function returns (ErrInProgress is silently ignored).
//
// To wait for connection completion, use SCTPDialer with a timeout set.
func DialSCTP4(laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewSCTPSocket4()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		sa := sctpAddrToSockaddr4(laddr)
		if err := sock.Bind(sa); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := sctpAddrToSockaddr4(raddr)
	if err := sock.Connect(sa); err != nil && err != ErrInProgress {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet4, ok := sa.(*SockaddrInet4); ok {
				addr := inet4.Addr()
				actualLaddr = &SCTPAddr{IP: net.IP(addr[:]), Port: int(inet4.Port())}
			}
		}
	}
	return &SCTPConn{SCTPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// DialSCTP6 initiates a non-blocking SCTP connection to an IPv6 address.
//
// Unlike blocking dialers, this function returns immediately once the connection
// attempt starts. The SCTP handshake may still be in progress when this
// function returns (ErrInProgress is silently ignored).
//
// To wait for connection completion, use SCTPDialer with a timeout set.
func DialSCTP6(laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewSCTPSocket6()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		sa := sctpAddrToSockaddr6(laddr)
		if err := sock.Bind(sa); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := sctpAddrToSockaddr6(raddr)
	if err := sock.Connect(sa); err != nil && err != ErrInProgress {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet6, ok := sa.(*SockaddrInet6); ok {
				addr := inet6.Addr()
				actualLaddr = &SCTPAddr{IP: net.IP(addr[:]), Port: int(inet6.Port())}
			}
		}
	}
	return &SCTPConn{SCTPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// DialSCTP initiates a non-blocking SCTP connection, auto-detecting IPv4/IPv6.
//
// Unlike blocking dialers, this function returns immediately once the connection
// attempt starts. The SCTP handshake may still be in progress when this
// function returns (ErrInProgress is silently ignored).
//
// To wait for connection completion, use SCTPDialer with a timeout set.
func DialSCTP(network string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	family := networkIPFamily(network, raddr.IP)
	if family == NetworkIPv4 {
		return DialSCTP4(laddr, raddr)
	}
	return DialSCTP6(laddr, raddr)
}

// Helper functions

func sctpAddrToSockaddr4(addr *SCTPAddr) *SockaddrInet4 {
	var ip [4]byte
	if addr.IP != nil {
		if ip4 := addr.IP.To4(); ip4 != nil {
			copy(ip[:], ip4)
		}
	}
	return NewSockaddrInet4(ip, uint16(addr.Port))
}

func sctpAddrToSockaddr6(addr *SCTPAddr) *SockaddrInet6 {
	var ip [16]byte
	if addr.IP != nil {
		if ip6 := addr.IP.To16(); ip6 != nil {
			copy(ip[:], ip6)
		}
	}
	return NewSockaddrInet6(ip, uint16(addr.Port), zoneToScopeID(addr.Zone))
}

func decodeSCTPAddr(raw *RawSockaddrAny) *SCTPAddr {
	if raw == nil {
		return nil
	}
	switch raw.Addr.Family {
	case AF_INET:
		sa := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		return &SCTPAddr{
			IP:   net.IP(sa.Addr[:]),
			Port: int(ntohs(sa.Port)),
		}
	case AF_INET6:
		sa := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		return &SCTPAddr{
			IP:   net.IP(sa.Addr[:]),
			Port: int(ntohs(sa.Port)),
			Zone: scopeIDToZone(sa.ScopeID),
		}
	}
	return nil
}

// Compile-time interface assertions
var (
	_ Socket = (*SCTPSocket)(nil)
	_ Socket = (*SCTPConn)(nil)
	_ Conn   = (*SCTPConn)(nil)
)
