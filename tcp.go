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

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// TCPSocket represents a TCP socket with SO_REUSEADDR and SO_REUSEPORT.
type TCPSocket struct {
	*NetSocket
}

// NewTCPSocket4 creates a new IPv4 TCP socket with SO_REUSEADDR, SO_REUSEPORT, and SO_ZEROCOPY.
func NewTCPSocket4() (*TCPSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET, zcall.SOCK_STREAM, zcall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	if err := applyTCPDefaults(sock.fd); err != nil {
		sock.Close()
		return nil, err
	}
	return &TCPSocket{NetSocket: sock}, nil
}

// NewTCPSocket6 creates a new IPv6 TCP socket with SO_REUSEADDR, SO_REUSEPORT, and SO_ZEROCOPY.
func NewTCPSocket6() (*TCPSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET6, zcall.SOCK_STREAM, zcall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	if err := applyTCPDefaults(sock.fd); err != nil {
		sock.Close()
		return nil, err
	}
	return &TCPSocket{NetSocket: sock}, nil
}

func applyTCPDefaults(fd *iofd.FD) error {
	if err := SetReuseAddr(fd, true); err != nil {
		return err
	}
	if err := SetReusePort(fd, true); err != nil {
		return err
	}
	_ = SetZeroCopy(fd, true)
	return nil
}

//go:nosplit
func (s *TCPSocket) Protocol() UnderlyingProtocol { return UnderlyingProtocolStream }

// TCPConn represents a TCP connection.
type TCPConn struct {
	*TCPSocket
	laddr    *TCPAddr
	raddr    *TCPAddr
	deadline deadlineState
}

//go:nosplit
func (c *TCPConn) LocalAddr() Addr { return c.laddr }

//go:nosplit
func (c *TCPConn) RemoteAddr() Addr { return c.raddr }

func (c *TCPConn) SetDeadline(t time.Time) error {
	c.deadline.setDeadline(t)
	return nil
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	c.deadline.setReadDeadline(t)
	return nil
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	c.deadline.setWriteDeadline(t)
	return nil
}

func (c *TCPConn) Read(p []byte) (int, error) {
	n, err := adaptiveRead(func() (int, error) { return c.fd.Read(p) }, &c.deadline)
	if n == 0 && err == nil {
		return 0, io.EOF // Stream closed
	}
	return n, err
}

func (c *TCPConn) Write(p []byte) (int, error) {
	return adaptiveWrite(func() (int, error) { return c.fd.Write(p) }, &c.deadline)
}

func (c *TCPConn) SetNoDelay(noDelay bool) error     { return SetTCPNoDelay(c.fd, noDelay) }
func (c *TCPConn) SetKeepAlive(keepalive bool) error { return SetKeepAlive(c.fd, keepalive) }

func (c *TCPConn) SetKeepAlivePeriod(d time.Duration) error {
	secs := int(d.Seconds())
	if secs == 0 {
		secs = 1
	}
	if err := SetTCPKeepIdle(c.fd, secs); err != nil {
		return err
	}
	return SetTCPKeepIntvl(c.fd, secs)
}

// SyscallConn returns a raw network connection for direct syscall access.
// This implements the syscall.Conn interface.
func (c *TCPConn) SyscallConn() (syscall.RawConn, error) {
	if c.fd.Raw() < 0 {
		return nil, ErrClosed
	}
	return newRawConn(c.fd), nil
}

// TCPListener represents a TCP listener socket.
type TCPListener struct {
	*TCPSocket
	laddr    *TCPAddr
	deadline atomic.Int64
}

func (l *TCPListener) SetDeadline(t time.Time) error {
	if t.IsZero() {
		l.deadline.Store(0)
	} else {
		l.deadline.Store(t.UnixNano())
	}
	return nil
}

func (l *TCPListener) Accept() (*TCPConn, error) {
	return adaptiveAccept(func() (*TCPConn, error) {
		sock, rawAddr, err := l.NetSocket.Accept()
		if err != nil {
			return nil, err
		}
		return &TCPConn{
			TCPSocket: &TCPSocket{NetSocket: sock},
			laddr:     l.laddr,
			raddr:     decodeTCPAddr(rawAddr),
		}, nil
	}, l.deadline.Load())
}

func (l *TCPListener) AcceptSocket() (Socket, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

//go:nosplit
func (l *TCPListener) Addr() Addr { return l.laddr }

// TCPDialer provides TCP connection with configurable timeout.
// By default (zero Timeout), Dial is non-blocking and returns immediately.
// When Timeout is set, Dial retries with backoff until connected or timeout exceeded.
type TCPDialer struct {
	Timeout time.Duration
}

// SetDialTimeout sets the connection timeout.
// Zero disables the timeout (pure non-blocking mode).
func (d *TCPDialer) SetDialTimeout(timeout time.Duration) {
	d.Timeout = timeout
}

// Dial4 connects to an IPv4 TCP address.
// If Timeout is zero, returns immediately (non-blocking, may return ErrInProgress).
// If Timeout is set, retries with backoff until connected or ErrTimedOut.
func (d *TCPDialer) Dial4(laddr, raddr *TCPAddr) (*TCPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewTCPSocket4()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		if err := sock.Bind(tcpAddrToSockaddr4(laddr)); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := tcpAddrToSockaddr4(raddr)
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
				actualLaddr = &TCPAddr{IP: net.IP(addr[:]), Port: int(inet4.Port())}
			}
		}
	}
	return &TCPConn{TCPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// Dial6 connects to an IPv6 TCP address.
// If Timeout is zero, returns immediately (non-blocking, may return ErrInProgress).
// If Timeout is set, retries with backoff until connected or ErrTimedOut.
func (d *TCPDialer) Dial6(laddr, raddr *TCPAddr) (*TCPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewTCPSocket6()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		if err := sock.Bind(tcpAddrToSockaddr6(laddr)); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := tcpAddrToSockaddr6(raddr)
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
				actualLaddr = &TCPAddr{IP: net.IP(addr[:]), Port: int(inet6.Port())}
			}
		}
	}
	return &TCPConn{TCPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// Dial connects to a TCP address, auto-detecting IPv4/IPv6.
// If Timeout is zero, returns immediately (non-blocking, may return ErrInProgress).
// If Timeout is set, retries with backoff until connected or ErrTimedOut.
func (d *TCPDialer) Dial(network string, laddr, raddr *TCPAddr) (*TCPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	if networkIPFamily(network, raddr.IP) == NetworkIPv4 {
		return d.Dial4(laddr, raddr)
	}
	return d.Dial6(laddr, raddr)
}

// ListenTCP4 creates a TCP listener on an IPv4 address.
// Returns ErrInvalidParam if laddr is nil.
func ListenTCP4(laddr *TCPAddr) (*TCPListener, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewTCPSocket4()
	if err != nil {
		return nil, err
	}
	if err := sock.Bind(tcpAddrToSockaddr4(laddr)); err != nil {
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
			actualLaddr = &TCPAddr{IP: net.IP(addr[:]), Port: int(inet4.Port())}
		}
	}
	return &TCPListener{TCPSocket: sock, laddr: actualLaddr}, nil
}

// ListenTCP6 creates a TCP listener on an IPv6 address.
// Returns ErrInvalidParam if laddr is nil.
func ListenTCP6(laddr *TCPAddr) (*TCPListener, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewTCPSocket6()
	if err != nil {
		return nil, err
	}
	if err := sock.Bind(tcpAddrToSockaddr6(laddr)); err != nil {
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
			actualLaddr = &TCPAddr{IP: net.IP(addr[:]), Port: int(inet6.Port()), Zone: scopeIDToZone(inet6.ScopeID())}
		}
	}
	return &TCPListener{TCPSocket: sock, laddr: actualLaddr}, nil
}

// ListenTCP creates a TCP listener, auto-detecting IPv4/IPv6 based on network and address.
// Returns ErrInvalidParam if laddr is nil.
func ListenTCP(network string, laddr *TCPAddr) (*TCPListener, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	if networkIPFamily(network, laddr.IP) == NetworkIPv4 {
		return ListenTCP4(laddr)
	}
	return ListenTCP6(laddr)
}

// DialTCP4 initiates a non-blocking TCP connection to an IPv4 address.
//
// Unlike net.Dial, this function returns immediately once the connection
// attempt starts. The TCP handshake may still be in progress when this
// function returns (ErrInProgress is silently ignored).
//
// To wait for connection completion, use TCPDialer with a timeout set.
//
// If laddr is nil, the system chooses a local address.
// Returns ErrInvalidParam if raddr is nil.
func DialTCP4(laddr, raddr *TCPAddr) (*TCPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewTCPSocket4()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		if err := sock.Bind(tcpAddrToSockaddr4(laddr)); err != nil {
			sock.Close()
			return nil, err
		}
	}
	if err := sock.Connect(tcpAddrToSockaddr4(raddr)); err != nil && err != ErrInProgress {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet4, ok := sa.(*SockaddrInet4); ok {
				addr := inet4.Addr()
				actualLaddr = &TCPAddr{IP: net.IP(addr[:]), Port: int(inet4.Port())}
			}
		}
	}
	return &TCPConn{TCPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// DialTCP6 initiates a non-blocking TCP connection to an IPv6 address.
//
// Unlike net.Dial, this function returns immediately once the connection
// attempt starts. The TCP handshake may still be in progress when this
// function returns (ErrInProgress is silently ignored).
//
// To wait for connection completion, use TCPDialer with a timeout set.
//
// If laddr is nil, the system chooses a local address.
// Returns ErrInvalidParam if raddr is nil.
func DialTCP6(laddr, raddr *TCPAddr) (*TCPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewTCPSocket6()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		if err := sock.Bind(tcpAddrToSockaddr6(laddr)); err != nil {
			sock.Close()
			return nil, err
		}
	}
	if err := sock.Connect(tcpAddrToSockaddr6(raddr)); err != nil && err != ErrInProgress {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet6, ok := sa.(*SockaddrInet6); ok {
				addr := inet6.Addr()
				actualLaddr = &TCPAddr{IP: net.IP(addr[:]), Port: int(inet6.Port())}
			}
		}
	}
	return &TCPConn{TCPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// DialTCP initiates a non-blocking TCP connection, auto-detecting IPv4/IPv6.
//
// Unlike net.Dial, this function returns immediately once the connection
// attempt starts. The TCP handshake may still be in progress when this
// function returns (ErrInProgress is silently ignored).
//
// To wait for connection completion, use TCPDialer with a timeout set.
//
// If laddr is nil, the system chooses a local address.
// Returns ErrInvalidParam if raddr is nil.
func DialTCP(network string, laddr, raddr *TCPAddr) (*TCPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	if networkIPFamily(network, raddr.IP) == NetworkIPv4 {
		return DialTCP4(laddr, raddr)
	}
	return DialTCP6(laddr, raddr)
}

// tcpAddrToSockaddr4 converts a TCPAddr to a SockaddrInet4.
// If addr.IP is nil or not an IPv4 address, the result contains a zero IP.
// This is an internal helper for zero-allocation address conversion.
func tcpAddrToSockaddr4(addr *TCPAddr) *SockaddrInet4 {
	var ip [4]byte
	if addr.IP != nil {
		if ip4 := addr.IP.To4(); ip4 != nil {
			copy(ip[:], ip4)
		}
	}
	return NewSockaddrInet4(ip, uint16(addr.Port))
}

// tcpAddrToSockaddr6 converts a TCPAddr to a SockaddrInet6.
// If addr.IP is nil, the result contains a zero IP.
// The Zone field is converted to a numeric scope ID via zoneToScopeID.
// This is an internal helper for zero-allocation address conversion.
func tcpAddrToSockaddr6(addr *TCPAddr) *SockaddrInet6 {
	var ip [16]byte
	if addr.IP != nil {
		if ip6 := addr.IP.To16(); ip6 != nil {
			copy(ip[:], ip6)
		}
	}
	return NewSockaddrInet6(ip, uint16(addr.Port), zoneToScopeID(addr.Zone))
}

// decodeTCPAddr converts a raw kernel sockaddr to a TCPAddr.
// Returns nil if raw is nil or has an unsupported address family.
// Supports AF_INET and AF_INET6. This is an internal helper for
// decoding addresses returned from accept(2) and getsockname(2).
func decodeTCPAddr(raw *RawSockaddrAny) *TCPAddr {
	if raw == nil {
		return nil
	}
	switch raw.Addr.Family {
	case AF_INET:
		sa := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		return &TCPAddr{IP: net.IP(sa.Addr[:]), Port: int(ntohs(sa.Port))}
	case AF_INET6:
		sa := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		return &TCPAddr{IP: net.IP(sa.Addr[:]), Port: int(ntohs(sa.Port)), Zone: scopeIDToZone(sa.ScopeID)}
	}
	return nil
}

var (
	_ Socket = (*TCPSocket)(nil)
	_ Socket = (*TCPConn)(nil)
	_ Conn   = (*TCPConn)(nil)
)
