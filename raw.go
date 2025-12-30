// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"net"
	"time"
	"unsafe"

	"code.hybscloud.com/zcall"
)

// RawSocket represents a raw socket for direct IP/ICMP access.
// Raw sockets require CAP_NET_RAW capability.
type RawSocket struct {
	*NetSocket
}

// NewRawSocket4 creates a new IPv4 raw socket for the specified protocol.
// Common protocols: IPPROTO_ICMP, IPPROTO_RAW.
func NewRawSocket4(protocol int) (*RawSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET, SOCK_RAW, protocol)
	if err != nil {
		return nil, err
	}
	return &RawSocket{NetSocket: sock}, nil
}

// NewRawSocket6 creates a new IPv6 raw socket for the specified protocol.
// Common protocols: IPPROTO_ICMPV6, IPPROTO_RAW.
func NewRawSocket6(protocol int) (*RawSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET6, SOCK_RAW, protocol)
	if err != nil {
		return nil, err
	}
	return &RawSocket{NetSocket: sock}, nil
}

// NewICMPSocket4 creates an IPv4 ICMP socket.
func NewICMPSocket4() (*RawSocket, error) {
	return NewRawSocket4(IPPROTO_ICMP)
}

// NewICMPSocket6 creates an IPv6 ICMP socket.
func NewICMPSocket6() (*RawSocket, error) {
	return NewRawSocket6(IPPROTO_ICMPV6)
}

// Protocol returns UnderlyingProtocolRaw.
//
//go:nosplit
func (s *RawSocket) Protocol() UnderlyingProtocol { return UnderlyingProtocolRaw }

// RecvFrom receives a packet and returns the sender's address.
func (s *RawSocket) RecvFrom(buf []byte) (int, *IPAddr, error) {
	raw := s.fd.Raw()
	if raw < 0 {
		return 0, nil, ErrClosed
	}
	var rsa RawSockaddrAny
	rsaLen := uint32(SizeofSockaddrAny)
	n, errno := zcall.Recvfrom(
		uintptr(raw),
		buf,
		0,
		unsafe.Pointer(&rsa),
		unsafe.Pointer(&rsaLen),
	)
	if errno != 0 {
		return int(n), nil, errFromErrno(errno)
	}
	addr := decodeIPAddr(&rsa)
	return int(n), addr, nil
}

// SendTo sends a packet to the specified address.
func (s *RawSocket) SendTo(buf []byte, addr *IPAddr) (int, error) {
	raw := s.fd.Raw()
	if raw < 0 {
		return 0, ErrClosed
	}
	var sa Sockaddr
	if addr.IP.To4() != nil {
		sa = ipAddrToSockaddr4(addr)
	} else {
		sa = ipAddrToSockaddr6(addr)
	}
	ptr, length := sa.Raw()
	n, errno := zcall.Sendto(uintptr(raw), buf, 0, ptr, uintptr(length))
	if errno != 0 {
		return int(n), errFromErrno(errno)
	}
	return int(n), nil
}

// SetIPHeaderIncluded enables or disables IP_HDRINCL.
// When enabled, the user must provide the complete IP header.
func (s *RawSocket) SetIPHeaderIncluded(include bool) error {
	return setSockoptInt(s.fd, SOL_IP, IP_HDRINCL, boolToInt(include))
}

// IP_HDRINCL option
const IP_HDRINCL = 3

// RawConn represents a raw IP connection with adaptive I/O support.
// By default, Read/Write are non-blocking and return iox.ErrWouldBlock immediately.
// When a deadline is set via SetDeadline/SetReadDeadline/SetWriteDeadline,
// operations will retry with backoff until success or deadline exceeded.
type RawConn struct {
	*RawSocket
	laddr    *IPAddr
	raddr    *IPAddr
	deadline deadlineState
}

// LocalAddr returns the local address.
//
//go:nosplit
func (c *RawConn) LocalAddr() Addr { return c.laddr }

// RemoteAddr returns the remote address.
//
//go:nosplit
func (c *RawConn) RemoteAddr() Addr { return c.raddr }

// SetDeadline sets both read and write deadlines.
// A zero value disables the deadline (pure non-blocking mode).
func (c *RawConn) SetDeadline(t time.Time) error {
	c.deadline.setDeadline(t)
	return nil
}

// SetReadDeadline sets the read deadline.
// A zero value disables the deadline (pure non-blocking mode).
func (c *RawConn) SetReadDeadline(t time.Time) error {
	c.deadline.setReadDeadline(t)
	return nil
}

// SetWriteDeadline sets the write deadline.
// A zero value disables the deadline (pure non-blocking mode).
func (c *RawConn) SetWriteDeadline(t time.Time) error {
	c.deadline.setWriteDeadline(t)
	return nil
}

// Read reads data from a connected raw socket with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if not ready.
func (c *RawConn) Read(buf []byte) (int, error) {
	return adaptiveRead(func() (int, error) {
		if c.raddr == nil {
			n, _, err := c.RawSocket.RecvFrom(buf)
			return n, err
		}
		return c.NetSocket.Read(buf)
	}, &c.deadline)
}

// Write writes data to a connected raw socket with adaptive I/O.
// If no deadline is set, returns immediately with iox.ErrWouldBlock if not ready.
func (c *RawConn) Write(buf []byte) (int, error) {
	if c.raddr == nil {
		return 0, ErrNotConnected
	}
	return adaptiveWrite(func() (int, error) {
		return c.NetSocket.Write(buf)
	}, &c.deadline)
}

// RecvFrom receives a packet and returns the sender's address.
func (c *RawConn) RecvFrom(buf []byte) (int, *IPAddr, error) {
	return c.RawSocket.RecvFrom(buf)
}

// SendTo sends a packet to the specified address.
func (c *RawConn) SendTo(buf []byte, addr *IPAddr) (int, error) {
	return c.RawSocket.SendTo(buf, addr)
}

// ListenRaw4 creates an unconnected IPv4 raw socket bound to the local address.
func ListenRaw4(laddr *IPAddr, protocol int) (*RawConn, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewRawSocket4(protocol)
	if err != nil {
		return nil, err
	}
	sa := ipAddrToSockaddr4(laddr)
	if err := sock.Bind(sa); err != nil {
		sock.Close()
		return nil, err
	}
	return &RawConn{RawSocket: sock, laddr: laddr, raddr: nil}, nil
}

// ListenRaw6 creates an unconnected IPv6 raw socket bound to the local address.
func ListenRaw6(laddr *IPAddr, protocol int) (*RawConn, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewRawSocket6(protocol)
	if err != nil {
		return nil, err
	}
	sa := ipAddrToSockaddr6(laddr)
	if err := sock.Bind(sa); err != nil {
		sock.Close()
		return nil, err
	}
	return &RawConn{RawSocket: sock, laddr: laddr, raddr: nil}, nil
}

// ListenRaw creates an unconnected raw socket, auto-detecting IPv4/IPv6.
func ListenRaw(network string, laddr *IPAddr, protocol int) (*RawConn, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	family := networkIPFamily(network, laddr.IP)
	if family == NetworkIPv4 {
		return ListenRaw4(laddr, protocol)
	}
	return ListenRaw6(laddr, protocol)
}

// DialRaw4 initiates a non-blocking connection to an IPv4 raw address.
//
// For raw sockets, connect() sets the default destination address.
// This function returns immediately; ErrInProgress is silently ignored.
func DialRaw4(laddr, raddr *IPAddr, protocol int) (*RawConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewRawSocket4(protocol)
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		sa := ipAddrToSockaddr4(laddr)
		if err := sock.Bind(sa); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := ipAddrToSockaddr4(raddr)
	if err := sock.Connect(sa); err != nil && err != ErrInProgress {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet4, ok := sa.(*SockaddrInet4); ok {
				addr := inet4.Addr()
				actualLaddr = &IPAddr{IP: net.IP(addr[:])}
			}
		}
	}
	return &RawConn{RawSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// DialRaw6 initiates a non-blocking connection to an IPv6 raw address.
//
// For raw sockets, connect() sets the default destination address.
// This function returns immediately; ErrInProgress is silently ignored.
func DialRaw6(laddr, raddr *IPAddr, protocol int) (*RawConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewRawSocket6(protocol)
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		sa := ipAddrToSockaddr6(laddr)
		if err := sock.Bind(sa); err != nil {
			sock.Close()
			return nil, err
		}
	}
	sa := ipAddrToSockaddr6(raddr)
	if err := sock.Connect(sa); err != nil && err != ErrInProgress {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet6, ok := sa.(*SockaddrInet6); ok {
				addr := inet6.Addr()
				actualLaddr = &IPAddr{IP: net.IP(addr[:]), Zone: scopeIDToZone(inet6.ScopeID())}
			}
		}
	}
	return &RawConn{RawSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// DialRaw initiates a non-blocking connection, auto-detecting IPv4/IPv6.
//
// For raw sockets, connect() sets the default destination address.
// This function returns immediately; ErrInProgress is silently ignored.
func DialRaw(network string, laddr, raddr *IPAddr, protocol int) (*RawConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	family := networkIPFamily(network, raddr.IP)
	if family == NetworkIPv4 {
		return DialRaw4(laddr, raddr, protocol)
	}
	return DialRaw6(laddr, raddr, protocol)
}

// Helper functions

func ipAddrToSockaddr4(addr *IPAddr) *SockaddrInet4 {
	var ip [4]byte
	if addr.IP != nil {
		if ip4 := addr.IP.To4(); ip4 != nil {
			copy(ip[:], ip4)
		}
	}
	return NewSockaddrInet4(ip, 0)
}

func ipAddrToSockaddr6(addr *IPAddr) *SockaddrInet6 {
	var ip [16]byte
	if addr.IP != nil {
		if ip6 := addr.IP.To16(); ip6 != nil {
			copy(ip[:], ip6)
		}
	}
	return NewSockaddrInet6(ip, 0, zoneToScopeID(addr.Zone))
}

func decodeIPAddr(raw *RawSockaddrAny) *IPAddr {
	if raw == nil {
		return nil
	}
	switch raw.Addr.Family {
	case AF_INET:
		sa := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		return &IPAddr{IP: net.IP(sa.Addr[:])}
	case AF_INET6:
		sa := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		return &IPAddr{IP: net.IP(sa.Addr[:]), Zone: scopeIDToZone(sa.ScopeID)}
	}
	return nil
}

// Compile-time interface assertions
var (
	_ Socket = (*RawSocket)(nil)
	_ Socket = (*RawConn)(nil)
	_ Conn   = (*RawConn)(nil)
)
