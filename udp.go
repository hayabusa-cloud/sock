// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock

import (
	"net"
	"syscall"
	"time"
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// UDPSocket represents a UDP socket.
type UDPSocket struct {
	*NetSocket
}

// NewUDPSocket4 creates a new IPv4 UDP socket with SO_REUSEADDR, SO_REUSEPORT, and SO_ZEROCOPY.
func NewUDPSocket4() (*UDPSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	if err := applyUDPDefaults(sock.fd); err != nil {
		sock.Close()
		return nil, err
	}
	return &UDPSocket{NetSocket: sock}, nil
}

// NewUDPSocket6 creates a new IPv6 UDP socket with SO_REUSEADDR, SO_REUSEPORT, and SO_ZEROCOPY.
func NewUDPSocket6() (*UDPSocket, error) {
	sock, err := NewNetSocket(zcall.AF_INET6, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	if err := applyUDPDefaults(sock.fd); err != nil {
		sock.Close()
		return nil, err
	}
	return &UDPSocket{NetSocket: sock}, nil
}

func applyUDPDefaults(fd *iofd.FD) error {
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
func (s *UDPSocket) Protocol() UnderlyingProtocol { return UnderlyingProtocolDgram }

func (s *UDPSocket) RecvFrom(buf []byte) (int, *UDPAddr, error) {
	raw := s.fd.Raw()
	if raw < 0 {
		return 0, nil, ErrClosed
	}
	var rsa RawSockaddrAny
	rsaLen := uint32(SizeofSockaddrAny)
	n, errno := zcall.Recvfrom(uintptr(raw), buf, 0, unsafe.Pointer(&rsa), unsafe.Pointer(&rsaLen))
	if errno != 0 {
		return int(n), nil, errFromErrno(errno)
	}
	return int(n), decodeUDPAddr(&rsa), nil
}

func (s *UDPSocket) SendTo(buf []byte, addr *UDPAddr) (int, error) {
	raw := s.fd.Raw()
	if raw < 0 {
		return 0, ErrClosed
	}
	var sa Sockaddr
	if addr.IP.To4() != nil {
		sa = udpAddrToSockaddr4(addr)
	} else {
		sa = udpAddrToSockaddr6(addr)
	}
	ptr, length := sa.Raw()
	n, errno := zcall.Sendto(uintptr(raw), buf, 0, ptr, uintptr(length))
	if errno != 0 {
		return int(n), errFromErrno(errno)
	}
	return int(n), nil
}

// UDPConn represents a UDP connection (connected or unconnected).
type UDPConn struct {
	*UDPSocket
	laddr    *UDPAddr
	raddr    *UDPAddr
	deadline deadlineState
}

//go:nosplit
func (c *UDPConn) LocalAddr() Addr { return c.laddr }

//go:nosplit
func (c *UDPConn) RemoteAddr() Addr { return c.raddr }

func (c *UDPConn) SetDeadline(t time.Time) error {
	c.deadline.setDeadline(t)
	return nil
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	c.deadline.setReadDeadline(t)
	return nil
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	c.deadline.setWriteDeadline(t)
	return nil
}

func (c *UDPConn) ReadFrom(buf []byte) (int, Addr, error) {
	var n int
	var addr *UDPAddr
	n, err := adaptiveRead(func() (int, error) {
		var recvErr error
		n, addr, recvErr = c.UDPSocket.RecvFrom(buf)
		return n, recvErr
	}, &c.deadline)
	return n, addr, err
}

func (c *UDPConn) WriteTo(buf []byte, addr Addr) (int, error) {
	udpAddr, ok := addr.(*UDPAddr)
	if !ok {
		return 0, ErrInvalidParam
	}
	return adaptiveWrite(func() (int, error) { return c.UDPSocket.SendTo(buf, udpAddr) }, &c.deadline)
}

func (c *UDPConn) Read(buf []byte) (int, error) {
	return adaptiveRead(func() (int, error) {
		if c.raddr == nil {
			n, _, err := c.UDPSocket.RecvFrom(buf)
			return n, err
		}
		return c.NetSocket.Read(buf)
	}, &c.deadline)
}

func (c *UDPConn) Write(buf []byte) (int, error) {
	if c.raddr == nil {
		return 0, ErrNotConnected
	}
	return adaptiveWrite(func() (int, error) { return c.NetSocket.Write(buf) }, &c.deadline)
}

// SyscallConn returns a raw network connection for direct syscall access.
// This implements the syscall.Conn interface.
func (c *UDPConn) SyscallConn() (syscall.RawConn, error) {
	if c.fd.Raw() < 0 {
		return nil, ErrClosed
	}
	return newRawConn(c.fd), nil
}

func (c *UDPConn) SetBroadcast(enable bool) error {
	return setSockoptInt(c.fd, SOL_SOCKET, SO_BROADCAST, boolToInt(enable))
}

func (c *UDPConn) GetBroadcast() (bool, error) {
	v, err := getSockoptInt(c.fd, SOL_SOCKET, SO_BROADCAST)
	return v != 0, err
}

// ListenUDP4 creates a bound IPv4 UDP socket.
// Returns ErrInvalidParam if laddr is nil.
func ListenUDP4(laddr *UDPAddr) (*UDPConn, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewUDPSocket4()
	if err != nil {
		return nil, err
	}
	if err := sock.Bind(udpAddrToSockaddr4(laddr)); err != nil {
		sock.Close()
		return nil, err
	}
	// Query actual bound address (handles port 0 → ephemeral port)
	actualLaddr := laddr
	if sa, err := GetSockname(sock.fd); err == nil {
		if inet4, ok := sa.(*SockaddrInet4); ok {
			addr := inet4.Addr()
			actualLaddr = &UDPAddr{IP: net.IP(addr[:]), Port: int(inet4.Port())}
		}
	}
	return &UDPConn{UDPSocket: sock, laddr: actualLaddr}, nil
}

// ListenUDP6 creates a bound IPv6 UDP socket.
// Returns ErrInvalidParam if laddr is nil.
func ListenUDP6(laddr *UDPAddr) (*UDPConn, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewUDPSocket6()
	if err != nil {
		return nil, err
	}
	if err := sock.Bind(udpAddrToSockaddr6(laddr)); err != nil {
		sock.Close()
		return nil, err
	}
	// Query actual bound address (handles port 0 → ephemeral port)
	actualLaddr := laddr
	if sa, err := GetSockname(sock.fd); err == nil {
		if inet6, ok := sa.(*SockaddrInet6); ok {
			addr := inet6.Addr()
			actualLaddr = &UDPAddr{IP: net.IP(addr[:]), Port: int(inet6.Port()), Zone: scopeIDToZone(inet6.ScopeID())}
		}
	}
	return &UDPConn{UDPSocket: sock, laddr: actualLaddr}, nil
}

// ListenUDP creates a bound UDP socket, auto-detecting IPv4/IPv6 based on network and address.
// Returns ErrInvalidParam if laddr is nil.
func ListenUDP(network string, laddr *UDPAddr) (*UDPConn, error) {
	if laddr == nil {
		return nil, ErrInvalidParam
	}
	if networkIPFamily(network, laddr.IP) == NetworkIPv4 {
		return ListenUDP4(laddr)
	}
	return ListenUDP6(laddr)
}

// DialUDP4 creates a connected IPv4 UDP socket.
// Returns ErrInvalidParam if raddr is nil.
func DialUDP4(laddr, raddr *UDPAddr) (*UDPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewUDPSocket4()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		if err := sock.Bind(udpAddrToSockaddr4(laddr)); err != nil {
			sock.Close()
			return nil, err
		}
	}
	if err := sock.Connect(udpAddrToSockaddr4(raddr)); err != nil {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet4, ok := sa.(*SockaddrInet4); ok {
				addr := inet4.Addr()
				actualLaddr = &UDPAddr{IP: net.IP(addr[:]), Port: int(inet4.Port())}
			}
		}
	}
	return &UDPConn{UDPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// DialUDP6 creates a connected IPv6 UDP socket.
// Returns ErrInvalidParam if raddr is nil.
func DialUDP6(laddr, raddr *UDPAddr) (*UDPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	sock, err := NewUDPSocket6()
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		if err := sock.Bind(udpAddrToSockaddr6(laddr)); err != nil {
			sock.Close()
			return nil, err
		}
	}
	if err := sock.Connect(udpAddrToSockaddr6(raddr)); err != nil {
		sock.Close()
		return nil, err
	}
	actualLaddr := laddr
	if actualLaddr == nil {
		if sa, err := GetSockname(sock.fd); err == nil {
			if inet6, ok := sa.(*SockaddrInet6); ok {
				addr := inet6.Addr()
				actualLaddr = &UDPAddr{IP: net.IP(addr[:]), Port: int(inet6.Port())}
			}
		}
	}
	return &UDPConn{UDPSocket: sock, laddr: actualLaddr, raddr: raddr}, nil
}

// DialUDP creates a connected UDP socket, auto-detecting IPv4/IPv6 based on network and address.
// Returns ErrInvalidParam if raddr is nil.
func DialUDP(network string, laddr, raddr *UDPAddr) (*UDPConn, error) {
	if raddr == nil {
		return nil, ErrInvalidParam
	}
	if networkIPFamily(network, raddr.IP) == NetworkIPv4 {
		return DialUDP4(laddr, raddr)
	}
	return DialUDP6(laddr, raddr)
}

func udpAddrToSockaddr4(addr *UDPAddr) *SockaddrInet4 {
	var ip [4]byte
	if addr.IP != nil {
		if ip4 := addr.IP.To4(); ip4 != nil {
			copy(ip[:], ip4)
		}
	}
	return NewSockaddrInet4(ip, uint16(addr.Port))
}

func udpAddrToSockaddr6(addr *UDPAddr) *SockaddrInet6 {
	var ip [16]byte
	if addr.IP != nil {
		if ip6 := addr.IP.To16(); ip6 != nil {
			copy(ip[:], ip6)
		}
	}
	return NewSockaddrInet6(ip, uint16(addr.Port), zoneToScopeID(addr.Zone))
}

func decodeUDPAddr(raw *RawSockaddrAny) *UDPAddr {
	if raw == nil {
		return nil
	}
	switch raw.Addr.Family {
	case AF_INET:
		sa := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		return &UDPAddr{IP: net.IP(sa.Addr[:]), Port: int(ntohs(sa.Port))}
	case AF_INET6:
		sa := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		return &UDPAddr{IP: net.IP(sa.Addr[:]), Port: int(ntohs(sa.Port)), Zone: scopeIDToZone(sa.ScopeID)}
	}
	return nil
}

var (
	_ Socket     = (*UDPSocket)(nil)
	_ Socket     = (*UDPConn)(nil)
	_ Conn       = (*UDPConn)(nil)
	_ PacketConn = (*UDPConn)(nil)
)
