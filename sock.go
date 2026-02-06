// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock

import (
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

func newFDPtr(fd int) *iofd.FD {
	f := iofd.NewFD(fd)
	return &f
}

// NetSocket represents a network socket with NONBLOCK and CLOEXEC flags.
type NetSocket struct {
	fd      *iofd.FD
	domain  int
	typ     int
	proto   int
	network NetworkType
}

// NewNetSocket creates a new socket with the specified domain, type, and protocol.
func NewNetSocket(domain, typ, proto int) (*NetSocket, error) {
	typ |= socketFlags()
	fd, errno := zcall.Socket(uintptr(domain), uintptr(typ), uintptr(proto))
	if errno != 0 {
		return nil, errFromErrno(errno)
	}
	if err := socketPostCreate(int(fd)); err != nil {
		zcall.Close(fd)
		return nil, err
	}
	return &NetSocket{
		fd:      newFDPtr(int(fd)),
		domain:  domain,
		typ:     typ,
		proto:   proto,
		network: NetworkType(domain),
	}, nil
}

// NewNetTCPSocket creates a new TCP socket returning the generic *NetSocket type.
func NewNetTCPSocket(ipv6 bool) (*NetSocket, error) {
	domain := zcall.AF_INET
	if ipv6 {
		domain = zcall.AF_INET6
	}
	return NewNetSocket(domain, zcall.SOCK_STREAM, zcall.IPPROTO_TCP)
}

// NewNetUDPSocket creates a new UDP socket returning the generic *NetSocket type.
func NewNetUDPSocket(ipv6 bool) (*NetSocket, error) {
	domain := zcall.AF_INET
	if ipv6 {
		domain = zcall.AF_INET6
	}
	return NewNetSocket(domain, zcall.SOCK_DGRAM, zcall.IPPROTO_UDP)
}

// NewNetUnixSocket creates a Unix socket returning the generic *NetSocket type.
func NewNetUnixSocket(typ int) (*NetSocket, error) {
	return NewNetSocket(zcall.AF_UNIX, typ, 0)
}

//go:nosplit
func (s *NetSocket) FD() *iofd.FD { return s.fd }

//go:nosplit
func (s *NetSocket) NetworkType() NetworkType { return s.network }

// Protocol returns the socket type (SOCK_STREAM, SOCK_DGRAM, etc.) as UnderlyingProtocol.
// The socket type is masked to remove flags like SOCK_NONBLOCK and SOCK_CLOEXEC.
func (s *NetSocket) Protocol() UnderlyingProtocol {
	return UnderlyingProtocol(s.typ & 0xF)
}
func (s *NetSocket) Close() error                { return s.fd.Close() }
func (s *NetSocket) Read(p []byte) (int, error)  { return s.fd.Read(p) }
func (s *NetSocket) Write(p []byte) (int, error) { return s.fd.Write(p) }

func (s *NetSocket) Bind(addr Sockaddr) error {
	raw := s.fd.Raw()
	if raw < 0 {
		return ErrClosed
	}
	ptr, length := addr.Raw()
	errno := zcall.Bind(uintptr(raw), ptr, uintptr(length))
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

func (s *NetSocket) Listen(backlog int) error {
	raw := s.fd.Raw()
	if raw < 0 {
		return ErrClosed
	}
	errno := zcall.Listen(uintptr(raw), uintptr(backlog))
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

func (s *NetSocket) Accept() (*NetSocket, *RawSockaddrAny, uint32, error) {
	raw := s.fd.Raw()
	if raw < 0 {
		return nil, nil, 0, ErrClosed
	}
	var addr RawSockaddrAny
	addrlen := uint32(SizeofSockaddrAny)
	nfd, err := accept4(int(raw), unsafe.Pointer(&addr), unsafe.Pointer(&addrlen))
	if err != nil {
		return nil, nil, 0, err
	}
	newSock := &NetSocket{
		fd:      newFDPtr(nfd),
		domain:  s.domain,
		typ:     s.typ,
		proto:   s.proto,
		network: s.network,
	}
	return newSock, &addr, addrlen, nil
}

func (s *NetSocket) Connect(addr Sockaddr) error {
	raw := s.fd.Raw()
	if raw < 0 {
		return ErrClosed
	}
	ptr, length := addr.Raw()
	errno := zcall.Connect(uintptr(raw), ptr, uintptr(length))
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

func (s *NetSocket) Shutdown(how int) error {
	raw := s.fd.Raw()
	if raw < 0 {
		return ErrClosed
	}
	errno := zcall.Shutdown(uintptr(raw), uintptr(how))
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// NetSocketPair creates a pair of connected sockets.
func NetSocketPair(domain, typ, proto int) ([2]*NetSocket, error) {
	typ |= socketFlags()
	var fds [2]int32
	errno := zcall.Socketpair(uintptr(domain), uintptr(typ), uintptr(proto), &fds)
	if errno != 0 {
		return [2]*NetSocket{}, errFromErrno(errno)
	}
	if err := socketPostCreate(int(fds[0])); err != nil {
		zcall.Close(uintptr(fds[0]))
		zcall.Close(uintptr(fds[1]))
		return [2]*NetSocket{}, err
	}
	if err := socketPostCreate(int(fds[1])); err != nil {
		zcall.Close(uintptr(fds[0]))
		zcall.Close(uintptr(fds[1]))
		return [2]*NetSocket{}, err
	}
	return [2]*NetSocket{
		{fd: newFDPtr(int(fds[0])), domain: domain, typ: typ, proto: proto, network: NetworkType(domain)},
		{fd: newFDPtr(int(fds[1])), domain: domain, typ: typ, proto: proto, network: NetworkType(domain)},
	}, nil
}

// UnixSocketPair creates a pair of connected Unix domain sockets.
func UnixSocketPair() ([2]*NetSocket, error) {
	return NetSocketPair(zcall.AF_UNIX, zcall.SOCK_STREAM, 0)
}

var _ Socket = (*NetSocket)(nil)
