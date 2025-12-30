// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux && sock_unix

package sock_test

import (
	"unsafe"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
	"code.hybscloud.com/zcall"
)

// test helper socket
type socket struct {
	network sock.NetworkType
	typ     sock.UnderlyingProtocol
	fd      int
	sa      sock.Sockaddr
}

func (s *socket) Fd() int {
	return s.fd
}

func (s *socket) NetworkType() sock.NetworkType {
	return s.network
}

func (s *socket) Protocol() sock.UnderlyingProtocol {
	if s.typ > 0 {
		return s.typ
	}
	var v int32
	optlen := uint32(4)
	errno := zcall.Getsockopt(uintptr(s.fd), zcall.SOL_SOCKET, zcall.SO_TYPE, unsafe.Pointer(&v), unsafe.Pointer(&optlen))
	if errno != 0 {
		return 0
	}
	s.typ = sock.UnderlyingProtocol(v & 0xff)
	return s.typ
}

func (s *socket) Read(b []byte) (n int, err error) {
	rn, errno := zcall.Read(uintptr(s.fd), b)
	if errno != 0 {
		return int(rn), errFromZcallErrno(errno)
	}
	return int(rn), nil
}

func (s *socket) Write(b []byte) (n int, err error) {
	_, errno := zcall.Sendto(uintptr(s.fd), b, zcall.MSG_ZEROCOPY, nil, 0)
	if errno != 0 {
		return 0, errFromZcallErrno(errno)
	}
	return len(b), nil
}

func (s *socket) Close() error {
	errno := zcall.Close(uintptr(s.fd))
	if errno != 0 {
		return zcall.Errno(errno)
	}
	return nil
}

func errFromZcallErrno(errno uintptr) error {
	if errno == 0 {
		return nil
	}
	switch zcall.Errno(errno) {
	case zcall.EAGAIN:
		return iox.ErrWouldBlock
	case zcall.EINTR:
		return sock.ErrInterrupted
	case zcall.EINPROGRESS:
		return sock.ErrInProgress
	case zcall.EINVAL:
		return sock.ErrInvalidParam
	case zcall.ENOMEM:
		return sock.ErrNoMemory
	case zcall.EPERM, zcall.EACCES:
		return sock.ErrPermission
	default:
		return zcall.Errno(errno)
	}
}
