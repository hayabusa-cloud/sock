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

// Socket option wrappers using zcall for zero-overhead syscalls.
// These functions provide type-safe access to common socket options
// for performance tuning.

// SetReuseAddr enables or disables the SO_REUSEADDR socket option.
// When enabled, allows binding to an address that is already in use.
func SetReuseAddr(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_SOCKET, SO_REUSEADDR, boolToInt(enable))
}

// GetReuseAddr returns the current SO_REUSEADDR setting.
func GetReuseAddr(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_SOCKET, SO_REUSEADDR)
	return v != 0, err
}

// SetReusePort enables or disables the SO_REUSEPORT socket option.
// When enabled, allows multiple sockets to bind to the same port.
// The kernel distributes incoming connections among the sockets.
func SetReusePort(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_SOCKET, SO_REUSEPORT, boolToInt(enable))
}

// GetReusePort returns the current SO_REUSEPORT setting.
func GetReusePort(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_SOCKET, SO_REUSEPORT)
	return v != 0, err
}

// SetKeepAlive enables or disables the SO_KEEPALIVE socket option.
// When enabled, the socket sends keepalive probes to detect dead peers.
func SetKeepAlive(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_SOCKET, SO_KEEPALIVE, boolToInt(enable))
}

// GetKeepAlive returns the current SO_KEEPALIVE setting.
func GetKeepAlive(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_SOCKET, SO_KEEPALIVE)
	return v != 0, err
}

// SetTCPNoDelay enables or disables the TCP_NODELAY socket option.
// When enabled, disables Nagle's algorithm for lower latency.
func SetTCPNoDelay(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_TCP, TCP_NODELAY, boolToInt(enable))
}

// GetTCPNoDelay returns the current TCP_NODELAY setting.
func GetTCPNoDelay(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_TCP, TCP_NODELAY)
	return v != 0, err
}

// SetSendBuffer sets the SO_SNDBUF socket option.
// This sets the send buffer size in bytes.
func SetSendBuffer(fd *iofd.FD, size int) error {
	return setSockoptInt(fd, SOL_SOCKET, SO_SNDBUF, size)
}

// GetSendBuffer returns the current SO_SNDBUF setting.
func GetSendBuffer(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_SOCKET, SO_SNDBUF)
}

// SetRecvBuffer sets the SO_RCVBUF socket option.
// This sets the receive buffer size in bytes.
func SetRecvBuffer(fd *iofd.FD, size int) error {
	return setSockoptInt(fd, SOL_SOCKET, SO_RCVBUF, size)
}

// GetRecvBuffer returns the current SO_RCVBUF setting.
func GetRecvBuffer(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_SOCKET, SO_RCVBUF)
}

// SetTCPKeepIntvl sets the TCP_KEEPINTVL socket option.
// This sets the time (in seconds) between individual keepalive probes.
func SetTCPKeepIntvl(fd *iofd.FD, secs int) error {
	return setSockoptInt(fd, SOL_TCP, TCP_KEEPINTVL, secs)
}

// GetTCPKeepIntvl returns the current TCP_KEEPINTVL setting.
func GetTCPKeepIntvl(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_TCP, TCP_KEEPINTVL)
}

// SetTCPKeepCnt sets the TCP_KEEPCNT socket option.
// This sets the maximum number of keepalive probes before dropping the connection.
func SetTCPKeepCnt(fd *iofd.FD, count int) error {
	return setSockoptInt(fd, SOL_TCP, TCP_KEEPCNT, count)
}

// GetTCPKeepCnt returns the current TCP_KEEPCNT setting.
func GetTCPKeepCnt(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_TCP, TCP_KEEPCNT)
}

// GetSocketError retrieves and clears the pending socket error.
func GetSocketError(fd *iofd.FD) error {
	v, err := getSockoptInt(fd, SOL_SOCKET, SO_ERROR)
	if err != nil {
		return err
	}
	if v != 0 {
		return errFromErrno(uintptr(v))
	}
	return nil
}

// GetSocketType returns the socket type (SOCK_STREAM, SOCK_DGRAM, etc.).
func GetSocketType(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_SOCKET, SO_TYPE)
}

// Linger represents the SO_LINGER socket option value.
type Linger struct {
	Onoff  int32 // Whether linger is enabled
	Linger int32 // Linger time in seconds
}

// SetLinger sets the SO_LINGER socket option.
// When enabled with a non-zero timeout, Close() will block until
// pending data is sent or the timeout expires.
// When enabled with zero timeout, Close() sends RST immediately.
// When disabled, Close() returns immediately (default).
func SetLinger(fd *iofd.FD, enable bool, secs int) error {
	raw := fd.Raw()
	if raw < 0 {
		return ErrClosed
	}
	var l Linger
	if enable {
		l.Onoff = 1
		l.Linger = int32(secs)
	}
	errno := zcall.Setsockopt(
		uintptr(raw),
		uintptr(SOL_SOCKET),
		uintptr(SO_LINGER),
		unsafe.Pointer(&l),
		unsafe.Sizeof(l),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// GetLinger returns the current SO_LINGER setting.
// Returns (enabled, seconds, error).
func GetLinger(fd *iofd.FD) (bool, int, error) {
	raw := fd.Raw()
	if raw < 0 {
		return false, 0, ErrClosed
	}
	var l Linger
	llen := uint32(unsafe.Sizeof(l))
	errno := zcall.Getsockopt(
		uintptr(raw),
		uintptr(SOL_SOCKET),
		uintptr(SO_LINGER),
		unsafe.Pointer(&l),
		unsafe.Pointer(&llen),
	)
	if errno != 0 {
		return false, 0, errFromErrno(errno)
	}
	return l.Onoff != 0, int(l.Linger), nil
}

// Low-level setsockopt/getsockopt wrappers.

func setSockoptInt(fd *iofd.FD, level, opt, value int) error {
	raw := fd.Raw()
	if raw < 0 {
		return ErrClosed
	}
	v := int32(value)
	errno := zcall.Setsockopt(
		uintptr(raw),
		uintptr(level),
		uintptr(opt),
		unsafe.Pointer(&v),
		unsafe.Sizeof(v),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

func getSockoptInt(fd *iofd.FD, level, opt int) (int, error) {
	raw := fd.Raw()
	if raw < 0 {
		return 0, ErrClosed
	}
	var v int32
	vlen := uint32(unsafe.Sizeof(v))
	errno := zcall.Getsockopt(
		uintptr(raw),
		uintptr(level),
		uintptr(opt),
		unsafe.Pointer(&v),
		unsafe.Pointer(&vlen),
	)
	if errno != 0 {
		return 0, errFromErrno(errno)
	}
	return int(v), nil
}

// boolToInt converts a bool to an int (0 or 1).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// fcntl constants and SYS_FCNTL are defined in platform-specific files:
// - fcntl_linux.go
// - fcntl_bsd.go (FreeBSD/Darwin)

// SetNonBlock sets the O_NONBLOCK flag on the file descriptor.
func SetNonBlock(fd *iofd.FD, nonblock bool) error {
	flags, err := getFdFlags(fd)
	if err != nil {
		return err
	}
	if nonblock {
		flags |= O_NONBLOCK
	} else {
		flags &^= O_NONBLOCK
	}
	return setFdFlags(fd, flags)
}

// SetCloseOnExec sets the FD_CLOEXEC flag on the file descriptor.
func SetCloseOnExec(fd *iofd.FD, cloexec bool) error {
	var flags uintptr
	if cloexec {
		flags = FD_CLOEXEC
	}
	_, errno := zcall.Syscall4(SYS_FCNTL, uintptr(fd.Raw()), F_SETFD, flags, 0)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

func getFdFlags(fd *iofd.FD) (int, error) {
	flags, errno := zcall.Syscall4(SYS_FCNTL, uintptr(fd.Raw()), F_GETFL, 0, 0)
	if errno != 0 {
		return 0, errFromErrno(errno)
	}
	return int(flags), nil
}

func setFdFlags(fd *iofd.FD, flags int) error {
	_, errno := zcall.Syscall4(SYS_FCNTL, uintptr(fd.Raw()), F_SETFL, uintptr(flags), 0)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}
