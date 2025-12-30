// ©Hayabusa Cloud Co., Ltd. 2022. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sock

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/iox"
)

// Common errors reused from iofd for semantic consistency.
var (
	ErrInvalidParam = iofd.ErrInvalidParam
	ErrInterrupted  = iofd.ErrInterrupted
	ErrNoMemory     = iofd.ErrNoMemory
	ErrPermission   = iofd.ErrPermission
)

// Socket-specific errors.
var (
	ErrInProgress   = errors.New("sock: operation in progress")
	ErrNotSupported = errors.New("sock: operation not supported")
)

// NetworkType represents the address family.
type NetworkType int

const (
	NetworkUnix NetworkType = 1
	NetworkIPv4 NetworkType = 2
	NetworkIPv6 NetworkType = 10
)

// Socket is a network socket with handle-based resource management.
type Socket interface {
	FD() *iofd.FD
	NetworkType() NetworkType
	Protocol() UnderlyingProtocol
	io.Reader
	io.Writer
	io.Closer
}

// ListenerSocket accepts incoming connections.
type ListenerSocket interface {
	Socket
	Accept() (Socket, error)
}

// Type aliases for net package compatibility.
type (
	Listener            = net.Listener
	Conn                = net.Conn
	PacketConn          = net.PacketConn
	Addr                = net.Addr
	OpError             = net.OpError
	AddrError           = net.AddrError
	InvalidAddrError    = net.InvalidAddrError
	UnknownNetworkError = net.UnknownNetworkError
)

var (
	DefaultResolver  = net.DefaultResolver
	NetworkByteOrder = binary.BigEndian
)

// rawConn implements syscall.RawConn for raw syscall access.
// This allows users to perform custom operations on the underlying
// file descriptor while maintaining proper synchronization.
type rawConn struct {
	fd *iofd.FD
}

// Control invokes f on the underlying file descriptor.
// The file descriptor is guaranteed to remain valid while f executes.
func (c *rawConn) Control(f func(fd uintptr)) error {
	raw := c.fd.Raw()
	if raw < 0 {
		return ErrClosed
	}
	f(uintptr(raw))
	return nil
}

// Read invokes f on the underlying file descriptor for reading.
// If f returns true, Read returns nil. If f returns false, Read
// retries in a tight loop until f returns true or the fd is closed.
//
// WARNING: This implements busy-wait semantics for non-blocking sockets.
// The function f should return true on EAGAIN if immediate return is acceptable,
// otherwise this will spin indefinitely consuming CPU. For event-driven I/O,
// use io_uring or epoll integration instead of this interface.
func (c *rawConn) Read(f func(fd uintptr) (done bool)) error {
	for {
		raw := c.fd.Raw()
		if raw < 0 {
			return ErrClosed
		}
		if f(uintptr(raw)) {
			return nil
		}
		// For non-blocking FDs, yield and retry
		// The caller's f should return true when EAGAIN is acceptable
	}
}

// Write invokes f on the underlying file descriptor for writing.
// If f returns true, Write returns nil. If f returns false, Write
// retries in a tight loop until f returns true or the fd is closed.
//
// WARNING: This implements busy-wait semantics for non-blocking sockets.
// The function f should return true on EAGAIN if immediate return is acceptable,
// otherwise this will spin indefinitely consuming CPU. For event-driven I/O,
// use io_uring or epoll integration instead of this interface.
func (c *rawConn) Write(f func(fd uintptr) (done bool)) error {
	for {
		raw := c.fd.Raw()
		if raw < 0 {
			return ErrClosed
		}
		if f(uintptr(raw)) {
			return nil
		}
		// For non-blocking FDs, yield and retry
		// The caller's f should return true when EAGAIN is acceptable
	}
}

// newRawConn creates a new rawConn wrapping the given file descriptor.
func newRawConn(fd *iofd.FD) *rawConn {
	return &rawConn{fd: fd}
}

// Compile-time assertion that rawConn implements syscall.RawConn.
var _ syscall.RawConn = (*rawConn)(nil)

// Suppress unused import warning - iox is used in other files with unix build tag
var _ = iox.ErrWouldBlock
