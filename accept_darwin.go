// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build darwin

package sock

import (
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// fcntl constants are imported from iofd package.

// accept4 emulates accept4 on Darwin using accept + fcntl.
// Darwin does not support accept4, so we must set O_NONBLOCK and FD_CLOEXEC
// after accepting the connection.
func accept4(fd int, addr unsafe.Pointer, addrlen unsafe.Pointer) (int, error) {
	nfd, errno := zcall.Accept(uintptr(fd), addr, addrlen)
	if errno != 0 {
		return -1, errFromErrno(errno)
	}

	// Set O_NONBLOCK
	flags, errno := zcall.Syscall4(iofd.SYS_FCNTL, nfd, iofd.F_GETFL, 0, 0)
	if errno != 0 {
		zcall.Close(nfd)
		return -1, errFromErrno(errno)
	}
	_, errno = zcall.Syscall4(iofd.SYS_FCNTL, nfd, iofd.F_SETFL, flags|zcall.O_NONBLOCK, 0)
	if errno != 0 {
		zcall.Close(nfd)
		return -1, errFromErrno(errno)
	}

	// Set FD_CLOEXEC
	_, errno = zcall.Syscall4(iofd.SYS_FCNTL, nfd, iofd.F_SETFD, iofd.FD_CLOEXEC, 0)
	if errno != 0 {
		zcall.Close(nfd)
		return -1, errFromErrno(errno)
	}

	return int(nfd), nil
}

// setNonBlockCloexec sets O_NONBLOCK and FD_CLOEXEC on a file descriptor.
// On Darwin, this is required after socket() and accept() since Darwin
// does not support SOCK_NONBLOCK|SOCK_CLOEXEC flags in these syscalls.
func setNonBlockCloexec(fd *iofd.FD) error {
	raw := fd.Raw()
	if raw < 0 {
		return ErrClosed
	}

	// Set O_NONBLOCK
	flags, errno := zcall.Syscall4(iofd.SYS_FCNTL, uintptr(raw), iofd.F_GETFL, 0, 0)
	if errno != 0 {
		return errFromErrno(errno)
	}
	_, errno = zcall.Syscall4(iofd.SYS_FCNTL, uintptr(raw), iofd.F_SETFL, flags|zcall.O_NONBLOCK, 0)
	if errno != 0 {
		return errFromErrno(errno)
	}

	// Set FD_CLOEXEC
	_, errno = zcall.Syscall4(iofd.SYS_FCNTL, uintptr(raw), iofd.F_SETFD, iofd.FD_CLOEXEC, 0)
	if errno != 0 {
		return errFromErrno(errno)
	}

	return nil
}
