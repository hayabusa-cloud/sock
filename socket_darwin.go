// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build darwin

package sock

import (
	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// socketFlags returns the flags to add to socket type for NONBLOCK and CLOEXEC.
// Darwin does NOT support SOCK_NONBLOCK and SOCK_CLOEXEC in socket().
// These must be set via fcntl after socket creation.
func socketFlags() int {
	return 0
}

// socketPostCreate performs post-creation setup needed for the socket.
// On Darwin, we must use fcntl to set O_NONBLOCK and FD_CLOEXEC since
// Darwin's socket() syscall does not support SOCK_NONBLOCK|SOCK_CLOEXEC flags.
func socketPostCreate(fd int) error {
	// Set O_NONBLOCK
	flags, errno := zcall.Syscall4(SYS_FCNTL, uintptr(fd), F_GETFL, 0, 0)
	if errno != 0 {
		return errFromErrno(errno)
	}
	_, errno = zcall.Syscall4(SYS_FCNTL, uintptr(fd), F_SETFL, flags|zcall.O_NONBLOCK, 0)
	if errno != 0 {
		return errFromErrno(errno)
	}

	// Set FD_CLOEXEC
	_, errno = zcall.Syscall4(SYS_FCNTL, uintptr(fd), F_SETFD, FD_CLOEXEC, 0)
	if errno != 0 {
		return errFromErrno(errno)
	}

	return nil
}

// socketPostCreateFD is a convenience wrapper for iofd.FD.
func socketPostCreateFD(fd iofd.FD) error {
	raw := fd.Raw()
	if raw < 0 {
		return ErrClosed
	}
	return socketPostCreate(int(raw))
}
