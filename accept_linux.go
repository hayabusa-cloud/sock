// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"unsafe"

	"code.hybscloud.com/zcall"
)

// accept4 wraps the accept4 syscall with SOCK_NONBLOCK and SOCK_CLOEXEC flags.
// Linux supports accept4 natively.
func accept4(fd int, addr unsafe.Pointer, addrlen unsafe.Pointer) (int, error) {
	nfd, errno := zcall.Accept4(
		uintptr(fd),
		addr,
		addrlen,
		zcall.SOCK_NONBLOCK|zcall.SOCK_CLOEXEC,
	)
	if errno != 0 {
		return -1, errFromErrno(errno)
	}
	return int(nfd), nil
}
