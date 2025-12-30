// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import "code.hybscloud.com/zcall"

// socketFlags returns the flags to add to socket type for NONBLOCK and CLOEXEC.
// Linux supports SOCK_NONBLOCK and SOCK_CLOEXEC directly in socket().
func socketFlags() int {
	return zcall.SOCK_NONBLOCK | zcall.SOCK_CLOEXEC
}

// socketPostCreate performs any post-creation setup needed for the socket.
// On Linux, nothing is needed since SOCK_NONBLOCK|SOCK_CLOEXEC are set at creation.
func socketPostCreate(fd int) error {
	return nil
}
