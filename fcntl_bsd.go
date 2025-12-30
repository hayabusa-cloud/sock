// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build freebsd || darwin

package sock

// fcntl constants for BSD/Darwin.
// These values are consistent across FreeBSD and Darwin.
const (
	F_GETFD    = 1
	F_SETFD    = 2
	F_GETFL    = 3
	F_SETFL    = 4
	FD_CLOEXEC = 1
)

// SYS_FCNTL is the syscall number for fcntl.
// Darwin: 92, FreeBSD: 92
const SYS_FCNTL = 92
