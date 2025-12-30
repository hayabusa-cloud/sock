// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

// fcntl command constants for Linux.
// These are consistent across all Linux architectures.
const (
	F_GETFD    = 1
	F_SETFD    = 2
	F_GETFL    = 3
	F_SETFL    = 4
	FD_CLOEXEC = 1
)
