// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux && arm64

package sock

// SYS_FCNTL is the syscall number for fcntl on Linux arm64.
// arm64 uses the generic syscall table.
const SYS_FCNTL = 25
