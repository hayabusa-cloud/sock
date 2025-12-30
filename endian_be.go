// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build ppc64 || s390x || mips64 || mips

package sock

// nativeIsLittleEndian indicates the host byte order.
// This constant is false for big-endian architectures.
const nativeIsLittleEndian = false
