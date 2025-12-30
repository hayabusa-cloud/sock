// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build amd64 || arm64 || riscv64 || loong64 || 386 || arm || mips64le || mipsle || ppc64le || wasm

package sock

// nativeIsLittleEndian indicates the host byte order.
// This constant is true for little-endian architectures.
const nativeIsLittleEndian = true
