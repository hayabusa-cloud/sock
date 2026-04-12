// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

func unixSockaddrPath(raw *RawSockaddrUnix, length uint32) string {
	if length < 2 {
		for i, b := range raw.Path {
			if b == 0 {
				return string(raw.Path[:i])
			}
		}
		return ""
	}

	pathLen := int(length) - 2
	if pathLen <= 0 {
		return ""
	}
	if pathLen > len(raw.Path) {
		pathLen = len(raw.Path)
	}

	if raw.Path[0] == 0 {
		if pathLen == 1 {
			return "@"
		}
		return "@" + string(raw.Path[1:pathLen])
	}

	for i := range pathLen {
		if raw.Path[i] == 0 {
			return string(raw.Path[:i])
		}
	}
	return string(raw.Path[:pathLen])
}

func encodeUnixSockaddrPath(raw *RawSockaddrUnix, path string) uint32 {
	for i := range raw.Path {
		raw.Path[i] = 0
	}

	n := copy(raw.Path[:], path)
	if n == 0 {
		return 2 // Family only; unnamed socket / empty path
	}
	if path[0] == '@' || path[0] == 0 {
		raw.Path[0] = 0
		return uint32(2 + n) // Family + abstract name (no trailing NUL)
	}
	if n < len(raw.Path) {
		raw.Path[n] = 0
		return uint32(2 + n + 1) // Family + pathname + NUL terminator
	}
	return uint32(2 + n) // Family + truncated pathname (no room for NUL)
}
