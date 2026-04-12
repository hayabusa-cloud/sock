// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build freebsd || darwin

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
	length := uint32(2)
	if n == 0 {
		raw.Len = uint8(length)
		return length // Family only; unnamed socket / empty path
	}
	if n < len(raw.Path) {
		raw.Path[n] = 0
	}
	// BSD/Darwin pathname socket addrlen follows SUN_LEN: the trailing NUL is
	// required in sun_path when present, but it is not part of the address.
	length += uint32(n)
	raw.Len = uint8(length)
	return length
}
