// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build freebsd || darwin

package sock

import "testing"

func TestSockaddrUnixBSDRawLengthExcludesTrailingNUL(t *testing.T) {
	sa := NewSockaddrUnix("/tmp/sock.test")
	ptr, length := sa.Raw()
	raw := (*RawSockaddrUnix)(ptr)

	if got, want := length, uint32(2+len("/tmp/sock.test")); got != want {
		t.Fatalf("Raw length = %d, want %d", got, want)
	}
	if got, want := raw.Len, uint8(length); got != want {
		t.Fatalf("sun_len = %d, want %d", got, want)
	}
	if raw.Path[len("/tmp/sock.test")] != 0 {
		t.Fatal("expected NUL terminator after BSD pathname socket")
	}
}
