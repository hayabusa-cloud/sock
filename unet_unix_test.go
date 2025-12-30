// ©Hayabusa Cloud Co., Ltd. 2022. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"

	"code.hybscloud.com/zcall"
)

const (
	sizeofShort = 2 // sizeof(unsigned short) on Linux
)

func TestUnixSockaddr(t *testing.T) {
	t.Run("abstract", func(t *testing.T) {
		// Note: "@" is stored as-is, not converted to NUL
		// Length = family(2) + path("@"=1) + NUL(1) = 4
		unixAddr, err := ResolveUnixAddr("unixpacket", "@")
		if err != nil {
			t.Fatalf("ResolveUnixAddr: %v", err)
		}
		sa := UnixAddrToSockaddr(unixAddr)
		unixSa, ok := sa.(*SockaddrUnix)
		if !ok {
			t.Fatalf("expected *SockaddrUnix, got %T", sa)
		}
		if unixAddr.Name != unixSa.Path() {
			t.Errorf("unix sockaddr expected name=%s but got %s", unixAddr.Name, unixSa.Path())
			return
		}
		ptr, n := unixSa.Raw()
		expectedLen := uint32(sizeofShort + 1 + 1) // family + "@" + NUL
		if n != expectedLen {
			t.Errorf("unix sockaddr bad length expected %d but got %d", expectedLen, n)
			return
		}
		b := unsafe.Slice((*byte)(ptr), n)
		family := binary.LittleEndian.Uint16(b[:sizeofShort])
		if zcall.AF_UNIX != int(family) {
			t.Errorf("unix sockaddr bad family expected AF_UNIX but got %x", family)
			return
		}
		// Path should be "@" followed by NUL
		if b[sizeofShort] != '@' {
			t.Errorf("unix sockaddr expected '@' but got %c", b[sizeofShort])
			return
		}
	})

	t.Run("pathname", func(t *testing.T) {
		name := "uds_test"
		unixAddr, err := ResolveUnixAddr("unixpacket", name)
		if err != nil {
			t.Fatalf("ResolveUnixAddr: %v", err)
		}
		sa := UnixAddrToSockaddr(unixAddr)
		unixSa, ok := sa.(*SockaddrUnix)
		if !ok {
			t.Fatalf("expected *SockaddrUnix, got %T", sa)
		}
		if unixAddr.Name != unixSa.Path() {
			t.Errorf("unix sockaddr expected name=%s but got %s", unixAddr.Name, unixSa.Path())
			return
		}
		ptr, n := unixSa.Raw()
		expectedLen := uint32(sizeofShort + len(name) + 1)
		if n != expectedLen {
			t.Errorf("unix sockaddr bad length expected %d but got %d", expectedLen, n)
			return
		}
		b := unsafe.Slice((*byte)(ptr), n)
		family := binary.LittleEndian.Uint16(b[:sizeofShort])
		if zcall.AF_UNIX != int(family) {
			t.Errorf("unix sockaddr bad family expected AF_UNIX but got %x", family)
			return
		}
		// Check path bytes (excluding null terminator)
		pathBytes := b[sizeofShort : sizeofShort+len(name)]
		if !bytes.Equal(pathBytes, []byte(name)) {
			t.Errorf("unix sockaddr expected %s but got %s", name, pathBytes)
			return
		}
	})
}
