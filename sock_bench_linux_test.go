// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"net"
	"testing"
)

func BenchmarkSockaddrInet4_Create(b *testing.B) {
	addr := [4]byte{127, 0, 0, 1}
	port := uint16(8080)
	for b.Loop() {
		NewSockaddrInet4(addr, port)
	}
}

func BenchmarkSockaddrInet4_Raw(b *testing.B) {
	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 8080)
	for b.Loop() {
		sa.Raw()
	}
}

func BenchmarkSockaddrInet6_Create(b *testing.B) {
	addr := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	port := uint16(8080)
	for b.Loop() {
		NewSockaddrInet6(addr, port, 0)
	}
}

func BenchmarkSockaddrInet6_Raw(b *testing.B) {
	sa := NewSockaddrInet6([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 8080, 0)
	for b.Loop() {
		sa.Raw()
	}
}

func BenchmarkSockaddrUnix_Create(b *testing.B) {
	path := "/tmp/bench.sock"
	for b.Loop() {
		NewSockaddrUnix(path)
	}
}

func BenchmarkSockaddrUnix_Raw(b *testing.B) {
	sa := NewSockaddrUnix("/tmp/bench.sock")
	for b.Loop() {
		sa.Raw()
	}
}

func BenchmarkTCPAddrToSockaddr_IPv4(b *testing.B) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	for b.Loop() {
		TCPAddrToSockaddr(addr)
	}
}

func BenchmarkTCPAddrToSockaddr_IPv6(b *testing.B) {
	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 8080}
	for b.Loop() {
		TCPAddrToSockaddr(addr)
	}
}

func BenchmarkUDPAddrToSockaddr_IPv4(b *testing.B) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353}
	for b.Loop() {
		UDPAddrToSockaddr(addr)
	}
}

func BenchmarkDecodeSockaddr_IPv4(b *testing.B) {
	raw := &RawSockaddrAny{}
	raw.Addr.Family = AF_INET
	for b.Loop() {
		DecodeSockaddr(raw, SizeofSockaddrInet4)
	}
}

func BenchmarkDecodeSockaddr_IPv6(b *testing.B) {
	raw := &RawSockaddrAny{}
	raw.Addr.Family = AF_INET6
	for b.Loop() {
		DecodeSockaddr(raw, SizeofSockaddrInet6)
	}
}

func BenchmarkHtons(b *testing.B) {
	port := uint16(8080)
	for b.Loop() {
		port = htons(port)
	}
}

func BenchmarkNtohs(b *testing.B) {
	port := uint16(0x901F) // 8080 in network byte order
	for b.Loop() {
		port = ntohs(port)
	}
}

func BenchmarkNewTCPSocket4(b *testing.B) {
	for b.Loop() {
		sock, err := NewTCPSocket4()
		if err != nil {
			b.Fatal(err)
		}
		if err := sock.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewUDPSocket4(b *testing.B) {
	for b.Loop() {
		sock, err := NewUDPSocket4()
		if err != nil {
			b.Fatal(err)
		}
		if err := sock.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewUnixStreamSocket(b *testing.B) {
	for b.Loop() {
		sock, err := NewUnixStreamSocket()
		if err != nil {
			b.Fatal(err)
		}
		if err := sock.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnixSocketPair(b *testing.B) {
	for b.Loop() {
		socks, err := UnixSocketPair()
		if err != nil {
			b.Fatal(err)
		}
		leftErr := socks[0].Close()
		rightErr := socks[1].Close()
		if leftErr != nil || rightErr != nil {
			b.Fatalf("close socket pair: %v, %v", leftErr, rightErr)
		}
	}
}

func BenchmarkUnixSocketPair_ReadWrite(b *testing.B) {
	socks, err := UnixSocketPair()
	if err != nil {
		b.Fatal(err)
	}
	defer socks[0].Close()
	defer socks[1].Close()

	data := []byte("hello")
	buf := make([]byte, len(data))
	b.SetBytes(int64(len(data)))

	for b.Loop() {
		n, err := socks[0].Write(data)
		if err != nil || n != len(data) {
			b.Fatalf("write: got (%d, %v), want (%d, nil)", n, err, len(data))
		}
		n, err = socks[1].Read(buf)
		if err != nil || n != len(data) {
			b.Fatalf("read: got (%d, %v), want (%d, nil)", n, err, len(data))
		}
	}
}

func BenchmarkZoneToScopeID(b *testing.B) {
	zone := "42"
	for b.Loop() {
		zoneToScopeID(zone)
	}
}

func BenchmarkScopeIDToZone(b *testing.B) {
	id := uint32(42)
	for b.Loop() {
		scopeIDToZone(id)
	}
}

func BenchmarkIP4AddressToBytes(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	for b.Loop() {
		IP4AddressToBytes(ip)
	}
}

func BenchmarkIP6AddressToBytes(b *testing.B) {
	ip := net.ParseIP("fe80::1")
	for b.Loop() {
		IP6AddressToBytes(ip)
	}
}
