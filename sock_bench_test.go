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
	b.ResetTimer()
	for range b.N {
		_ = NewSockaddrInet4(addr, port)
	}
}

func BenchmarkSockaddrInet4_Raw(b *testing.B) {
	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 8080)
	b.ResetTimer()
	for range b.N {
		_, _ = sa.Raw()
	}
}

func BenchmarkSockaddrInet6_Create(b *testing.B) {
	addr := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	port := uint16(8080)
	b.ResetTimer()
	for range b.N {
		_ = NewSockaddrInet6(addr, port, 0)
	}
}

func BenchmarkSockaddrInet6_Raw(b *testing.B) {
	sa := NewSockaddrInet6([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 8080, 0)
	b.ResetTimer()
	for range b.N {
		_, _ = sa.Raw()
	}
}

func BenchmarkSockaddrUnix_Create(b *testing.B) {
	path := "/tmp/bench.sock"
	b.ResetTimer()
	for range b.N {
		_ = NewSockaddrUnix(path)
	}
}

func BenchmarkSockaddrUnix_Raw(b *testing.B) {
	sa := NewSockaddrUnix("/tmp/bench.sock")
	b.ResetTimer()
	for range b.N {
		_, _ = sa.Raw()
	}
}

func BenchmarkTCPAddrToSockaddr_IPv4(b *testing.B) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	b.ResetTimer()
	for range b.N {
		_ = TCPAddrToSockaddr(addr)
	}
}

func BenchmarkTCPAddrToSockaddr_IPv6(b *testing.B) {
	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 8080}
	b.ResetTimer()
	for range b.N {
		_ = TCPAddrToSockaddr(addr)
	}
}

func BenchmarkUDPAddrToSockaddr_IPv4(b *testing.B) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353}
	b.ResetTimer()
	for range b.N {
		_ = UDPAddrToSockaddr(addr)
	}
}

func BenchmarkDecodeSockaddr_IPv4(b *testing.B) {
	raw := &RawSockaddrAny{}
	raw.Addr.Family = AF_INET
	b.ResetTimer()
	for range b.N {
		_ = DecodeSockaddr(raw, SizeofSockaddrInet4)
	}
}

func BenchmarkDecodeSockaddr_IPv6(b *testing.B) {
	raw := &RawSockaddrAny{}
	raw.Addr.Family = AF_INET6
	b.ResetTimer()
	for range b.N {
		_ = DecodeSockaddr(raw, SizeofSockaddrInet6)
	}
}

func BenchmarkHtons(b *testing.B) {
	port := uint16(8080)
	b.ResetTimer()
	for range b.N {
		_ = htons(port)
	}
}

func BenchmarkNtohs(b *testing.B) {
	port := uint16(0x901F) // 8080 in network byte order
	b.ResetTimer()
	for range b.N {
		_ = ntohs(port)
	}
}

func BenchmarkNewTCPSocket4(b *testing.B) {
	for range b.N {
		sock, err := NewTCPSocket4()
		if err != nil {
			b.Fatal(err)
		}
		sock.Close()
	}
}

func BenchmarkNewUDPSocket4(b *testing.B) {
	for range b.N {
		sock, err := NewUDPSocket4()
		if err != nil {
			b.Fatal(err)
		}
		sock.Close()
	}
}

func BenchmarkNewUnixStreamSocket(b *testing.B) {
	for range b.N {
		sock, err := NewUnixStreamSocket()
		if err != nil {
			b.Fatal(err)
		}
		sock.Close()
	}
}

func BenchmarkUnixSocketPair(b *testing.B) {
	for range b.N {
		socks, err := UnixSocketPair()
		if err != nil {
			b.Fatal(err)
		}
		socks[0].Close()
		socks[1].Close()
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
	buf := make([]byte, 16)
	b.ResetTimer()

	for range b.N {
		_, _ = socks[0].Write(data)
		_, _ = socks[1].Read(buf)
	}
}

func BenchmarkZoneToScopeID(b *testing.B) {
	zone := "42"
	b.ResetTimer()
	for range b.N {
		_ = zoneToScopeID(zone)
	}
}

func BenchmarkScopeIDToZone(b *testing.B) {
	id := uint32(42)
	b.ResetTimer()
	for range b.N {
		_ = scopeIDToZone(id)
	}
}

func BenchmarkIP4AddressToBytes(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	b.ResetTimer()
	for range b.N {
		_ = IP4AddressToBytes(ip)
	}
}

func BenchmarkIP6AddressToBytes(b *testing.B) {
	ip := net.ParseIP("fe80::1")
	b.ResetTimer()
	for range b.N {
		_ = IP6AddressToBytes(ip)
	}
}
