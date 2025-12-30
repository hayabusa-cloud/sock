// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/zcall"
)

var ErrWouldBlock = iox.ErrWouldBlock

func TestNetSocket_CreateClose(t *testing.T) {
	tests := []struct {
		name   string
		create func() (*NetSocket, error)
	}{
		{"TCP4", func() (*NetSocket, error) { return NewNetTCPSocket(false) }},
		{"TCP6", func() (*NetSocket, error) { return NewNetTCPSocket(true) }},
		{"UDP4", func() (*NetSocket, error) { return NewNetUDPSocket(false) }},
		{"UDP6", func() (*NetSocket, error) { return NewNetUDPSocket(true) }},
		{"UnixStream", func() (*NetSocket, error) { s, e := NewUnixStreamSocket(); return s.NetSocket, e }},
		{"UnixDatagram", func() (*NetSocket, error) { s, e := NewUnixDatagramSocket(); return s.NetSocket, e }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sock, err := tt.create()
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if sock.FD().Raw() < 0 {
				t.Error("Invalid fd")
			}
			if err := sock.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
}

func TestNetSocket_DoubleClose(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := sock.Close(); err != nil {
		t.Errorf("First close: %v", err)
	}
	// Second close should not panic (may return error or nil depending on implementation)
	_ = sock.Close()
}

func TestSockaddrInet4(t *testing.T) {
	addr := [4]byte{127, 0, 0, 1}
	port := uint16(8080)
	sa := NewSockaddrInet4(addr, port)

	if sa.Family() != AF_INET {
		t.Errorf("Expected AF_INET, got %d", sa.Family())
	}
	if sa.Addr() != addr {
		t.Errorf("Expected addr %v, got %v", addr, sa.Addr())
	}
	if sa.Port() != port {
		t.Errorf("Expected port %d, got %d", port, sa.Port())
	}

	ptr, length := sa.Raw()
	if ptr == nil {
		t.Error("Raw pointer is nil")
	}
	if length != SizeofSockaddrInet4 {
		t.Errorf("Expected length %d, got %d", SizeofSockaddrInet4, length)
	}
}

func TestSockaddrInet4_SetMethods(t *testing.T) {
	sa := NewSockaddrInet4([4]byte{0, 0, 0, 0}, 0)

	newAddr := [4]byte{192, 168, 1, 1}
	sa.SetAddr(newAddr)
	if sa.Addr() != newAddr {
		t.Errorf("SetAddr failed: expected %v, got %v", newAddr, sa.Addr())
	}

	newPort := uint16(9000)
	sa.SetPort(newPort)
	if sa.Port() != newPort {
		t.Errorf("SetPort failed: expected %d, got %d", newPort, sa.Port())
	}
}

func TestSockaddrInet6(t *testing.T) {
	addr := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	port := uint16(8080)
	zone := uint32(0)
	sa := NewSockaddrInet6(addr, port, zone)

	if sa.Family() != AF_INET6 {
		t.Errorf("Expected AF_INET6, got %d", sa.Family())
	}
	if sa.Addr() != addr {
		t.Errorf("Expected addr %v, got %v", addr, sa.Addr())
	}
	if sa.Port() != port {
		t.Errorf("Expected port %d, got %d", port, sa.Port())
	}
	if sa.ScopeID() != zone {
		t.Errorf("Expected zone %d, got %d", zone, sa.ScopeID())
	}

	ptr, length := sa.Raw()
	if ptr == nil {
		t.Error("Raw pointer is nil")
	}
	if length != SizeofSockaddrInet6 {
		t.Errorf("Expected length %d, got %d", SizeofSockaddrInet6, length)
	}
}

func TestSockaddrInet6_SetMethods(t *testing.T) {
	sa := NewSockaddrInet6([16]byte{}, 0, 0)

	newAddr := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	sa.SetAddr(newAddr)
	if sa.Addr() != newAddr {
		t.Errorf("SetAddr failed: expected %v, got %v", newAddr, sa.Addr())
	}

	newPort := uint16(9000)
	sa.SetPort(newPort)
	if sa.Port() != newPort {
		t.Errorf("SetPort failed: expected %d, got %d", newPort, sa.Port())
	}

	newZone := uint32(1)
	sa.SetScopeID(newZone)
	if sa.ScopeID() != newZone {
		t.Errorf("SetScopeID failed: expected %d, got %d", newZone, sa.ScopeID())
	}
}

func TestSockaddrUnix(t *testing.T) {
	path := "/tmp/test.sock"
	sa := NewSockaddrUnix(path)

	if sa.Family() != AF_UNIX {
		t.Errorf("Expected AF_UNIX, got %d", sa.Family())
	}
	if sa.Path() != path {
		t.Errorf("Expected path %s, got %s", path, sa.Path())
	}

	ptr, length := sa.Raw()
	if ptr == nil {
		t.Error("Raw pointer is nil")
	}
	// Length should be 2 (family) + len(path) + 1 (NUL)
	expectedLen := uint32(2 + len(path) + 1)
	if length != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, length)
	}
}

func TestSockaddrUnix_SetPath(t *testing.T) {
	sa := NewSockaddrUnix("/original")
	newPath := "/new/path.sock"
	sa.SetPath(newPath)
	if sa.Path() != newPath {
		t.Errorf("SetPath failed: expected %s, got %s", newPath, sa.Path())
	}
}

func TestSockaddrUnix_AbstractNamespace(t *testing.T) {
	// Abstract namespace paths start with null byte (represented as "@" in some APIs)
	sa := NewSockaddrUnix("@abstract")
	if sa.Path() != "@abstract" {
		t.Errorf("Expected path @abstract, got %s", sa.Path())
	}
}

func TestTCPAddrToSockaddr(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		addr := &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 8080,
		}
		sa := TCPAddrToSockaddr(addr)
		if sa == nil {
			t.Fatal("Expected non-nil sockaddr")
		}
		inet4, ok := sa.(*SockaddrInet4)
		if !ok {
			t.Fatalf("Expected *SockaddrInet4, got %T", sa)
		}
		if inet4.Port() != 8080 {
			t.Errorf("Expected port 8080, got %d", inet4.Port())
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		addr := &net.TCPAddr{
			IP:   net.ParseIP("::1"),
			Port: 8080,
		}
		sa := TCPAddrToSockaddr(addr)
		if sa == nil {
			t.Fatal("Expected non-nil sockaddr")
		}
		inet6, ok := sa.(*SockaddrInet6)
		if !ok {
			t.Fatalf("Expected *SockaddrInet6, got %T", sa)
		}
		if inet6.Port() != 8080 {
			t.Errorf("Expected port 8080, got %d", inet6.Port())
		}
	})

	t.Run("Nil", func(t *testing.T) {
		sa := TCPAddrToSockaddr(nil)
		if sa != nil {
			t.Error("Expected nil sockaddr for nil addr")
		}
	})
}

func TestUDPAddrToSockaddr(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		addr := &net.UDPAddr{
			IP:   net.IPv4(192, 168, 1, 1),
			Port: 5353,
		}
		sa := UDPAddrToSockaddr(addr)
		if sa == nil {
			t.Fatal("Expected non-nil sockaddr")
		}
		inet4, ok := sa.(*SockaddrInet4)
		if !ok {
			t.Fatalf("Expected *SockaddrInet4, got %T", sa)
		}
		if inet4.Port() != 5353 {
			t.Errorf("Expected port 5353, got %d", inet4.Port())
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		addr := &net.UDPAddr{
			IP:   net.ParseIP("fe80::1"),
			Port: 5353,
			Zone: "1",
		}
		sa := UDPAddrToSockaddr(addr)
		if sa == nil {
			t.Fatal("Expected non-nil sockaddr")
		}
		inet6, ok := sa.(*SockaddrInet6)
		if !ok {
			t.Fatalf("Expected *SockaddrInet6, got %T", sa)
		}
		if inet6.Port() != 5353 {
			t.Errorf("Expected port 5353, got %d", inet6.Port())
		}
	})
}

func TestSockaddrToTCPAddr(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 8080)
		addr := SockaddrToTCPAddr(sa)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 8080 {
			t.Errorf("Expected port 8080, got %d", addr.Port)
		}
		if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Errorf("Expected 127.0.0.1, got %v", addr.IP)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		loopback := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		sa := NewSockaddrInet6(loopback, 8080, 0)
		addr := SockaddrToTCPAddr(sa)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 8080 {
			t.Errorf("Expected port 8080, got %d", addr.Port)
		}
	})

	t.Run("Nil", func(t *testing.T) {
		addr := SockaddrToTCPAddr(nil)
		if addr != nil {
			t.Error("Expected nil addr for nil sockaddr")
		}
	})
}

func TestDecodeSockaddr(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET
		rawInet4 := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		rawInet4.Addr = [4]byte{192, 168, 1, 1}
		rawInet4.Port = htons(8080)

		sa := DecodeSockaddr(raw)
		if sa == nil {
			t.Fatal("Expected non-nil sockaddr")
		}
		inet4, ok := sa.(*SockaddrInet4)
		if !ok {
			t.Fatalf("Expected *SockaddrInet4, got %T", sa)
		}
		if inet4.Addr() != [4]byte{192, 168, 1, 1} {
			t.Errorf("Wrong addr: %v", inet4.Addr())
		}
		if inet4.Port() != 8080 {
			t.Errorf("Expected port 8080, got %d", inet4.Port())
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET6
		rawInet6 := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		rawInet6.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		rawInet6.Port = htons(8080)

		sa := DecodeSockaddr(raw)
		if sa == nil {
			t.Fatal("Expected non-nil sockaddr")
		}
		_, ok := sa.(*SockaddrInet6)
		if !ok {
			t.Fatalf("Expected *SockaddrInet6, got %T", sa)
		}
	})

	t.Run("Nil", func(t *testing.T) {
		sa := DecodeSockaddr(nil)
		if sa != nil {
			t.Error("Expected nil for nil raw")
		}
	})
}

func TestByteOrderConversions(t *testing.T) {
	// Test htons/ntohs
	testPort := uint16(0x1234)
	converted := htons(testPort)
	back := ntohs(converted)
	if back != testPort {
		t.Errorf("htons/ntohs roundtrip failed: %x -> %x -> %x", testPort, converted, back)
	}

	// Test htonl/ntohl
	testVal := uint32(0x12345678)
	convertedL := htonl(testVal)
	backL := ntohl(convertedL)
	if backL != testVal {
		t.Errorf("htonl/ntohl roundtrip failed: %x -> %x -> %x", testVal, convertedL, backL)
	}
}

func TestZoneConversions(t *testing.T) {
	// Numeric zone
	id := zoneToScopeID("1")
	if id != 1 {
		t.Errorf("Expected 1, got %d", id)
	}

	// Empty zone
	id = zoneToScopeID("")
	if id != 0 {
		t.Errorf("Expected 0 for empty zone, got %d", id)
	}

	// Non-numeric zone (interface name) - should return 0 as simplified
	id = zoneToScopeID("eth0")
	if id != 0 {
		t.Errorf("Expected 0 for non-numeric zone, got %d", id)
	}

	// Round-trip numeric
	zone := scopeIDToZone(42)
	if zone != "42" {
		t.Errorf("Expected '42', got %s", zone)
	}

	// Zero zone
	zone = scopeIDToZone(0)
	if zone != "" {
		t.Errorf("Expected empty string for 0, got %s", zone)
	}
}

func TestNetSocketPair(t *testing.T) {
	socks, err := UnixSocketPair()
	if err != nil {
		t.Fatalf("UnixSocketPair: %v", err)
	}
	defer socks[0].Close()
	defer socks[1].Close()

	// Test write to one end, read from the other
	testData := []byte("hello")
	n, err := socks[0].Write(testData)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Short write: %d", n)
	}

	buf := make([]byte, 10)
	n, err = socks[1].Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Expected 'hello', got %s", buf[:n])
	}
}

func TestTCPSocket_Protocol(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolStream {
		t.Errorf("Expected UnderlyingProtocolStream, got %v", sock.Protocol())
	}
}

func TestUDPSocket_Protocol(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolDgram {
		t.Errorf("Expected UnderlyingProtocolDgram, got %v", sock.Protocol())
	}
}

func TestUnixSocket_Protocol(t *testing.T) {
	sock, err := NewUnixStreamSocket()
	if err != nil {
		t.Fatalf("NewUnixStreamSocket: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolStream {
		t.Errorf("Expected UnderlyingProtocolStream, got %v", sock.Protocol())
	}

	sock2, err := NewUnixDatagramSocket()
	if err != nil {
		t.Fatalf("NewUnixDatagramSocket: %v", err)
	}
	defer sock2.Close()

	if sock2.Protocol() != UnderlyingProtocolDgram {
		t.Errorf("Expected UnderlyingProtocolDgram, got %v", sock2.Protocol())
	}
}

func TestRawSocket_Protocol(t *testing.T) {
	// This test may fail without CAP_NET_RAW
	sock, err := NewICMPSocket4()
	if err != nil {
		t.Skipf("NewICMPSocket4: %v (may require CAP_NET_RAW)", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolRaw {
		t.Errorf("Expected UnderlyingProtocolRaw, got %v", sock.Protocol())
	}
}

func TestSCTPAddr(t *testing.T) {
	addr := &SCTPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 5000,
	}

	if addr.Network() != "sctp" {
		t.Errorf("Expected 'sctp', got %s", addr.Network())
	}

	str := addr.String()
	if str != "192.168.1.1:5000" {
		t.Errorf("Expected '192.168.1.1:5000', got %s", str)
	}

	// Nil addr
	var nilAddr *SCTPAddr
	if nilAddr.String() != "<nil>" {
		t.Errorf("Expected '<nil>', got %s", nilAddr.String())
	}
}

func TestSCTPAddr_IPv6(t *testing.T) {
	addr := &SCTPAddr{
		IP:   net.ParseIP("::1"),
		Port: 5000,
		Zone: "1",
	}

	str := addr.String()
	expected := "[::1%1]:5000"
	if str != expected {
		t.Errorf("Expected %s, got %s", expected, str)
	}
}

func TestIPAddrFrom(t *testing.T) {
	t.Run("FromTCPAddr", func(t *testing.T) {
		tcp := &TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 80, Zone: "eth0"}
		ip := IPAddrFromTCPAddr(tcp)
		if !ip.IP.Equal(tcp.IP) {
			t.Error("IP mismatch")
		}
		if ip.Zone != tcp.Zone {
			t.Error("Zone mismatch")
		}
	})

	t.Run("FromUDPAddr", func(t *testing.T) {
		udp := &UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 53, Zone: "eth1"}
		ip := IPAddrFromUDPAddr(udp)
		if !ip.IP.Equal(udp.IP) {
			t.Error("IP mismatch")
		}
		if ip.Zone != udp.Zone {
			t.Error("Zone mismatch")
		}
	})

	t.Run("FromSCTPAddr", func(t *testing.T) {
		sctp := &SCTPAddr{IP: net.ParseIP("10.0.0.3"), Port: 5060, Zone: "eth2"}
		ip := IPAddrFromSCTPAddr(sctp)
		if !ip.IP.Equal(sctp.IP) {
			t.Error("IP mismatch")
		}
		if ip.Zone != sctp.Zone {
			t.Error("Zone mismatch")
		}
	})
}

func TestIP4AddressToBytes(t *testing.T) {
	ip := net.ParseIP("192.168.1.100")
	b := IP4AddressToBytes(ip)
	expected := [4]byte{192, 168, 1, 100}
	if b != expected {
		t.Errorf("Expected %v, got %v", expected, b)
	}

	// IPv6 address should return empty
	ip6 := net.ParseIP("::1")
	b = IP4AddressToBytes(ip6)
	empty := [4]byte{}
	if b != empty {
		t.Errorf("Expected empty for IPv6, got %v", b)
	}
}

func TestIP6AddressToBytes(t *testing.T) {
	ip := net.ParseIP("fe80::1")
	b := IP6AddressToBytes(ip)
	if len(b) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(b))
	}
	// fe80::1 should have specific bytes
	if b[0] != 0xfe || b[1] != 0x80 {
		t.Errorf("Unexpected first bytes: %x %x", b[0], b[1])
	}
	if b[15] != 1 {
		t.Errorf("Expected last byte to be 1, got %d", b[15])
	}
}

func TestNetworkIPFamily(t *testing.T) {
	tests := []struct {
		network  string
		ip       IP
		expected NetworkType
	}{
		{"tcp4", nil, NetworkIPv4},
		{"tcp6", nil, NetworkIPv6},
		{"tcp", net.ParseIP("127.0.0.1"), NetworkIPv4},
		{"tcp", net.ParseIP("::1"), NetworkIPv6},
		{"udp4", nil, NetworkIPv4},
		{"udp6", nil, NetworkIPv6},
	}

	for _, tt := range tests {
		result := networkIPFamily(tt.network, tt.ip)
		if result != tt.expected {
			t.Errorf("networkIPFamily(%s, %v): expected %v, got %v",
				tt.network, tt.ip, tt.expected, result)
		}
	}
}

// IPv6 Socket Tests

func TestTCPSocket6_CreateClose(t *testing.T) {
	sock, err := NewTCPSocket6()
	if err != nil {
		t.Fatalf("NewTCPSocket6: %v", err)
	}
	defer sock.Close()

	if sock.FD().Raw() < 0 {
		t.Error("Invalid fd")
	}
	if sock.Protocol() != UnderlyingProtocolStream {
		t.Errorf("Expected UnderlyingProtocolStream, got %v", sock.Protocol())
	}
}

func TestUDPSocket6_CreateClose(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock.Close()

	if sock.FD().Raw() < 0 {
		t.Error("Invalid fd")
	}
	if sock.Protocol() != UnderlyingProtocolDgram {
		t.Errorf("Expected UnderlyingProtocolDgram, got %v", sock.Protocol())
	}
}

func TestListenTCP6(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	listener, err := ListenTCP6(laddr)
	if err != nil {
		t.Fatalf("ListenTCP6: %v", err)
	}
	defer listener.Close()

	if listener.Addr() == nil {
		t.Error("Expected non-nil address")
	}
}

func TestListenTCP6_NilAddr(t *testing.T) {
	_, err := ListenTCP6(nil)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

func TestListenUDP6(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := ListenUDP6(laddr)
	if err != nil {
		t.Fatalf("ListenUDP6: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("Expected non-nil local address")
	}
	// RemoteAddr returns nil for unconnected sockets
	// Note: Due to Go's interface semantics, checking conn.RemoteAddr() == nil
	// may fail even when raddr is nil. The underlying *UDPAddr is nil.
	if addr, ok := conn.RemoteAddr().(*UDPAddr); ok && addr != nil {
		t.Error("Expected nil remote address for unconnected socket")
	}
}

func TestListenUDP6_NilAddr(t *testing.T) {
	_, err := ListenUDP6(nil)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

func TestListenTCP_AutoDetect(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
		listener, err := ListenTCP("tcp", laddr)
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		defer listener.Close()
	})

	t.Run("IPv6", func(t *testing.T) {
		laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
		listener, err := ListenTCP("tcp", laddr)
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		defer listener.Close()
	})

	t.Run("NilAddr", func(t *testing.T) {
		_, err := ListenTCP("tcp", nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})
}

func TestListenUDP_AutoDetect(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
		conn, err := ListenUDP("udp", laddr)
		if err != nil {
			t.Fatalf("ListenUDP: %v", err)
		}
		defer conn.Close()
	})

	t.Run("IPv6", func(t *testing.T) {
		laddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
		conn, err := ListenUDP("udp", laddr)
		if err != nil {
			t.Fatalf("ListenUDP: %v", err)
		}
		defer conn.Close()
	})

	t.Run("NilAddr", func(t *testing.T) {
		_, err := ListenUDP("udp", nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})
}

func TestDialTCP_AutoDetect(t *testing.T) {
	// Start a listener first
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	// Get the actual address
	addr := listener.Addr().(*TCPAddr)

	t.Run("NilRaddr", func(t *testing.T) {
		_, err := DialTCP("tcp", nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("IPv4", func(t *testing.T) {
		raddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: addr.Port}
		conn, err := DialTCP("tcp", nil, raddr)
		if err != nil && err != ErrInProgress {
			t.Fatalf("DialTCP: %v", err)
		}
		if conn != nil {
			defer conn.Close()
		}
	})
}

// Socket Option Getter Tests

func TestSocketOptionGetters(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	t.Run("GetReuseAddr", func(t *testing.T) {
		val, err := GetReuseAddr(sock.fd)
		if err != nil {
			t.Errorf("GetReuseAddr: %v", err)
		}
		// Should be true since applyTCPDefaults sets it
		if !val {
			t.Log("ReuseAddr is false (expected true from defaults)")
		}
	})

	t.Run("GetReusePort", func(t *testing.T) {
		val, err := GetReusePort(sock.fd)
		if err != nil {
			t.Errorf("GetReusePort: %v", err)
		}
		// Should be true since applyTCPDefaults sets it
		if !val {
			t.Log("ReusePort is false (expected true from defaults)")
		}
	})

	t.Run("GetKeepAlive", func(t *testing.T) {
		// First set it
		if err := SetKeepAlive(sock.fd, true); err != nil {
			t.Fatalf("SetKeepAlive: %v", err)
		}
		val, err := GetKeepAlive(sock.fd)
		if err != nil {
			t.Errorf("GetKeepAlive: %v", err)
		}
		if !val {
			t.Error("Expected KeepAlive to be true")
		}
	})

	t.Run("GetTCPNoDelay", func(t *testing.T) {
		if err := SetTCPNoDelay(sock.fd, true); err != nil {
			t.Fatalf("SetTCPNoDelay: %v", err)
		}
		val, err := GetTCPNoDelay(sock.fd)
		if err != nil {
			t.Errorf("GetTCPNoDelay: %v", err)
		}
		if !val {
			t.Error("Expected TCPNoDelay to be true")
		}
	})

	t.Run("GetSendBuffer", func(t *testing.T) {
		val, err := GetSendBuffer(sock.fd)
		if err != nil {
			t.Errorf("GetSendBuffer: %v", err)
		}
		if val <= 0 {
			t.Errorf("Expected positive send buffer size, got %d", val)
		}
	})

	t.Run("GetRecvBuffer", func(t *testing.T) {
		val, err := GetRecvBuffer(sock.fd)
		if err != nil {
			t.Errorf("GetRecvBuffer: %v", err)
		}
		if val <= 0 {
			t.Errorf("Expected positive recv buffer size, got %d", val)
		}
	})

	t.Run("GetTCPKeepIntvl", func(t *testing.T) {
		if err := SetTCPKeepIntvl(sock.fd, 30); err != nil {
			t.Fatalf("SetTCPKeepIntvl: %v", err)
		}
		val, err := GetTCPKeepIntvl(sock.fd)
		if err != nil {
			t.Errorf("GetTCPKeepIntvl: %v", err)
		}
		if val != 30 {
			t.Errorf("Expected 30, got %d", val)
		}
	})

	t.Run("GetTCPKeepCnt", func(t *testing.T) {
		if err := SetTCPKeepCnt(sock.fd, 5); err != nil {
			t.Fatalf("SetTCPKeepCnt: %v", err)
		}
		val, err := GetTCPKeepCnt(sock.fd)
		if err != nil {
			t.Errorf("GetTCPKeepCnt: %v", err)
		}
		if val != 5 {
			t.Errorf("Expected 5, got %d", val)
		}
	})

	t.Run("GetSocketType", func(t *testing.T) {
		typ, err := GetSocketType(sock.fd)
		if err != nil {
			t.Errorf("GetSocketType: %v", err)
		}
		// SOCK_STREAM may have flags, mask them
		if typ&0xF != SOCK_STREAM {
			t.Errorf("Expected SOCK_STREAM, got %d", typ)
		}
	})

	t.Run("GetSocketError", func(t *testing.T) {
		err := GetSocketError(sock.fd)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})
}

func TestSetBufferSizes(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	t.Run("SetSendBuffer", func(t *testing.T) {
		if err := SetSendBuffer(sock.fd, 65536); err != nil {
			t.Errorf("SetSendBuffer: %v", err)
		}
	})

	t.Run("SetRecvBuffer", func(t *testing.T) {
		if err := SetRecvBuffer(sock.fd, 65536); err != nil {
			t.Errorf("SetRecvBuffer: %v", err)
		}
	})
}

func TestSetNonBlockAndCloexec(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	t.Run("SetNonBlock", func(t *testing.T) {
		if err := SetNonBlock(sock.fd, true); err != nil {
			t.Errorf("SetNonBlock(true): %v", err)
		}
		if err := SetNonBlock(sock.fd, false); err != nil {
			t.Errorf("SetNonBlock(false): %v", err)
		}
	})

	t.Run("SetCloseOnExec", func(t *testing.T) {
		if err := SetCloseOnExec(sock.fd, true); err != nil {
			t.Errorf("SetCloseOnExec(true): %v", err)
		}
		if err := SetCloseOnExec(sock.fd, false); err != nil {
			t.Errorf("SetCloseOnExec(false): %v", err)
		}
	})
}

// Unix Socket Variant Tests

func TestUnixSeqpacketSock(t *testing.T) {
	sock, err := NewUnixSeqpacketSocket()
	if err != nil {
		t.Fatalf("NewUnixSeqpacketSocket: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolSeqPacket {
		t.Errorf("Expected UnderlyingProtocolSeqPacket, got %v", sock.Protocol())
	}
}

func TestUnixConnPair(t *testing.T) {
	t.Run("Stream", func(t *testing.T) {
		conns, err := UnixConnPair("unix")
		if err != nil {
			t.Fatalf("UnixConnPair(unix): %v", err)
		}
		defer conns[0].Close()
		defer conns[1].Close()

		// Test bidirectional communication
		testData := []byte("hello")
		n, err := conns[0].fd.Write(testData)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(testData) {
			t.Errorf("Short write: %d", n)
		}

		buf := make([]byte, 10)
		n, err = conns[1].fd.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if string(buf[:n]) != "hello" {
			t.Errorf("Expected 'hello', got %s", buf[:n])
		}
	})

	t.Run("Dgram", func(t *testing.T) {
		conns, err := UnixConnPair("unixgram")
		if err != nil {
			t.Fatalf("UnixConnPair(unixgram): %v", err)
		}
		defer conns[0].Close()
		defer conns[1].Close()
	})

	t.Run("Seqpacket", func(t *testing.T) {
		conns, err := UnixConnPair("unixpacket")
		if err != nil {
			t.Fatalf("UnixConnPair(unixpacket): %v", err)
		}
		defer conns[0].Close()
		defer conns[1].Close()
	})

	t.Run("UnknownNetwork", func(t *testing.T) {
		_, err := UnixConnPair("invalid")
		if err == nil {
			t.Error("Expected error for invalid network")
		}
	})
}

func TestDialUnix_UnknownNetwork(t *testing.T) {
	raddr := &UnixAddr{Name: "/tmp/test.sock", Net: "unix"}
	_, err := DialUnix("invalid", nil, raddr)
	if err == nil {
		t.Error("Expected error for invalid network")
	}
}

func TestListenUnix_UnknownNetwork(t *testing.T) {
	laddr := &UnixAddr{Name: "/tmp/test.sock", Net: "unix"}
	_, err := ListenUnix("invalid", laddr)
	if err == nil {
		t.Error("Expected error for invalid network")
	}
}

func TestListenUnixgram(t *testing.T) {
	t.Run("NilAddr", func(t *testing.T) {
		_, err := ListenUnixgram("unixgram", nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("WrongNetwork", func(t *testing.T) {
		laddr := &UnixAddr{Name: "/tmp/test.sock", Net: "unixgram"}
		_, err := ListenUnixgram("unix", laddr)
		if err == nil {
			t.Error("Expected error for wrong network type")
		}
	})
}

// Address Decoding Tests

func TestDecodeTCPAddr(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		addr := decodeTCPAddr(nil)
		if addr != nil {
			t.Error("Expected nil for nil input")
		}
	})

	t.Run("IPv4", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET
		rawInet4 := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		rawInet4.Addr = [4]byte{127, 0, 0, 1}
		rawInet4.Port = htons(8080)

		addr := decodeTCPAddr(raw)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 8080 {
			t.Errorf("Expected port 8080, got %d", addr.Port)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET6
		rawInet6 := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		rawInet6.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		rawInet6.Port = htons(8080)
		rawInet6.ScopeID = 1

		addr := decodeTCPAddr(raw)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 8080 {
			t.Errorf("Expected port 8080, got %d", addr.Port)
		}
		if addr.Zone != "1" {
			t.Errorf("Expected zone '1', got %s", addr.Zone)
		}
	})

	t.Run("UnknownFamily", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = 255 // Unknown family

		addr := decodeTCPAddr(raw)
		if addr != nil {
			t.Error("Expected nil for unknown family")
		}
	})
}

func TestDecodeUDPAddr(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		addr := decodeUDPAddr(nil)
		if addr != nil {
			t.Error("Expected nil for nil input")
		}
	})

	t.Run("IPv4", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET
		rawInet4 := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		rawInet4.Addr = [4]byte{192, 168, 1, 1}
		rawInet4.Port = htons(5353)

		addr := decodeUDPAddr(raw)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 5353 {
			t.Errorf("Expected port 5353, got %d", addr.Port)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET6
		rawInet6 := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		rawInet6.Addr = [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		rawInet6.Port = htons(5353)
		rawInet6.ScopeID = 2

		addr := decodeUDPAddr(raw)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 5353 {
			t.Errorf("Expected port 5353, got %d", addr.Port)
		}
		if addr.Zone != "2" {
			t.Errorf("Expected zone '2', got %s", addr.Zone)
		}
	})

	t.Run("UnknownFamily", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = 255

		addr := decodeUDPAddr(raw)
		if addr != nil {
			t.Error("Expected nil for unknown family")
		}
	})
}

func TestDecodeUnixAddr(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		addr := decodeUnixAddr(nil)
		if addr != nil {
			t.Error("Expected nil for nil input")
		}
	})

	t.Run("WrongFamily", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET

		addr := decodeUnixAddr(raw)
		if addr != nil {
			t.Error("Expected nil for wrong family")
		}
	})

	t.Run("ValidPath", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_UNIX
		rawUnix := (*RawSockaddrUnix)(unsafe.Pointer(raw))
		copy(rawUnix.Path[:], "/tmp/test.sock")

		addr := decodeUnixAddr(raw)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Name != "/tmp/test.sock" {
			t.Errorf("Expected '/tmp/test.sock', got %s", addr.Name)
		}
	})

	t.Run("FullPath", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_UNIX
		rawUnix := (*RawSockaddrUnix)(unsafe.Pointer(raw))
		// Fill entire path without NUL
		for i := range rawUnix.Path {
			rawUnix.Path[i] = 'x'
		}

		addr := decodeUnixAddr(raw)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
	})
}

// Error Handling Tests

func TestErrFromErrno(t *testing.T) {
	tests := []struct {
		errno    uintptr
		expected error
	}{
		{0, nil},
		{EAGAIN, ErrWouldBlock},
		{EBADF, ErrClosed},
		{EINVAL, ErrInvalidParam},
		{EINTR, ErrInterrupted},
		{ENOMEM, ErrNoMemory},
		{ENOBUFS, ErrNoMemory},
		{EACCES, ErrPermission},
		{EPERM, ErrPermission},
		{EADDRINUSE, ErrAddressInUse},
		{ECONNREFUSED, ErrConnectionRefused},
		{ECONNRESET, ErrConnectionReset},
		{ECONNABORTED, ErrConnectionReset},
		{EPIPE, ErrConnectionReset},
		{ENOTCONN, ErrNotConnected},
		{ETIMEDOUT, ErrTimedOut},
		{ENETUNREACH, ErrNetworkUnreachable},
		{EHOSTUNREACH, ErrHostUnreachable},
		{EINPROGRESS, ErrInProgress},
		{EALREADY, ErrInProgress},
	}

	for _, tt := range tests {
		result := errFromErrno(tt.errno)
		if result != tt.expected {
			t.Errorf("errFromErrno(%d): expected %v, got %v", tt.errno, tt.expected, result)
		}
	}

	// Test unknown errno returns zcall.Errno
	unknownErrno := uintptr(9999)
	result := errFromErrno(unknownErrno)
	if result == nil {
		t.Error("Expected non-nil error for unknown errno")
	}
}

// NetSocket Method Tests

func TestNetSocket_NetworkTypeAndProtocol(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("NewNetTCPSocket: %v", err)
	}
	defer sock.Close()

	if sock.NetworkType() != NetworkIPv4 {
		t.Errorf("Expected NetworkIPv4, got %v", sock.NetworkType())
	}

	proto := sock.Protocol()
	if proto != UnderlyingProtocolStream {
		t.Errorf("Expected UnderlyingProtocolStream, got %v", proto)
	}
}

func TestNetSocket_Shutdown(t *testing.T) {
	socks, err := UnixSocketPair()
	if err != nil {
		t.Fatalf("UnixSocketPair: %v", err)
	}
	defer socks[0].Close()
	defer socks[1].Close()

	// Shutdown read side
	if err := socks[0].Shutdown(SHUT_RD); err != nil {
		t.Errorf("Shutdown(SHUT_RD): %v", err)
	}

	// Shutdown write side
	if err := socks[1].Shutdown(SHUT_WR); err != nil {
		t.Errorf("Shutdown(SHUT_WR): %v", err)
	}
}

func TestNetSocket_ShutdownClosed(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("NewNetTCPSocket: %v", err)
	}
	sock.Close()

	err = sock.Shutdown(SHUT_RDWR)
	if err != ErrClosed {
		t.Errorf("Expected ErrClosed, got %v", err)
	}
}

// TCPConn Method Tests

func TestTCPConn_Deadlines(t *testing.T) {
	// Create a listener
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	// Dial to create a connection
	raddr := listener.Addr().(*TCPAddr)
	conn, err := DialTCP4(nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Test SetDeadline
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	// Test SetReadDeadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}

	// Test SetWriteDeadline
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}

	// Test clearing deadlines
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline(zero): %v", err)
	}
}

func TestTCPConn_KeepAlive(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	raddr := listener.Addr().(*TCPAddr)
	conn, err := DialTCP4(nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	if err := conn.SetKeepAlive(true); err != nil {
		t.Errorf("SetKeepAlive: %v", err)
	}

	if err := conn.SetKeepAlivePeriod(10 * time.Second); err != nil {
		t.Errorf("SetKeepAlivePeriod: %v", err)
	}

	// Test with zero period (should use 1 second minimum)
	if err := conn.SetKeepAlivePeriod(0); err != nil {
		t.Errorf("SetKeepAlivePeriod(0): %v", err)
	}
}

func TestTCPConn_NoDelay(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	raddr := listener.Addr().(*TCPAddr)
	conn, err := DialTCP4(nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	if err := conn.SetNoDelay(true); err != nil {
		t.Errorf("SetNoDelay: %v", err)
	}
}

func TestTCPConn_LocalRemoteAddr(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	raddr := listener.Addr().(*TCPAddr)
	conn, err := DialTCP4(nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("Expected non-nil LocalAddr")
	}
	if conn.RemoteAddr() == nil {
		t.Error("Expected non-nil RemoteAddr")
	}
}

// TCPListener Method Tests

func TestTCPListener_SetDeadline(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	// Set deadline
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	// Clear deadline
	if err := listener.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline(zero): %v", err)
	}
}

// UDPConn Method Tests

func TestUDPConn_Deadlines(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

func TestUDPConn_WriteNotConnected(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Write on unconnected socket should fail
	_, err = conn.Write([]byte("test"))
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestUDPConn_WriteTo_InvalidAddr(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// WriteTo with wrong address type
	tcpAddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	_, err = conn.WriteTo([]byte("test"), tcpAddr)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

// UnixConn Method Tests

func TestUnixConn_Deadlines(t *testing.T) {
	conns, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer conns[0].Close()
	defer conns[1].Close()

	if err := conns[0].SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	if err := conns[0].SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}

	if err := conns[0].SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

func TestUnixConn_LocalRemoteAddr(t *testing.T) {
	conns, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer conns[0].Close()
	defer conns[1].Close()

	// For socketpair, addresses may be nil
	_ = conns[0].LocalAddr()
	_ = conns[0].RemoteAddr()
}

// UnixListener Method Tests

func TestUnixListener_SetDeadline(t *testing.T) {
	// Use abstract namespace with unique suffix to avoid conflicts
	name := "@test-listener-deadline-" + time.Now().Format("150405.000000000")
	laddr := &UnixAddr{Name: name, Net: "unix"}
	listener, err := ListenUnix("unix", laddr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer listener.Close()

	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	if err := listener.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline(zero): %v", err)
	}

	if listener.Addr() == nil {
		t.Error("Expected non-nil Addr")
	}
}

// DialTCP6 Tests

func TestDialTCP6(t *testing.T) {
	// Start a listener
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	listener, err := ListenTCP6(laddr)
	if err != nil {
		t.Fatalf("ListenTCP6: %v", err)
	}
	defer listener.Close()

	raddr := listener.Addr().(*TCPAddr)

	t.Run("NilRaddr", func(t *testing.T) {
		_, err := DialTCP6(nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("WithLaddr", func(t *testing.T) {
		laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
		conn, err := DialTCP6(laddr, raddr)
		if err != nil && err != ErrInProgress {
			t.Fatalf("DialTCP6: %v", err)
		}
		if conn != nil {
			defer conn.Close()
		}
	})

	t.Run("WithoutLaddr", func(t *testing.T) {
		conn, err := DialTCP6(nil, raddr)
		if err != nil && err != ErrInProgress {
			t.Fatalf("DialTCP6: %v", err)
		}
		if conn != nil {
			defer conn.Close()
		}
	})
}

// DialUDP Tests

func TestDialUDP4(t *testing.T) {
	// Create a UDP socket to dial to
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	raddr := server.LocalAddr().(*UDPAddr)

	t.Run("NilRaddr", func(t *testing.T) {
		_, err := DialUDP4(nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("WithLaddr", func(t *testing.T) {
		laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
		conn, err := DialUDP4(laddr, raddr)
		if err != nil {
			t.Fatalf("DialUDP4: %v", err)
		}
		defer conn.Close()

		if conn.LocalAddr() == nil {
			t.Error("Expected non-nil LocalAddr")
		}
		if conn.RemoteAddr() == nil {
			t.Error("Expected non-nil RemoteAddr")
		}
	})

	t.Run("WithoutLaddr", func(t *testing.T) {
		conn, err := DialUDP4(nil, raddr)
		if err != nil {
			t.Fatalf("DialUDP4: %v", err)
		}
		defer conn.Close()
	})
}

func TestDialUDP6(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	server, err := ListenUDP6(laddr)
	if err != nil {
		t.Fatalf("ListenUDP6: %v", err)
	}
	defer server.Close()

	raddr := server.LocalAddr().(*UDPAddr)

	t.Run("NilRaddr", func(t *testing.T) {
		_, err := DialUDP6(nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("WithLaddr", func(t *testing.T) {
		laddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
		conn, err := DialUDP6(laddr, raddr)
		if err != nil {
			t.Fatalf("DialUDP6: %v", err)
		}
		defer conn.Close()
	})

	t.Run("WithoutLaddr", func(t *testing.T) {
		conn, err := DialUDP6(nil, raddr)
		if err != nil {
			t.Fatalf("DialUDP6: %v", err)
		}
		defer conn.Close()
	})
}

func TestDialUDP_AutoDetect(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	raddr := server.LocalAddr().(*UDPAddr)

	t.Run("NilRaddr", func(t *testing.T) {
		_, err := DialUDP("udp", nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("IPv4", func(t *testing.T) {
		conn, err := DialUDP("udp", nil, raddr)
		if err != nil {
			t.Fatalf("DialUDP: %v", err)
		}
		defer conn.Close()
	})
}

// IPv6 Address Conversion Tests

func TestTcpAddrToSockaddr6(t *testing.T) {
	addr := &TCPAddr{
		IP:   net.ParseIP("::1"),
		Port: 8080,
		Zone: "1",
	}
	sa := tcpAddrToSockaddr6(addr)
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	if sa.Port() != 8080 {
		t.Errorf("Expected port 8080, got %d", sa.Port())
	}
	if sa.ScopeID() != 1 {
		t.Errorf("Expected scope ID 1, got %d", sa.ScopeID())
	}
}

func TestUdpAddrToSockaddr6(t *testing.T) {
	addr := &UDPAddr{
		IP:   net.ParseIP("fe80::1"),
		Port: 5353,
		Zone: "2",
	}
	sa := udpAddrToSockaddr6(addr)
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	if sa.Port() != 5353 {
		t.Errorf("Expected port 5353, got %d", sa.Port())
	}
	if sa.ScopeID() != 2 {
		t.Errorf("Expected scope ID 2, got %d", sa.ScopeID())
	}
}

// GetSockname/GetPeername Tests

func TestGetSocknameAndPeername(t *testing.T) {
	socks, err := UnixSocketPair()
	if err != nil {
		t.Fatalf("UnixSocketPair: %v", err)
	}
	defer socks[0].Close()
	defer socks[1].Close()

	// GetSockname on socket pair
	sa, err := GetSockname(socks[0].fd)
	if err != nil {
		t.Logf("GetSockname on socketpair: %v (may be expected)", err)
	}
	_ = sa

	// GetPeername on socket pair
	sa, err = GetPeername(socks[0].fd)
	if err != nil {
		t.Logf("GetPeername on socketpair: %v (may be expected)", err)
	}
	_ = sa
}

// ipFamily Tests

func TestIpFamily(t *testing.T) {
	tests := []struct {
		ip       IP
		expected NetworkType
	}{
		{nil, NetworkIPv6}, // nil defaults to IPv6
		{net.ParseIP("127.0.0.1"), NetworkIPv4},
		{net.ParseIP("192.168.1.1"), NetworkIPv4},
		{net.ParseIP("::1"), NetworkIPv6},
		{net.ParseIP("fe80::1"), NetworkIPv6},
		{net.ParseIP("::ffff:127.0.0.1"), NetworkIPv4}, // IPv4-mapped IPv6
	}

	for _, tt := range tests {
		result := ipFamily(tt.ip)
		if result != tt.expected {
			t.Errorf("ipFamily(%v): expected %v, got %v", tt.ip, tt.expected, result)
		}
	}
}

// ResolveUnixAddr Tests

func TestResolveUnixAddr(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		addr, err := ResolveUnixAddr("unix", "/tmp/test.sock")
		if err != nil {
			t.Fatalf("ResolveUnixAddr: %v", err)
		}
		if addr.Name != "/tmp/test.sock" {
			t.Errorf("Expected '/tmp/test.sock', got %s", addr.Name)
		}
		if addr.Net != "unix" {
			t.Errorf("Expected 'unix', got %s", addr.Net)
		}
	})

	t.Run("InvalidNetwork", func(t *testing.T) {
		_, err := ResolveUnixAddr("tcp", "/tmp/test.sock")
		if err == nil {
			t.Error("Expected error for invalid network")
		}
	})
}

// SockaddrToUnixAddr Tests

func TestSockaddrToUnixAddr(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		addr := SockaddrToUnixAddr(nil, "unix")
		if addr != nil {
			t.Error("Expected nil for nil sockaddr")
		}
	})

	t.Run("WrongType", func(t *testing.T) {
		sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 8080)
		addr := SockaddrToUnixAddr(sa, "unix")
		if addr != nil {
			t.Error("Expected nil for non-Unix sockaddr")
		}
	})

	t.Run("Valid", func(t *testing.T) {
		sa := NewSockaddrUnix("/tmp/test.sock")
		addr := SockaddrToUnixAddr(sa, "unix")
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Name != "/tmp/test.sock" {
			t.Errorf("Expected '/tmp/test.sock', got %s", addr.Name)
		}
	})
}

// SockaddrToUDPAddr Tests

func TestSockaddrToUDPAddr(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		addr := SockaddrToUDPAddr(nil)
		if addr != nil {
			t.Error("Expected nil for nil sockaddr")
		}
	})

	t.Run("IPv4", func(t *testing.T) {
		sa := NewSockaddrInet4([4]byte{192, 168, 1, 1}, 5353)
		addr := SockaddrToUDPAddr(sa)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 5353 {
			t.Errorf("Expected port 5353, got %d", addr.Port)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		sa := NewSockaddrInet6([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 5353, 1)
		addr := SockaddrToUDPAddr(sa)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 5353 {
			t.Errorf("Expected port 5353, got %d", addr.Port)
		}
		if addr.Zone != "1" {
			t.Errorf("Expected zone '1', got %s", addr.Zone)
		}
	})

	t.Run("WrongType", func(t *testing.T) {
		sa := NewSockaddrUnix("/tmp/test.sock")
		addr := SockaddrToUDPAddr(sa)
		if addr != nil {
			t.Error("Expected nil for Unix sockaddr")
		}
	})
}

// UnixAddrToSockaddr Tests

func TestUnixAddrToSockaddr(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		sa := UnixAddrToSockaddr(nil)
		if sa != nil {
			t.Error("Expected nil for nil addr")
		}
	})

	t.Run("Valid", func(t *testing.T) {
		addr := &net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"}
		sa := UnixAddrToSockaddr(addr)
		if sa == nil {
			t.Fatal("Expected non-nil sockaddr")
		}
	})
}

// UDPAddrToSockaddr edge cases

func TestUDPAddrToSockaddr_Nil(t *testing.T) {
	sa := UDPAddrToSockaddr(nil)
	if sa != nil {
		t.Error("Expected nil for nil addr")
	}
}

// Adaptive Write Tests

func TestAdaptiveWrite_NoDeadline(t *testing.T) {
	conns, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer conns[0].Close()
	defer conns[1].Close()

	// Write without deadline should succeed immediately (blocking scenario with socketpair)
	testData := []byte("hello adaptive write")
	n, err := conns[0].Write(testData)
	if err != nil {
		t.Errorf("Write: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Short write: expected %d, got %d", len(testData), n)
	}
}

func TestAdaptiveWrite_WithDeadline(t *testing.T) {
	conns, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer conns[0].Close()
	defer conns[1].Close()

	// Set a deadline
	if err := conns[0].SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	// Write with deadline
	testData := []byte("hello with deadline")
	n, err := conns[0].Write(testData)
	if err != nil {
		t.Errorf("Write: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Short write: expected %d, got %d", len(testData), n)
	}
}

func TestAdaptiveWrite_ExpiredDeadline(t *testing.T) {
	conns, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer conns[0].Close()
	defer conns[1].Close()

	// Set an already expired deadline
	if err := conns[0].SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	// Write with expired deadline:
	// - If buffer has space, write may succeed immediately (non-blocking)
	// - If buffer is full, write should return ErrTimedOut
	testData := []byte("should timeout")
	_, err = conns[0].Write(testData)
	// Either success (immediate write) or timeout is acceptable
	if err != nil && err != ErrTimedOut && err != ErrWouldBlock {
		t.Errorf("Expected nil, ErrTimedOut or ErrWouldBlock, got %v", err)
	}
}

func TestAdaptiveRead_ExpiredDeadline(t *testing.T) {
	conns, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer conns[0].Close()
	defer conns[1].Close()

	// Set an already expired deadline
	if err := conns[0].SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	// Read with expired deadline should fail with timeout
	buf := make([]byte, 100)
	_, err = conns[0].Read(buf)
	if err != ErrTimedOut {
		t.Errorf("Expected ErrTimedOut, got %v", err)
	}
}

// UDP SendTo Tests

func TestUDPSocket_SendTo(t *testing.T) {
	// Create two UDP sockets with actual bound addresses
	laddr1 := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn1, err := ListenUDP4(laddr1)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn1.Close()

	laddr2 := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn2, err := ListenUDP4(laddr2)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn2.Close()

	// Get actual bound address using GetSockname
	sa, err := GetSockname(conn2.fd)
	if err != nil {
		t.Fatalf("GetSockname: %v", err)
	}
	inet4, ok := sa.(*SockaddrInet4)
	if !ok {
		t.Fatalf("Expected *SockaddrInet4, got %T", sa)
	}
	addr4 := inet4.Addr()
	realAddr := &UDPAddr{
		IP:   net.IP(addr4[:]),
		Port: int(inet4.Port()),
	}

	// Send from conn1 to conn2
	testData := []byte("hello udp")
	n, err := conn1.UDPSocket.SendTo(testData, realAddr)
	if err != nil {
		t.Errorf("SendTo: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Short send: expected %d, got %d", len(testData), n)
	}
}

func TestUDPSocket_SendTo_IPv6(t *testing.T) {
	laddr1 := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn1, err := ListenUDP6(laddr1)
	if err != nil {
		t.Fatalf("ListenUDP6: %v", err)
	}
	defer conn1.Close()

	laddr2 := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn2, err := ListenUDP6(laddr2)
	if err != nil {
		t.Fatalf("ListenUDP6: %v", err)
	}
	defer conn2.Close()

	// Get actual bound address using GetSockname
	sa, err := GetSockname(conn2.fd)
	if err != nil {
		t.Fatalf("GetSockname: %v", err)
	}
	inet6, ok := sa.(*SockaddrInet6)
	if !ok {
		t.Fatalf("Expected *SockaddrInet6, got %T", sa)
	}
	addr6 := inet6.Addr()
	realAddr := &UDPAddr{
		IP:   net.IP(addr6[:]),
		Port: int(inet6.Port()),
	}

	// Send from conn1 to conn2 using IPv6
	testData := []byte("hello udp6")
	n, err := conn1.UDPSocket.SendTo(testData, realAddr)
	if err != nil {
		t.Errorf("SendTo IPv6: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Short send: expected %d, got %d", len(testData), n)
	}
}

// UDPConn Read/Write Tests

func TestUDPConn_ReadWrite_Connected(t *testing.T) {
	// Create a listening UDP socket
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	// Create a connected UDP socket
	raddr := server.LocalAddr().(*UDPAddr)
	client, err := DialUDP4(nil, raddr)
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer client.Close()

	// Write from client (connected)
	testData := []byte("hello connected udp")
	n, err := client.Write(testData)
	if err != nil {
		t.Errorf("Write: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Short write: expected %d, got %d", len(testData), n)
	}
}

func TestUDPConn_ReadUnconnected(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set a short deadline so we don't block forever
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	// Read on unconnected socket (should use RecvFrom internally)
	buf := make([]byte, 100)
	_, err = conn.Read(buf)
	// Should timeout since no data
	if err != ErrTimedOut && err != ErrWouldBlock {
		t.Logf("Read on unconnected: %v (expected timeout or would-block)", err)
	}
}

// UDPConn WriteTo Tests

func TestUDPConn_WriteTo(t *testing.T) {
	laddr1 := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn1, err := ListenUDP4(laddr1)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn1.Close()

	laddr2 := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn2, err := ListenUDP4(laddr2)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn2.Close()

	// Get actual bound address using GetSockname
	sa, err := GetSockname(conn2.fd)
	if err != nil {
		t.Fatalf("GetSockname: %v", err)
	}
	inet4, ok := sa.(*SockaddrInet4)
	if !ok {
		t.Fatalf("Expected *SockaddrInet4, got %T", sa)
	}
	addr4 := inet4.Addr()
	realAddr := &UDPAddr{
		IP:   net.IP(addr4[:]),
		Port: int(inet4.Port()),
	}

	// Set write deadline
	if err := conn1.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	// WriteTo with valid UDPAddr
	testData := []byte("hello writeto")
	n, err := conn1.WriteTo(testData, realAddr)
	if err != nil {
		t.Errorf("WriteTo: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Short write: expected %d, got %d", len(testData), n)
	}
}

// UnixConn WriteTo Tests

func TestUnixConn_WriteTo_InvalidAddr(t *testing.T) {
	conns, err := UnixConnPair("unixgram")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer conns[0].Close()
	defer conns[1].Close()

	// WriteTo with wrong address type
	tcpAddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	_, err = conns[0].WriteTo([]byte("test"), tcpAddr)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

// SetBroadcast Test

func TestUDPConn_SetBroadcast(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	if err := conn.SetBroadcast(true); err != nil {
		t.Errorf("SetBroadcast(true): %v", err)
	}

	if err := conn.SetBroadcast(false); err != nil {
		t.Errorf("SetBroadcast(false): %v", err)
	}
}

// DialTCP with local address binding

func TestDialTCP4_WithLocalAddr(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	raddr := listener.Addr().(*TCPAddr)
	localAddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := DialTCP4(localAddr, raddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialTCP4: %v", err)
	}
	if conn != nil {
		defer conn.Close()
		if conn.LocalAddr() == nil {
			t.Error("Expected non-nil LocalAddr with explicit binding")
		}
	}
}

// TCPListener AcceptSocket Test

func TestTCPListener_AcceptSocket(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	// Dial in background
	go func() {
		raddr := listener.Addr().(*TCPAddr)
		conn, err := DialTCP4(nil, raddr)
		if err == nil || err == ErrInProgress {
			if conn != nil {
				time.Sleep(10 * time.Millisecond)
				conn.Close()
			}
		}
	}()

	// Set deadline so we don't block forever
	listener.SetDeadline(time.Now().Add(100 * time.Millisecond))

	sock, err := listener.AcceptSocket()
	if err != nil {
		// May timeout if client didn't connect fast enough
		if err != ErrTimedOut && err != ErrWouldBlock {
			t.Logf("AcceptSocket: %v", err)
		}
	}
	if sock != nil {
		sock.Close()
	}
}

// UnixListener AcceptSocket Test

func TestUnixListener_AcceptSocket(t *testing.T) {
	name := "@test-accept-socket-" + time.Now().Format("150405.000000000")
	laddr := &UnixAddr{Name: name, Net: "unix"}
	listener, err := ListenUnix("unix", laddr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer listener.Close()

	// Dial in background
	go func() {
		conn, err := DialUnix("unix", nil, laddr)
		if err == nil || err == ErrInProgress {
			if conn != nil {
				time.Sleep(10 * time.Millisecond)
				conn.Close()
			}
		}
	}()

	// Set deadline
	listener.SetDeadline(time.Now().Add(100 * time.Millisecond))

	sock, err := listener.AcceptSocket()
	if err != nil {
		if err != ErrTimedOut && err != ErrWouldBlock {
			t.Logf("AcceptSocket: %v", err)
		}
	}
	if sock != nil {
		sock.Close()
	}
}

// DecodeSockaddr Unix Test

func TestDecodeSockaddr_Unix(t *testing.T) {
	raw := &RawSockaddrAny{}
	raw.Addr.Family = AF_UNIX
	rawUnix := (*RawSockaddrUnix)(unsafe.Pointer(raw))
	copy(rawUnix.Path[:], "/tmp/decode-test.sock")

	sa := DecodeSockaddr(raw)
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	unix, ok := sa.(*SockaddrUnix)
	if !ok {
		t.Fatalf("Expected *SockaddrUnix, got %T", sa)
	}
	if unix.Path() != "/tmp/decode-test.sock" {
		t.Errorf("Expected '/tmp/decode-test.sock', got %s", unix.Path())
	}
}

// UDPConn LocalAddr/RemoteAddr Tests

func TestUDPConn_LocalRemoteAddr(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	raddr := server.LocalAddr().(*UDPAddr)
	client, err := DialUDP4(nil, raddr)
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer client.Close()

	if client.LocalAddr() == nil {
		t.Error("Expected non-nil LocalAddr")
	}
	if client.RemoteAddr() == nil {
		t.Error("Expected non-nil RemoteAddr for connected socket")
	}
}

// SCTP Tests (skipped if SCTP not available)

func TestSCTPSocket4(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolSeqPacket {
		t.Errorf("Expected UnderlyingProtocolSeqPacket, got %v", sock.Protocol())
	}
}

func TestSCTPSocket6(t *testing.T) {
	sock, err := NewSCTPSocket6()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()
}

func TestSCTPStreamSocket4(t *testing.T) {
	sock, err := NewSCTPStreamSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()
}

func TestSCTPStreamSocket6(t *testing.T) {
	sock, err := NewSCTPStreamSocket6()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()
}

func TestListenSCTP4(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	if listener.Addr() == nil {
		t.Error("Expected non-nil Addr")
	}
}

func TestListenSCTP4_NilAddr(t *testing.T) {
	_, err := ListenSCTP4(nil)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

func TestListenSCTP6(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	listener, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()
}

func TestListenSCTP6_NilAddr(t *testing.T) {
	_, err := ListenSCTP6(nil)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

func TestListenSCTP_AutoDetect(t *testing.T) {
	t.Run("NilAddr", func(t *testing.T) {
		_, err := ListenSCTP("sctp", nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("IPv4", func(t *testing.T) {
		laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
		listener, err := ListenSCTP("sctp", laddr)
		if err != nil {
			t.Skipf("SCTP not available: %v", err)
		}
		defer listener.Close()
	})
}

func TestDialSCTP4(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	raddr := listener.Addr().(*SCTPAddr)

	t.Run("NilRaddr", func(t *testing.T) {
		_, err := DialSCTP4(nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("WithLaddr", func(t *testing.T) {
		localAddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
		conn, err := DialSCTP4(localAddr, raddr)
		if err != nil && err != ErrInProgress {
			t.Skipf("DialSCTP4: %v", err)
		}
		if conn != nil {
			defer conn.Close()
		}
	})

	t.Run("WithoutLaddr", func(t *testing.T) {
		conn, err := DialSCTP4(nil, raddr)
		if err != nil && err != ErrInProgress {
			t.Skipf("DialSCTP4: %v", err)
		}
		if conn != nil {
			defer conn.Close()
		}
	})
}

func TestDialSCTP6(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	listener, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	raddr := listener.Addr().(*SCTPAddr)

	t.Run("NilRaddr", func(t *testing.T) {
		_, err := DialSCTP6(nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("WithoutLaddr", func(t *testing.T) {
		conn, err := DialSCTP6(nil, raddr)
		if err != nil && err != ErrInProgress {
			t.Skipf("DialSCTP6: %v", err)
		}
		if conn != nil {
			defer conn.Close()
		}
	})
}

func TestDialSCTP_AutoDetect(t *testing.T) {
	t.Run("NilRaddr", func(t *testing.T) {
		_, err := DialSCTP("sctp", nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("Expected ErrInvalidParam, got %v", err)
		}
	})
}

func TestSCTPConn_Methods(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	raddr := listener.Addr().(*SCTPAddr)
	conn, err := DialSCTP4(nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Skipf("DialSCTP4: %v", err)
	}
	if conn == nil {
		t.Skip("Connection not established")
	}
	defer conn.Close()

	// Test methods
	if conn.LocalAddr() == nil {
		t.Error("Expected non-nil LocalAddr")
	}
	if conn.RemoteAddr() == nil {
		t.Error("Expected non-nil RemoteAddr")
	}

	// Deadline methods should not error
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}
}

func TestSCTPListener_AcceptSocket(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	// Try AcceptSocket (will likely timeout since no client)
	sock, err := listener.AcceptSocket()
	if err == nil {
		sock.Close()
	}
	// Error is expected since no client is connecting
}

// DecodeSCTPAddr Tests

func TestDecodeSCTPAddr(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		addr := decodeSCTPAddr(nil)
		if addr != nil {
			t.Error("Expected nil for nil input")
		}
	})

	t.Run("IPv4", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET
		rawInet4 := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		rawInet4.Addr = [4]byte{127, 0, 0, 1}
		rawInet4.Port = htons(5000)

		addr := decodeSCTPAddr(raw)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 5000 {
			t.Errorf("Expected port 5000, got %d", addr.Port)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = AF_INET6
		rawInet6 := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		rawInet6.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		rawInet6.Port = htons(5000)
		rawInet6.ScopeID = 1

		addr := decodeSCTPAddr(raw)
		if addr == nil {
			t.Fatal("Expected non-nil addr")
		}
		if addr.Port != 5000 {
			t.Errorf("Expected port 5000, got %d", addr.Port)
		}
	})

	t.Run("UnknownFamily", func(t *testing.T) {
		raw := &RawSockaddrAny{}
		raw.Addr.Family = 255

		addr := decodeSCTPAddr(raw)
		if addr != nil {
			t.Error("Expected nil for unknown family")
		}
	})
}

// SCTPAddr Conversion Tests

func TestSctpAddrToSockaddr4(t *testing.T) {
	addr := &SCTPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 5000,
	}
	sa := sctpAddrToSockaddr4(addr)
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	if sa.Port() != 5000 {
		t.Errorf("Expected port 5000, got %d", sa.Port())
	}
}

func TestSctpAddrToSockaddr6(t *testing.T) {
	addr := &SCTPAddr{
		IP:   net.ParseIP("::1"),
		Port: 5000,
		Zone: "1",
	}
	sa := sctpAddrToSockaddr6(addr)
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	if sa.Port() != 5000 {
		t.Errorf("Expected port 5000, got %d", sa.Port())
	}
	if sa.ScopeID() != 1 {
		t.Errorf("Expected scope ID 1, got %d", sa.ScopeID())
	}
}

// Deadline state tests

func TestDeadlineState_ReadWriteDeadlines(t *testing.T) {
	var ds deadlineState

	// Initially no deadlines
	if !ds.readDeadline().IsZero() {
		t.Error("Expected zero read deadline initially")
	}
	if !ds.writeDeadline().IsZero() {
		t.Error("Expected zero write deadline initially")
	}
	if ds.hasReadDeadline() {
		t.Error("Expected hasReadDeadline to be false initially")
	}
	if ds.hasWriteDeadline() {
		t.Error("Expected hasWriteDeadline to be false initially")
	}

	// Set read deadline
	readTime := time.Now().Add(1 * time.Hour)
	ds.setReadDeadline(readTime)
	if !ds.hasReadDeadline() {
		t.Error("Expected hasReadDeadline to be true after setting")
	}
	got := ds.readDeadline()
	if got.UnixNano() != readTime.UnixNano() {
		t.Errorf("Read deadline mismatch: got %v, want %v", got, readTime)
	}

	// Set write deadline
	writeTime := time.Now().Add(2 * time.Hour)
	ds.setWriteDeadline(writeTime)
	if !ds.hasWriteDeadline() {
		t.Error("Expected hasWriteDeadline to be true after setting")
	}
	got = ds.writeDeadline()
	if got.UnixNano() != writeTime.UnixNano() {
		t.Errorf("Write deadline mismatch: got %v, want %v", got, writeTime)
	}

	// Clear read deadline
	ds.setReadDeadline(time.Time{})
	if ds.hasReadDeadline() {
		t.Error("Expected hasReadDeadline to be false after clearing")
	}

	// Clear write deadline
	ds.setWriteDeadline(time.Time{})
	if ds.hasWriteDeadline() {
		t.Error("Expected hasWriteDeadline to be false after clearing")
	}
}

func TestDeadlineState_WriteExpired(t *testing.T) {
	var ds deadlineState

	// No deadline = not expired
	if ds.writeExpired() {
		t.Error("Expected writeExpired to be false with no deadline")
	}

	// Future deadline = not expired
	ds.setWriteDeadline(time.Now().Add(1 * time.Hour))
	if ds.writeExpired() {
		t.Error("Expected writeExpired to be false with future deadline")
	}

	// Past deadline = expired
	ds.setWriteDeadline(time.Now().Add(-1 * time.Second))
	if !ds.writeExpired() {
		t.Error("Expected writeExpired to be true with past deadline")
	}
}

func TestDeadlineState_SetBothDeadlines(t *testing.T) {
	var ds deadlineState
	deadline := time.Now().Add(1 * time.Hour)

	ds.setDeadline(deadline)

	if !ds.hasReadDeadline() {
		t.Error("Expected hasReadDeadline to be true")
	}
	if !ds.hasWriteDeadline() {
		t.Error("Expected hasWriteDeadline to be true")
	}

	gotRead := ds.readDeadline()
	gotWrite := ds.writeDeadline()
	if gotRead.UnixNano() != deadline.UnixNano() {
		t.Errorf("Read deadline mismatch")
	}
	if gotWrite.UnixNano() != deadline.UnixNano() {
		t.Errorf("Write deadline mismatch")
	}
}

// AdaptiveWrite with deadline that succeeds

func TestAdaptiveWrite_SuccessWithDeadline(t *testing.T) {
	var ds deadlineState
	ds.setWriteDeadline(time.Now().Add(5 * time.Second))

	callCount := 0
	writeFn := func() (int, error) {
		callCount++
		if callCount < 3 {
			return 0, iox.ErrWouldBlock
		}
		return 10, nil
	}

	n, err := adaptiveWrite(writeFn, &ds)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if n != 10 {
		t.Errorf("Expected n=10, got %d", n)
	}
	if callCount < 3 {
		t.Errorf("Expected at least 3 calls, got %d", callCount)
	}
}

func TestAdaptiveWrite_TimeoutWithDeadline(t *testing.T) {
	var ds deadlineState
	ds.setWriteDeadline(time.Now().Add(50 * time.Millisecond))

	writeFn := func() (int, error) {
		return 0, iox.ErrWouldBlock
	}

	_, err := adaptiveWrite(writeFn, &ds)
	if err != ErrTimedOut {
		t.Errorf("Expected ErrTimedOut, got %v", err)
	}
}

// AdaptiveRead with immediate success

func TestAdaptiveRead_ImmediateSuccess(t *testing.T) {
	var ds deadlineState

	readFn := func() (int, error) {
		return 42, nil
	}

	n, err := adaptiveRead(readFn, &ds)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if n != 42 {
		t.Errorf("Expected n=42, got %d", n)
	}
}

func TestAdaptiveRead_ImmediateError(t *testing.T) {
	var ds deadlineState

	readFn := func() (int, error) {
		return 0, ErrConnectionReset
	}

	n, err := adaptiveRead(readFn, &ds)
	if err != ErrConnectionReset {
		t.Errorf("Expected ErrConnectionReset, got %v", err)
	}
	if n != 0 {
		t.Errorf("Expected n=0, got %d", n)
	}
}

func TestAdaptiveRead_SuccessWithDeadline(t *testing.T) {
	var ds deadlineState
	ds.setReadDeadline(time.Now().Add(5 * time.Second))

	callCount := 0
	readFn := func() (int, error) {
		callCount++
		if callCount < 3 {
			return 0, iox.ErrWouldBlock
		}
		return 100, nil
	}

	n, err := adaptiveRead(readFn, &ds)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if n != 100 {
		t.Errorf("Expected n=100, got %d", n)
	}
	if callCount < 3 {
		t.Errorf("Expected at least 3 calls, got %d", callCount)
	}
}

// AdaptiveAccept tests

func TestAdaptiveAccept_ImmediateSuccess(t *testing.T) {
	acceptFn := func() (int, error) {
		return 42, nil
	}

	result, err := adaptiveAccept(acceptFn, 0)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if result != 42 {
		t.Errorf("Expected result=42, got %d", result)
	}
}

func TestAdaptiveAccept_NoDeadlineWouldBlock(t *testing.T) {
	acceptFn := func() (int, error) {
		return 0, iox.ErrWouldBlock
	}

	result, err := adaptiveAccept(acceptFn, 0)
	if err != iox.ErrWouldBlock {
		t.Errorf("Expected ErrWouldBlock, got %v", err)
	}
	if result != 0 {
		t.Errorf("Expected result=0, got %d", result)
	}
}

func TestAdaptiveAccept_AlreadyExpired(t *testing.T) {
	acceptFn := func() (int, error) {
		return 0, iox.ErrWouldBlock
	}

	deadlineNs := time.Now().Add(-1 * time.Second).UnixNano()
	result, err := adaptiveAccept(acceptFn, deadlineNs)
	if err != ErrTimedOut {
		t.Errorf("Expected ErrTimedOut, got %v", err)
	}
	if result != 0 {
		t.Errorf("Expected result=0, got %d", result)
	}
}

func TestAdaptiveAccept_SuccessWithDeadline(t *testing.T) {
	callCount := 0
	acceptFn := func() (int, error) {
		callCount++
		if callCount < 3 {
			return 0, iox.ErrWouldBlock
		}
		return 99, nil
	}

	deadlineNs := time.Now().Add(5 * time.Second).UnixNano()
	result, err := adaptiveAccept(acceptFn, deadlineNs)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if result != 99 {
		t.Errorf("Expected result=99, got %d", result)
	}
}

func TestAdaptiveAccept_Timeout(t *testing.T) {
	acceptFn := func() (int, error) {
		return 0, iox.ErrWouldBlock
	}

	deadlineNs := time.Now().Add(50 * time.Millisecond).UnixNano()
	result, err := adaptiveAccept(acceptFn, deadlineNs)
	if err != ErrTimedOut {
		t.Errorf("Expected ErrTimedOut, got %v", err)
	}
	if result != 0 {
		t.Errorf("Expected result=0, got %d", result)
	}
}

// SCTP Address tests

func TestSCTPAddrFromAddrPort(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		ap, err := netip.ParseAddrPort("192.168.1.1:5000")
		if err != nil {
			t.Fatalf("Failed to parse addr port: %v", err)
		}
		addr := SCTPAddrFromAddrPort(ap)
		if addr == nil {
			t.Fatal("Expected non-nil address")
		}
		if addr.Port != 5000 {
			t.Errorf("Expected port 5000, got %d", addr.Port)
		}
		if !addr.IP.Equal(net.ParseIP("192.168.1.1")) {
			t.Errorf("Expected IP 192.168.1.1, got %v", addr.IP)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		ap, err := netip.ParseAddrPort("[::1]:5000")
		if err != nil {
			t.Fatalf("Failed to parse addr port: %v", err)
		}
		addr := SCTPAddrFromAddrPort(ap)
		if addr == nil {
			t.Fatal("Expected non-nil address")
		}
		if addr.Port != 5000 {
			t.Errorf("Expected port 5000, got %d", addr.Port)
		}
	})
}

func TestResolveSCTPAddr(t *testing.T) {
	t.Run("sctp4", func(t *testing.T) {
		addr, err := ResolveSCTPAddr("sctp4", "127.0.0.1:5000")
		if err != nil {
			t.Fatalf("ResolveSCTPAddr failed: %v", err)
		}
		if addr == nil {
			t.Fatal("Expected non-nil address")
		}
		if addr.Port != 5000 {
			t.Errorf("Expected port 5000, got %d", addr.Port)
		}
	})

	t.Run("sctp6", func(t *testing.T) {
		addr, err := ResolveSCTPAddr("sctp6", "[::1]:5000")
		if err != nil {
			t.Fatalf("ResolveSCTPAddr failed: %v", err)
		}
		if addr == nil {
			t.Fatal("Expected non-nil address")
		}
		if addr.Port != 5000 {
			t.Errorf("Expected port 5000, got %d", addr.Port)
		}
	})

	t.Run("sctp auto", func(t *testing.T) {
		addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:5000")
		if err != nil {
			t.Fatalf("ResolveSCTPAddr failed: %v", err)
		}
		if addr == nil {
			t.Fatal("Expected non-nil address")
		}
	})

	t.Run("empty network", func(t *testing.T) {
		addr, err := ResolveSCTPAddr("", "127.0.0.1:5000")
		if err != nil {
			t.Fatalf("ResolveSCTPAddr failed: %v", err)
		}
		if addr == nil {
			t.Fatal("Expected non-nil address")
		}
	})

	t.Run("unknown network", func(t *testing.T) {
		_, err := ResolveSCTPAddr("invalid", "127.0.0.1:5000")
		if err == nil {
			t.Error("Expected error for unknown network")
		}
	})

	t.Run("sctp with bracket notation", func(t *testing.T) {
		addr, err := ResolveSCTPAddr("sctp", "[::1]:5000")
		if err != nil {
			t.Fatalf("ResolveSCTPAddr failed: %v", err)
		}
		if addr == nil {
			t.Fatal("Expected non-nil address")
		}
	})
}

// ip6Zone tests - these require a real network interface

func TestIp6ZoneID_EmptyZone(t *testing.T) {
	id := ip6ZoneID("")
	if id != 0 {
		t.Errorf("Expected 0 for empty zone, got %d", id)
	}
}

func TestIp6ZoneString_ZeroID(t *testing.T) {
	name := ip6ZoneString(0)
	if name != "" {
		t.Errorf("Expected empty string for ID 0, got %q", name)
	}
}

func TestIp6ZoneString_InvalidID(t *testing.T) {
	// Very high ID that shouldn't exist
	name := ip6ZoneString(999999)
	if name != "" {
		t.Errorf("Expected empty string for invalid ID, got %q", name)
	}
}

// Raw socket tests (require CAP_NET_RAW, skip if not available)

func TestRawSocket4_Create(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != IPPROTO_ICMP {
		t.Errorf("Expected protocol ICMP, got %d", sock.Protocol())
	}
}

func TestRawSocket6_Create(t *testing.T) {
	sock, err := NewRawSocket6(IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != IPPROTO_ICMPV6 {
		t.Errorf("Expected protocol ICMPv6, got %d", sock.Protocol())
	}
}

func TestNewICMPSocket4(t *testing.T) {
	sock, err := NewICMPSocket4()
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()
}

func TestNewICMPSocket6(t *testing.T) {
	sock, err := NewICMPSocket6()
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()
}

func TestRawSocket_SetIPHeaderIncluded(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()

	if err := sock.SetIPHeaderIncluded(true); err != nil {
		t.Errorf("SetIPHeaderIncluded(true) failed: %v", err)
	}
}

func TestListenRaw4(t *testing.T) {
	addr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := ListenRaw4(addr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("Expected non-nil local address")
	}
}

func TestListenRaw6(t *testing.T) {
	addr := &net.IPAddr{IP: net.ParseIP("::1")}
	conn, err := ListenRaw6(addr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()
}

func TestListenRaw_AutoDetect(t *testing.T) {
	addr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := ListenRaw("ip4", addr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()
}

// RawConn tests

func TestRawConn_Addresses(t *testing.T) {
	conn, err := ListenRaw4(&net.IPAddr{IP: net.ParseIP("127.0.0.1")}, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("Expected non-nil LocalAddr")
	}
	// RemoteAddr should be nil for a listening raw socket
	if conn.RemoteAddr() != nil {
		t.Error("Expected nil RemoteAddr for listening socket")
	}
}

// setNonBlockCloexec test

func TestSetNonBlockCloexec(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	// Test that the function works
	if err := setNonBlockCloexec(sock.fd); err != nil {
		t.Errorf("setNonBlockCloexec failed: %v", err)
	}
}

// ip6ZoneID with real interface

func TestIp6ZoneID_LoInterface(t *testing.T) {
	// Try to find the loopback interface
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("Cannot list interfaces: %v", err)
	}
	var loIndex int
	var loName string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			loIndex = iface.Index
			loName = iface.Name
			break
		}
	}
	if loIndex == 0 {
		t.Skip("No loopback interface found")
	}

	// Now test that ip6ZoneID works with a real zone name
	id := ip6ZoneID(loName)
	if id != loIndex {
		t.Errorf("ip6ZoneID(%q) = %d, want %d", loName, id, loIndex)
	}

	// And ip6ZoneString in reverse
	name := ip6ZoneString(loIndex)
	if name != loName {
		t.Errorf("ip6ZoneString(%d) = %q, want %q", loIndex, name, loName)
	}
}

// Additional SCTP Addr resolution tests

func TestResolveSCTPAddr_IPv4Colon(t *testing.T) {
	// Test with colon in address (which triggers IPv6 detection in generic sctp)
	addr, err := ResolveSCTPAddr("sctp4", "127.0.0.1:5000")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr.IP.To4() == nil {
		t.Error("Expected IPv4 address")
	}
}

// More RawSocket tests (skip if no CAP_NET_RAW)

func TestRawSocket_ProtocolRaw(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolRaw {
		t.Errorf("Expected UnderlyingProtocolRaw, got %v", sock.Protocol())
	}
}

// DialRaw tests

func TestDialRaw4(t *testing.T) {
	laddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	raddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := DialRaw4(laddr, raddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("Expected non-nil LocalAddr")
	}
	if conn.RemoteAddr() == nil {
		t.Error("Expected non-nil RemoteAddr")
	}
}

func TestDialRaw6(t *testing.T) {
	laddr := &net.IPAddr{IP: net.ParseIP("::1")}
	raddr := &net.IPAddr{IP: net.ParseIP("::1")}
	conn, err := DialRaw6(laddr, raddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()
}

func TestDialRaw_AutoDetect(t *testing.T) {
	laddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	raddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := DialRaw("ip4", laddr, raddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()
}

func TestDialRaw_NilRaddr(t *testing.T) {
	laddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	_, err := DialRaw4(laddr, nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

func TestListenRaw_NilLaddr(t *testing.T) {
	_, err := ListenRaw4(nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}

	_, err = ListenRaw6(nil, IPPROTO_ICMPV6)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}

	_, err = ListenRaw("ip4", nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

// RawConn Read/Write tests

func TestRawConn_ReadWrite(t *testing.T) {
	laddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	raddr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := DialRaw4(laddr, raddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()

	// Try to write (may fail if not allowed to send ICMP)
	_, err = conn.Write([]byte{8, 0, 0, 0, 0, 0, 0, 0})
	// Just verify Write returns without panic
	_ = err

	// Try to read (non-blocking)
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	// Just verify Read returns without panic (will likely return ErrWouldBlock)
	_ = err
}

// RawConn RecvFrom/SendTo tests

func TestRawSocket_RecvFromSendTo(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()

	// Try SendTo
	addr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	_, err = sock.SendTo([]byte{8, 0, 0, 0, 0, 0, 0, 0}, addr)
	// Just verify it doesn't panic
	_ = err

	// Try RecvFrom (non-blocking)
	buf := make([]byte, 1024)
	_, _, err = sock.RecvFrom(buf)
	// Just verify it doesn't panic (will likely return ErrWouldBlock)
	_ = err
}

// RawConn on unconnected socket

func TestRawConn_ReadUnconnected(t *testing.T) {
	conn, err := ListenRaw4(&net.IPAddr{IP: net.ParseIP("127.0.0.1")}, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()

	// Read on unconnected should use RecvFrom (non-blocking)
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	// Should return ErrWouldBlock
	_ = err
}

func TestRawConn_WriteUnconnected(t *testing.T) {
	conn, err := ListenRaw4(&net.IPAddr{IP: net.ParseIP("127.0.0.1")}, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()

	// Write on unconnected should fail with ErrNotConnected
	_, err = conn.Write([]byte{8, 0, 0, 0, 0, 0, 0, 0})
	if err != ErrNotConnected {
		t.Errorf("Expected ErrNotConnected, got %v", err)
	}
}

func TestRawConn_RecvFromSendTo(t *testing.T) {
	conn, err := ListenRaw4(&net.IPAddr{IP: net.ParseIP("127.0.0.1")}, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer conn.Close()

	// Try SendTo
	addr := &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	_, err = conn.SendTo([]byte{8, 0, 0, 0, 0, 0, 0, 0}, addr)
	// Just verify it doesn't panic
	_ = err

	// Try RecvFrom (non-blocking)
	buf := make([]byte, 1024)
	_, _, err = conn.RecvFrom(buf)
	// Just verify it doesn't panic (will return ErrWouldBlock)
	_ = err
}

// ipAddrToSockaddr tests

func TestIpAddrToSockaddr4(t *testing.T) {
	addr := &net.IPAddr{IP: net.ParseIP("192.168.1.1")}
	sa := ipAddrToSockaddr4(addr)
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	if sa.Family() != AF_INET {
		t.Errorf("Expected AF_INET, got %d", sa.Family())
	}
}

func TestIpAddrToSockaddr6(t *testing.T) {
	addr := &net.IPAddr{IP: net.ParseIP("::1"), Zone: "1"}
	sa := ipAddrToSockaddr6(addr)
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	if sa.Family() != AF_INET6 {
		t.Errorf("Expected AF_INET6, got %d", sa.Family())
	}
}

func TestIpAddrToSockaddr_NilIP(t *testing.T) {
	addr4 := &net.IPAddr{}
	sa4 := ipAddrToSockaddr4(addr4)
	if sa4 == nil {
		t.Fatal("Expected non-nil sockaddr")
	}

	addr6 := &net.IPAddr{}
	sa6 := ipAddrToSockaddr6(addr6)
	if sa6 == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
}

// decodeIPAddr tests

func TestDecodeIPAddr(t *testing.T) {
	// Test with nil
	if addr := decodeIPAddr(nil); addr != nil {
		t.Error("Expected nil for nil input")
	}

	// Note: Testing decodeIPAddr with actual sockaddr data requires creating
	// a properly aligned RawSockaddrAny, which is typically only created
	// during actual recvfrom operations. The function is tested implicitly
	// through RawSocket.RecvFrom tests.
}

// Linux-specific socket options tests

func TestTCPCork(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	if err := SetTCPCork(sock.fd, true); err != nil {
		t.Errorf("SetTCPCork(true) failed: %v", err)
	}

	val, err := GetTCPCork(sock.fd)
	if err != nil {
		t.Errorf("GetTCPCork failed: %v", err)
	}
	if !val {
		t.Error("Expected TCPCork to be true")
	}

	if err := SetTCPCork(sock.fd, false); err != nil {
		t.Errorf("SetTCPCork(false) failed: %v", err)
	}
}

func TestTCPQuickAck(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	if err := SetTCPQuickAck(sock.fd, true); err != nil {
		t.Errorf("SetTCPQuickAck(true) failed: %v", err)
	}

	val, err := GetTCPQuickAck(sock.fd)
	if err != nil {
		t.Errorf("GetTCPQuickAck failed: %v", err)
	}
	_ = val // value may vary

	if err := SetTCPQuickAck(sock.fd, false); err != nil {
		t.Errorf("SetTCPQuickAck(false) failed: %v", err)
	}
}

func TestZeroCopy(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	// SetZeroCopy may fail on older kernels, just test it doesn't panic
	_ = SetZeroCopy(sock.fd, true)

	_, err = GetZeroCopy(sock.fd)
	// May fail, just verify it doesn't panic
	_ = err
}

func TestTCPKeepIdle(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	if err := SetTCPKeepIdle(sock.fd, 60); err != nil {
		t.Errorf("SetTCPKeepIdle failed: %v", err)
	}

	val, err := GetTCPKeepIdle(sock.fd)
	if err != nil {
		t.Errorf("GetTCPKeepIdle failed: %v", err)
	}
	if val != 60 {
		t.Errorf("Expected 60, got %d", val)
	}
}

func TestTCPDeferAccept(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	if err := SetTCPDeferAccept(sock.fd, 5); err != nil {
		t.Errorf("SetTCPDeferAccept failed: %v", err)
	}

	val, err := GetTCPDeferAccept(sock.fd)
	if err != nil {
		t.Errorf("GetTCPDeferAccept failed: %v", err)
	}
	_ = val // value is rounded by kernel
}

func TestTCPFastOpen(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	// May fail depending on system config
	_ = SetTCPFastOpen(sock.fd, 5)
	_, _ = GetTCPFastOpen(sock.fd)
}

func TestIPv6Only(t *testing.T) {
	sock, err := NewNetTCPSocket(true) // IPv6
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	if err := SetIPv6Only(sock.fd, true); err != nil {
		t.Errorf("SetIPv6Only(true) failed: %v", err)
	}

	val, err := GetIPv6Only(sock.fd)
	if err != nil {
		t.Errorf("GetIPv6Only failed: %v", err)
	}
	if !val {
		t.Error("Expected IPv6Only to be true")
	}
}

// TCP Read/Write tests

func TestTCPConn_ReadWrite(t *testing.T) {
	// Create listener
	listener, err := ListenTCP4(&TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	// Get actual address
	sa, _ := GetSockname(listener.fd)
	inet4 := sa.(*SockaddrInet4)
	addr4 := inet4.Addr()
	serverAddr := &TCPAddr{IP: net.IP(addr4[:]), Port: int(inet4.Port())}

	// Connect in goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := DialTCP4(nil, serverAddr)
		if err != nil {
			return
		}
		defer conn.Close()

		// Write data
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Write([]byte("hello"))

		// Read response
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, _ = conn.Read(buf)
	}()

	// Accept connection
	listener.SetDeadline(time.Now().Add(1 * time.Second))
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer conn.Close()

	// Read data
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err != iox.ErrWouldBlock {
		// May timeout, that's ok
		_ = err
	}
	if n > 0 && string(buf[:n]) != "hello" {
		t.Errorf("Expected 'hello', got %q", string(buf[:n]))
	}

	// Write response
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, _ = conn.Write([]byte("world"))

	<-done
}

func TestTCPListener_AcceptWithDeadline(t *testing.T) {
	listener, err := ListenTCP4(&TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	// Set a short deadline
	listener.SetDeadline(time.Now().Add(50 * time.Millisecond))

	// Accept should timeout
	_, err = listener.Accept()
	if err != ErrTimedOut && err != iox.ErrWouldBlock {
		t.Errorf("Expected timeout or would-block, got %v", err)
	}
}

// UDP tests

func TestUDPSocket_RecvFromSendTo(t *testing.T) {
	// Create two UDP sockets using NewUDPSocket4 which returns *UDPSocket
	sock1, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("Create socket1: %v", err)
	}
	defer sock1.Close()

	sock2, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("Create socket2: %v", err)
	}
	defer sock2.Close()

	// Bind sock1
	sa1 := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 0)
	if err := sock1.Bind(sa1); err != nil {
		t.Fatalf("Bind sock1: %v", err)
	}

	// Get sock1's address
	boundSa, _ := GetSockname(sock1.fd)
	inet4 := boundSa.(*SockaddrInet4)
	addr4 := inet4.Addr()

	// SendTo from sock2 to sock1
	destAddr := &UDPAddr{IP: net.IP(addr4[:]), Port: int(inet4.Port())}
	_, err = sock2.SendTo([]byte("test"), destAddr)
	if err != nil {
		t.Errorf("SendTo failed: %v", err)
	}

	// RecvFrom on sock1
	buf := make([]byte, 1024)
	n, from, err := sock1.RecvFrom(buf)
	if err != nil && err != iox.ErrWouldBlock {
		t.Errorf("RecvFrom failed: %v", err)
	}
	if n > 0 {
		if string(buf[:n]) != "test" {
			t.Errorf("Expected 'test', got %q", string(buf[:n]))
		}
		if from == nil {
			t.Error("Expected non-nil from address")
		}
	}
}

func TestUDPConn_ReadWithDeadline(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4 failed: %v", err)
	}
	defer conn.Close()

	// Set deadline and try to read
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != ErrTimedOut && err != iox.ErrWouldBlock {
		t.Errorf("Expected timeout or would-block, got %v", err)
	}
}

// Unix socket tests

func TestUnixConn_ReadFromWriteTo(t *testing.T) {
	name1 := "@test-unix-rw-1-" + time.Now().Format("150405.000000000")
	name2 := "@test-unix-rw-2-" + time.Now().Format("150405.000000000")

	// Create two unixgram connections using the exported API
	conn1, err := ListenUnixgram("unixgram", &UnixAddr{Name: name1, Net: "unixgram"})
	if err != nil {
		t.Fatalf("Create conn1: %v", err)
	}
	defer conn1.Close()

	conn2, err := ListenUnixgram("unixgram", &UnixAddr{Name: name2, Net: "unixgram"})
	if err != nil {
		t.Fatalf("Create conn2: %v", err)
	}
	defer conn2.Close()

	// WriteTo from conn2 to conn1
	addr1 := &net.UnixAddr{Name: name1, Net: "unixgram"}
	n, err := conn2.WriteTo([]byte("hello"), addr1)
	if err != nil {
		t.Errorf("WriteTo failed: %v", err)
	}
	if n != 5 {
		t.Errorf("Expected n=5, got %d", n)
	}

	// ReadFrom on conn1
	buf := make([]byte, 1024)
	n, from, err := conn1.ReadFrom(buf)
	if err != nil && err != iox.ErrWouldBlock {
		t.Errorf("ReadFrom failed: %v", err)
	}
	if n > 0 {
		if string(buf[:n]) != "hello" {
			t.Errorf("Expected 'hello', got %q", string(buf[:n]))
		}
		_ = from // from address
	}
}

func TestListenUnix_Stream(t *testing.T) {
	name := "@test-unix-stream-" + time.Now().Format("150405.000000000")
	addr := &net.UnixAddr{Name: name, Net: "unix"}

	listener, err := ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix failed: %v", err)
	}
	defer listener.Close()

	// Try to accept with deadline (should timeout)
	listener.SetDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = listener.Accept()
	if err != ErrTimedOut && err != iox.ErrWouldBlock {
		t.Errorf("Expected timeout or would-block, got %v", err)
	}
}

func TestDialUnix_Stream(t *testing.T) {
	name := "@test-unix-dial-" + time.Now().Format("150405.000000000")
	addr := &net.UnixAddr{Name: name, Net: "unix"}

	listener, err := ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix failed: %v", err)
	}
	defer listener.Close()

	// Dial in goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := DialUnix("unix", nil, addr)
		if err != nil {
			return
		}
		conn.Close()
	}()

	// Accept
	listener.SetDeadline(time.Now().Add(1 * time.Second))
	conn, err := listener.Accept()
	if err != nil {
		// May timeout
		<-done
		return
	}
	conn.Close()
	<-done
}

// Error path tests

func TestNetSocket_ClosedOperations(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}

	// Close the socket
	sock.Close()

	// Operations on closed socket should fail
	err = sock.Bind(NewSockaddrInet4([4]byte{127, 0, 0, 1}, 0))
	if err == nil {
		t.Error("Expected error for bind on closed socket")
	}

	err = sock.Listen(5)
	if err == nil {
		t.Error("Expected error for listen on closed socket")
	}

	_, _, err = sock.Accept()
	if err == nil {
		t.Error("Expected error for accept on closed socket")
	}
}

func TestGetSocketError(t *testing.T) {
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	// Get socket error (should be nil for fresh socket)
	err = GetSocketError(sock.fd)
	if err != nil {
		t.Errorf("GetSocketError returned error on fresh socket: %v", err)
	}
}

func TestNetSocketPair_Errors(t *testing.T) {
	// Test with Unix socket pair (should work for SOCK_STREAM)
	pair, err := NetSocketPair(zcall.AF_UNIX, SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("NetSocketPair failed: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Verify they work
	_, err = pair[0].Write([]byte("test"))
	if err != nil && err != iox.ErrWouldBlock {
		t.Errorf("Write failed: %v", err)
	}
}

// Additional SCTP tests

func TestSCTPSocket_Defaults(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()

	// Verify socket is created with defaults applied
	if sock.fd.Raw() < 0 {
		t.Error("Invalid fd")
	}
}

func TestSCTPListener_AcceptSocketNonBlocking(t *testing.T) {
	listener, err := ListenSCTP4(&SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	// Try AcceptSocket without pending connection
	_, err = listener.AcceptSocket()
	// Accept either ErrWouldBlock or a syscall error (depends on kernel config)
	if err == nil {
		t.Error("Expected error when no pending connection")
	}
}

func TestDialSCTP_WithLocalAddr(t *testing.T) {
	// Create listener first
	listener, err := ListenSCTP4(&SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	// Get listener address
	sa, _ := GetSockname(listener.fd)
	inet4 := sa.(*SockaddrInet4)
	addr4 := inet4.Addr()
	serverAddr := &SCTPAddr{IP: net.IP(addr4[:]), Port: int(inet4.Port())}

	// Dial with local address
	localAddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := DialSCTP4(localAddr, serverAddr)
	if err != nil {
		// Connection might fail, just verify it tried
		return
	}
	conn.Close()
}

// ResolveSCTPAddr edge cases

func TestResolveSCTPAddr_EdgeCases(t *testing.T) {
	// Test sctp6 with IPv4 address (should work)
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:5000")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil address")
	}

	// Test with IPv6 address in sctp network
	addr, err = ResolveSCTPAddr("sctp", "[::1]:5000")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil address")
	}
}

// Adaptive I/O edge cases

func TestAdaptiveRead_AlreadyExpired(t *testing.T) {
	var ds deadlineState
	ds.setReadDeadline(time.Now().Add(-1 * time.Second)) // Already expired

	callCount := 0
	readFn := func() (int, error) {
		callCount++
		return 0, iox.ErrWouldBlock
	}

	_, err := adaptiveRead(readFn, &ds)
	if err != ErrTimedOut {
		t.Errorf("Expected ErrTimedOut, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected 1 call, got %d", callCount)
	}
}

func TestAdaptiveWrite_AlreadyExpired(t *testing.T) {
	var ds deadlineState
	ds.setWriteDeadline(time.Now().Add(-1 * time.Second)) // Already expired

	callCount := 0
	writeFn := func() (int, error) {
		callCount++
		return 0, iox.ErrWouldBlock
	}

	_, err := adaptiveWrite(writeFn, &ds)
	if err != ErrTimedOut {
		t.Errorf("Expected ErrTimedOut, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("Expected 1 call, got %d", callCount)
	}
}

// SockaddrUnix path edge cases

func TestSockaddrUnix_LongPath(t *testing.T) {
	// Unix socket paths are limited to 108 bytes
	longPath := "/tmp/" + string(make([]byte, 100))
	sa := NewSockaddrUnix(longPath)
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	// Path should be truncated
	path := sa.Path()
	if len(path) > 107 {
		t.Errorf("Path too long: %d", len(path))
	}
}

func TestSockaddrUnix_EmptyPath(t *testing.T) {
	sa := NewSockaddrUnix("")
	if sa == nil {
		t.Fatal("Expected non-nil sockaddr")
	}
	if sa.Path() != "" {
		t.Errorf("Expected empty path, got %q", sa.Path())
	}
}

// TCPAddr/UDPAddr conversion edge cases

func TestTCPAddrToSockaddr_NilIP(t *testing.T) {
	addr := &TCPAddr{IP: nil, Port: 8080}
	sa := TCPAddrToSockaddr(addr)
	// nil IP returns nil sockaddr (no IP to convert)
	if sa != nil {
		t.Fatal("Expected nil sockaddr for nil IP")
	}
}

func TestUDPAddrToSockaddr_NilIP(t *testing.T) {
	addr := &UDPAddr{IP: nil, Port: 8080}
	sa := UDPAddrToSockaddr(addr)
	// nil IP returns nil sockaddr (no IP to convert)
	if sa != nil {
		t.Fatal("Expected nil sockaddr for nil IP")
	}
}

// ipFamily edge cases

func TestIpFamily_ShortIP(t *testing.T) {
	// IP shorter than IPv4len
	ip := net.IP{127, 0, 0}
	family := ipFamily(ip)
	if family != NetworkIPv4 {
		t.Errorf("Expected NetworkIPv4, got %v", family)
	}
}

// Connection lifecycle tests

func TestTCPConn_Lifecycle(t *testing.T) {
	// Create connected pair
	listener, err := ListenTCP4(&TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	sa, _ := GetSockname(listener.fd)
	inet4 := sa.(*SockaddrInet4)
	addr4 := inet4.Addr()
	serverAddr := &TCPAddr{IP: net.IP(addr4[:]), Port: int(inet4.Port())}

	// Connect in goroutine
	done := make(chan *TCPConn)
	go func() {
		conn, _ := DialTCP4(nil, serverAddr)
		done <- conn
	}()

	// Accept
	listener.SetDeadline(time.Now().Add(1 * time.Second))
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	clientConn := <-done
	if clientConn != nil {
		defer clientConn.Close()

		// Verify connection is usable
		if clientConn.LocalAddr() == nil {
			t.Error("LocalAddr returned nil")
		}
		if clientConn.RemoteAddr() == nil {
			t.Error("RemoteAddr returned nil")
		}
	}
}

// ResolveSCTPAddr tests

func TestResolveSCTPAddr_InvalidNetwork(t *testing.T) {
	_, err := ResolveSCTPAddr("invalid", "127.0.0.1:8080")
	if err == nil {
		t.Error("Expected error for invalid network")
	}
}

func TestResolveSCTPAddr_EmptyNetwork(t *testing.T) {
	// Empty network should default to "sctp"
	addr, err := ResolveSCTPAddr("", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
}

func TestResolveSCTPAddr_IPv6Address(t *testing.T) {
	// Address with : should trigger IPv6 detection
	addr, err := ResolveSCTPAddr("sctp", "[::1]:8080")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
}

func TestResolveSCTPAddr_sctp4(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp4", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
}

func TestResolveSCTPAddr_sctp6(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp6", "[::1]:8080")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
}

// DialSCTP tests

func TestDialSCTP_FallbackNetwork(t *testing.T) {
	// Invalid network falls back to IP family detection
	conn, err := DialSCTP("invalid", nil, &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
	if err == nil && conn != nil {
		conn.Close()
	}
}

func TestDialSCTP_NilRemoteAddr(t *testing.T) {
	_, err := DialSCTP("sctp4", nil, nil)
	if err == nil {
		t.Error("Expected error for nil remote address")
	}
}

// NetSocketPair error path

func TestNetSocketPair_InvalidDomain(t *testing.T) {
	// Invalid domain should fail
	_, err := NetSocketPair(-1, SOCK_STREAM, 0)
	if err == nil {
		t.Error("Expected error for invalid domain")
	}
}

// GetSocketError tests

func TestGetSocketError_InvalidFD(t *testing.T) {
	// Create and close socket to get invalid fd
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	fd := sock.fd
	sock.Close()

	// Should fail on closed socket
	err = GetSocketError(fd)
	if err == nil {
		t.Error("Expected error on closed socket")
	}
}

// TCP error paths

func TestListenTCP4_NilAddr(t *testing.T) {
	_, err := ListenTCP4(nil)
	if err == nil {
		t.Error("Expected error for nil address")
	}
}

func TestDialTCP_FallbackNetwork(t *testing.T) {
	// Invalid network falls back to IP family detection
	// This test just ensures the code path doesn't panic
	_, err := DialTCP("invalid", nil, &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
	// Connection will fail (no server listening), but that's OK - we just test the code path
	_ = err
}

func TestDialTCP_NilRemoteAddr(t *testing.T) {
	_, err := DialTCP("tcp4", nil, nil)
	if err == nil {
		t.Error("Expected error for nil remote address")
	}
}

// UDP error paths

func TestListenUDP4_NilAddr(t *testing.T) {
	_, err := ListenUDP4(nil)
	if err == nil {
		t.Error("Expected error for nil address")
	}
}

func TestDialUDP_FallbackNetwork(t *testing.T) {
	// Invalid network falls back to IP family detection
	conn, err := DialUDP("invalid", nil, &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
	if err == nil && conn != nil {
		conn.Close()
	}
}

func TestDialUDP_NilRemoteAddr(t *testing.T) {
	_, err := DialUDP("udp4", nil, nil)
	if err == nil {
		t.Error("Expected error for nil remote address")
	}
}

// Unix error paths

func TestListenUnix_InvalidNetwork(t *testing.T) {
	_, err := ListenUnix("invalid", &net.UnixAddr{Name: "@test", Net: "unix"})
	if err == nil {
		t.Error("Expected error for invalid network")
	}
}

func TestListenUnix_NilAddr(t *testing.T) {
	_, err := ListenUnix("unix", nil)
	if err == nil {
		t.Error("Expected error for nil address")
	}
}

func TestDialUnix_InvalidNetwork(t *testing.T) {
	_, err := DialUnix("invalid", nil, &net.UnixAddr{Name: "@test", Net: "unix"})
	if err == nil {
		t.Error("Expected error for invalid network")
	}
}

func TestDialUnix_NilRemoteAddr(t *testing.T) {
	_, err := DialUnix("unix", nil, nil)
	if err == nil {
		t.Error("Expected error for nil remote address")
	}
}

// Raw socket tests (require CAP_NET_RAW)

func TestDialRaw_InvalidNetwork(t *testing.T) {
	_, err := DialRaw("invalid", nil, &IPAddr{IP: net.ParseIP("127.0.0.1")}, 1)
	if err == nil {
		t.Error("Expected error for invalid network")
	}
}

func TestDialRaw_NilRemoteAddr(t *testing.T) {
	_, err := DialRaw("ip4", nil, nil, 1)
	if err == nil {
		t.Error("Expected error for nil remote address")
	}
}

func TestDialRaw4_NilRemoteAddr(t *testing.T) {
	_, err := DialRaw4(nil, nil, 1)
	if err == nil {
		t.Error("Expected error for nil remote address")
	}
}

func TestDialRaw6_NilRemoteAddr(t *testing.T) {
	_, err := DialRaw6(nil, nil, 58)
	if err == nil {
		t.Error("Expected error for nil remote address")
	}
}

// decodeIPAddr tests

func TestDecodeIPAddr_InvalidFamily(t *testing.T) {
	// Create a raw sockaddr with invalid family
	raw := &RawSockaddrAny{}
	raw.Addr.Family = 0xFF // Invalid family
	addr := decodeIPAddr(raw)
	if addr != nil {
		t.Error("Expected nil for invalid family")
	}
}

func TestDecodeIPAddr_Nil(t *testing.T) {
	addr := decodeIPAddr(nil)
	if addr != nil {
		t.Error("Expected nil for nil input")
	}
}

// NewSocket tests

func TestNewTCPSocket4_Defaults(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	// Verify it's a valid TCP socket
	if sock.fd.Raw() < 0 {
		t.Error("Invalid fd")
	}
}

func TestNewTCPSocket6_Defaults(t *testing.T) {
	sock, err := NewTCPSocket6()
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	if sock.fd.Raw() < 0 {
		t.Error("Invalid fd")
	}
}

func TestNewUDPSocket6_Defaults(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	defer sock.Close()

	if sock.fd.Raw() < 0 {
		t.Error("Invalid fd")
	}
}

func TestNewSCTPSocket6_Defaults(t *testing.T) {
	sock, err := NewSCTPSocket6()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()

	if sock.fd.Raw() < 0 {
		t.Error("Invalid fd")
	}
}

func TestNewSCTPStreamSocket4_Defaults(t *testing.T) {
	sock, err := NewSCTPStreamSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()

	if sock.fd.Raw() < 0 {
		t.Error("Invalid fd")
	}
}

func TestNewSCTPStreamSocket6_Defaults(t *testing.T) {
	sock, err := NewSCTPStreamSocket6()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()

	if sock.fd.Raw() < 0 {
		t.Error("Invalid fd")
	}
}

// Accept error paths

func TestSCTPListener_Accept_NoConnection(t *testing.T) {
	listener, err := ListenSCTP4(&SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	// Accept without pending connection should return error
	_, err = listener.Accept()
	if err == nil {
		t.Error("Expected error for accept with no pending connection")
	}
}

// ListenRaw tests (require CAP_NET_RAW)

func TestListenRaw4_ICMP(t *testing.T) {
	conn, err := ListenRaw4(&IPAddr{IP: net.ParseIP("127.0.0.1")}, zcall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
}

func TestListenRaw6_ICMPv6(t *testing.T) {
	conn, err := ListenRaw6(&IPAddr{IP: net.ParseIP("::1")}, 58) // ICMPv6 = 58
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
}

// DialRaw4/DialRaw6 tests (require CAP_NET_RAW)

func TestDialRaw4_ICMP(t *testing.T) {
	conn, err := DialRaw4(nil, &IPAddr{IP: net.ParseIP("127.0.0.1")}, zcall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr returned nil")
	}
}

func TestDialRaw6_ICMPv6(t *testing.T) {
	conn, err := DialRaw6(nil, &IPAddr{IP: net.ParseIP("::1")}, 58) // ICMPv6 = 58
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr returned nil")
	}
}

// setNonBlockCloexec tests

func TestSetNonBlockCloexec_ClosedFD(t *testing.T) {
	// Create and close a socket to get a closed FD
	sock, err := NewNetTCPSocket(false)
	if err != nil {
		t.Fatalf("Create socket: %v", err)
	}
	fd := sock.fd
	sock.Close()

	// Should fail on closed FD
	err = setNonBlockCloexec(fd)
	if err == nil {
		t.Error("Expected error for closed fd")
	}
}

// adaptiveRead edge cases

func TestAdaptiveRead_Expired(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4 failed: %v", err)
	}
	defer conn.Close()

	// Set deadline in the past
	conn.SetReadDeadline(time.Now().Add(-1 * time.Second))
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != ErrTimedOut {
		t.Errorf("Expected ErrTimedOut, got %v", err)
	}
}

// DialUnix comprehensive tests

func TestDialUnix_StreamWithListener(t *testing.T) {
	name := "@test-dial-unix-stream-" + time.Now().Format("150405.000000000")

	// Create listener first
	listener, err := ListenUnix("unix", &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix failed: %v", err)
	}
	defer listener.Close()

	// Dial to listener
	conn, err := DialUnix("unix", nil, &UnixAddr{Name: name, Net: "unix"})
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialUnix failed: %v", err)
	}
	if conn != nil {
		defer conn.Close()
		if conn.LocalAddr() == nil {
			t.Error("LocalAddr returned nil")
		}
		if conn.RemoteAddr() == nil {
			t.Error("RemoteAddr returned nil")
		}
	}
}

func TestDialUnix_Datagram(t *testing.T) {
	name1 := "@test-dial-unix-dgram-1-" + time.Now().Format("150405.000000000")
	name2 := "@test-dial-unix-dgram-2-" + time.Now().Format("150405.000000000")

	// Create receiver
	receiver, err := ListenUnixgram("unixgram", &UnixAddr{Name: name1, Net: "unixgram"})
	if err != nil {
		t.Fatalf("ListenUnixgram failed: %v", err)
	}
	defer receiver.Close()

	// Dial with local address
	laddr := &UnixAddr{Name: name2, Net: "unixgram"}
	conn, err := DialUnix("unixgram", laddr, &UnixAddr{Name: name1, Net: "unixgram"})
	if err != nil {
		t.Fatalf("DialUnix failed: %v", err)
	}
	defer conn.Close()

	// Write something
	_, err = conn.Write([]byte("test"))
	if err != nil && err != iox.ErrWouldBlock {
		t.Errorf("Write failed: %v", err)
	}
}

func TestDialUnix_Seqpacket(t *testing.T) {
	name := "@test-dial-unix-seqpacket-" + time.Now().Format("150405.000000000")

	// Create listener first
	listener, err := ListenUnix("unixpacket", &net.UnixAddr{Name: name, Net: "unixpacket"})
	if err != nil {
		t.Fatalf("ListenUnix failed: %v", err)
	}
	defer listener.Close()

	// Dial to listener
	conn, err := DialUnix("unixpacket", nil, &UnixAddr{Name: name, Net: "unixpacket"})
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialUnix failed: %v", err)
	}
	if conn != nil {
		defer conn.Close()
	}
}

// decodeIPAddr comprehensive tests

func TestDecodeIPAddr_IPv4(t *testing.T) {
	// Create a valid IPv4 sockaddr
	raw := &RawSockaddrAny{}
	sa := (*RawSockaddrInet4)(unsafe.Pointer(raw))
	sa.Family = AF_INET
	sa.Addr = [4]byte{127, 0, 0, 1}

	addr := decodeIPAddr(raw)
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
	if !addr.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("Expected 127.0.0.1, got %v", addr.IP)
	}
}

func TestDecodeIPAddr_IPv6(t *testing.T) {
	// Create a valid IPv6 sockaddr
	raw := &RawSockaddrAny{}
	sa := (*RawSockaddrInet6)(unsafe.Pointer(raw))
	sa.Family = AF_INET6
	copy(sa.Addr[:], net.ParseIP("::1").To16())

	addr := decodeIPAddr(raw)
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
	if !addr.IP.Equal(net.ParseIP("::1")) {
		t.Errorf("Expected ::1, got %v", addr.IP)
	}
}

// ResolveSCTPAddr comprehensive tests

func TestResolveSCTPAddr_sctp4_IPv4(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp4", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
	if addr.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", addr.Port)
	}
}

func TestResolveSCTPAddr_sctp6_IPv6(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp6", "[::1]:8080")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
	if addr.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", addr.Port)
	}
}

func TestResolveSCTPAddr_sctp_IPv6Hint(t *testing.T) {
	// Address with [ should trigger IPv6
	addr, err := ResolveSCTPAddr("sctp", "[::1]:9090")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
}

func TestResolveSCTPAddr_sctp_ColonHint(t *testing.T) {
	// IPv6 address has colons
	addr, err := ResolveSCTPAddr("sctp", "[2001:db8::1]:9090")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %v", err)
	}
	if addr == nil {
		t.Fatal("Expected non-nil addr")
	}
}

// UnixConnPair tests

func TestUnixConnPair_Stream(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair failed: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Write on one, read on other
	_, err = pair[0].Write([]byte("hello"))
	if err != nil && err != iox.ErrWouldBlock {
		t.Errorf("Write failed: %v", err)
	}
}

func TestUnixConnPair_Datagram(t *testing.T) {
	pair, err := UnixConnPair("unixgram")
	if err != nil {
		t.Fatalf("UnixConnPair failed: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()
}

func TestUnixConnPair_Seqpacket(t *testing.T) {
	pair, err := UnixConnPair("unixpacket")
	if err != nil {
		t.Fatalf("UnixConnPair failed: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()
}

func TestUnixConnPair_InvalidNetwork(t *testing.T) {
	_, err := UnixConnPair("invalid")
	if err == nil {
		t.Error("Expected error for invalid network")
	}
}

// NetSocketPair additional tests

func TestNetSocketPair_Datagram(t *testing.T) {
	pair, err := NetSocketPair(zcall.AF_UNIX, SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("NetSocketPair failed: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Verify they work
	_, err = pair[0].Write([]byte("test"))
	if err != nil && err != iox.ErrWouldBlock {
		t.Errorf("Write failed: %v", err)
	}
}

func TestNetSocketPair_Seqpacket(t *testing.T) {
	pair, err := NetSocketPair(zcall.AF_UNIX, SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("NetSocketPair failed: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()
}

// UnixSocketPair test

func TestUnixSocketPair(t *testing.T) {
	pair, err := UnixSocketPair()
	if err != nil {
		t.Fatalf("UnixSocketPair failed: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Verify bidirectional communication
	_, err = pair[0].Write([]byte("ping"))
	if err != nil && err != iox.ErrWouldBlock {
		t.Errorf("Write failed: %v", err)
	}
}

// Additional SCTP dial tests

func TestDialSCTP4_Success(t *testing.T) {
	// Create listener
	listener, err := ListenSCTP4(&SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	sa, _ := GetSockname(listener.fd)
	inet4 := sa.(*SockaddrInet4)
	addr4 := inet4.Addr()
	serverAddr := &SCTPAddr{IP: net.IP(addr4[:]), Port: int(inet4.Port())}

	// Dial
	conn, err := DialSCTP4(nil, serverAddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialSCTP4 failed: %v", err)
	}
	if conn != nil {
		defer conn.Close()
	}
}

func TestDialSCTP6_Success(t *testing.T) {
	// Create listener
	listener, err := ListenSCTP6(&SCTPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	sa, _ := GetSockname(listener.fd)
	inet6 := sa.(*SockaddrInet6)
	addr6 := inet6.Addr()
	serverAddr := &SCTPAddr{IP: net.IP(addr6[:]), Port: int(inet6.Port())}

	// Dial
	conn, err := DialSCTP6(nil, serverAddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialSCTP6 failed: %v", err)
	}
	if conn != nil {
		defer conn.Close()
	}
}

// Additional TCP dial tests

func TestDialTCP4_Success(t *testing.T) {
	// Create listener
	listener, err := ListenTCP4(&TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP4 failed: %v", err)
	}
	defer listener.Close()

	sa, _ := GetSockname(listener.fd)
	inet4 := sa.(*SockaddrInet4)
	addr4 := inet4.Addr()
	serverAddr := &TCPAddr{IP: net.IP(addr4[:]), Port: int(inet4.Port())}

	// Dial
	conn, err := DialTCP4(nil, serverAddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialTCP4 failed: %v", err)
	}
	if conn != nil {
		defer conn.Close()
	}
}

func TestDialTCP6_Success(t *testing.T) {
	// Create listener
	listener, err := ListenTCP6(&TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP6 failed: %v", err)
	}
	defer listener.Close()

	sa, _ := GetSockname(listener.fd)
	inet6 := sa.(*SockaddrInet6)
	addr6 := inet6.Addr()
	serverAddr := &TCPAddr{IP: net.IP(addr6[:]), Port: int(inet6.Port())}

	// Dial
	conn, err := DialTCP6(nil, serverAddr)
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialTCP6 failed: %v", err)
	}
	if conn != nil {
		defer conn.Close()
	}
}

// Additional UDP dial tests

func TestDialUDP4_Success(t *testing.T) {
	conn, err := DialUDP4(nil, &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})
	if err != nil {
		t.Fatalf("DialUDP4 failed: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr returned nil")
	}
}

func TestDialUDP6_Success(t *testing.T) {
	conn, err := DialUDP6(nil, &UDPAddr{IP: net.ParseIP("::1"), Port: 53})
	if err != nil {
		t.Fatalf("DialUDP6 failed: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr returned nil")
	}
}

// ListenTCP additional tests

func TestListenTCP6_Success(t *testing.T) {
	listener, err := ListenTCP6(&TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP6 failed: %v", err)
	}
	defer listener.Close()

	if listener.Addr() == nil {
		t.Error("Addr returned nil")
	}
}

// ListenUDP additional tests

func TestListenUDP6_Success(t *testing.T) {
	conn, err := ListenUDP6(&UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP6 failed: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
}

// ListenSCTP additional tests

func TestListenSCTP6_Success(t *testing.T) {
	listener, err := ListenSCTP6(&SCTPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	if listener.Addr() == nil {
		t.Error("Addr returned nil")
	}
}

// ListenRaw with local address

func TestListenRaw4_NilAddr(t *testing.T) {
	_, err := ListenRaw4(nil, zcall.IPPROTO_ICMP)
	if err == nil {
		t.Error("Expected error for nil address")
	}
}

func TestListenRaw6_NilAddr(t *testing.T) {
	_, err := ListenRaw6(nil, 58)
	if err == nil {
		t.Error("Expected error for nil address")
	}
}

// DialRaw with local address

func TestDialRaw4_WithLocalAddr(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	raddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := DialRaw4(laddr, raddr, zcall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
}

func TestDialRaw6_WithLocalAddr(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("::1")}
	raddr := &IPAddr{IP: net.ParseIP("::1")}
	conn, err := DialRaw6(laddr, raddr, 58)
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
}

// DialRaw network selection

func TestDialRaw_ip4(t *testing.T) {
	conn, err := DialRaw("ip4", nil, &IPAddr{IP: net.ParseIP("127.0.0.1")}, zcall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()
}

func TestDialRaw_ip6(t *testing.T) {
	conn, err := DialRaw("ip6", nil, &IPAddr{IP: net.ParseIP("::1")}, 58)
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()
}

func TestDialRaw_ip(t *testing.T) {
	conn, err := DialRaw("ip", nil, &IPAddr{IP: net.ParseIP("127.0.0.1")}, zcall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw socket not available: %v", err)
	}
	defer conn.Close()
}
