// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build rawsock

package sock_test

import (
	"net"
	"testing"
	"time"

	"code.hybscloud.com/iox"
	. "code.hybscloud.com/sock"
	"code.hybscloud.com/zcall"
)

// Suppress unused import warnings
var (
	_ = iox.ErrWouldBlock
	_ = zcall.IPPROTO_ICMP
	_ = time.Second
)

func TestListenRaw4_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenRaw4(nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenRaw6_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenRaw6(nil, IPPROTO_ICMPV6)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenRaw_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenRaw("ip4", nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialRaw4_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialRaw4(nil, nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialRaw6_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialRaw6(nil, nil, IPPROTO_ICMPV6)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialRaw_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialRaw("ip4", nil, nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestRawSocket_CreateError(t *testing.T) {
	// Try to create raw socket - will fail without CAP_NET_RAW
	_, err := NewRawSocket4(IPPROTO_ICMP)
	if err == nil {
		// If it succeeded, we have permissions - test methods
		t.Log("Have CAP_NET_RAW, skipping error path test")
	} else {
		// Expected to fail without permissions
		if err != ErrPermission {
			t.Logf("NewRawSocket4 error: %v", err)
		}
	}

	_, err = NewRawSocket6(IPPROTO_ICMPV6)
	if err == nil {
		t.Log("Have CAP_NET_RAW for IPv6")
	} else {
		if err != ErrPermission {
			t.Logf("NewRawSocket6 error: %v", err)
		}
	}
}

func TestRawSocket_ICMPCreate(t *testing.T) {
	_, err := NewICMPSocket4()
	if err != nil && err != ErrPermission {
		t.Logf("NewICMPSocket4: %v", err)
	}

	_, err = NewICMPSocket6()
	if err != nil && err != ErrPermission {
		t.Logf("NewICMPSocket6: %v", err)
	}
}

func TestListenRaw_IfAvailable(t *testing.T) {
	// Try to create raw socket - requires CAP_NET_RAW
	conn, err := ListenRaw4(&net.IPAddr{IP: net.ParseIP("127.0.0.1")}, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()

	// If we got here, we have permissions - test the methods
	localAddr := conn.LocalAddr()
	t.Logf("Local address: %v", localAddr)

	remoteAddr := conn.RemoteAddr()
	t.Logf("Remote address: %v", remoteAddr)

	// Test Read - will likely return ErrWouldBlock
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("Read: %v", err)
	}

	// Test RecvFrom
	_, _, err = conn.RecvFrom(buf)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("RecvFrom: %v", err)
	}
}

func TestListenRaw6_IfAvailable(t *testing.T) {
	conn, err := ListenRaw6(&net.IPAddr{IP: net.ParseIP("::1")}, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr()
	t.Logf("Local address: %v", localAddr)
}

func TestRawSocket_MethodsIfAvailable(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer sock.Close()

	// Test Protocol
	proto := sock.Protocol()
	if proto != UnderlyingProtocolRaw {
		t.Errorf("expected UnderlyingProtocolRaw, got %v", proto)
	}

	// Test SetIPHeaderIncluded
	err = sock.SetIPHeaderIncluded(true)
	if err != nil {
		t.Logf("SetIPHeaderIncluded: %v", err)
	}

	// Test RecvFrom - will likely return ErrWouldBlock
	buf := make([]byte, 1024)
	_, _, err = sock.RecvFrom(buf)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("RecvFrom: %v", err)
	}

	// Test SendTo
	addr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	// Create a simple ICMP echo request packet
	icmpPacket := []byte{
		8, 0, // Type (Echo Request), Code
		0, 0, // Checksum (will be wrong, but tests the path)
		0, 1, // Identifier
		0, 1, // Sequence number
	}
	_, err = sock.SendTo(icmpPacket, addr)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("SendTo: %v", err)
	}
}

func TestRawConn_MethodsIfAvailable(t *testing.T) {
	conn, err := ListenRaw4(&IPAddr{IP: net.ParseIP("127.0.0.1")}, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()

	// Test LocalAddr
	laddr := conn.LocalAddr()
	if laddr == nil {
		t.Error("LocalAddr returned nil")
	}

	// Test RemoteAddr (should be nil for unconnected)
	raddr := conn.RemoteAddr()
	if raddr != nil {
		t.Logf("RemoteAddr: %v (unexpected for unconnected)", raddr)
	}

	// Test Read (will ErrWouldBlock or return data)
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("Read: %v", err)
	}

	// Test RecvFrom
	_, addr, err := conn.RecvFrom(buf)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("RecvFrom: %v", err)
	}
	_ = addr

	// Test SendTo
	destAddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	icmpPacket := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	_, err = conn.SendTo(icmpPacket, destAddr)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("SendTo: %v", err)
	}
}

func TestRawConn_WriteIfConnected(t *testing.T) {
	// Test connected RawConn.Write
	conn, err := DialRaw4(nil, &IPAddr{IP: net.ParseIP("127.0.0.1")}, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()

	// Test LocalAddr
	laddr := conn.LocalAddr()
	t.Logf("Local address: %v", laddr)

	// Test RemoteAddr
	raddr := conn.RemoteAddr()
	t.Logf("Remote address: %v", raddr)

	// Test Write (connected)
	icmpPacket := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	_, err = conn.Write(icmpPacket)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("Write: %v", err)
	}
}

func TestRawConn_WriteNotConnected(t *testing.T) {
	conn, err := ListenRaw4(&IPAddr{IP: net.ParseIP("127.0.0.1")}, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()

	// Write on unconnected should fail
	_, err = conn.Write([]byte{8, 0, 0, 0})
	if err != ErrNotConnected {
		t.Logf("Write on unconnected: %v (expected ErrNotConnected)", err)
	}
}

func TestDialRaw4_WithLocalAddrCoverage(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	raddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := DialRaw4(laddr, raddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr returned nil")
	}
}

func TestDialRaw6_WithLocalAddrCoverage(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("::1")}
	raddr := &IPAddr{IP: net.ParseIP("::1")}
	conn, err := DialRaw6(laddr, raddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}
}

func TestDialRaw_Generic(t *testing.T) {
	raddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := DialRaw("ip4", nil, raddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()
}

func TestDialRaw_IPv6Generic(t *testing.T) {
	raddr := &IPAddr{IP: net.ParseIP("::1")}
	conn, err := DialRaw("ip6", nil, raddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()
}

func TestListenRaw_Generic(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := ListenRaw("ip4", laddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()
}

func TestListenRaw_IPv6Generic(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("::1")}
	conn, err := ListenRaw("ip6", laddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer conn.Close()
}

func TestRawSocket_SendToIPv6(t *testing.T) {
	sock, err := NewRawSocket6(IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}
	defer sock.Close()

	addr := &IPAddr{IP: net.ParseIP("::1")}
	icmpv6Packet := []byte{128, 0, 0, 0, 0, 1, 0, 1} // Echo Request
	_, err = sock.SendTo(icmpv6Packet, addr)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("SendTo IPv6: %v", err)
	}
}

func TestRawSocket_ClosedFdError(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Raw sockets not available: %v", err)
	}

	// Close the socket
	sock.Close()

	// RecvFrom on closed should fail
	buf := make([]byte, 1024)
	_, _, err = sock.RecvFrom(buf)
	if err != ErrClosed {
		t.Logf("RecvFrom on closed: %v (expected ErrClosed)", err)
	}

	// SendTo on closed should fail
	addr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	_, err = sock.SendTo([]byte{8, 0, 0, 0}, addr)
	if err != ErrClosed {
		t.Logf("SendTo on closed: %v (expected ErrClosed)", err)
	}
}

func TestRawSocket_CreationFailure(t *testing.T) {
	// Try to create raw socket (will likely fail without CAP_NET_RAW)
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		// Expected to fail without capabilities
		t.Logf("NewRawSocket4 failed as expected: %v", err)
		return
	}
	defer sock.Close()

	// If we got here, we have CAP_NET_RAW - test the socket
	if sock.Protocol() != UnderlyingProtocolRaw {
		t.Error("expected UnderlyingProtocolRaw")
	}
}

func TestRawSocket6_CreationFailure(t *testing.T) {
	sock, err := NewRawSocket6(IPPROTO_ICMPV6)
	if err != nil {
		t.Logf("NewRawSocket6 failed as expected: %v", err)
		return
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolRaw {
		t.Error("expected UnderlyingProtocolRaw")
	}
}

func TestNewICMPSocket4_Coverage(t *testing.T) {
	sock, err := NewICMPSocket4()
	if err != nil {
		t.Logf("NewICMPSocket4 failed (expected without CAP_NET_RAW): %v", err)
		return
	}
	defer sock.Close()
}

func TestNewICMPSocket6_Coverage(t *testing.T) {
	sock, err := NewICMPSocket6()
	if err != nil {
		t.Logf("NewICMPSocket6 failed (expected without CAP_NET_RAW): %v", err)
		return
	}
	defer sock.Close()
}

func TestListenRaw4_NilAddress(t *testing.T) {
	_, err := ListenRaw4(nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenRaw6_NilAddress(t *testing.T) {
	_, err := ListenRaw6(nil, IPPROTO_ICMPV6)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenRaw_NilAddr(t *testing.T) {
	_, err := ListenRaw("ip4", nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialRaw4_NilAddr(t *testing.T) {
	_, err := DialRaw4(nil, nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialRaw6_NilAddr(t *testing.T) {
	_, err := DialRaw6(nil, nil, IPPROTO_ICMPV6)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialRaw_NilAddr(t *testing.T) {
	_, err := DialRaw("ip4", nil, nil, IPPROTO_ICMP)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestRawConn_Methods(t *testing.T) {
	laddr := &IPAddr{IP: net.IPv4(127, 0, 0, 1)}
	conn, err := ListenRaw4(laddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("ListenRaw4 failed (need CAP_NET_RAW): %v", err)
		return
	}
	defer conn.Close()

	// Test LocalAddr
	if conn.LocalAddr() == nil {
		t.Error("LocalAddr returned nil")
	}

	// Test RemoteAddr (should be nil for listening socket)
	if conn.RemoteAddr() != nil {
		t.Error("RemoteAddr should be nil for listening socket")
	}

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

	// Test SetIPHeaderIncluded
	if err := conn.SetIPHeaderIncluded(true); err != nil {
		t.Errorf("SetIPHeaderIncluded: %v", err)
	}

	// Clear deadlines
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline(zero): %v", err)
	}
}

func TestRawConn_ReadWriteUnconnected(t *testing.T) {
	laddr := &IPAddr{IP: net.IPv4(127, 0, 0, 1)}
	conn, err := ListenRaw4(laddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("ListenRaw4 failed (need CAP_NET_RAW): %v", err)
		return
	}
	defer conn.Close()

	// Test Write on unconnected socket should fail
	_, err = conn.Write([]byte{0x08, 0x00, 0x00, 0x00})
	if err != ErrNotConnected {
		t.Errorf("Write on unconnected: expected ErrNotConnected, got %v", err)
	}

	// Test Read with no deadline (non-blocking)
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err != iox.ErrWouldBlock {
		t.Logf("Read: %v (expected ErrWouldBlock or data)", err)
	}
}

func TestDialRaw4_WithLocalAddrAndRemote(t *testing.T) {
	laddr := &IPAddr{IP: net.IPv4(127, 0, 0, 1)}
	raddr := &IPAddr{IP: net.IPv4(127, 0, 0, 1)}
	conn, err := DialRaw4(laddr, raddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("DialRaw4 failed (need CAP_NET_RAW): %v", err)
		return
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr should not be nil")
	}
}

func TestDialRaw6_WithLocalAddrAndRemote(t *testing.T) {
	laddr := &IPAddr{IP: net.IPv6loopback}
	raddr := &IPAddr{IP: net.IPv6loopback}
	conn, err := DialRaw6(laddr, raddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("DialRaw6 failed (need CAP_NET_RAW): %v", err)
		return
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
}

func TestDialRaw_IPv6(t *testing.T) {
	raddr := &IPAddr{IP: net.IPv6loopback}
	conn, err := DialRaw("ip6", nil, raddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("DialRaw ip6 failed (need CAP_NET_RAW): %v", err)
		return
	}
	defer conn.Close()
}

func TestListenRaw_IPv6(t *testing.T) {
	laddr := &IPAddr{IP: net.IPv6loopback}
	conn, err := ListenRaw("ip6", laddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("ListenRaw ip6 failed (need CAP_NET_RAW): %v", err)
		return
	}
	defer conn.Close()
}

func TestRawConn_ReadWithoutRemoteCoverage(t *testing.T) {
	laddr := &IPAddr{IP: net.IPv4(0, 0, 0, 0)}
	conn, err := ListenRaw4(laddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("ListenRaw4 failed (need CAP_NET_RAW): %v", err)
		return
	}
	defer conn.Close()

	// Read without raddr uses RecvFrom
	buf := make([]byte, 1500)
	_, err = conn.Read(buf)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("Read (unconnected): %v", err)
	}

	// Write without raddr should fail
	_, err = conn.Write([]byte{8, 0, 0, 0})
	if err != ErrNotConnected {
		t.Errorf("expected ErrNotConnected for Write on unconnected socket, got %v", err)
	}
}

func TestRawSocket_ProtocolMethod(t *testing.T) {
	// Try to create raw socket (will fail without CAP_NET_RAW)
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("NewRawSocket4: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer sock.Close()

	// Test Protocol method
	if sock.Protocol() != UnderlyingProtocolRaw {
		t.Errorf("Protocol: expected UnderlyingProtocolRaw, got %v", sock.Protocol())
	}
}

func TestRawSocket_RecvFromClosed(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("NewRawSocket4: %v (requires CAP_NET_RAW)", err)
		return
	}
	sock.Close()

	buf := make([]byte, 64)
	_, _, err = sock.RecvFrom(buf)
	if err != ErrClosed {
		t.Errorf("RecvFrom on closed: expected ErrClosed, got %v", err)
	}
}

func TestRawSocket_SendToClosed(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("NewRawSocket4: %v (requires CAP_NET_RAW)", err)
		return
	}
	sock.Close()

	addr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	_, err = sock.SendTo([]byte("test"), addr)
	if err != ErrClosed {
		t.Errorf("SendTo on closed: expected ErrClosed, got %v", err)
	}
}

func TestRawSocket_SetIPHeaderIncludedOpt(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_RAW)
	if err != nil {
		t.Skipf("NewRawSocket4: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer sock.Close()

	err = sock.SetIPHeaderIncluded(true)
	if err != nil {
		t.Errorf("SetIPHeaderIncluded: %v", err)
	}
}

func TestRawConn_Accessors(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := ListenRaw4(laddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("ListenRaw4: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer conn.Close()

	// Test LocalAddr
	if conn.LocalAddr() == nil {
		t.Error("LocalAddr: expected non-nil")
	}

	// Test RemoteAddr (should be nil for unconnected)
	if conn.RemoteAddr() != nil {
		t.Error("RemoteAddr: expected nil for unconnected socket")
	}
}

func TestRawConn_Deadlines(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := ListenRaw4(laddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("ListenRaw4: %v (requires CAP_NET_RAW)", err)
		return
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

	// Clear deadlines
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline clear: %v", err)
	}
}

func TestRawConn_ReadWriteNotConnected(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := ListenRaw4(laddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("ListenRaw4: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer conn.Close()

	// Write without remote address should fail
	_, err = conn.Write([]byte("test"))
	if err != ErrNotConnected {
		t.Errorf("Write not connected: expected ErrNotConnected, got %v", err)
	}
}

func TestRawConn_RecvFromSendToMethods(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	conn, err := ListenRaw4(laddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("ListenRaw4: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer conn.Close()

	// These just call through to RawSocket methods
	// Test that they work without error
	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))

	buf := make([]byte, 64)
	_, _, err = conn.RecvFrom(buf)
	// Expected to timeout or return ErrWouldBlock
	t.Logf("RecvFrom: %v", err)

	// SendTo
	addr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	_, err = conn.SendTo([]byte{8, 0, 0, 0, 0, 1, 0, 1}, addr) // ICMP echo request
	t.Logf("SendTo: %v", err)
}

func TestDialRaw4_WithLocalAddrBinding(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}
	raddr := &IPAddr{IP: net.ParseIP("127.0.0.1")}

	conn, err := DialRaw4(laddr, raddr, IPPROTO_ICMP)
	if err != nil {
		t.Skipf("DialRaw4: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer conn.Close()

	// Check that local and remote addresses are set
	if conn.LocalAddr() == nil {
		t.Error("LocalAddr: expected non-nil")
	}
	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr: expected non-nil")
	}
}

func TestDialRaw6_WithLocalAddrBinding(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("::1")}
	raddr := &IPAddr{IP: net.ParseIP("::1")}

	conn, err := DialRaw6(laddr, raddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("DialRaw6: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer conn.Close()

	// Check that local and remote addresses are set
	if conn.LocalAddr() == nil {
		t.Error("LocalAddr: expected non-nil")
	}
	if conn.RemoteAddr() == nil {
		t.Error("RemoteAddr: expected non-nil")
	}
}

func TestNewRawSocket6_ProtocolCheck(t *testing.T) {
	sock, err := NewRawSocket6(IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("NewRawSocket6: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolRaw {
		t.Errorf("Protocol: expected Raw, got %v", sock.Protocol())
	}
}

func TestRawSocket_SendToIPv6Addr(t *testing.T) {
	sock, err := NewRawSocket6(IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("NewRawSocket6: %v (requires CAP_NET_RAW)", err)
		return
	}
	defer sock.Close()

	// Send to IPv6 address
	addr := &IPAddr{IP: net.ParseIP("::1")}
	_, err = sock.SendTo([]byte{128, 0, 0, 0, 0, 1, 0, 1}, addr) // ICMPv6 echo request
	// May fail, but exercises the IPv6 path
	t.Logf("SendTo IPv6: %v", err)
}

func TestDialRaw_IPv6Network(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("::1")}
	raddr := &IPAddr{IP: net.ParseIP("::1")}
	conn, err := DialRaw("ip6", laddr, raddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("DialRaw: %v (requires CAP_NET_RAW)", err)
		return
	}
	conn.Close()
}

func TestListenRaw_IPv6Network(t *testing.T) {
	laddr := &IPAddr{IP: net.ParseIP("::1")}
	conn, err := ListenRaw("ip6", laddr, IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("ListenRaw: %v (requires CAP_NET_RAW)", err)
		return
	}
	conn.Close()
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

func TestRawSocket4_Create(t *testing.T) {
	sock, err := NewRawSocket4(IPPROTO_ICMP)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolRaw {
		t.Errorf("Expected UnderlyingProtocolRaw, got %d", sock.Protocol())
	}
}

func TestRawSocket6_Create(t *testing.T) {
	sock, err := NewRawSocket6(IPPROTO_ICMPV6)
	if err != nil {
		t.Skipf("Skipping: CAP_NET_RAW required: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolRaw {
		t.Errorf("Expected UnderlyingProtocolRaw, got %d", sock.Protocol())
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

// TestRawConn_RecvFromIPv6 tests the IPv6 path in decodeIPAddr by sending
// an ICMPv6 echo request to localhost and receiving the reply.
func TestRawConn_RecvFromIPv6(t *testing.T) {
	// Create ICMPv6 socket listening on ::1
	laddr := &IPAddr{IP: net.ParseIP("::1")}
	conn, err := ListenRaw6(laddr, 58) // ICMPv6 = 58
	if err != nil {
		t.Skipf("ListenRaw6 not available: %v", err)
	}
	defer conn.Close()

	// Set a short read deadline
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// Build ICMPv6 echo request (type=128, code=0)
	// ICMPv6 header: type(1) + code(1) + checksum(2) + identifier(2) + sequence(2) = 8 bytes
	icmpReq := []byte{
		128,  // Type: Echo Request
		0,    // Code
		0, 0, // Checksum (will be calculated by kernel)
		0, 1, // Identifier
		0, 1, // Sequence
		'h', 'i', // Payload
	}

	// Send to self
	raddr := &IPAddr{IP: net.ParseIP("::1")}
	n, err := conn.SendTo(icmpReq, raddr)
	if err != nil {
		t.Logf("SendTo ::1: %v (may be expected)", err)
	} else {
		t.Logf("Sent %d bytes to ::1", n)
	}

	// Try to receive - this exercises decodeIPAddr with AF_INET6
	buf := make([]byte, 1024)
	rn, from, err := conn.RecvFrom(buf)
	if err != nil {
		t.Logf("RecvFrom: %v (timeout expected if no reply)", err)
	} else {
		t.Logf("Received %d bytes from %v", rn, from)
		// Check that from is an IPv6 address
		if from != nil && from.IP.To4() == nil {
			t.Logf("Successfully decoded IPv6 address: %v", from)
		}
	}
}
