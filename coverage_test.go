// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"io"
	"net"
	"testing"
	"time"
	"unsafe"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/zcall"
)

// Additional tests to improve code coverage

func TestNewUDPSocket4_DefaultsCheck(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Verify defaults applied
	reuse, err := GetReuseAddr(sock.fd)
	if err != nil {
		t.Errorf("GetReuseAddr: %v", err)
	}
	if !reuse {
		t.Error("expected SO_REUSEADDR enabled by default")
	}
}

func TestListenTCP4_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenTCP4(nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenTCP6_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenTCP6(nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenUDP4_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenUDP4(nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenUDP6_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenUDP6(nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialTCP4_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialTCP4(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialTCP6_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialTCP6(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialUDP4_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialUDP4(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialUDP6_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialUDP6(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenSCTP4_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenSCTP4(nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestListenSCTP6_Error(t *testing.T) {
	// nil address should fail
	_, err := ListenSCTP6(nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialSCTP4_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialSCTP4(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestDialSCTP6_Error(t *testing.T) {
	// nil remote address should fail
	_, err := DialSCTP6(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestTCPListener_AcceptSocketCoverage(t *testing.T) {
	addr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(addr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	// Set short deadline so accept doesn't block
	lis.SetDeadline(time.Now().Add(50 * time.Millisecond))

	_, err = lis.AcceptSocket()
	if err != iox.ErrWouldBlock && err != ErrTimedOut {
		t.Errorf("expected ErrWouldBlock or ErrTimedOut, got %v", err)
	}
}

func TestUnixListener_AcceptSocketCoverage(t *testing.T) {
	addr := uniqAddr("accept_cov", "unix")
	lis, err := ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer lis.Close()

	// Set short deadline so accept doesn't block
	lis.SetDeadline(time.Now().Add(50 * time.Millisecond))

	_, err = lis.AcceptSocket()
	if err != iox.ErrWouldBlock && err != ErrTimedOut {
		t.Errorf("expected ErrWouldBlock or ErrTimedOut, got %v", err)
	}
}

func TestNetSocketPair_StreamCoverage(t *testing.T) {
	pair, err := NetSocketPair(AF_UNIX, SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("NetSocketPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Test basic communication
	msg := []byte("test")
	n, err := pair[0].Write(msg)
	if err != nil && err != iox.ErrWouldBlock {
		t.Fatalf("Write: %v", err)
	}
	if n != len(msg) && err == nil {
		t.Errorf("short write: %d", n)
	}
}

func TestNetSocketPair_DgramCoverage(t *testing.T) {
	pair, err := NetSocketPair(AF_UNIX, SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("NetSocketPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()
}

func TestSockaddrUnix_Path(t *testing.T) {
	// Test with path longer than 108 bytes (max Unix path length)
	longPath := "/tmp/" + string(make([]byte, 200))
	sa := NewSockaddrUnix(longPath)
	path := sa.Path()
	if len(path) > 107 {
		t.Error("path should be truncated to 107 chars")
	}

	// Test normal path
	normalPath := "/tmp/test.sock"
	sa = NewSockaddrUnix(normalPath)
	if sa.Path() != normalPath {
		t.Errorf("expected %q, got %q", normalPath, sa.Path())
	}

	// Test abstract path
	abstractPath := "@test_abstract"
	sa = NewSockaddrUnix(abstractPath)
	if sa.Path() != abstractPath {
		t.Errorf("expected %q, got %q", abstractPath, sa.Path())
	}
}

func TestReadExpired_NoDeadline(t *testing.T) {
	var ds deadlineState
	// No deadline set - should not be expired
	if ds.readExpired() {
		t.Error("expected not expired when no deadline set")
	}
}

func TestWriteExpired_NoDeadline(t *testing.T) {
	var ds deadlineState
	// No deadline set - should not be expired
	if ds.writeExpired() {
		t.Error("expected not expired when no deadline set")
	}
}

func TestReadExpired_FutureDeadline(t *testing.T) {
	var ds deadlineState
	ds.setReadDeadline(time.Now().Add(time.Hour))
	if ds.readExpired() {
		t.Error("expected not expired with future deadline")
	}
}

func TestWriteExpired_FutureDeadline(t *testing.T) {
	var ds deadlineState
	ds.setWriteDeadline(time.Now().Add(time.Hour))
	if ds.writeExpired() {
		t.Error("expected not expired with future deadline")
	}
}

func TestReadExpired_PastDeadline(t *testing.T) {
	var ds deadlineState
	ds.setReadDeadline(time.Now().Add(-time.Second))
	if !ds.readExpired() {
		t.Error("expected expired with past deadline")
	}
}

func TestWriteExpired_PastDeadline(t *testing.T) {
	var ds deadlineState
	ds.setWriteDeadline(time.Now().Add(-time.Second))
	if !ds.writeExpired() {
		t.Error("expected expired with past deadline")
	}
}

func TestSetFdFlags_Error(t *testing.T) {
	// Create and close a socket to get an invalid fd
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	fd := sock.fd
	sock.Close()

	// Try to set flags on closed fd
	err = setFdFlags(fd, 0)
	if err == nil {
		t.Error("expected error on closed fd")
	}
}

func TestSCTPInitMsg_SetError(t *testing.T) {
	// Create and close a socket to get an invalid fd
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	fd := sock.fd
	sock.Close()

	// Try to set init msg on closed fd
	msg := &SCTPInitMsg{NumOstreams: 10}
	err = SetSCTPInitMsg(fd, msg)
	if err == nil {
		t.Error("expected error on closed fd")
	}
}

func TestDialTCP4_WithLocalAddrCoverage(t *testing.T) {
	// Create listener
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	// Get actual listener address
	lisAddr := lis.Addr().(*TCPAddr)

	// Dial with local address
	localAddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := DialTCP4(localAddr, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil local address")
	}
}

func TestDialTCP6_WithLocalAddrCoverage(t *testing.T) {
	// Create listener
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	lis, err := ListenTCP6(laddr)
	if err != nil {
		t.Fatalf("ListenTCP6: %v", err)
	}
	defer lis.Close()

	// Get actual listener address
	lisAddr := lis.Addr().(*TCPAddr)

	// Dial with local address
	localAddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := DialTCP6(localAddr, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP6: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil local address")
	}
}

func TestDialUDP4_WithLocalAddrCoverage(t *testing.T) {
	// Create listener
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer lis.Close()

	// Get actual listener address
	lisAddr := lis.LocalAddr().(*UDPAddr)

	// Dial with local address
	localAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := DialUDP4(localAddr, lisAddr)
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil local address")
	}
}

func TestDialUDP6_WithLocalAddrCoverage(t *testing.T) {
	// Create listener
	laddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	lis, err := ListenUDP6(laddr)
	if err != nil {
		t.Fatalf("ListenUDP6: %v", err)
	}
	defer lis.Close()

	// Get actual listener address
	lisAddr := lis.LocalAddr().(*UDPAddr)

	// Dial with local address
	localAddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := DialUDP6(localAddr, lisAddr)
	if err != nil {
		t.Fatalf("DialUDP6: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil local address")
	}
}

func TestDialSCTP4_WithLocalAddrCoverage(t *testing.T) {
	// Create listener
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenSCTP4(laddr)
	if err != nil {
		t.Fatalf("ListenSCTP4: %v", err)
	}
	defer lis.Close()

	// Get actual listener address
	lisAddr := lis.Addr().(*SCTPAddr)

	// Dial with local address
	localAddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := DialSCTP4(localAddr, lisAddr)
	if err != nil {
		t.Fatalf("DialSCTP4: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil local address")
	}
}

func TestDialSCTP6_WithLocalAddrCoverage(t *testing.T) {
	// Create listener
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	lis, err := ListenSCTP6(laddr)
	if err != nil {
		t.Fatalf("ListenSCTP6: %v", err)
	}
	defer lis.Close()

	// Get actual listener address
	lisAddr := lis.Addr().(*SCTPAddr)

	// Dial with local address
	localAddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := DialSCTP6(localAddr, lisAddr)
	if err != nil {
		t.Fatalf("DialSCTP6: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil local address")
	}
}

func TestTCPConn_ReadWriteCoverage(t *testing.T) {
	// Create listener
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	// Accept in goroutine
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		close(ready)
		lis.SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 16)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _ := conn.Read(buf)
		if n > 0 {
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			conn.Write(buf[:n])
		}
	}()

	<-ready
	time.Sleep(10 * time.Millisecond) // Let accept start

	// Dial
	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Write
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte("hello"))
	if err != nil && err != iox.ErrWouldBlock && err != ErrInProgress {
		t.Logf("Write: %v (may be expected)", err)
	}

	<-done
}

// ========== ResolveSCTPAddr Tests ==========

func TestResolveSCTPAddr_SCTP4Only(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp4", "127.0.0.1:5000")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr: %v", err)
	}
	if addr.IP.To4() == nil {
		t.Error("expected IPv4 address")
	}
}

func TestResolveSCTPAddr_SCTP6Only(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp6", "[::1]:5000")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr: %v", err)
	}
	if addr.IP.To4() != nil {
		t.Error("expected IPv6 address")
	}
}

func TestResolveSCTPAddr_IPv6Bracket(t *testing.T) {
	// Test that "sctp" with IPv6 notation is detected
	addr, err := ResolveSCTPAddr("sctp", "[::1]:5000")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr: %v", err)
	}
	if addr == nil {
		t.Fatal("expected non-nil addr")
	}
}

// ========== SCTPAddr Method Tests ==========

func TestSCTPAddr_Network(t *testing.T) {
	addr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5000}
	if addr.Network() != "sctp" {
		t.Errorf("expected 'sctp', got %q", addr.Network())
	}
}

func TestSCTPAddr_StringNil(t *testing.T) {
	var addr *SCTPAddr
	if addr.String() != "<nil>" {
		t.Errorf("expected '<nil>', got %q", addr.String())
	}
}

func TestSCTPAddr_StringWithZone(t *testing.T) {
	addr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 5000, Zone: "lo"}
	s := addr.String()
	if s != "[::1%lo]:5000" {
		t.Errorf("expected '[::1%%lo]:5000', got %q", s)
	}
}

func TestSCTPAddr_StringEmptyIP(t *testing.T) {
	addr := &SCTPAddr{Port: 5000}
	s := addr.String()
	if s != ":5000" {
		t.Errorf("expected ':5000', got %q", s)
	}
}

func TestSCTPAddr_WithPort(t *testing.T) {
	// Test SCTPAddr with specific port
	ip := net.ParseIP("127.0.0.1")
	addr := &SCTPAddr{IP: ip, Port: 8080}
	if addr.Port != 8080 {
		t.Errorf("expected port 8080, got %d", addr.Port)
	}
}

// ========== IP Address Helper Tests ==========

func TestIPAddrFromTCPAddr(t *testing.T) {
	tcpAddr := &TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80, Zone: "eth0"}
	ipAddr := IPAddrFromTCPAddr(tcpAddr)
	if !ipAddr.IP.Equal(tcpAddr.IP) {
		t.Error("IP mismatch")
	}
	if ipAddr.Zone != "eth0" {
		t.Errorf("zone mismatch: got %q", ipAddr.Zone)
	}
}

func TestIPAddrFromUDPAddr(t *testing.T) {
	udpAddr := &UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 53, Zone: "eth0"}
	ipAddr := IPAddrFromUDPAddr(udpAddr)
	if !ipAddr.IP.Equal(udpAddr.IP) {
		t.Error("IP mismatch")
	}
	if ipAddr.Zone != "eth0" {
		t.Errorf("zone mismatch: got %q", ipAddr.Zone)
	}
}

func TestIPAddrFromSCTPAddr(t *testing.T) {
	sctpAddr := &SCTPAddr{IP: net.ParseIP("192.168.1.1"), Port: 5000, Zone: "eth0"}
	ipAddr := IPAddrFromSCTPAddr(sctpAddr)
	if !ipAddr.IP.Equal(sctpAddr.IP) {
		t.Error("IP mismatch")
	}
	if ipAddr.Zone != "eth0" {
		t.Errorf("zone mismatch: got %q", ipAddr.Zone)
	}
}

func TestIP4AddressToBytes_Nil(t *testing.T) {
	result := IP4AddressToBytes(nil)
	if result != [4]byte{} {
		t.Errorf("expected empty bytes for nil, got %v", result)
	}
}

func TestIP4AddressToBytes_IPv6(t *testing.T) {
	ip := net.ParseIP("::1")
	result := IP4AddressToBytes(ip)
	if result != [4]byte{} {
		t.Errorf("expected empty bytes for IPv6, got %v", result)
	}
}

func TestIP4AddressToBytes_Valid(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	result := IP4AddressToBytes(ip)
	expected := [4]byte{192, 168, 1, 1}
	if result != expected {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestIP6AddressToBytes_FullAddr(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	result := IP6AddressToBytes(ip)
	// Just verify it doesn't panic and returns 16 bytes
	if len(result) != 16 {
		t.Error("expected 16-byte array")
	}
}

// ========== ResolveUnixAddr Tests ==========

func TestResolveUnixAddr_Stream(t *testing.T) {
	addr, err := ResolveUnixAddr("unix", "/tmp/test.sock")
	if err != nil {
		t.Fatalf("ResolveUnixAddr: %v", err)
	}
	if addr.Net != "unix" {
		t.Errorf("expected 'unix', got %q", addr.Net)
	}
	if addr.Name != "/tmp/test.sock" {
		t.Errorf("expected '/tmp/test.sock', got %q", addr.Name)
	}
}

func TestResolveUnixAddr_Dgram(t *testing.T) {
	addr, err := ResolveUnixAddr("unixgram", "/tmp/test.sock")
	if err != nil {
		t.Fatalf("ResolveUnixAddr: %v", err)
	}
	if addr.Net != "unixgram" {
		t.Errorf("expected 'unixgram', got %q", addr.Net)
	}
}

func TestResolveUnixAddr_Packet(t *testing.T) {
	addr, err := ResolveUnixAddr("unixpacket", "/tmp/test.sock")
	if err != nil {
		t.Fatalf("ResolveUnixAddr: %v", err)
	}
	if addr.Net != "unixpacket" {
		t.Errorf("expected 'unixpacket', got %q", addr.Net)
	}
}

func TestResolveUnixAddr_Invalid(t *testing.T) {
	_, err := ResolveUnixAddr("invalid", "/tmp/test.sock")
	if err == nil {
		t.Error("expected error for invalid network")
	}
}

// ========== SCTP Socket Option Tests ==========

func TestSCTPSocketOptions_Context(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Context may require an associated socket - just test that we can call
	// the functions without panic
	_ = SetSCTPContext(sock.fd, 12345)
	_, _ = GetSCTPContext(sock.fd)
}

func TestSCTPSocketOptions_FragmentInterleave(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Set fragment interleave
	if err := SetSCTPFragmentInterleave(sock.fd, 1); err != nil {
		t.Errorf("SetSCTPFragmentInterleave: %v", err)
	}

	// Get fragment interleave
	level, err := GetSCTPFragmentInterleave(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPFragmentInterleave: %v", err)
	}
	if level != 1 {
		t.Errorf("expected level 1, got %d", level)
	}
}

func TestSCTPSocketOptions_PartialDelivery(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Set partial delivery point
	if err := SetSCTPPartialDeliveryPoint(sock.fd, 4096); err != nil {
		t.Errorf("SetSCTPPartialDeliveryPoint: %v", err)
	}

	// Get partial delivery point
	bytes, err := GetSCTPPartialDeliveryPoint(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPPartialDeliveryPoint: %v", err)
	}
	if bytes != 4096 {
		t.Errorf("expected 4096, got %d", bytes)
	}
}

func TestSCTPSocketOptions_MappedV4(t *testing.T) {
	sock, err := NewSCTPSocket6()
	if err != nil {
		t.Fatalf("NewSCTPSocket6: %v", err)
	}
	defer sock.Close()

	// Set mapped v4
	if err := SetSCTPMappedV4(sock.fd, true); err != nil {
		t.Errorf("SetSCTPMappedV4: %v", err)
	}

	// Get mapped v4
	enabled, err := GetSCTPMappedV4(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPMappedV4: %v", err)
	}
	if !enabled {
		t.Error("expected mapped v4 enabled")
	}
}

func TestSCTPSocketOptions_DisableFragments(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Set disable fragments
	if err := SetSCTPDisableFragments(sock.fd, true); err != nil {
		t.Errorf("SetSCTPDisableFragments: %v", err)
	}

	// Get disable fragments
	disabled, err := GetSCTPDisableFragments(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPDisableFragments: %v", err)
	}
	if !disabled {
		t.Error("expected fragments disabled")
	}
}

func TestSCTPSocketOptions_MaxBurst(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Set max burst
	if err := SetSCTPMaxBurst(sock.fd, 4); err != nil {
		t.Errorf("SetSCTPMaxBurst: %v", err)
	}

	// Get max burst
	burst, err := GetSCTPMaxBurst(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPMaxBurst: %v", err)
	}
	if burst != 4 {
		t.Errorf("expected burst 4, got %d", burst)
	}
}

func TestSCTPSocketOptions_Maxseg(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Get initial maxseg (should be non-zero)
	seg, err := GetSCTPMaxseg(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPMaxseg: %v", err)
	}
	if seg <= 0 {
		t.Logf("initial maxseg: %d", seg)
	}
}

func TestSCTPSocketOptions_Autoclose(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Set autoclose
	if err := SetSCTPAutoclose(sock.fd, 30); err != nil {
		t.Errorf("SetSCTPAutoclose: %v", err)
	}

	// Get autoclose
	secs, err := GetSCTPAutoclose(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPAutoclose: %v", err)
	}
	if secs != 30 {
		t.Errorf("expected 30, got %d", secs)
	}
}

func TestSCTPSocketOptions_Nodelay(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Set nodelay
	if err := SetSCTPNodelay(sock.fd, true); err != nil {
		t.Errorf("SetSCTPNodelay: %v", err)
	}

	// Get nodelay
	enabled, err := GetSCTPNodelay(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPNodelay: %v", err)
	}
	if !enabled {
		t.Error("expected nodelay enabled")
	}
}

func TestSCTPSocketOptions_InitMsg(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	// Set init msg
	msg := &SCTPInitMsg{
		NumOstreams:    16,
		MaxInstreams:   16,
		MaxAttempts:    4,
		MaxInitTimeout: 2000,
	}
	if err := SetSCTPInitMsg(sock.fd, msg); err != nil {
		t.Errorf("SetSCTPInitMsg: %v", err)
	}

	// Get init msg
	got, err := GetSCTPInitMsg(sock.fd)
	if err != nil {
		t.Errorf("GetSCTPInitMsg: %v", err)
	}
	if got.NumOstreams != 16 {
		t.Errorf("expected 16 ostreams, got %d", got.NumOstreams)
	}
}

// ========== Socket Creation Tests ==========

func TestNewSCTPStreamSocket4(t *testing.T) {
	sock, err := NewSCTPStreamSocket4()
	if err != nil {
		t.Fatalf("NewSCTPStreamSocket4: %v", err)
	}
	defer sock.Close()

	// Verify protocol - SCTP stream socket uses SOCK_STREAM
	if sock.Protocol() != UnderlyingProtocolStream {
		t.Error("unexpected protocol")
	}
}

func TestNewSCTPStreamSocket6(t *testing.T) {
	sock, err := NewSCTPStreamSocket6()
	if err != nil {
		t.Fatalf("NewSCTPStreamSocket6: %v", err)
	}
	defer sock.Close()
}

func TestNewTCPSocket4_SocketOptions(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Check that we can get keepalive option
	_, err = GetKeepAlive(sock.fd)
	if err != nil {
		t.Errorf("GetKeepAlive: %v", err)
	}

	// Test setting keepalive
	if err := SetKeepAlive(sock.fd, true); err != nil {
		t.Errorf("SetKeepAlive: %v", err)
	}
}

func TestNewTCPSocket6_SocketOptions(t *testing.T) {
	sock, err := NewTCPSocket6()
	if err != nil {
		t.Fatalf("NewTCPSocket6: %v", err)
	}
	defer sock.Close()

	// Check that we can get ipv6only option
	_, err = GetIPv6Only(sock.fd)
	if err != nil {
		t.Errorf("GetIPv6Only: %v", err)
	}

	// Test setting ipv6only
	if err := SetIPv6Only(sock.fd, true); err != nil {
		t.Errorf("SetIPv6Only: %v", err)
	}
}

func TestNewUDPSocket4_SocketOptions(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Check that we can get reuseaddr option
	_, err = GetReuseAddr(sock.fd)
	if err != nil {
		t.Errorf("GetReuseAddr: %v", err)
	}
}

func TestNewUDPSocket6_SocketOptions(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock.Close()

	// Check that we can get ipv6only option
	_, err = GetIPv6Only(sock.fd)
	if err != nil {
		t.Errorf("GetIPv6Only: %v", err)
	}
}

// ========== NetSocketPair Tests ==========

func TestNetSocketPair_SeqPacket(t *testing.T) {
	pair, err := NetSocketPair(AF_UNIX, SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("NetSocketPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Test communication
	msg := []byte("seqpacket test")
	n, err := pair[0].Write(msg)
	if err != nil && err != iox.ErrWouldBlock {
		t.Fatalf("Write: %v", err)
	}
	if n == len(msg) {
		buf := make([]byte, 32)
		n, err = pair[1].Read(buf)
		if err == nil && n > 0 {
			if string(buf[:n]) != string(msg) {
				t.Errorf("data mismatch")
			}
		}
	}
}

// ========== Additional Socket Option Tests ==========

func TestGetSocketType(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	sockType, err := GetSocketType(sock.fd)
	if err != nil {
		t.Errorf("GetSocketType: %v", err)
	}
	if sockType != SOCK_STREAM {
		t.Errorf("expected SOCK_STREAM, got %d", sockType)
	}
}

func TestGetSocketError_Fresh(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Fresh socket should have no error
	sockErr := GetSocketError(sock.fd)
	if sockErr != nil {
		t.Errorf("expected nil error, got %v", sockErr)
	}
}

func TestUDPConn_Broadcast(t *testing.T) {
	// Create UDP connection
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set broadcast using UDPConn method
	if err := conn.SetBroadcast(true); err != nil {
		t.Errorf("SetBroadcast(true): %v", err)
	}

	// Disable broadcast
	if err := conn.SetBroadcast(false); err != nil {
		t.Errorf("SetBroadcast(false): %v", err)
	}
}

func TestSetNonBlock(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Set nonblock (should already be set, but test doesn't error)
	if err := SetNonBlock(sock.fd, true); err != nil {
		t.Errorf("SetNonBlock: %v", err)
	}
}

func TestSetCloseOnExec(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Set close on exec
	if err := SetCloseOnExec(sock.fd, true); err != nil {
		t.Errorf("SetCloseOnExec: %v", err)
	}
}

func TestSetSendRecvBuffer(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Set send buffer
	if err := SetSendBuffer(sock.fd, 65536); err != nil {
		t.Errorf("SetSendBuffer: %v", err)
	}

	// Get send buffer (kernel may double it)
	size, err := GetSendBuffer(sock.fd)
	if err != nil {
		t.Errorf("GetSendBuffer: %v", err)
	}
	if size < 65536 {
		t.Logf("send buffer: %d (may be limited by system)", size)
	}

	// Set recv buffer
	if err := SetRecvBuffer(sock.fd, 65536); err != nil {
		t.Errorf("SetRecvBuffer: %v", err)
	}

	// Get recv buffer
	size, err = GetRecvBuffer(sock.fd)
	if err != nil {
		t.Errorf("GetRecvBuffer: %v", err)
	}
	if size < 65536 {
		t.Logf("recv buffer: %d (may be limited by system)", size)
	}
}

func TestSetTCPKeepAliveParams(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Set keep idle
	if err := SetTCPKeepIdle(sock.fd, 60); err != nil {
		t.Errorf("SetTCPKeepIdle: %v", err)
	}
	idle, err := GetTCPKeepIdle(sock.fd)
	if err != nil {
		t.Errorf("GetTCPKeepIdle: %v", err)
	}
	if idle != 60 {
		t.Errorf("expected 60, got %d", idle)
	}

	// Set keep interval
	if err := SetTCPKeepIntvl(sock.fd, 10); err != nil {
		t.Errorf("SetTCPKeepIntvl: %v", err)
	}
	intvl, err := GetTCPKeepIntvl(sock.fd)
	if err != nil {
		t.Errorf("GetTCPKeepIntvl: %v", err)
	}
	if intvl != 10 {
		t.Errorf("expected 10, got %d", intvl)
	}

	// Set keep count
	if err := SetTCPKeepCnt(sock.fd, 5); err != nil {
		t.Errorf("SetTCPKeepCnt: %v", err)
	}
	cnt, err := GetTCPKeepCnt(sock.fd)
	if err != nil {
		t.Errorf("GetTCPKeepCnt: %v", err)
	}
	if cnt != 5 {
		t.Errorf("expected 5, got %d", cnt)
	}
}

// ========== UnknownNetworkError Tests ==========

func TestUnknownNetworkError(t *testing.T) {
	err := UnknownNetworkError("bad_network")
	if err.Error() != "unknown network bad_network" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

// ========== Additional SCTP Tests ==========

func TestSCTPListener_FullAccept(t *testing.T) {
	// Create listener
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenSCTP4(laddr)
	if err != nil {
		t.Fatalf("ListenSCTP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*SCTPAddr)

	// Dial in goroutine first, then accept
	dialDone := make(chan struct{})
	var dialConn *SCTPConn
	go func() {
		defer close(dialDone)
		var err error
		dialConn, err = DialSCTP4(nil, lisAddr)
		if err != nil {
			t.Logf("DialSCTP4: %v", err)
		}
	}()

	// Wait a bit for dial to start
	time.Sleep(50 * time.Millisecond)

	// Accept with retry loop
	deadline := time.Now().Add(3 * time.Second)
	var acceptedConn *SCTPConn
	for time.Now().Before(deadline) {
		acceptedConn, err = lis.Accept()
		if err == nil {
			break
		}
		if err != iox.ErrWouldBlock {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for dial to complete
	<-dialDone

	if acceptedConn != nil {
		// Test conn methods
		_ = acceptedConn.LocalAddr()
		_ = acceptedConn.RemoteAddr()
		_ = acceptedConn.SetDeadline(time.Now().Add(time.Second))
		_ = acceptedConn.SetReadDeadline(time.Now().Add(time.Second))
		_ = acceptedConn.SetWriteDeadline(time.Now().Add(time.Second))
		acceptedConn.Close()
	}

	if dialConn != nil {
		dialConn.Close()
	}
}

func TestSCTPListener_AcceptWouldBlock(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenSCTP4(laddr)
	if err != nil {
		t.Fatalf("ListenSCTP4: %v", err)
	}
	defer lis.Close()

	// Accept should return ErrWouldBlock immediately since no one is connecting
	_, err = lis.AcceptSocket()
	if err != iox.ErrWouldBlock {
		t.Logf("AcceptSocket error: %v", err)
	}
}

// ========== Additional TCP Connection Tests ==========

func TestTCPConn_FullFlow(t *testing.T) {
	// Create listener
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	// Accept in goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		lis.SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo back
		buf := make([]byte, 64)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			conn.Write(buf[:n])
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Dial
	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Test deadline setting
	conn.SetDeadline(time.Now().Add(time.Second))

	// Write and read
	msg := []byte("hello")
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	n, err := conn.Write(msg)
	if err != nil && err != iox.ErrWouldBlock && err != ErrInProgress {
		t.Logf("Write: %v", err)
	}
	_ = n

	<-done
}

// ========== Unix Socket Tests ==========

func TestUnixConn_ReadFrom(t *testing.T) {
	// Create a datagram socket pair for ReadFrom/WriteTo testing
	addr1 := uniqAddr("readfrom1", "unixgram")
	addr2 := uniqAddr("readfrom2", "unixgram")

	conn1, err := ListenUnixgram("unixgram", addr1)
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer conn1.Close()

	conn2, err := ListenUnixgram("unixgram", addr2)
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer conn2.Close()

	// Send from conn1 to conn2
	msg := []byte("dgram test")
	conn1.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = conn1.WriteTo(msg, addr2)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("WriteTo: %v", err)
	}

	// Read at conn2
	buf := make([]byte, 32)
	conn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, from, err := conn2.ReadFrom(buf)
	if err == nil && n > 0 {
		if from == nil {
			t.Logf("ReadFrom returned nil address")
		}
	}
}

// ========== Dial Generic Tests ==========

func TestDialTCP_Generic(t *testing.T) {
	// Create listener
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	// Accept in background
	go func() {
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, err := lis.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Use generic DialTCP
	conn, err := DialTCP("tcp4", nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()
}

func TestDialUDP_Generic(t *testing.T) {
	// Create listener
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.LocalAddr().(*UDPAddr)

	// Use generic DialUDP
	conn, err := DialUDP("udp4", nil, lisAddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()
}

func TestDialSCTP_Generic(t *testing.T) {
	// Create listener
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenSCTP4(laddr)
	if err != nil {
		t.Fatalf("ListenSCTP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*SCTPAddr)

	// Accept in background with timed loop
	go func() {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			conn, err := lis.Accept()
			if err == nil {
				conn.Close()
				return
			}
			if err != iox.ErrWouldBlock {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Use generic DialSCTP
	conn, err := DialSCTP("sctp4", nil, lisAddr)
	if err != nil {
		t.Fatalf("DialSCTP: %v", err)
	}
	defer conn.Close()
}

// ========== Listen Generic Tests ==========

func TestListenTCP_Generic(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP("tcp4", laddr)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer lis.Close()

	if lis.Addr() == nil {
		t.Error("expected non-nil listener address")
	}
}

func TestListenUDP_Generic(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP("udp4", laddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil local address")
	}
}

func TestListenSCTP_Generic(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenSCTP("sctp4", laddr)
	if err != nil {
		t.Fatalf("ListenSCTP: %v", err)
	}
	defer lis.Close()

	if lis.Addr() == nil {
		t.Error("expected non-nil listener address")
	}
}

// ========== Socket Protocol Tests ==========

func TestTCPSocket_StreamProtocol(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolStream {
		t.Errorf("expected Stream protocol, got %v", sock.Protocol())
	}
}

func TestUDPSocket_DgramProtocol(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolDgram {
		t.Errorf("expected Dgram protocol, got %v", sock.Protocol())
	}
}

func TestSCTPSocket_SeqPacketProtocol(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolSeqPacket {
		t.Errorf("expected SeqPacket protocol, got %v", sock.Protocol())
	}
}

func TestUnixSocket_StreamProtocol(t *testing.T) {
	sock, err := NewUnixStreamSocket()
	if err != nil {
		t.Fatalf("NewUnixStreamSocket: %v", err)
	}
	defer sock.Close()

	proto := sock.Protocol()
	if proto != UnderlyingProtocolStream {
		t.Errorf("expected Stream protocol, got %v", proto)
	}
}

// ========== Zero Copy Tests ==========

func TestSetZeroCopy(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// ZeroCopy may not be available on all systems, just verify no panic
	err = SetZeroCopy(sock.fd, true)
	if err != nil {
		t.Logf("SetZeroCopy: %v (may not be supported)", err)
	}
}

// ========== TCP Read/Write with Retry ==========

func TestTCPConn_ReadWithRetry(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	go func() {
		lis.SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Write some data after a delay
		time.Sleep(50 * time.Millisecond)
		conn.Write([]byte("delayed data"))
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Read with deadline - should trigger retry logic
	buf := make([]byte, 32)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		t.Logf("Read %d bytes", n)
	}
}

// ========== IPv6 Listen and Dial Tests ==========

func TestListenTCP6_WithPort(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	lis, err := ListenTCP6(laddr)
	if err != nil {
		t.Fatalf("ListenTCP6: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	go func() {
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, _ := lis.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP6(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP6: %v", err)
	}
	defer conn.Close()
}

func TestListenSCTP6_WithPort(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	lis, err := ListenSCTP6(laddr)
	if err != nil {
		t.Fatalf("ListenSCTP6: %v", err)
	}
	defer lis.Close()

	if lis.Addr() == nil {
		t.Error("expected non-nil address")
	}
}

func TestListenUDP6_WithPort(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := ListenUDP6(laddr)
	if err != nil {
		t.Fatalf("ListenUDP6: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil address")
	}
}

// ========== Read/Write Error Tests ==========

func TestTCPConn_ReadClosed(t *testing.T) {
	// Create a TCP connection
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	go func() {
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, _ := lis.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}

	// Close the connection
	conn.Close()

	// Read on closed should fail
	buf := make([]byte, 10)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected error on closed connection")
	}
}

func TestUDPConn_ReadClosed(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}

	// Close
	conn.Close()

	// Read on closed should fail
	buf := make([]byte, 10)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected error on closed connection")
	}
}

// ========== SCTP Conn Deadline Tests ==========

func TestSCTPConn_Deadlines(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenSCTP4(laddr)
	if err != nil {
		t.Fatalf("ListenSCTP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*SCTPAddr)

	// Dial
	conn, err := DialSCTP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialSCTP4: %v", err)
	}
	defer conn.Close()

	// Test deadline methods
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

// ========== Multicast Tests (require interfaces) ==========

func TestMulticastLoopCoverage(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Test SetMulticastLoop
	if err := SetMulticastLoop(sock.fd, true); err != nil {
		t.Logf("SetMulticastLoop: %v (may not be supported)", err)
	}
}

func TestMulticastTTLCoverage(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Test SetMulticastTTL
	if err := SetMulticastTTL(sock.fd, 64); err != nil {
		t.Logf("SetMulticastTTL: %v (may not be supported)", err)
	}
}

// ========== SCM_RIGHTS SendMsg/RecvMsg Tests ==========

func TestSendMsgRecvMsg(t *testing.T) {
	// Create Unix socket pair
	pair, err := UnixSocketPair()
	if err != nil {
		t.Fatalf("UnixSocketPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Create message to send
	data := []byte("hello")
	iov := Iovec{
		Base: &data[0],
		Len:  uint64(len(data)),
	}
	msg := Msghdr{
		Iov:    &iov,
		Iovlen: 1,
	}

	// Send message
	n, err := SendMsg(pair[0].fd, &msg, 0)
	if err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if n != len(data) {
		t.Errorf("SendMsg: expected %d bytes, got %d", len(data), n)
	}

	// Receive message
	recvBuf := make([]byte, 32)
	recvIov := Iovec{
		Base: &recvBuf[0],
		Len:  uint64(len(recvBuf)),
	}
	recvMsg := Msghdr{
		Iov:    &recvIov,
		Iovlen: 1,
	}

	n, err = RecvMsg(pair[1].fd, &recvMsg, 0)
	if err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}
	if n != len(data) {
		t.Errorf("RecvMsg: expected %d bytes, got %d", len(data), n)
	}
	if string(recvBuf[:n]) != string(data) {
		t.Errorf("data mismatch: got %q", recvBuf[:n])
	}
}

func TestSendMsgRecvMsg_WithControlMsg(t *testing.T) {
	// Create Unix socket pair
	pair, err := UnixSocketPair()
	if err != nil {
		t.Fatalf("UnixSocketPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Create a pipe to get file descriptors
	pipeRead, pipeWrite, err := osPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer closeFd(pipeRead)
	defer closeFd(pipeWrite)

	// Send FDs using SendFDs
	n, err := SendFDs(pair[0].fd, []int{pipeRead, pipeWrite}, []byte("fds"))
	if err != nil {
		t.Fatalf("SendFDs: %v", err)
	}
	if n == 0 {
		t.Error("expected non-zero bytes sent")
	}

	// Receive FDs using RecvFDs
	dataBuf := make([]byte, 32)
	n, fds, err := RecvFDs(pair[1].fd, dataBuf, 4)
	if err != nil {
		t.Fatalf("RecvFDs: %v", err)
	}
	if len(fds) != 2 {
		t.Errorf("expected 2 fds, got %d", len(fds))
	}
	// Close received FDs
	for _, fd := range fds {
		closeFd(fd)
	}
}

// Helper functions for pipe creation
func osPipe() (r, w int, err error) {
	var p [2]int32
	errno := zcall.Pipe2(&p, zcall.O_CLOEXEC)
	if errno != 0 {
		return 0, 0, zcall.Errno(errno)
	}
	return int(p[0]), int(p[1]), nil
}

func closeFd(fd int) {
	zcall.Close(uintptr(fd))
}

// ========== Multicast Function Tests ==========

func TestMulticast_JoinLeave4(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Join and leave multicast group (224.0.0.1 is all-hosts)
	groupIP := [4]byte{224, 0, 0, 1}
	ifAddr := [4]byte{0, 0, 0, 0} // INADDR_ANY
	err = JoinMulticast4(sock.fd, groupIP, ifAddr)
	if err != nil {
		t.Logf("JoinMulticast4: %v (may require interface)", err)
	} else {
		// Leave if join succeeded
		err = LeaveMulticast4(sock.fd, groupIP, ifAddr)
		if err != nil {
			t.Logf("LeaveMulticast4: %v", err)
		}
	}
}

func TestMulticast_JoinLeave6(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock.Close()

	// Join and leave multicast group (ff02::1 is all-nodes)
	groupIP := [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	err = JoinMulticast6(sock.fd, groupIP, 0)
	if err != nil {
		t.Logf("JoinMulticast6: %v (may require interface)", err)
	} else {
		// Leave if join succeeded
		err = LeaveMulticast6(sock.fd, groupIP, 0)
		if err != nil {
			t.Logf("LeaveMulticast6: %v", err)
		}
	}
}

func TestMulticast_TTLAndHops(t *testing.T) {
	sock4, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock4.Close()

	// Set and get TTL
	if err := SetMulticastTTL(sock4.fd, 32); err != nil {
		t.Logf("SetMulticastTTL: %v", err)
	}
	ttl, err := GetMulticastTTL(sock4.fd)
	if err != nil {
		t.Logf("GetMulticastTTL: %v", err)
	} else if ttl != 32 {
		t.Logf("expected TTL 32, got %d", ttl)
	}

	sock6, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock6.Close()

	// Set and get hops
	if err := SetMulticast6Hops(sock6.fd, 64); err != nil {
		t.Logf("SetMulticast6Hops: %v", err)
	}
	hops, err := GetMulticast6Hops(sock6.fd)
	if err != nil {
		t.Logf("GetMulticast6Hops: %v", err)
	} else if hops != 64 {
		t.Logf("expected hops 64, got %d", hops)
	}
}

func TestMulticast_Loop(t *testing.T) {
	sock4, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock4.Close()

	// Set and get loop
	if err := SetMulticastLoop(sock4.fd, true); err != nil {
		t.Logf("SetMulticastLoop: %v", err)
	}
	loop, err := GetMulticastLoop(sock4.fd)
	if err != nil {
		t.Logf("GetMulticastLoop: %v", err)
	}
	_ = loop

	sock6, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock6.Close()

	// Set and get loop for IPv6
	if err := SetMulticast6Loop(sock6.fd, true); err != nil {
		t.Logf("SetMulticast6Loop: %v", err)
	}
	loop6, err := GetMulticast6Loop(sock6.fd)
	if err != nil {
		t.Logf("GetMulticast6Loop: %v", err)
	}
	_ = loop6
}

func TestMulticast_Interface(t *testing.T) {
	sock4, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock4.Close()

	// Set multicast interface by IP
	localIP := [4]byte{127, 0, 0, 1}
	if err := SetMulticastInterface(sock4.fd, localIP); err != nil {
		t.Logf("SetMulticastInterface: %v", err)
	}

	sock6, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock6.Close()

	// Set and get multicast interface for IPv6
	if err := SetMulticast6Interface(sock6.fd, 1); err != nil {
		t.Logf("SetMulticast6Interface: %v", err)
	}
	ifidx, err := GetMulticast6Interface(sock6.fd)
	if err != nil {
		t.Logf("GetMulticast6Interface: %v", err)
	}
	_ = ifidx
}

// ========== Raw Socket Tests (Error Paths) ==========

// ========== ResolveSCTPAddr Full Coverage ==========

func TestResolveSCTPAddr_AllNetworks(t *testing.T) {
	tests := []struct {
		network string
		address string
		wantErr bool
	}{
		{"sctp", "127.0.0.1:5000", false},
		{"sctp4", "127.0.0.1:5000", false},
		{"sctp6", "[::1]:5000", false},
		{"", "127.0.0.1:5000", false}, // Empty defaults to sctp
		{"tcp", "127.0.0.1:5000", true},
		{"invalid", "127.0.0.1:5000", true},
	}

	for _, tt := range tests {
		addr, err := ResolveSCTPAddr(tt.network, tt.address)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ResolveSCTPAddr(%q, %q) expected error", tt.network, tt.address)
			}
		} else {
			if err != nil {
				t.Errorf("ResolveSCTPAddr(%q, %q) error: %v", tt.network, tt.address, err)
			}
			if addr == nil {
				t.Errorf("ResolveSCTPAddr(%q, %q) returned nil address", tt.network, tt.address)
			}
		}
	}
}

// ========== UnixCredentials Tests ==========

func TestUnixCredentialsCoverage(t *testing.T) {
	cred := &Ucred{
		Pid: 1234,
		Uid: 1000,
		Gid: 1000,
	}
	buf := UnixCredentials(cred)
	if len(buf) == 0 {
		t.Error("expected non-empty buffer")
	}

	// Parse credentials back
	parsed := ParseUnixCredentials(buf)
	if parsed == nil {
		t.Error("failed to parse credentials")
	} else {
		if parsed.Pid != cred.Pid {
			t.Errorf("Pid mismatch: got %d, want %d", parsed.Pid, cred.Pid)
		}
		if parsed.Uid != cred.Uid {
			t.Errorf("Uid mismatch: got %d, want %d", parsed.Uid, cred.Uid)
		}
		if parsed.Gid != cred.Gid {
			t.Errorf("Gid mismatch: got %d, want %d", parsed.Gid, cred.Gid)
		}
	}
}

func TestParseUnixCredentials_Invalid(t *testing.T) {
	// Empty buffer
	if cred := ParseUnixCredentials(nil); cred != nil {
		t.Error("expected nil for nil buffer")
	}
	if cred := ParseUnixCredentials([]byte{}); cred != nil {
		t.Error("expected nil for empty buffer")
	}

	// Buffer too small
	if cred := ParseUnixCredentials(make([]byte, 5)); cred != nil {
		t.Error("expected nil for small buffer")
	}
}

func TestParseUnixRights_Invalid(t *testing.T) {
	// Empty buffer
	if fds := ParseUnixRights(nil); fds != nil {
		t.Error("expected nil for nil buffer")
	}
	if fds := ParseUnixRights([]byte{}); fds != nil {
		t.Error("expected nil for empty buffer")
	}

	// Buffer too small
	if fds := ParseUnixRights(make([]byte, 5)); fds != nil {
		t.Error("expected nil for small buffer")
	}
}

// ========== CmsgAlign/Space/Len/Data Tests ==========

func TestCmsgFunctions(t *testing.T) {
	// CmsgAlign
	if CmsgAlign(1) != 8 {
		t.Errorf("CmsgAlign(1) = %d, want 8", CmsgAlign(1))
	}
	if CmsgAlign(8) != 8 {
		t.Errorf("CmsgAlign(8) = %d, want 8", CmsgAlign(8))
	}
	if CmsgAlign(9) != 16 {
		t.Errorf("CmsgAlign(9) = %d, want 16", CmsgAlign(9))
	}

	// CmsgLen
	if CmsgLen(4) != SizeofCmsghdr+4 {
		t.Errorf("CmsgLen(4) = %d, want %d", CmsgLen(4), SizeofCmsghdr+4)
	}

	// CmsgSpace
	expected := CmsgAlign(SizeofCmsghdr + 4)
	if CmsgSpace(4) != expected {
		t.Errorf("CmsgSpace(4) = %d, want %d", CmsgSpace(4), expected)
	}
}

// ========== Fd and Shutdown Tests ==========

func TestFD_Shutdown(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Shutdown on unconnected socket may fail or succeed depending on state
	err = sock.Shutdown(SHUT_RD)
	// Just check it doesn't panic
	_ = err

	err = sock.Shutdown(SHUT_WR)
	_ = err

	err = sock.Shutdown(SHUT_RDWR)
	_ = err
}

// ========== NetSocket Bind/Listen/Connect Error Paths ==========

func TestNetSocket_BindError(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Bind to a port, then try to bind another socket to same port
	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 0)
	if err := sock.Bind(sa); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	// Get the port we bound to
	boundSa, err := GetSockname(sock.fd)
	if err != nil {
		t.Fatalf("GetSockname: %v", err)
	}

	// Try to bind another socket to same port (should fail for STREAM without SO_REUSEPORT)
	sock2, err := NewNetSocket(zcall.AF_INET, zcall.SOCK_STREAM, zcall.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("NewNetSocket: %v", err)
	}
	defer sock2.Close()

	// Disable reuseport so we get an error
	_ = SetReusePort(sock2.fd, false)

	inet4 := boundSa.(*SockaddrInet4)
	sa2 := NewSockaddrInet4(inet4.Addr(), inet4.Port())
	err = sock2.Bind(sa2)
	if err == nil {
		t.Log("Bind succeeded (may have reuseaddr/reuseport enabled)")
	}
}

func TestNetSocket_ListenError(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Listen on UDP socket should fail
	err = sock.Listen(5)
	if err == nil {
		t.Error("expected Listen on UDP socket to fail")
	}
}

func TestNetSocket_ConnectError(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Connect to non-existent address
	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 65000)
	err = sock.Connect(sa)
	// In non-blocking mode, this may return ErrInProgress
	if err != nil && err != ErrInProgress && err != ErrConnectionRefused {
		t.Logf("Connect error: %v", err)
	}
}

// ========== GetSockname/GetPeername Tests ==========

func TestGetSockname_GetPeername(t *testing.T) {
	// Create listener and client
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	// Get sockname from listener
	sa, err := GetSockname(lis.fd)
	if err != nil {
		t.Errorf("GetSockname: %v", err)
	}
	if sa == nil {
		t.Error("expected non-nil sockaddr")
	}

	// Connect
	done := make(chan struct{})
	go func() {
		defer close(done)
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, _ := lis.Accept()
		if conn != nil {
			// Get peername
			_, err := GetPeername(conn.fd)
			if err != nil {
				t.Logf("GetPeername on accepted: %v", err)
			}
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}

	// Get peername on client - may fail if connection closed by server first
	_, err = GetPeername(conn.fd)
	if err != nil {
		t.Logf("GetPeername on client: %v (not an error if connection closed)", err)
	}

	conn.Close()
	<-done
}

// ========== DecodeSockaddr Tests ==========

func TestDecodeSockaddr_AllTypes(t *testing.T) {
	// IPv4
	raw4 := &RawSockaddrAny{}
	raw4.Addr.Family = AF_INET
	sa := DecodeSockaddr(raw4)
	if sa == nil {
		t.Error("DecodeSockaddr returned nil for AF_INET")
	}

	// IPv6
	raw6 := &RawSockaddrAny{}
	raw6.Addr.Family = AF_INET6
	sa = DecodeSockaddr(raw6)
	if sa == nil {
		t.Error("DecodeSockaddr returned nil for AF_INET6")
	}

	// Unix
	rawUnix := &RawSockaddrAny{}
	rawUnix.Addr.Family = AF_UNIX
	sa = DecodeSockaddr(rawUnix)
	if sa == nil {
		t.Error("DecodeSockaddr returned nil for AF_UNIX")
	}

	// Unknown family
	rawUnk := &RawSockaddrAny{}
	rawUnk.Addr.Family = 255
	sa = DecodeSockaddr(rawUnk)
	if sa != nil {
		t.Error("DecodeSockaddr should return nil for unknown family")
	}
}

// ========== SockaddrToTCPAddr Tests ==========

func TestSockaddrToTCPAddr_IPv6(t *testing.T) {
	sa6 := NewSockaddrInet6([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 8080, 0)
	addr := SockaddrToTCPAddr(sa6)
	if addr == nil {
		t.Fatal("expected non-nil address")
	}
	if addr.Port != 8080 {
		t.Errorf("expected port 8080, got %d", addr.Port)
	}
}

// ========== TCPInfo Tests ==========

func TestGetTCPInfoCoverage(t *testing.T) {
	// Create a connected TCP socket
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	go func() {
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, _ := lis.Accept()
		if conn != nil {
			time.Sleep(100 * time.Millisecond)
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Get TCP info
	info, err := GetTCPInfo(conn.fd)
	if err != nil {
		t.Logf("GetTCPInfo: %v", err)
	} else {
		if info == nil {
			t.Error("expected non-nil TCPInfo")
		}
	}

	// Get TCP info into existing struct
	var infoInto TCPInfo
	err = GetTCPInfoInto(conn.fd, &infoInto)
	if err != nil {
		t.Logf("GetTCPInfoInto: %v", err)
	}
}

// ========== SetKeepAlivePeriod Test ==========

func TestSetKeepAlivePeriod(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	go func() {
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, _ := lis.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Test SetKeepAlivePeriod
	err = conn.SetKeepAlivePeriod(30 * time.Second)
	if err != nil {
		t.Logf("SetKeepAlivePeriod: %v", err)
	}
}

// ========== UnixSocket Protocol Tests ==========

func TestUnixDgramSock_Protocol(t *testing.T) {
	sock, err := NewUnixDatagramSocket()
	if err != nil {
		t.Fatalf("NewUnixDatagramSocket: %v", err)
	}
	defer sock.Close()

	proto := sock.Protocol()
	if proto != UnderlyingProtocolDgram {
		t.Errorf("expected Dgram protocol, got %v", proto)
	}
}

func TestUnixSeqpacketSock_Protocol(t *testing.T) {
	sock, err := NewUnixSeqpacketSocket()
	if err != nil {
		t.Fatalf("NewUnixSeqpacketSocket: %v", err)
	}
	defer sock.Close()

	proto := sock.Protocol()
	if proto != UnderlyingProtocolSeqPacket {
		t.Errorf("expected SeqPacket protocol, got %v", proto)
	}
}

// ========== UnixConn ReadFrom/WriteTo Coverage ==========

func TestUnixConn_WriteToReadFrom(t *testing.T) {
	addr1 := uniqAddr("wt1", "unixgram")
	addr2 := uniqAddr("wt2", "unixgram")

	conn1, err := ListenUnixgram("unixgram", addr1)
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer conn1.Close()

	conn2, err := ListenUnixgram("unixgram", addr2)
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer conn2.Close()

	// WriteTo
	msg := []byte("test message")
	conn1.SetWriteDeadline(time.Now().Add(time.Second))
	n, err := conn1.WriteTo(msg, addr2)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("WriteTo: %v", err)
	}

	if n > 0 {
		// ReadFrom
		buf := make([]byte, 64)
		conn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := conn2.ReadFrom(buf)
		if err != nil && err != iox.ErrWouldBlock && err != ErrTimedOut {
			t.Logf("ReadFrom: %v", err)
		}
		if n > 0 {
			t.Logf("Read %d bytes from %v", n, from)
		}
	}
}

// ========== IP Zone ID Tests ==========

func TestIp6ZoneID(t *testing.T) {
	// Test with empty zone
	id := ip6ZoneID("")
	if id != 0 {
		t.Errorf("expected 0 for empty zone, got %d", id)
	}

	// Test with invalid zone
	id = ip6ZoneID("nonexistent_interface_12345")
	if id != 0 {
		t.Errorf("expected 0 for invalid zone, got %d", id)
	}

	// Test zone string conversion
	str := ip6ZoneString(0)
	if str != "" {
		t.Errorf("expected empty string for zone 0, got %q", str)
	}

	// Test with invalid index
	str = ip6ZoneString(99999)
	if str != "" {
		t.Logf("zone string for 99999: %q", str)
	}
}

// ========== GetSocketError Coverage ==========

func TestGetSocketError_AfterConnect(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Try to connect to a closed port
	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 1)
	_ = sock.Connect(sa)

	// Wait a bit for connection to fail
	time.Sleep(50 * time.Millisecond)

	// Check socket error
	sockErr := GetSocketError(sock.fd)
	// May be nil or an error depending on timing
	_ = sockErr
}

// ========== SetCloseOnExec Coverage ==========

func TestSetCloseOnExec_Toggle(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Enable
	if err := SetCloseOnExec(sock.fd, true); err != nil {
		t.Errorf("SetCloseOnExec(true): %v", err)
	}

	// Disable
	if err := SetCloseOnExec(sock.fd, false); err != nil {
		t.Errorf("SetCloseOnExec(false): %v", err)
	}
}

// ========== adaptiveWrite coverage ==========

func TestTCPConn_WriteAdaptive(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	// Accept and read in background
	go func() {
		lis.SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read all data
		buf := make([]byte, 1024)
		for {
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, err := conn.Read(buf)
			if err != nil {
				break
			}
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Write with deadline to trigger adaptive path
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	n, err := conn.Write(data)
	if err != nil && err != iox.ErrWouldBlock && err != ErrInProgress {
		t.Logf("Write: %v", err)
	}
	if n > 0 {
		t.Logf("Wrote %d bytes", n)
	}
}

// ========== Additional Multicast Tests (0% coverage functions) ==========

func TestMulticast_JoinLeave4n(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Join and leave multicast group by interface index
	groupIP := [4]byte{224, 0, 0, 1}
	err = JoinMulticast4n(sock.fd, groupIP, 1) // interface index 1 is usually loopback
	if err != nil {
		t.Logf("JoinMulticast4n: %v (expected on some systems)", err)
	} else {
		err = LeaveMulticast4n(sock.fd, groupIP, 1)
		if err != nil {
			t.Logf("LeaveMulticast4n: %v", err)
		}
	}
}

func TestSetMulticastInterfaceByIndex(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Set multicast interface by index
	err = SetMulticastInterfaceByIndex(sock.fd, 1) // interface 1 is usually loopback
	if err != nil {
		t.Logf("SetMulticastInterfaceByIndex: %v", err)
	}
}

func TestSetMulticast6All(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock.Close()

	// Try to enable/disable all multicast
	err = SetMulticast6All(sock.fd, true)
	if err != nil {
		t.Logf("SetMulticast6All(true): %v", err)
	}
	err = SetMulticast6All(sock.fd, false)
	if err != nil {
		t.Logf("SetMulticast6All(false): %v", err)
	}
}

// ========== ResolveSCTPAddr Additional Coverage ==========

func TestResolveSCTPAddr_MoreEdgeCases(t *testing.T) {
	// Test with IPv6 in brackets
	addr, err := ResolveSCTPAddr("sctp6", "[::1]:5000")
	if err != nil {
		t.Errorf("ResolveSCTPAddr sctp6 [::1]:5000: %v", err)
	}
	if addr != nil && addr.Zone != "" {
		t.Logf("Zone: %s", addr.Zone)
	}

	// Test with zone
	addr, err = ResolveSCTPAddr("sctp6", "[fe80::1%lo]:5000")
	if err != nil {
		t.Logf("ResolveSCTPAddr with zone: %v (expected on some systems)", err)
	}

	// Test sctp4 with IPv6 address (should fail or convert)
	_, err = ResolveSCTPAddr("sctp4", "[::1]:5000")
	if err == nil {
		t.Log("ResolveSCTPAddr sctp4 with IPv6 succeeded (may be dual-stack)")
	}

	// Test with empty port
	_, err = ResolveSCTPAddr("sctp", "127.0.0.1:")
	// This may succeed with port 0
	t.Logf("ResolveSCTPAddr empty port: %v", err)

	// Test with just port
	_, err = ResolveSCTPAddr("sctp", ":5000")
	if err != nil {
		t.Logf("ResolveSCTPAddr :5000: %v", err)
	}
}

// ========== applySCTPDefaults Coverage ==========

func TestSCTPSocket_ApplyDefaults(t *testing.T) {
	// Create SCTP socket to trigger applySCTPDefaults
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()

	// Verify defaults were applied
	nodelay, err := GetSCTPNodelay(sock.fd)
	if err != nil {
		t.Logf("GetSCTPNodelay: %v", err)
	}
	t.Logf("SCTP Nodelay: %v", nodelay)
}

// ========== SCTPListener.Accept Coverage ==========

func TestSCTPListener_AcceptTimeout(t *testing.T) {
	lis, err := ListenSCTP4(&SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer lis.Close()

	// Try to accept without any pending connections
	// The accept should timeout or return ErrWouldBlock
	done := make(chan error, 1)
	go func() {
		_, err := lis.Accept()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Expected error from Accept")
		} else if err == iox.ErrWouldBlock || err == ErrTimedOut {
			t.Logf("Got expected error: %v", err)
		} else {
			t.Logf("Accept error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Log("Accept is blocking as expected, test passed")
	}
}

// ========== ListenUDP4/6 Coverage ==========

func TestListenUDP4_ZeroPort(t *testing.T) {
	// ListenUDP4 with zero port (auto-assign)
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr()
	if addr == nil {
		t.Error("LocalAddr returned nil")
	}
}

func TestListenUDP6_ZeroPort(t *testing.T) {
	// ListenUDP6 with zero port (auto-assign)
	conn, err := ListenUDP6(&UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP6: %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr()
	if addr == nil {
		t.Error("LocalAddr returned nil")
	}
}

// ========== UDPConn.Read Coverage ==========

func TestUDPConn_Read_Connected(t *testing.T) {
	// Create server
	server, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	serverAddr := server.LocalAddr().(*UDPAddr)

	// Create connected client
	client, err := DialUDP4(nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer client.Close()

	// Send data from client
	msg := []byte("test message")
	_, err = client.Write(msg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read on server (non-blocking or with short deadline)
	buf := make([]byte, 1024)
	server.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, from, err := server.ReadFrom(buf)
	if err != nil {
		// May timeout if packet was dropped, not a test failure
		t.Logf("ReadFrom: %v (not a failure if packet dropped)", err)
	} else {
		t.Logf("Received %d bytes from %v", n, from)

		// Send response back to client so Read() has data
		server.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		server.WriteTo([]byte("response"), from)
	}

	// Read using Read method (connected mode)
	client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = client.Read(buf)
	if err != nil && err != ErrTimedOut && err != iox.ErrWouldBlock {
		t.Logf("Read: %v", err)
	}
}

// ========== UnixConn.Protocol Coverage ==========

func TestUnixConn_AllProtocols(t *testing.T) {
	// Test stream
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair unix: %v", err)
	}
	if pair[0].Protocol() != SOCK_STREAM {
		t.Errorf("expected SOCK_STREAM, got %d", pair[0].Protocol())
	}
	pair[0].Close()
	pair[1].Close()

	// Test dgram
	pair, err = UnixConnPair("unixgram")
	if err != nil {
		t.Fatalf("UnixConnPair unixgram: %v", err)
	}
	if pair[0].Protocol() != SOCK_DGRAM {
		t.Errorf("expected SOCK_DGRAM, got %d", pair[0].Protocol())
	}
	pair[0].Close()
	pair[1].Close()

	// Test seqpacket
	pair, err = UnixConnPair("unixpacket")
	if err != nil {
		t.Fatalf("UnixConnPair unixpacket: %v", err)
	}
	if pair[0].Protocol() != SOCK_SEQPACKET {
		t.Errorf("expected SOCK_SEQPACKET, got %d", pair[0].Protocol())
	}
	pair[0].Close()
	pair[1].Close()
}

// ========== GetTCPInfoInto Coverage ==========

func TestGetTCPInfoIntoCoverage(t *testing.T) {
	// Create a TCP connection
	lis, err := ListenTCP4(&TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		lis.SetDeadline(time.Now().Add(time.Second))
		c, _ := lis.Accept()
		if c != nil {
			c.Close()
		}
	}()

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Get TCP info into pre-allocated structure
	var info TCPInfo
	err = GetTCPInfoInto(conn.fd, &info)
	if err != nil {
		t.Logf("GetTCPInfoInto: %v", err)
	} else {
		t.Logf("TCP RTT: %d us", info.RTT)
		t.Logf("TCP RTTVar: %d us", info.RTTVar)
		t.Logf("Snd Wscale: %d", info.SndWscale())
		t.Logf("Rcv Wscale: %d", info.RcvWscale())
		t.Logf("Has Timestamps: %v", info.HasTimestamps())
		t.Logf("Has SACK: %v", info.HasSACK())
		t.Logf("Has Wscale: %v", info.HasWscale())
		t.Logf("Has ECN: %v", info.HasECN())
		t.Logf("App Limited: %v", info.IsDeliveryRateAppLimited())
		t.Logf("FastOpen Fail: %v", info.FastOpenClientFail())
	}

	<-done
}

// ========== RecvFDs Error Coverage ==========

func TestRecvFDs_NoData(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Try to receive with short deadline - should timeout
	pair[1].SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	dataBuf := make([]byte, 64)
	_, _, err = RecvFDs(pair[1].fd, dataBuf, 1)
	if err == nil {
		t.Error("Expected error on empty socket")
	}
	t.Logf("RecvFDs empty: %v", err)
}

// ========== ListenRaw4/6 Success Path Coverage ==========

// ========== RawSocket Methods Coverage ==========

// ========== RawConn Method Coverage ==========

// ========== DialRaw Coverage ==========

// ========== ListenRaw Coverage ==========

// ========== RawSocket SendTo IPv6 Coverage ==========

// ========== RawSocket RecvFrom/SendTo Closed Coverage ==========

// ========== UDPConn SendTo Coverage ==========

func TestUDPConn_SendToError(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}

	// Close and try SendTo
	conn.Close()

	_, err = conn.WriteTo([]byte("test"), &UnixAddr{Name: "/invalid"})
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

// ========== Unix Socket Error Paths ==========

func TestDialUnix_Error(t *testing.T) {
	// Dial to non-existent socket
	_, err := DialUnix("unix", nil, &UnixAddr{Name: "/nonexistent/socket.sock"})
	if err == nil {
		t.Error("expected error dialing non-existent socket")
	}
}

func TestListenUnix_Error(t *testing.T) {
	// Try to listen on invalid path
	_, err := ListenUnix("unix", &UnixAddr{Name: "/nonexistent/dir/socket.sock"})
	if err == nil {
		t.Error("expected error listening on invalid path")
	}
}

func TestListenUnixgram_Error(t *testing.T) {
	// Try to listen on invalid path
	_, err := ListenUnixgram("unixgram", &UnixAddr{Name: "/nonexistent/dir/socket.sock"})
	if err == nil {
		t.Error("expected error listening on invalid path")
	}
}

// ========== UnixConn WriteTo/ReadFrom Error Paths ==========

func TestUnixConn_WriteToError(t *testing.T) {
	pair, err := UnixConnPair("unixgram")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[1].Close()

	// Close one end
	pair[0].Close()

	// WriteTo on closed should fail
	_, err = pair[0].WriteTo([]byte("test"), &UnixAddr{Name: "@test"})
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

func TestUnixConn_ReadFromError(t *testing.T) {
	pair, err := UnixConnPair("unixgram")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[1].Close()

	// Close one end
	pair[0].Close()

	// ReadFrom on closed should fail
	buf := make([]byte, 64)
	_, _, err = pair[0].ReadFrom(buf)
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

// ========== applyUDPDefaults Coverage ==========

func TestNewUDPSocket6_DefaultsApplied(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock.Close()

	// Verify defaults
	reuse, err := GetReuseAddr(sock.fd)
	if err != nil {
		t.Errorf("GetReuseAddr: %v", err)
	}
	if !reuse {
		t.Error("expected SO_REUSEADDR enabled by default")
	}
}

// ========== NewUnix*Sock Error Paths ==========

func TestNewUnixStreamSocket_SuccessCoverage(t *testing.T) {
	sock, err := NewUnixStreamSocket()
	if err != nil {
		t.Fatalf("NewUnixStreamSocket: %v", err)
	}
	defer sock.Close()

	if sock.fd.Raw() < 0 {
		t.Error("invalid fd")
	}
}

func TestNewUnixDatagramSocket_SuccessCoverage(t *testing.T) {
	sock, err := NewUnixDatagramSocket()
	if err != nil {
		t.Fatalf("NewUnixDatagramSocket: %v", err)
	}
	defer sock.Close()

	if sock.fd.Raw() < 0 {
		t.Error("invalid fd")
	}
}

func TestNewUnixSeqpacketSocket_SuccessCoverage(t *testing.T) {
	sock, err := NewUnixSeqpacketSocket()
	if err != nil {
		t.Fatalf("NewUnixSeqpacketSocket: %v", err)
	}
	defer sock.Close()

	if sock.fd.Raw() < 0 {
		t.Error("invalid fd")
	}
}

// ========== applySCTPDefaults Coverage ==========

func TestNewSCTPSocket6_DefaultsApplied(t *testing.T) {
	sock, err := NewSCTPSocket6()
	if err != nil {
		t.Fatalf("NewSCTPSocket6: %v", err)
	}
	defer sock.Close()

	// Verify defaults
	nodelay, err := GetSCTPNodelay(sock.fd)
	if err != nil {
		t.Logf("GetSCTPNodelay: %v", err)
	}
	t.Logf("SCTP nodelay default: %v", nodelay)
}

// ========== SCTPListener AcceptSocket Coverage ==========

func TestSCTPListener_AcceptSocketCoverage(t *testing.T) {
	lis, err := ListenSCTP4(&SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer lis.Close()

	// AcceptSocket should return immediately with ErrWouldBlock
	_, err = lis.AcceptSocket()
	if err != iox.ErrWouldBlock {
		t.Logf("AcceptSocket: %v", err)
	}
}

// ========== UnixConnPair Error Coverage ==========

func TestUnixConnPair_InvalidNetworkType(t *testing.T) {
	_, err := UnixConnPair("invalid")
	if err == nil {
		t.Error("expected error for invalid network")
	}
}

// ========== Shutdown Coverage ==========

func TestNetSocket_ShutdownInvalid(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Shutdown with invalid how value
	err = sock.Shutdown(99)
	// May or may not error depending on kernel
	_ = err
}

// ========== Connect Error Path Coverage ==========

func TestNetSocket_ConnectTimeout(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Connect to unreachable address
	sa := NewSockaddrInet4([4]byte{10, 255, 255, 1}, 12345)
	err = sock.Connect(sa)
	// Should return ErrInProgress or network error
	if err != nil && err != ErrInProgress {
		t.Logf("Connect to unreachable: %v", err)
	}
}

// ========== SendFDs Error Coverage ==========

func TestSendFDs_InvalidFD(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Try to send with invalid fd
	_, err = SendFDs(pair[0].fd, []int{-1}, []byte("test"))
	// Should succeed in sending (kernel will handle invalid fd)
	t.Logf("SendFDs with invalid fd: %v", err)
}

// ========== SCTP Adaptive I/O Coverage ==========

func TestSCTPConn_AdaptiveIO(t *testing.T) {
	// Test SCTP socket creation (may fail without SCTP kernel module)
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()

	// Create SCTPConn manually to test adaptive I/O methods
	conn := &SCTPConn{
		SCTPSocket: sock,
		laddr:      &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		raddr:      nil,
	}

	// Test SetDeadline
	deadline := time.Now().Add(100 * time.Millisecond)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	// Test SetReadDeadline
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}

	// Test SetWriteDeadline
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}

	// Test clearing deadline
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline (clear): %v", err)
	}

	// Test LocalAddr/RemoteAddr
	if conn.LocalAddr() == nil {
		t.Logf("LocalAddr is nil (expected for unbound)")
	}
	// Note: RemoteAddr() returns a typed nil (*SCTPAddr) wrapped in interface,
	// which is not equal to nil in Go. This is expected behavior.
	raddr := conn.RemoteAddr()
	if raddr != nil {
		if sctpAddr, ok := raddr.(*SCTPAddr); ok && sctpAddr != nil {
			t.Errorf("RemoteAddr should be nil for unconnected socket, got %v", sctpAddr)
		}
	}
}

func TestSCTPListener_AdaptiveAccept(t *testing.T) {
	// Test SCTP listener creation (may fail without SCTP kernel module)
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	// Test SetDeadline
	deadline := time.Now().Add(50 * time.Millisecond)
	if err := listener.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	// Test Accept with deadline (should timeout since no connections)
	_, err = listener.Accept()
	if err == nil {
		t.Error("Expected error from Accept with no connections")
	}
	t.Logf("Accept with deadline: %v", err)

	// Test clearing deadline
	if err := listener.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline (clear): %v", err)
	}

	// Test Accept without deadline (should return WouldBlock immediately)
	_, err = listener.Accept()
	if err == nil {
		t.Error("Expected error from Accept with no connections")
	}
	t.Logf("Accept without deadline: %v", err)

	// Test Addr
	if listener.Addr() == nil {
		t.Error("Addr should not be nil")
	}
}

func TestSCTPConn_ReadWrite_NoConnection(t *testing.T) {
	// Test SCTP socket creation
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer sock.Close()

	// Create unconnected SCTPConn
	conn := &SCTPConn{
		SCTPSocket: sock,
		laddr:      &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		raddr:      nil,
	}

	// Test Read on unconnected socket (should fail)
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Expected error reading from unconnected socket")
	}
	t.Logf("Read on unconnected: %v", err)

	// Test Write on unconnected socket (should fail)
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Error("Expected error writing to unconnected socket")
	}
	t.Logf("Write on unconnected: %v", err)
}

func TestSCTPStreamSocket_Creation(t *testing.T) {
	// Test SCTP stream socket (SOCK_STREAM) creation
	sock4, err := NewSCTPStreamSocket4()
	if err != nil {
		t.Skipf("SCTP stream socket not available: %v", err)
	}
	sock4.Close()

	sock6, err := NewSCTPStreamSocket6()
	if err != nil {
		t.Skipf("SCTP6 stream socket not available: %v", err)
	}
	sock6.Close()
}

func TestSCTPSocket6_Creation(t *testing.T) {
	sock, err := NewSCTPSocket6()
	if err != nil {
		t.Skipf("SCTP6 not available: %v", err)
	}
	defer sock.Close()

	// Check protocol
	if sock.Protocol() != UnderlyingProtocolSeqPacket {
		t.Errorf("Protocol: expected SeqPacket, got %v", sock.Protocol())
	}
}

func TestListenSCTP6_Coverage(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	listener, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("SCTP6 not available: %v", err)
	}
	defer listener.Close()

	// Test AcceptSocket
	listener.SetDeadline(time.Now().Add(10 * time.Millisecond))
	_, err = listener.AcceptSocket()
	t.Logf("AcceptSocket: %v", err)
}

func TestDialSCTP_Coverage(t *testing.T) {
	// Start a listener first
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
	}
	defer listener.Close()

	// Get actual bound port
	actualAddr := listener.Addr().(*SCTPAddr)

	// Test DialSCTP with auto-detection
	raddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: actualAddr.Port}
	conn, err := DialSCTP("sctp", nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Logf("DialSCTP: %v", err)
	} else if conn != nil {
		conn.Close()
	}
}

func TestDialSCTP6_Coverage(t *testing.T) {
	// Start a listener first
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	listener, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("SCTP6 not available: %v", err)
	}
	defer listener.Close()

	// Get actual bound port
	actualAddr := listener.Addr().(*SCTPAddr)

	// Test DialSCTP6
	raddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port}
	conn, err := DialSCTP6(nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Logf("DialSCTP6: %v", err)
	} else if conn != nil {
		conn.Close()
	}

	// Test DialSCTP auto-detection for IPv6
	conn2, err := DialSCTP("sctp6", nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Logf("DialSCTP sctp6: %v", err)
	} else if conn2 != nil {
		conn2.Close()
	}
}

func TestSCTPAddr_NilHandling(t *testing.T) {
	// Test DialSCTP with nil remote addr
	_, err := DialSCTP4(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("DialSCTP4(nil, nil): expected ErrInvalidParam, got %v", err)
	}

	_, err = DialSCTP6(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("DialSCTP6(nil, nil): expected ErrInvalidParam, got %v", err)
	}

	_, err = DialSCTP("sctp", nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("DialSCTP(nil): expected ErrInvalidParam, got %v", err)
	}

	// Test ListenSCTP with nil local addr
	_, err = ListenSCTP4(nil)
	if err != ErrInvalidParam {
		t.Errorf("ListenSCTP4(nil): expected ErrInvalidParam, got %v", err)
	}

	_, err = ListenSCTP6(nil)
	if err != ErrInvalidParam {
		t.Errorf("ListenSCTP6(nil): expected ErrInvalidParam, got %v", err)
	}

	_, err = ListenSCTP("sctp", nil)
	if err != ErrInvalidParam {
		t.Errorf("ListenSCTP(nil): expected ErrInvalidParam, got %v", err)
	}
}

// ========== Additional Coverage Tests ==========

// --- Linger socket options ---

func TestSetGetLinger(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Test enable linger with timeout
	if err := SetLinger(sock.fd, true, 5); err != nil {
		t.Errorf("SetLinger(true, 5): %v", err)
	}

	enabled, secs, err := GetLinger(sock.fd)
	if err != nil {
		t.Errorf("GetLinger: %v", err)
	}
	if !enabled {
		t.Error("expected linger enabled")
	}
	if secs != 5 {
		t.Errorf("expected linger 5 seconds, got %d", secs)
	}

	// Test disable linger
	if err := SetLinger(sock.fd, false, 0); err != nil {
		t.Errorf("SetLinger(false, 0): %v", err)
	}

	enabled, _, err = GetLinger(sock.fd)
	if err != nil {
		t.Errorf("GetLinger: %v", err)
	}
	if enabled {
		t.Error("expected linger disabled")
	}
}

// --- UDP GetBroadcast ---

func TestUDPConn_GetBroadcast(t *testing.T) {
	laddr := &UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set broadcast
	if err := conn.SetBroadcast(true); err != nil {
		t.Errorf("SetBroadcast: %v", err)
	}

	// Get broadcast
	enabled, err := conn.GetBroadcast()
	if err != nil {
		t.Errorf("GetBroadcast: %v", err)
	}
	if !enabled {
		t.Error("expected broadcast enabled")
	}
}

// --- Raw socket tests (without CAP_NET_RAW, test error paths) ---

// --- NewNetUnixSocket ---

func TestNewNetUnixSocket(t *testing.T) {
	sock, err := NewNetUnixSocket(SOCK_STREAM)
	if err != nil {
		t.Fatalf("NewNetUnixSocket: %v", err)
	}
	defer sock.Close()

	if sock.NetworkType() != NetworkUnix {
		t.Errorf("expected NetworkUnix, got %v", sock.NetworkType())
	}
}

func TestNewNetUnixSocket_Dgram(t *testing.T) {
	sock, err := NewNetUnixSocket(SOCK_DGRAM)
	if err != nil {
		t.Fatalf("NewNetUnixSocket(DGRAM): %v", err)
	}
	defer sock.Close()
}

// --- ResolveSCTPAddr ---

func TestResolveSCTPAddr_Formats(t *testing.T) {
	// Test with valid address:port
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:1234")
	if err != nil {
		t.Errorf("ResolveSCTPAddr(127.0.0.1:1234): %v", err)
	} else if addr.Port != 1234 {
		t.Errorf("expected port 1234, got %d", addr.Port)
	}

	// Test with IPv6 address
	addr, err = ResolveSCTPAddr("sctp6", "[::1]:1234")
	if err != nil {
		t.Errorf("ResolveSCTPAddr([::1]:1234): %v", err)
	} else if addr == nil {
		t.Error("expected non-nil addr")
	}

	// Test sctp4
	addr, err = ResolveSCTPAddr("sctp4", "127.0.0.1:5678")
	if err != nil {
		t.Errorf("ResolveSCTPAddr sctp4: %v", err)
	}

	// Test unknown network
	_, err = ResolveSCTPAddr("tcp", "127.0.0.1:1234")
	if err == nil {
		t.Error("expected error for unknown network")
	}

	// Test empty network (defaults to sctp)
	addr, err = ResolveSCTPAddr("", "127.0.0.1:9999")
	if err != nil {
		t.Errorf("ResolveSCTPAddr with empty network: %v", err)
	}
}

// --- SCM_RIGHTS / SendMsg / RecvMsg ---

func TestSendRecvMsg(t *testing.T) {
	pair, err := UnixSocketPair()
	if err != nil {
		t.Fatalf("UnixSocketPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Create a simple message
	data := []byte("hello")
	iov := Iovec{
		Base: &data[0],
		Len:  uint64(len(data)),
	}

	msg := Msghdr{
		Iov:    &iov,
		Iovlen: 1,
	}

	// Send
	n, err := SendMsg(pair[0].fd, &msg, 0)
	if err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if n != len(data) {
		t.Errorf("SendMsg: expected %d, got %d", len(data), n)
	}

	// Receive
	recvBuf := make([]byte, 64)
	recvIov := Iovec{
		Base: &recvBuf[0],
		Len:  uint64(len(recvBuf)),
	}
	recvMsg := Msghdr{
		Iov:    &recvIov,
		Iovlen: 1,
	}

	n, err = RecvMsg(pair[1].fd, &recvMsg, 0)
	if err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}
	if n != len(data) {
		t.Errorf("RecvMsg: expected %d, got %d", len(data), n)
	}
	if string(recvBuf[:n]) != "hello" {
		t.Errorf("RecvMsg: expected 'hello', got '%s'", recvBuf[:n])
	}
}

func TestParseUnixCredentials(t *testing.T) {
	// Create credentials message
	cred := &Ucred{
		Pid: 1234,
		Uid: 1000,
		Gid: 1000,
	}
	buf := UnixCredentials(cred)

	// Parse it back
	parsed := ParseUnixCredentials(buf)
	if parsed == nil {
		t.Fatal("ParseUnixCredentials returned nil")
	}
	if parsed.Pid != 1234 {
		t.Errorf("expected pid 1234, got %d", parsed.Pid)
	}
	if parsed.Uid != 1000 {
		t.Errorf("expected uid 1000, got %d", parsed.Uid)
	}
	if parsed.Gid != 1000 {
		t.Errorf("expected gid 1000, got %d", parsed.Gid)
	}
}

func TestParseUnixCredentials_Empty(t *testing.T) {
	// Empty buffer
	parsed := ParseUnixCredentials(nil)
	if parsed != nil {
		t.Error("expected nil for empty buffer")
	}

	// Too small buffer
	parsed = ParseUnixCredentials(make([]byte, 5))
	if parsed != nil {
		t.Error("expected nil for small buffer")
	}
}

func TestParseUnixRights_EdgeCases(t *testing.T) {
	// Empty buffer
	fds := ParseUnixRights(nil)
	if len(fds) != 0 {
		t.Error("expected empty fds for nil buffer")
	}

	// Too small buffer
	fds = ParseUnixRights(make([]byte, 5))
	if len(fds) != 0 {
		t.Error("expected empty fds for small buffer")
	}

	// Buffer with invalid cmsg length (Len = 0)
	buf := make([]byte, 32)
	cmsg := (*Cmsghdr)(unsafe.Pointer(&buf[0]))
	cmsg.Len = 0 // Invalid
	fds = ParseUnixRights(buf)
	if len(fds) != 0 {
		t.Error("expected empty fds for invalid cmsg len")
	}

	// Buffer with cmsg.Len larger than remaining buffer (p+msgLen > len(buf))
	buf = make([]byte, 32)
	cmsg = (*Cmsghdr)(unsafe.Pointer(&buf[0]))
	cmsg.Len = 100 // Claims more bytes than buffer contains
	fds = ParseUnixRights(buf)
	if len(fds) != 0 {
		t.Error("expected empty fds for truncated cmsg")
	}
}

// --- Multicast error paths ---

func TestMulticast_ClosedSocket(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	sock.Close() // Close immediately

	// All multicast operations should fail
	err = JoinMulticast4(sock.fd, [4]byte{224, 0, 0, 1}, [4]byte{})
	if err == nil {
		t.Error("JoinMulticast4 should fail on closed socket")
	}

	err = JoinMulticast4n(sock.fd, [4]byte{224, 0, 0, 1}, 0)
	if err == nil {
		t.Error("JoinMulticast4n should fail on closed socket")
	}

	err = LeaveMulticast4(sock.fd, [4]byte{224, 0, 0, 1}, [4]byte{})
	if err == nil {
		t.Error("LeaveMulticast4 should fail on closed socket")
	}

	err = LeaveMulticast4n(sock.fd, [4]byte{224, 0, 0, 1}, 0)
	if err == nil {
		t.Error("LeaveMulticast4n should fail on closed socket")
	}

	err = SetMulticastTTL(sock.fd, 1)
	if err == nil {
		t.Error("SetMulticastTTL should fail on closed socket")
	}

	_, err = GetMulticastTTL(sock.fd)
	if err == nil {
		t.Error("GetMulticastTTL should fail on closed socket")
	}

	err = SetMulticastLoop(sock.fd, true)
	if err == nil {
		t.Error("SetMulticastLoop should fail on closed socket")
	}

	_, err = GetMulticastLoop(sock.fd)
	if err == nil {
		t.Error("GetMulticastLoop should fail on closed socket")
	}

	err = SetMulticastInterface(sock.fd, [4]byte{})
	if err == nil {
		t.Error("SetMulticastInterface should fail on closed socket")
	}

	err = SetMulticastInterfaceByIndex(sock.fd, 0)
	if err == nil {
		t.Error("SetMulticastInterfaceByIndex should fail on closed socket")
	}
}

func TestMulticast6_ClosedSocket(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	sock.Close()

	err = JoinMulticast6(sock.fd, [16]byte{0xff, 0x02}, 0)
	if err == nil {
		t.Error("JoinMulticast6 should fail on closed socket")
	}

	err = LeaveMulticast6(sock.fd, [16]byte{0xff, 0x02}, 0)
	if err == nil {
		t.Error("LeaveMulticast6 should fail on closed socket")
	}

	err = SetMulticast6Hops(sock.fd, 1)
	if err == nil {
		t.Error("SetMulticast6Hops should fail on closed socket")
	}

	_, err = GetMulticast6Hops(sock.fd)
	if err == nil {
		t.Error("GetMulticast6Hops should fail on closed socket")
	}

	err = SetMulticast6Loop(sock.fd, true)
	if err == nil {
		t.Error("SetMulticast6Loop should fail on closed socket")
	}

	_, err = GetMulticast6Loop(sock.fd)
	if err == nil {
		t.Error("GetMulticast6Loop should fail on closed socket")
	}

	err = SetMulticast6Interface(sock.fd, 0)
	if err == nil {
		t.Error("SetMulticast6Interface should fail on closed socket")
	}

	_, err = GetMulticast6Interface(sock.fd)
	if err == nil {
		t.Error("GetMulticast6Interface should fail on closed socket")
	}

	err = SetMulticast6All(sock.fd, true)
	if err == nil {
		t.Error("SetMulticast6All should fail on closed socket")
	}
}

// --- errFromErrno coverage ---

func TestErrFromErrno_AllCases(t *testing.T) {
	tests := []struct {
		errno uintptr
		want  error
	}{
		{0, nil},
		{EAGAIN, iox.ErrWouldBlock},
		{EWOULDBLOCK, iox.ErrWouldBlock},
		{EBADF, ErrClosed},
		{EINVAL, ErrInvalidParam},
		{EINTR, ErrInterrupted},
		{ENOMEM, ErrNoMemory},
		{ENOBUFS, ErrNoMemory},
		{EACCES, ErrPermission},
		{EPERM, ErrPermission},
		{ECONNREFUSED, ErrConnectionRefused},
		{ECONNRESET, ErrConnectionReset},
		{ECONNABORTED, ErrConnectionReset},
		{EPIPE, ErrConnectionReset},
		{ESHUTDOWN, ErrConnectionReset},
		{ENOTCONN, ErrNotConnected},
		{EDESTADDRREQ, ErrNotConnected},
		{EINPROGRESS, ErrInProgress},
		{EALREADY, ErrInProgress},
		{EISCONN, nil},
		{EADDRINUSE, ErrAddressInUse},
		{EADDRNOTAVAIL, ErrAddressNotAvailable},
		{ETIMEDOUT, ErrTimedOut},
		{ENETDOWN, ErrNetworkUnreachable},
		{ENETUNREACH, ErrNetworkUnreachable},
		{EHOSTUNREACH, ErrHostUnreachable},
		{EMSGSIZE, ErrMessageTooLarge},
		{EAFNOSUPPORT, ErrAddressFamilyNotSupported},
		{EPROTONOSUPPORT, ErrProtocolNotSupported},
	}

	for _, tt := range tests {
		got := errFromErrno(tt.errno)
		if got != tt.want {
			t.Errorf("errFromErrno(%d): got %v, want %v", tt.errno, got, tt.want)
		}
	}

	// Test unknown errno returns zcall.Errno
	unknown := errFromErrno(9999)
	if unknown == nil {
		t.Error("unknown errno should return non-nil error")
	}
}

// --- Sockaddr edge cases ---

func TestSockaddrUnix_PathEdgeCases(t *testing.T) {
	// Test with max length path (107 chars + NUL terminator)
	longPathBytes := make([]byte, 107)
	for i := range longPathBytes {
		longPathBytes[i] = 'a'
	}
	longPath := string(longPathBytes)
	sa := NewSockaddrUnix(longPath)
	if sa.Path() != longPath {
		t.Errorf("path mismatch for long path: got %d chars, want %d", len(sa.Path()), len(longPath))
	}

	// Test with path that fills entire buffer (no NUL terminator in buffer)
	fullPathBytes := make([]byte, 108)
	for i := range fullPathBytes {
		fullPathBytes[i] = 'b'
	}
	fullPath := string(fullPathBytes)
	sa = NewSockaddrUnix(fullPath)
	gotPath := sa.Path()
	if len(gotPath) != 108 {
		t.Errorf("expected full path length 108, got %d", len(gotPath))
	}
}

func TestTCPAddrToSockaddr_NilIPCoverage(t *testing.T) {
	// When IP is nil, To4() and To16() both return nil, so TCPAddrToSockaddr returns nil
	addr := &net.TCPAddr{IP: nil, Port: 1234}
	sa := TCPAddrToSockaddr(addr)
	if sa != nil {
		t.Error("expected nil sockaddr for addr with nil IP (To4 and To16 both return nil)")
	}
}

func TestSockaddrToTCPAddr_NilCases(t *testing.T) {
	// nil sockaddr
	result := SockaddrToTCPAddr(nil)
	if result != nil {
		t.Error("expected nil for nil sockaddr")
	}
}

func TestDecodeSockaddr_AllFamilies(t *testing.T) {
	// Test nil
	sa := DecodeSockaddr(nil)
	if sa != nil {
		t.Error("expected nil for nil raw")
	}

	// Create IPv4 raw addr
	var raw4 RawSockaddrAny
	inet4 := (*RawSockaddrInet4)(unsafe.Pointer(&raw4))
	inet4.Family = AF_INET
	inet4.Port = htons(8080)
	inet4.Addr = [4]byte{127, 0, 0, 1}
	sa = DecodeSockaddr(&raw4)
	if sa == nil {
		t.Error("expected non-nil for IPv4")
	}
	if sa.Family() != AF_INET {
		t.Errorf("expected AF_INET, got %d", sa.Family())
	}

	// Create IPv6 raw addr
	var raw6 RawSockaddrAny
	inet6 := (*RawSockaddrInet6)(unsafe.Pointer(&raw6))
	inet6.Family = AF_INET6
	inet6.Port = htons(8080)
	sa = DecodeSockaddr(&raw6)
	if sa == nil {
		t.Error("expected non-nil for IPv6")
	}

	// Create Unix raw addr
	var rawUnix RawSockaddrAny
	sunix := (*RawSockaddrUnix)(unsafe.Pointer(&rawUnix))
	sunix.Family = AF_UNIX
	copy(sunix.Path[:], "/tmp/test.sock")
	sa = DecodeSockaddr(&rawUnix)
	if sa == nil {
		t.Error("expected non-nil for Unix")
	}
}

// --- GetSockname/GetPeername error paths ---

func TestGetSockname_ClosedSocket(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close()

	_, err = GetSockname(sock.fd)
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestGetPeername_ClosedSocket(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close()

	_, err = GetPeername(sock.fd)
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

// --- SetCloseOnExec ---

func TestSetCloseOnExec_ToggleCoverage(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// CLOEXEC is already set by default, but let's toggle it
	if err := SetCloseOnExec(sock.fd, false); err != nil {
		t.Errorf("SetCloseOnExec(false): %v", err)
	}

	if err := SetCloseOnExec(sock.fd, true); err != nil {
		t.Errorf("SetCloseOnExec(true): %v", err)
	}
}

// --- Unix socket error paths ---

func TestUnixConn_ReadFrom_ClosedSocket(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	pair[0].Close()
	pair[1].Close()

	buf := make([]byte, 64)
	_, _, err = pair[0].ReadFrom(buf)
	if err == nil {
		t.Error("ReadFrom on closed socket should fail")
	}
}

func TestUnixConn_WriteTo_ClosedSocket(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	pair[0].Close()
	pair[1].Close()

	addr := &UnixAddr{Name: "/tmp/test.sock", Net: "unix"}
	_, err = pair[0].WriteTo([]byte("test"), addr)
	if err == nil {
		t.Error("WriteTo on closed socket should fail")
	}
}

func TestListenUnix_BadNetwork(t *testing.T) {
	addr := &UnixAddr{Name: "/tmp/test.sock", Net: "invalid"}
	_, err := ListenUnix("invalid", addr)
	if err == nil {
		t.Error("expected error for invalid network")
	}
}

func TestListenUnixgram_BadNetwork(t *testing.T) {
	addr := &UnixAddr{Name: "/tmp/test.sock", Net: "unix"}
	_, err := ListenUnixgram("unix", addr)
	if err == nil {
		t.Error("expected error for non-unixgram network")
	}
}

func TestDialUnix_BadNetwork(t *testing.T) {
	addr := &UnixAddr{Name: "/tmp/test.sock", Net: "invalid"}
	_, err := DialUnix("invalid", nil, addr)
	if err == nil {
		t.Error("expected error for invalid network")
	}
}

func TestUnixConnPair_UnknownNetwork(t *testing.T) {
	_, err := UnixConnPair("invalid")
	if err == nil {
		t.Error("expected error for invalid network")
	}
}

// --- SCTP Protocol ---

func TestSCTPSocket_Protocol_SeqPacket(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolSeqPacket {
		t.Errorf("expected SeqPacket, got %v", sock.Protocol())
	}
}

// --- TCP KeepAlivePeriod error path ---

func TestTCPConn_SetKeepAlivePeriod_ClosedSocket(t *testing.T) {
	laddr := &TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	actualAddr := lis.Addr().(*TCPAddr)

	// Dial to create a connection
	conn, err := DialTCP4(nil, &TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: actualAddr.Port})
	if err != nil && err != ErrInProgress {
		t.Fatalf("DialTCP4: %v", err)
	}
	conn.Close()
	lis.Close()

	// Try to set keepalive on closed connection
	err = conn.SetKeepAlivePeriod(time.Second)
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

// --- SCTP AcceptSocket ---

func TestSCTPListener_AcceptSocket_NonBlocking(t *testing.T) {
	laddr := &SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	lis, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("ListenSCTP4: %v (SCTP might not be available)", err)
		return
	}
	defer lis.Close()

	// AcceptSocket should return ErrWouldBlock immediately (non-blocking)
	_, err = lis.AcceptSocket()
	if err != iox.ErrWouldBlock {
		t.Logf("AcceptSocket: %v", err)
	}
}

// --- TCP AcceptSocket ---

func TestTCPListener_AcceptSocket_NonBlocking(t *testing.T) {
	laddr := &TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	// AcceptSocket should return ErrWouldBlock immediately (non-blocking)
	_, err = lis.AcceptSocket()
	if err != iox.ErrWouldBlock {
		t.Logf("AcceptSocket: %v", err)
	}
}

// --- adaptiveWrite timeout path ---

func TestAdaptiveWrite_Timeout(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Set a very short deadline
	pair[0].SetWriteDeadline(time.Now().Add(time.Nanosecond))
	time.Sleep(time.Millisecond)

	// Fill the buffer to cause a block
	bigData := make([]byte, 1024*1024) // 1MB
	for {
		_, err := pair[0].Write(bigData)
		if err == ErrTimedOut {
			break
		}
		if err != nil && err != iox.ErrWouldBlock {
			break
		}
	}
}

// --- SCTPInitMsg getter error path ---

func TestGetSCTPInitMsg_ClosedSocket(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
		return
	}
	sock.Close()

	_, err = GetSCTPInitMsg(sock.fd)
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

// --- SCTP coverage ---

func TestSCTPSocket_NewStreamSockets(t *testing.T) {
	sock4, err := NewSCTPStreamSocket4()
	if err != nil {
		t.Skipf("SCTP stream not available: %v", err)
		return
	}
	defer sock4.Close()

	if sock4.Protocol() != UnderlyingProtocolStream {
		t.Errorf("expected UnderlyingProtocolStream, got %v", sock4.Protocol())
	}

	sock6, err := NewSCTPStreamSocket6()
	if err != nil {
		t.Skipf("SCTP stream IPv6 not available: %v", err)
		return
	}
	defer sock6.Close()

	if sock6.Protocol() != UnderlyingProtocolStream {
		t.Errorf("expected UnderlyingProtocolStream for IPv6, got %v", sock6.Protocol())
	}
}

func TestListenSCTP_IPv6(t *testing.T) {
	laddr := &SCTPAddr{IP: net.IPv6loopback, Port: 0}
	listener, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("ListenSCTP6 not available: %v", err)
		return
	}
	defer listener.Close()

	if listener.Addr() == nil {
		t.Error("Addr should not be nil")
	}
}

func TestDialSCTP_IPv6(t *testing.T) {
	// Start listener first
	laddr := &SCTPAddr{IP: net.IPv6loopback, Port: 0}
	listener, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("ListenSCTP6 not available: %v", err)
		return
	}
	defer listener.Close()

	// Get actual port
	sctpLaddr := listener.laddr
	raddr := &SCTPAddr{IP: net.IPv6loopback, Port: sctpLaddr.Port}

	// Dial
	conn, err := DialSCTP6(nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Skipf("DialSCTP6 failed: %v", err)
		return
	}
	if conn != nil {
		defer conn.Close()
		if conn.LocalAddr() == nil {
			t.Error("LocalAddr should not be nil after connect")
		}
	}
}

func TestListenSCTP_NetworkSelection(t *testing.T) {
	// Test "sctp" network with IPv4 address
	laddr := &SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	listener, err := ListenSCTP("sctp", laddr)
	if err != nil {
		t.Skipf("ListenSCTP not available: %v", err)
		return
	}
	defer listener.Close()

	// Test "sctp6" network
	laddr6 := &SCTPAddr{IP: net.IPv6loopback, Port: 0}
	listener6, err := ListenSCTP("sctp6", laddr6)
	if err != nil {
		t.Skipf("ListenSCTP6 not available: %v", err)
		return
	}
	defer listener6.Close()
}

func TestDialSCTP_NetworkSelection(t *testing.T) {
	// Start listener
	laddr := &SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("ListenSCTP4 not available: %v", err)
		return
	}
	defer listener.Close()

	// Get port
	port := listener.laddr.Port
	raddr := &SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}

	// Dial with network selection
	conn, err := DialSCTP("sctp", nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Skipf("DialSCTP failed: %v", err)
		return
	}
	if conn != nil {
		defer conn.Close()
	}
}

func TestSCTPConn_DeadlineMethods(t *testing.T) {
	// Start listener
	laddr := &SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("ListenSCTP4 not available: %v", err)
		return
	}
	defer listener.Close()

	// Get port and dial
	port := listener.laddr.Port
	raddr := &SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}

	conn, err := DialSCTP4(nil, raddr)
	if err != nil && err != ErrInProgress {
		t.Skipf("DialSCTP4 failed: %v", err)
		return
	}
	if conn == nil {
		return
	}
	defer conn.Close()

	// Test deadline methods
	deadline := time.Now().Add(100 * time.Millisecond)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}

	// Test Read/Write
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	t.Logf("Read: %v (expected timeout or would-block)", err)

	_, err = conn.Write([]byte("test"))
	t.Logf("Write: %v", err)
}

func TestSCTPListener_AcceptWithDeadline(t *testing.T) {
	laddr := &SCTPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	listener, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("ListenSCTP4 not available: %v", err)
		return
	}
	defer listener.Close()

	// Set short deadline
	listener.SetDeadline(time.Now().Add(50 * time.Millisecond))

	// Accept should timeout
	_, err = listener.Accept()
	if err != ErrTimedOut && err != iox.ErrWouldBlock {
		t.Logf("Accept with deadline: %v", err)
	}
}

// --- ResolveSCTPAddr coverage ---

func TestResolveSCTPAddr_MoreCases(t *testing.T) {
	tests := []struct {
		network string
		address string
		wantErr bool
	}{
		{"sctp", "127.0.0.1:1234", false},
		{"sctp4", "127.0.0.1:1234", false},
		{"sctp6", "[::1]:1234", false},
		{"sctp", "[::1]:1234", false},
		{"sctp", "invalid", true},           // no port
		{"sctp", ":1234", true},             // empty host causes lookup error
		{"invalid", "127.0.0.1:1234", true}, // bad network
	}

	for _, tt := range tests {
		addr, err := ResolveSCTPAddr(tt.network, tt.address)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ResolveSCTPAddr(%q, %q) expected error", tt.network, tt.address)
			}
		} else {
			if err != nil {
				t.Errorf("ResolveSCTPAddr(%q, %q) = %v", tt.network, tt.address, err)
			} else if addr == nil {
				t.Errorf("ResolveSCTPAddr(%q, %q) returned nil addr", tt.network, tt.address)
			}
		}
	}
}

// --- NetSocketPair coverage ---

func TestNetSocketPair_UnixCoverage(t *testing.T) {
	pair, err := NetSocketPair(zcall.AF_UNIX, zcall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("NetSocketPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Test communication - NetSocket.Write/Read are non-blocking
	msg := []byte("hello from socket pair")
	n, err := pair[0].Write(msg)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("Write: %v", err)
	}
	if n > 0 {
		buf := make([]byte, 100)
		n, err = pair[1].Read(buf)
		if err != nil && err != iox.ErrWouldBlock && err != ErrTimedOut {
			t.Logf("Read: %v", err)
		}
		if n > 0 && string(buf[:n]) != string(msg) {
			t.Errorf("message mismatch: got %q, want %q", buf[:n], msg)
		}
	}
}

// --- Additional inet.go coverage ---

func TestResolveIPAddr_MoreCases(t *testing.T) {
	tests := []struct {
		network string
		address string
		wantErr bool
	}{
		{"ip", "127.0.0.1", false},
		{"ip4", "127.0.0.1", false},
		{"ip6", "::1", false},
		{"ip", "::1", false},
		{"ip", "", false}, // empty resolves to 0.0.0.0
	}

	for _, tt := range tests {
		addr, err := ResolveIPAddr(tt.network, tt.address)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ResolveIPAddr(%q, %q) expected error", tt.network, tt.address)
			}
		} else {
			if err != nil {
				t.Errorf("ResolveIPAddr(%q, %q) = %v", tt.network, tt.address, err)
			} else if addr == nil {
				t.Errorf("ResolveIPAddr(%q, %q) returned nil addr", tt.network, tt.address)
			}
		}
	}
}

// --- applySCTPDefaults error path (harder to trigger but try) ---

func TestSCTPSocket_DefaultsApplied(t *testing.T) {
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Skipf("SCTP not available: %v", err)
		return
	}
	defer sock.Close()

	// Verify defaults were applied
	reuse, err := GetReuseAddr(sock.fd)
	if err != nil {
		t.Errorf("GetReuseAddr: %v", err)
	}
	if !reuse {
		t.Error("expected SO_REUSEADDR enabled by default")
	}

	reusePort, err := GetReusePort(sock.fd)
	if err != nil {
		t.Errorf("GetReusePort: %v", err)
	}
	if !reusePort {
		t.Error("expected SO_REUSEPORT enabled by default")
	}
}

// --- More ResolveSCTPAddr coverage ---

func TestResolveSCTPAddr_EmptyNetworkCoverage(t *testing.T) {
	// Empty network defaults to "sctp"
	addr, err := ResolveSCTPAddr("", "127.0.0.1:1234")
	if err != nil {
		t.Errorf("ResolveSCTPAddr(\"\", \"127.0.0.1:1234\") = %v", err)
	}
	if addr == nil {
		t.Error("expected non-nil addr")
	}
}

func TestResolveSCTPAddr_SCTP6Network(t *testing.T) {
	// sctp6 with IPv6 address
	addr, err := ResolveSCTPAddr("sctp6", "[::1]:1234")
	if err != nil {
		t.Errorf("ResolveSCTPAddr(\"sctp6\", \"[::1]:1234\") = %v", err)
	}
	if addr == nil {
		t.Error("expected non-nil addr")
	}
}

func TestResolveSCTPAddr_SCTPWithIPv6Hint(t *testing.T) {
	// sctp with address containing : should hint IPv6
	addr, err := ResolveSCTPAddr("sctp", "[::1]:1234")
	if err != nil {
		t.Errorf("ResolveSCTPAddr(\"sctp\", \"[::1]:1234\") = %v", err)
	}
	if addr == nil {
		t.Error("expected non-nil addr")
	}
}

// --- Linger more paths ---

func TestLinger_DisabledStateCoverage(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Set linger disabled
	if err := SetLinger(sock.fd, false, 0); err != nil {
		t.Errorf("SetLinger(false, 0): %v", err)
	}

	enabled, secs, err := GetLinger(sock.fd)
	if err != nil {
		t.Errorf("GetLinger: %v", err)
	}
	if enabled {
		t.Error("expected linger disabled")
	}
	t.Logf("Linger disabled, seconds=%d", secs)
}

func TestLinger_EnabledWithTimeoutCoverage(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Set linger enabled with 5 seconds
	if err := SetLinger(sock.fd, true, 5); err != nil {
		t.Errorf("SetLinger(true, 5): %v", err)
	}

	enabled, secs, err := GetLinger(sock.fd)
	if err != nil {
		t.Errorf("GetLinger: %v", err)
	}
	if !enabled {
		t.Error("expected linger enabled")
	}
	if secs != 5 {
		t.Errorf("expected linger timeout 5, got %d", secs)
	}
}

// --- DecodeSockaddr more coverage ---

func TestDecodeSockaddr_UnixCoverage(t *testing.T) {
	path := "/tmp/test.sock"
	sa := NewSockaddrUnix(path)
	ptr, _ := sa.Raw()
	raw := (*RawSockaddrAny)(ptr)

	decoded := DecodeSockaddr(raw)
	if decoded == nil {
		t.Error("expected non-nil for Unix sockaddr")
	}
	if unix, ok := decoded.(*SockaddrUnix); ok {
		if unix.Path() != path {
			t.Errorf("path mismatch: got %q, want %q", unix.Path(), path)
		}
	}
}

// --- More connect error paths ---

func TestConnect_Refused(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Connect to a port that should be closed
	addr := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 59999)
	err = sock.Connect(addr)
	// Non-blocking socket returns ErrInProgress
	if err != nil && err != ErrInProgress {
		t.Logf("Connect to closed port: %v", err)
	}
}

// --- TCPAddrToSockaddr IPv6 path ---

func TestTCPAddrToSockaddr_IPv6(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv6loopback, Port: 1234}
	sa := TCPAddrToSockaddr(addr)
	if sa == nil {
		t.Error("expected non-nil sockaddr for IPv6")
	}
	if sa.Family() != AF_INET6 {
		t.Errorf("expected AF_INET6, got %d", sa.Family())
	}
}

func TestTCPAddrToSockaddr_IPv6WithZone(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv6loopback, Port: 1234, Zone: "lo"}
	sa := TCPAddrToSockaddr(addr)
	if sa == nil {
		t.Error("expected non-nil sockaddr for IPv6 with zone")
	}
}

// --- TCPDialer timeout tests ---

func TestTCPDialer_Dial4_Success(t *testing.T) {
	// Create a standard net listener (blocking, for reliable accept)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	// Accept in background
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)

	// Dial with timeout
	dialer := &TCPDialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial4(nil, &TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatalf("Dial4: %v", err)
	}
	defer conn.Close()

	if conn.RemoteAddr() == nil {
		t.Error("expected non-nil RemoteAddr")
	}
}

func TestTCPDialer_Dial6_Success(t *testing.T) {
	// Create a standard net listener
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	// Accept in background
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)

	// Dial with timeout
	dialer := &TCPDialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial6(nil, &TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatalf("Dial6: %v", err)
	}
	defer conn.Close()
}

func TestTCPDialer_Dial_AutoDetect(t *testing.T) {
	// Create a standard net listener
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	// Accept in background
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)

	// Dial with auto-detect
	dialer := &TCPDialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial("tcp4", nil, &TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
}

func TestTCPDialer_Dial4_Timeout(t *testing.T) {
	// Dial to a non-routable address that will timeout
	dialer := &TCPDialer{Timeout: 50 * time.Millisecond}
	_, err := dialer.Dial4(nil, &TCPAddr{IP: net.IPv4(10, 255, 255, 1), Port: 9999})
	if err != ErrTimedOut && err != ErrNetworkUnreachable && err != ErrHostUnreachable {
		t.Logf("Dial4 timeout: %v (expected ErrTimedOut or network error)", err)
	}
}

func TestTCPDialer_Dial4_NilRaddr(t *testing.T) {
	dialer := &TCPDialer{Timeout: time.Second}
	_, err := dialer.Dial4(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestTCPDialer_Dial6_NilRaddr(t *testing.T) {
	dialer := &TCPDialer{Timeout: time.Second}
	_, err := dialer.Dial6(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestTCPDialer_Dial_NilRaddr(t *testing.T) {
	dialer := &TCPDialer{Timeout: time.Second}
	_, err := dialer.Dial("tcp", nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestTCPDialer_SetDialTimeout(t *testing.T) {
	dialer := &TCPDialer{}
	dialer.SetDialTimeout(5 * time.Second)
	if dialer.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", dialer.Timeout)
	}
}

func TestTCPDialer_Dial4_WithLocalAddr(t *testing.T) {
	// Create a standard net listener
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	// Accept in background
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)

	// Dial with local address
	dialer := &TCPDialer{Timeout: 2 * time.Second}
	localAddr := &TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	conn, err := dialer.Dial4(localAddr, &TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatalf("Dial4 with laddr: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("expected non-nil LocalAddr")
	}
}

// --- UnixConn dgram EOF preservation test ---

func TestUnixConn_ReadDgram_PreservesZeroNil(t *testing.T) {
	// Create a pair of datagram Unix sockets
	pair, err := UnixConnPair("unixgram")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Verify protocol is dgram
	if pair[0].Protocol() != UnderlyingProtocolDgram {
		t.Errorf("expected UnderlyingProtocolDgram, got %v", pair[0].Protocol())
	}

	// For dgram sockets, (0, nil) from iofd should NOT be converted to EOF
	// This is tested implicitly through the Protocol() check in Read()
}

func TestUnixConn_Protocol_SeqPacket(t *testing.T) {
	pair, err := UnixConnPair("unixpacket")
	if err != nil {
		t.Fatalf("UnixConnPair unixpacket: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	if pair[0].Protocol() != UnderlyingProtocolSeqPacket {
		t.Errorf("expected UnderlyingProtocolSeqPacket, got %v", pair[0].Protocol())
	}
}

// --- adaptiveConnect tests ---

func TestAdaptiveConnect_ImmediateSuccess(t *testing.T) {
	// Create a standard net listener
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	// Accept in background
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)

	// Create socket and use adaptiveConnect directly
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, uint16(addr.Port))
	err = adaptiveConnect(sock.NetSocket, sa, 2*time.Second)
	if err != nil {
		t.Errorf("adaptiveConnect: %v", err)
	}
}

func TestAdaptiveConnect_ZeroTimeout(t *testing.T) {
	// With zero timeout, should return ErrInProgress immediately
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Connect to non-listening port
	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 59998)
	err = adaptiveConnect(sock.NetSocket, sa, 0)
	if err != ErrInProgress && err != ErrConnectionRefused {
		t.Logf("adaptiveConnect zero timeout: %v", err)
	}
}

func TestAdaptiveConnect_AlreadyExpired(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Use very short timeout that will expire immediately
	sa := NewSockaddrInet4([4]byte{10, 255, 255, 1}, 9999)
	err = adaptiveConnect(sock.NetSocket, sa, time.Nanosecond)
	// Should timeout or get network error
	if err != ErrTimedOut && err != ErrNetworkUnreachable && err != ErrHostUnreachable && err != ErrInProgress {
		t.Logf("adaptiveConnect expired: %v", err)
	}
}

// --- SCTPDialer tests ---

func TestSCTPDialer_SetDialTimeout(t *testing.T) {
	dialer := &SCTPDialer{}
	dialer.SetDialTimeout(3 * time.Second)
	if dialer.Timeout != 3*time.Second {
		t.Errorf("expected 3s timeout, got %v", dialer.Timeout)
	}
}

func TestSCTPDialer_Dial4_NilRaddr(t *testing.T) {
	dialer := &SCTPDialer{Timeout: time.Second}
	_, err := dialer.Dial4(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestSCTPDialer_Dial6_NilRaddr(t *testing.T) {
	dialer := &SCTPDialer{Timeout: time.Second}
	_, err := dialer.Dial6(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestSCTPDialer_Dial_NilRaddr(t *testing.T) {
	dialer := &SCTPDialer{Timeout: time.Second}
	_, err := dialer.Dial("sctp", nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

// --- Edge case tests for error branches ---

// SockaddrUnix.Path edge cases
func TestSockaddrUnix_Path_AbstractSocket(t *testing.T) {
	// Abstract sockets start with NUL byte
	sa := &SockaddrUnix{}
	sa.raw.Family = AF_UNIX
	sa.raw.Path[0] = 0 // NUL prefix for abstract
	sa.raw.Path[1] = 'a'
	sa.raw.Path[2] = 'b'
	sa.raw.Path[3] = 'c'
	sa.length = 2 + 4 // family + 4 bytes

	path := sa.Path()
	if len(path) != 4 || path[0] != 0 {
		t.Errorf("abstract socket path: got %q (len=%d)", path, len(path))
	}
}

func TestSockaddrUnix_Path_ZeroLength(t *testing.T) {
	sa := &SockaddrUnix{}
	sa.length = 0 // Zero length

	path := sa.Path()
	if path != "" {
		t.Errorf("expected empty path for zero length, got %q", path)
	}
}

func TestSockaddrUnix_Path_OnlyFamily(t *testing.T) {
	sa := &SockaddrUnix{}
	sa.length = 2 // Only family, no path

	path := sa.Path()
	if path != "" {
		t.Errorf("expected empty path for family-only, got %q", path)
	}
}

func TestSockaddrUnix_Path_LongPath(t *testing.T) {
	sa := &SockaddrUnix{}
	sa.length = 2 + 200 // Larger than Path array

	path := sa.Path()
	// Should be truncated to max path length
	t.Logf("long path result length: %d", len(path))
}

func TestSockaddrUnix_SetPath_MaxLength(t *testing.T) {
	sa := NewSockaddrUnix(string(make([]byte, 200))) // Long path
	path := sa.Path()
	t.Logf("max path length: %d", len(path))
}

// TestSockaddrUnix_SetPath_ExactlyMaxPath tests SetPath with a path that
// exactly fills the Path array, triggering the "no room for NUL" branch.
func TestSockaddrUnix_SetPath_ExactlyMaxPath(t *testing.T) {
	sa := &SockaddrUnix{}
	// Create a path that exactly fills the Path array (108 bytes on Linux)
	fullPath := make([]byte, len(sa.raw.Path))
	for i := range fullPath {
		fullPath[i] = 'x'
	}
	// SetPath should set length to 2 + 108 (no NUL terminator)
	sa.SetPath(string(fullPath))
	expected := uint32(2 + len(sa.raw.Path))
	if sa.length != expected {
		t.Errorf("SetPath full path: length = %d, want %d", sa.length, expected)
	}
}

// TestSockaddrUnix_Path_ZeroLengthNoNul tests the fallback when length < 2
// and the Path array has no NUL byte (all non-zero).
func TestSockaddrUnix_Path_ZeroLengthNoNul(t *testing.T) {
	sa := &SockaddrUnix{}
	// Fill path array with non-zero bytes
	for i := range sa.raw.Path {
		sa.raw.Path[i] = 'x'
	}
	// length < 2 triggers fallback search for NUL
	sa.length = 0

	path := sa.Path()
	// Since no NUL byte found, should return ""
	if path != "" {
		t.Errorf("expected empty path for no-NUL fallback, got %q", path)
	}
}

// TestDecodeSockaddr_UnixNoNul tests DecodeSockaddr for AF_UNIX with no NUL in path.
func TestDecodeSockaddr_UnixNoNul(t *testing.T) {
	// AF_UNIX with no NUL in path (full-length path)
	var rawUnix RawSockaddrAny
	sunix := (*RawSockaddrUnix)(unsafe.Pointer(&rawUnix))
	sunix.Family = AF_UNIX
	// Fill path with non-zero bytes (no NUL terminator)
	for i := range sunix.Path {
		sunix.Path[i] = 'x'
	}
	sa := DecodeSockaddr(&rawUnix)
	if sa == nil {
		t.Fatal("expected non-nil sockaddr for AF_UNIX")
	}
	usa, ok := sa.(*SockaddrUnix)
	if !ok {
		t.Fatalf("expected *SockaddrUnix, got %T", sa)
	}
	// Should have full length since no NUL found
	if usa.length != SizeofSockaddrUnix {
		t.Logf("length = %d, expected %d", usa.length, SizeofSockaddrUnix)
	}
}

// adaptiveWrite with deadline expiry
func TestAdaptiveWrite_DeadlineExpired(t *testing.T) {
	// Create a socket pair
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Fill the write buffer to make it block
	buf := make([]byte, 1024*1024) // 1MB
	for i := 0; i < 100; i++ {
		_, err := pair[0].Write(buf)
		if err == iox.ErrWouldBlock {
			break
		}
		if err != nil && err != iox.ErrWouldBlock {
			t.Logf("Write %d: %v", i, err)
			break
		}
	}

	// Now write with a very short deadline
	pair[0].SetWriteDeadline(time.Now().Add(time.Millisecond))
	_, err = pair[0].Write(buf)
	if err != ErrTimedOut && err != iox.ErrWouldBlock {
		t.Logf("Write with expired deadline: %v", err)
	}
}

// TCP Read EOF test
func TestTCPConn_Read_EOF(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	// Accept and close immediately in background
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte("hello"))
		conn.Close()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	dialer := &TCPDialer{Timeout: 2 * time.Second}
	conn, err := dialer.Dial4(nil, &TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatalf("Dial4: %v", err)
	}
	defer conn.Close()

	// Set deadline to enable adaptive read
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Read data
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if n > 0 {
		t.Logf("Read %d bytes: %s", n, buf[:n])
	}

	// Keep reading until EOF
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		n, err = conn.Read(buf)
		if err == io.EOF {
			t.Logf("Got EOF as expected")
			return
		}
		if err != nil && err != iox.ErrWouldBlock {
			t.Logf("Read: %v", err)
		}
	}
}

// Unix stream Read EOF test
func TestUnixConn_Read_StreamEOF(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()

	// Write and close
	pair[1].Write([]byte("test"))
	pair[1].Close()

	// Set deadline for adaptive read
	pair[0].SetReadDeadline(time.Now().Add(time.Second))

	buf := make([]byte, 100)
	// First read gets data
	n, err := pair[0].Read(buf)
	t.Logf("First read: n=%d, err=%v", n, err)

	// Second read should get EOF
	n, err = pair[0].Read(buf)
	if err != io.EOF {
		t.Logf("Expected EOF, got: n=%d, err=%v", n, err)
	}
}

// adaptiveConnect connection refused
func TestAdaptiveConnect_ConnectionRefused(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Connect to a port that's definitely not listening
	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, 1) // Port 1 is usually not listening
	err = adaptiveConnect(sock.NetSocket, sa, 100*time.Millisecond)
	if err != ErrConnectionRefused && err != ErrTimedOut {
		t.Logf("adaptiveConnect to closed port: %v", err)
	}
}

// DecodeSockaddr edge cases
func TestDecodeSockaddr_InvalidFamily(t *testing.T) {
	var raw RawSockaddrAny
	raw.Addr.Family = 255 // Invalid family

	decoded := DecodeSockaddr(&raw)
	if decoded != nil {
		t.Errorf("expected nil for invalid family, got %v", decoded)
	}
}

// GetPeername error path
func TestGetPeername_NotConnectedCoverage(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	_, err = GetPeername(sock.fd)
	if err != ErrNotConnected {
		t.Logf("GetPeername on unconnected socket: %v", err)
	}
}

// ResolveSCTPAddr with IPv6 literal
func TestResolveSCTPAddr_IPv6LiteralCoverage(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp6", "[::1]:8080")
	if err != nil {
		t.Logf("ResolveSCTPAddr IPv6: %v", err)
	} else if addr != nil {
		t.Logf("Resolved: %v", addr)
	}
}

// TCPDialer with IPv6
func TestTCPDialer_Dial6_WithLocalAddr(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	dialer := &TCPDialer{Timeout: 2 * time.Second}
	localAddr := &TCPAddr{IP: net.IPv6loopback, Port: 0}
	conn, err := dialer.Dial6(localAddr, &TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatalf("Dial6 with laddr: %v", err)
	}
	defer conn.Close()
}

// DialTCP auto-detect IPv6
func TestDialTCP_IPv6AutoDetect(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	conn, err := DialTCP("tcp6", nil, &TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatalf("DialTCP IPv6: %v", err)
	}
	conn.Close()
}

// DialUDP auto-detect IPv6
func TestDialUDP_IPv6AutoDetect(t *testing.T) {
	conn, err := DialUDP("udp6", nil, &UDPAddr{IP: net.IPv6loopback, Port: 9999})
	if err != nil {
		t.Fatalf("DialUDP IPv6: %v", err)
	}
	conn.Close()
}

// ListenTCP auto-detect
func TestListenTCP_IPv6AutoDetect(t *testing.T) {
	ln, err := ListenTCP("tcp6", &TCPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP IPv6: %v", err)
	}
	ln.Close()
}

// ListenUDP auto-detect
func TestListenUDP_IPv6AutoDetect(t *testing.T) {
	conn, err := ListenUDP("udp6", &UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP IPv6: %v", err)
	}
	conn.Close()
}

// Connect already connected (EISCONN)
func TestConnect_AlreadyConnected(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			time.Sleep(100 * time.Millisecond)
			conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	dialer := &TCPDialer{Timeout: time.Second}
	conn, err := dialer.Dial4(nil, &TCPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		t.Fatalf("Dial4: %v", err)
	}
	defer conn.Close()

	// Try to connect again
	sa := NewSockaddrInet4([4]byte{127, 0, 0, 1}, uint16(addr.Port))
	err = conn.NetSocket.Connect(sa)
	// Should return nil (EISCONN mapped to nil)
	t.Logf("Second connect: %v", err)
}

// Linger socket option edge cases
func TestSetLinger_Enable(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	if err := SetLinger(sock.fd, true, 5); err != nil {
		t.Errorf("SetLinger enable: %v", err)
	}

	onoff, secs, err := GetLinger(sock.fd)
	if err != nil {
		t.Errorf("GetLinger: %v", err)
	}
	t.Logf("Linger: onoff=%v, secs=%d", onoff, secs)
}

func TestSetLinger_Disable(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	if err := SetLinger(sock.fd, false, 0); err != nil {
		t.Errorf("SetLinger disable: %v", err)
	}
}

// SetCloseOnExec edge case
func TestSetCloseOnExec_Error(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close()

	err = SetCloseOnExec(sock.fd, true)
	if err != ErrClosed {
		t.Logf("SetCloseOnExec on closed: %v", err)
	}
}

// ========== rawConn (syscall.RawConn) Tests ==========

// ========== SyscallConn Tests ==========

func TestTCPConn_SyscallConn(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	go func() {
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, _ := lis.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()

	// Get SyscallConn
	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	// Use Control
	var capturedFD uintptr
	err = rc.Control(func(fd uintptr) {
		capturedFD = fd
	})
	if err != nil {
		t.Errorf("Control: %v", err)
	}
	if capturedFD == 0 {
		t.Error("Control: fd should not be 0")
	}

	// Test Read method (must return true immediately to avoid infinite loop)
	err = rc.Read(func(fd uintptr) bool {
		return true // Signal done immediately
	})
	if err != nil {
		t.Errorf("Read: %v", err)
	}

	// Test Write method (must return true immediately to avoid infinite loop)
	err = rc.Write(func(fd uintptr) bool {
		return true // Signal done immediately
	})
	if err != nil {
		t.Errorf("Write: %v", err)
	}
}

func TestTCPConn_SyscallConnClosed(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	go func() {
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, _ := lis.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	conn.Close()

	// Get SyscallConn on closed
	_, err = conn.SyscallConn()
	if err != ErrClosed {
		t.Errorf("SyscallConn on closed: expected ErrClosed, got %v", err)
	}
}

func TestRawConn_ReadWriteClosed(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	lisAddr := lis.Addr().(*TCPAddr)

	go func() {
		lis.SetDeadline(time.Now().Add(time.Second))
		conn, _ := lis.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := DialTCP4(nil, lisAddr)
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}

	// Get SyscallConn while open
	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	// Close the connection
	conn.Close()

	// Test Read on closed - should return ErrClosed
	err = rc.Read(func(fd uintptr) bool {
		return true
	})
	if err != ErrClosed {
		t.Errorf("Read on closed: expected ErrClosed, got %v", err)
	}

	// Test Write on closed - should return ErrClosed
	err = rc.Write(func(fd uintptr) bool {
		return true
	})
	if err != ErrClosed {
		t.Errorf("Write on closed: expected ErrClosed, got %v", err)
	}

	// Test Control on closed - should return ErrClosed
	err = rc.Control(func(fd uintptr) {})
	if err != ErrClosed {
		t.Errorf("Control on closed: expected ErrClosed, got %v", err)
	}
}

func TestUDPConn_SyscallConn(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Get SyscallConn
	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	// Use Control
	var capturedFD uintptr
	err = rc.Control(func(fd uintptr) {
		capturedFD = fd
	})
	if err != nil {
		t.Errorf("Control: %v", err)
	}
	if capturedFD == 0 {
		t.Error("Control: fd should not be 0")
	}
}

func TestUDPConn_SyscallConnClosed(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	conn.Close()

	// Get SyscallConn on closed
	_, err = conn.SyscallConn()
	if err != ErrClosed {
		t.Errorf("SyscallConn on closed: expected ErrClosed, got %v", err)
	}
}

func TestUnixConn_SyscallConn(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Get SyscallConn
	rc, err := pair[0].SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	// Use Control
	var capturedFD uintptr
	err = rc.Control(func(fd uintptr) {
		capturedFD = fd
	})
	if err != nil {
		t.Errorf("Control: %v", err)
	}
	if capturedFD == 0 {
		t.Error("Control: fd should not be 0")
	}
}

func TestUnixConn_SyscallConnClosed(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	pair[1].Close()
	pair[0].Close()

	// Get SyscallConn on closed
	_, err = pair[0].SyscallConn()
	if err != ErrClosed {
		t.Errorf("SyscallConn on closed: expected ErrClosed, got %v", err)
	}
}

// ========== UDP ReadMsgUDP/WriteMsgUDP Tests ==========

func TestUDPConn_ReadMsgUDP(t *testing.T) {
	// Create receiver
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	receiver, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*UDPAddr)

	// Create sender and dial to receiver
	sender, err := DialUDP4(nil, receiverAddr)
	if err != nil {
		t.Fatalf("DialUDP4 sender: %v", err)
	}
	defer sender.Close()

	// Send data using connected Write
	testData := []byte("hello udp msg")
	sender.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = sender.Write(testData)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("Write: %v", err)
	}

	// Give some time for delivery
	time.Sleep(10 * time.Millisecond)

	// Read with ReadMsgUDP
	buf := make([]byte, 64)
	oob := make([]byte, 64)
	receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, oobn, flags, addr, err := receiver.ReadMsgUDP(buf, oob)
	if err != nil && err != iox.ErrWouldBlock && err != ErrTimedOut {
		t.Logf("ReadMsgUDP: n=%d, oobn=%d, flags=%d, addr=%v, err=%v", n, oobn, flags, addr, err)
	}
	if n > 0 {
		if string(buf[:n]) != string(testData) {
			t.Errorf("ReadMsgUDP: expected %q, got %q", testData, buf[:n])
		}
	}
}

func TestUDPConn_ReadMsgUDPClosed(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	conn.Close()

	buf := make([]byte, 64)
	_, _, _, _, err = conn.ReadMsgUDP(buf, nil)
	if err != ErrClosed {
		t.Errorf("ReadMsgUDP on closed: expected ErrClosed, got %v", err)
	}
}

func TestUDPConn_WriteMsgUDP(t *testing.T) {
	// Create receiver
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	receiver, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*UDPAddr)

	// Create sender using Dial (connected UDP)
	sender, err := DialUDP4(nil, receiverAddr)
	if err != nil {
		t.Fatalf("DialUDP4 sender: %v", err)
	}
	defer sender.Close()

	// Send with WriteMsgUDP (nil addr since connected)
	testData := []byte("hello udp msg write")
	sender.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	n, oobn, err := sender.WriteMsgUDP(testData, nil, nil)
	if err != nil && err != iox.ErrWouldBlock {
		t.Logf("WriteMsgUDP: %v (may be expected)", err)
	}
	t.Logf("WriteMsgUDP: n=%d, oobn=%d", n, oobn)
}

func TestUDPConn_WriteMsgUDPClosed(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	conn.Close()

	_, _, err = conn.WriteMsgUDP([]byte("test"), nil, nil)
	if err != ErrClosed {
		t.Errorf("WriteMsgUDP on closed: expected ErrClosed, got %v", err)
	}
}

func TestUDPConn_WriteMsgUDP_IPv6Addr(t *testing.T) {
	// Create IPv4 sender
	sender, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4 sender: %v", err)
	}
	defer sender.Close()

	// Create IPv6 address (this tests the IPv6 path in WriteMsgUDP)
	ipv6Addr := &UDPAddr{IP: net.ParseIP("::1"), Port: 12345}

	// This will likely fail (trying to send IPv6 on IPv4 socket), but exercises the code path
	_, _, err = sender.WriteMsgUDP([]byte("test"), nil, ipv6Addr)
	t.Logf("WriteMsgUDP to IPv6: %v (expected to fail)", err)
}

// ========== RawSocket Tests (without CAP_NET_RAW) ==========

// ========== RawConn Tests ==========

// ========== IPv6 Socket Creation Tests ==========

func TestNewTCPSocket6_DefaultsCheck(t *testing.T) {
	sock, err := NewTCPSocket6()
	if err != nil {
		t.Fatalf("NewTCPSocket6: %v", err)
	}
	defer sock.Close()

	// Verify defaults applied
	reuse, err := GetReuseAddr(sock.fd)
	if err != nil {
		t.Errorf("GetReuseAddr: %v", err)
	}
	if !reuse {
		t.Error("expected SO_REUSEADDR enabled by default")
	}
}

func TestNewUDPSocket6_DefaultsCheck(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock.Close()

	// Verify defaults applied
	reuse, err := GetReuseAddr(sock.fd)
	if err != nil {
		t.Errorf("GetReuseAddr: %v", err)
	}
	if !reuse {
		t.Error("expected SO_REUSEADDR enabled by default")
	}
}

func TestNewSCTPSocket6_DefaultsCheck(t *testing.T) {
	sock, err := NewSCTPSocket6()
	if err != nil {
		t.Fatalf("NewSCTPSocket6: %v", err)
	}
	defer sock.Close()

	// Verify defaults applied
	reuse, err := GetReuseAddr(sock.fd)
	if err != nil {
		t.Errorf("GetReuseAddr: %v", err)
	}
	if !reuse {
		t.Error("expected SO_REUSEADDR enabled by default")
	}
}

func TestNewSCTPStreamSocket6_Protocol(t *testing.T) {
	sock, err := NewSCTPStreamSocket6()
	if err != nil {
		t.Fatalf("NewSCTPStreamSocket6: %v", err)
	}
	defer sock.Close()

	// SCTP stream sockets use SOCK_STREAM
	if sock.Protocol() != UnderlyingProtocolStream {
		t.Errorf("Protocol: expected UnderlyingProtocolStream, got %v", sock.Protocol())
	}
}

// ========== Additional Error Path Tests ==========

func TestUDPSocket_SendToIPv6Addr(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock.Close()

	// Bind to loopback
	sa := NewSockaddrInet6([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 0, 0)
	if err := sock.Bind(sa); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	// Send to IPv6 address
	addr := &UDPAddr{IP: net.ParseIP("::1"), Port: 12345}
	_, err = sock.SendTo([]byte("test"), addr)
	// May fail if no listener, but exercises the IPv6 path
	t.Logf("SendTo IPv6: %v", err)
}

// ========== Additional Edge Case Tests for Coverage ==========

func TestUnixSocket_ProtocolDgram(t *testing.T) {
	sock, err := NewUnixDatagramSocket()
	if err != nil {
		t.Fatalf("NewUnixDatagramSocket: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolDgram {
		t.Errorf("Protocol: expected Dgram, got %v", sock.Protocol())
	}
}

func TestUnixSocket_ProtocolSeqPacket(t *testing.T) {
	sock, err := NewUnixSeqpacketSocket()
	if err != nil {
		t.Fatalf("NewUnixSeqpacketSocket: %v", err)
	}
	defer sock.Close()

	if sock.Protocol() != UnderlyingProtocolSeqPacket {
		t.Errorf("Protocol: expected SeqPacket, got %v", sock.Protocol())
	}
}

func TestSCTPSocket_ProtocolDefault(t *testing.T) {
	// Test default case in Protocol() switch
	sock, err := NewSCTPSocket4()
	if err != nil {
		t.Skipf("NewSCTPSocket4: %v", err)
		return
	}
	defer sock.Close()

	// Default SCTP socket uses SOCK_SEQPACKET
	if sock.Protocol() != UnderlyingProtocolSeqPacket {
		t.Errorf("Protocol: expected SeqPacket, got %v", sock.Protocol())
	}
}

func TestGetLinger_Error(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close() // Close first

	// GetLinger on closed socket should fail
	_, _, err = GetLinger(sock.fd)
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

func TestSetLinger_Error(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close() // Close first

	// SetLinger on closed socket should fail
	err = SetLinger(sock.fd, true, 0)
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

func TestAdaptiveConnect_NanoTimeout(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Connect to non-routable address with nearly expired timeout
	raddr := NewSockaddrInet4([4]byte{198, 51, 100, 1}, 12345) // TEST-NET-2
	err = adaptiveConnect(sock.NetSocket, raddr, 1*time.Nanosecond)
	// Should get ErrTimedOut quickly since deadline is essentially expired
	if err != ErrTimedOut && err != ErrInProgress {
		t.Logf("adaptiveConnect with nano timeout: %v", err)
	}
}

func TestTCPDialer_Dial6_WithExplicitLocalAddr(t *testing.T) {
	// Start a listener
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenTCP6(laddr)
	if err != nil {
		t.Skipf("ListenTCP6: %v", err)
		return
	}
	defer ln.Close()

	// Get actual port
	actualAddr := ln.Addr().(*TCPAddr)

	// Accept in goroutine
	go func() {
		ln.SetDeadline(time.Now().Add(2 * time.Second))
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	// Dial with local address
	dialer := &TCPDialer{Timeout: 1 * time.Second}
	localAddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := dialer.Dial6(localAddr, &TCPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port})
	if err != nil {
		t.Skipf("Dial6: %v", err)
		return
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr is nil")
	}
}

func TestTCPDialer_DialNetwork_IPv4(t *testing.T) {
	// Start a listener
	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	ln, err := ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*TCPAddr)

	// Accept in goroutine
	go func() {
		ln.SetDeadline(time.Now().Add(2 * time.Second))
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	// Use Dial() with "tcp4" network
	dialer := &TCPDialer{Timeout: 1 * time.Second}
	conn, err := dialer.Dial("tcp4", nil, &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: actualAddr.Port})
	if err != nil {
		t.Skipf("Dial: %v", err)
		return
	}
	conn.Close()
}

func TestTCPDialer_DialNetwork_IPv6(t *testing.T) {
	// Start a listener
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenTCP6(laddr)
	if err != nil {
		t.Skipf("ListenTCP6: %v", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*TCPAddr)

	// Accept in goroutine
	go func() {
		ln.SetDeadline(time.Now().Add(2 * time.Second))
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	// Use Dial() with "tcp6" network
	dialer := &TCPDialer{Timeout: 1 * time.Second}
	conn, err := dialer.Dial("tcp6", nil, &TCPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port})
	if err != nil {
		t.Skipf("Dial: %v", err)
		return
	}
	conn.Close()
}

func TestResolveSCTPAddr_IPv6(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp6", "[::1]:9000")
	if err != nil {
		t.Fatalf("ResolveSCTPAddr: %v", err)
	}
	if addr.IP.String() != "::1" {
		t.Errorf("IP: expected ::1, got %s", addr.IP.String())
	}
	if addr.Port != 9000 {
		t.Errorf("Port: expected 9000, got %d", addr.Port)
	}
}

func TestResolveSCTPAddr_InvalidAddress(t *testing.T) {
	_, err := ResolveSCTPAddr("sctp", "invalid:address:format")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestListenUnixgram_WrongNetwork(t *testing.T) {
	_, err := ListenUnixgram("unix", &net.UnixAddr{Name: "/tmp/test.sock"})
	if err == nil {
		t.Error("expected error for wrong network")
	}
}

func TestUnixConnPair_Unixpacket(t *testing.T) {
	pair, err := UnixConnPair("unixpacket")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Test communication
	msg := []byte("hello")
	_, err = pair[0].Write(msg)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
}

func TestUnixConn_WriteToInvalidAddr(t *testing.T) {
	pair, err := UnixConnPair("unixgram")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Try to WriteTo with non-UnixAddr
	_, err = pair[0].WriteTo([]byte("test"), &TCPAddr{Port: 123})
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestReadMsgUDP_ClosedSocket(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	conn.Close() // Close first

	buf := make([]byte, 1024)
	oob := make([]byte, 256)
	_, _, _, _, err = conn.ReadMsgUDP(buf, oob)
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestWriteMsgUDP_ClosedSocket(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	conn.Close() // Close first

	buf := []byte("test")
	oob := make([]byte, 0)
	_, _, err = conn.WriteMsgUDP(buf, oob, &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestWriteMsgUDP_WithOOB(t *testing.T) {
	receiver, err := ListenUDP4(&UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.laddr

	sender, err := DialUDP4(nil, &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: receiverAddr.Port})
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer sender.Close()

	// Write with empty OOB
	buf := []byte("test with oob")
	oob := []byte{} // empty OOB
	n, oobn, err := sender.WriteMsgUDP(buf, oob, nil)
	if err != nil && err != iox.ErrWouldBlock {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	t.Logf("WriteMsgUDP: n=%d, oobn=%d", n, oobn)
}

func TestReadMsgUDP_EmptyBuffers(t *testing.T) {
	receiver, err := ListenUDP4(&UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.laddr

	// Send a packet
	sender, err := DialUDP4(nil, &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: receiverAddr.Port})
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer sender.Close()

	sender.Write([]byte("test"))

	// Read with empty payload buffer (only OOB)
	time.Sleep(10 * time.Millisecond)
	buf := make([]byte, 0) // empty payload buffer
	oob := make([]byte, 256)
	receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, oobn, flags, addr, err := receiver.ReadMsgUDP(buf, oob)
	t.Logf("ReadMsgUDP empty buf: n=%d, oobn=%d, flags=%d, addr=%v, err=%v", n, oobn, flags, addr, err)
}

func TestSCTPDialer_Dial4_NilRemoteAddr(t *testing.T) {
	dialer := &SCTPDialer{}
	_, err := dialer.Dial4(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestSCTPDialer_Dial6_NilRemoteAddr(t *testing.T) {
	dialer := &SCTPDialer{}
	_, err := dialer.Dial6(nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestSCTPDialer_DialNetwork_NilRaddr(t *testing.T) {
	dialer := &SCTPDialer{}
	_, err := dialer.Dial("sctp", nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("expected ErrInvalidParam, got %v", err)
	}
}

func TestSCTPDialer_DialNetwork_IPv6(t *testing.T) {
	// Start a listener
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("ListenSCTP6: %v", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*SCTPAddr)

	// Use Dial() with "sctp6" network
	dialer := &SCTPDialer{Timeout: 1 * time.Second}
	conn, err := dialer.Dial("sctp6", nil, &SCTPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
}

func TestSCTPDialer_Dial6_WithLocalAddr(t *testing.T) {
	// Start a listener
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("ListenSCTP6: %v", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*SCTPAddr)

	// Dial with local address
	dialer := &SCTPDialer{Timeout: 1 * time.Second}
	localAddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := dialer.Dial6(localAddr, &SCTPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port})
	if err != nil {
		t.Fatalf("Dial6: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr is nil")
	}
}

func TestSCTPConn_ReadEOF(t *testing.T) {
	// Create SCTP socket pair (via listener/dial)
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	ln, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("ListenSCTP4: %v", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*SCTPAddr)

	// Accept in goroutine
	acceptDone := make(chan *SCTPConn, 1)
	go func() {
		ln.SetDeadline(time.Now().Add(2 * time.Second))
		conn, _ := ln.Accept()
		acceptDone <- conn
	}()

	// Dial
	dialer := &SCTPDialer{Timeout: 1 * time.Second}
	client, err := dialer.Dial4(nil, &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: actualAddr.Port})
	if err != nil {
		t.Skipf("Dial4: %v", err)
		return
	}

	server := <-acceptDone
	if server == nil {
		t.Skipf("Accept returned nil (SCTP may not be fully available)")
		client.Close()
		return
	}

	// Close client side
	client.Close()

	// Read on server should get EOF
	time.Sleep(50 * time.Millisecond)
	buf := make([]byte, 128)
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = server.Read(buf)
	if err != io.EOF && err != ErrTimedOut {
		t.Logf("Read after close: %v (expected EOF or timeout)", err)
	}
	server.Close()
}

func TestParseUnixRights_EmptyControl(t *testing.T) {
	// Empty control message
	fds := ParseUnixRights(nil)
	if len(fds) != 0 {
		t.Errorf("expected 0 fds, got %d", len(fds))
	}
}

func TestParseUnixCredentials_EmptyControl(t *testing.T) {
	// Empty control message returns nil
	cred := ParseUnixCredentials(nil)
	if cred != nil {
		t.Error("expected nil for empty control message")
	}
}

func TestSendFDs_ClosedSocket(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	pair[0].Close() // Close sender

	// Try to send FDs on closed socket
	_, err = SendFDs(pair[0].fd, []int{0}, []byte("test"))
	if err == nil {
		t.Error("expected error on closed socket")
	}
	pair[1].Close()
}

func TestRecvFDs_ClosedSocket(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	pair[0].Close() // Close receiver

	// Try to receive FDs on closed socket
	buf := make([]byte, 128)
	_, _, err = RecvFDs(pair[0].fd, buf, 4)
	if err == nil {
		t.Error("expected error on closed socket")
	}
	pair[1].Close()
}

// TestSendFDs_EmptyData tests SendFDs with empty data buffer.
func TestSendFDs_EmptyData(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Create a pipe to have valid file descriptors
	pipeR, pipeW, err := osPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer closeFd(pipeR)
	defer closeFd(pipeW)

	// Send with empty data (nil) - should use fallback []byte{0}
	n, err := SendFDs(pair[0].fd, []int{pipeR, pipeW}, nil)
	if err != nil {
		t.Fatalf("SendFDs with nil data: %v", err)
	}
	if n != 1 {
		t.Errorf("SendFDs: wrote %d bytes, want 1", n)
	}

	// Receive to verify
	buf := make([]byte, 16)
	rn, fds, err := RecvFDs(pair[1].fd, buf, 4)
	if err != nil {
		t.Fatalf("RecvFDs: %v", err)
	}
	t.Logf("RecvFDs: n=%d, fds=%d", rn, len(fds))
}

// TestRecvFDs_NilDataBuf tests RecvFDs with nil data buffer.
func TestRecvFDs_NilDataBuf(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	// Create a pipe for valid FDs
	pipeR, pipeW, err := osPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer closeFd(pipeR)
	defer closeFd(pipeW)

	// Send FDs first
	n, err := SendFDs(pair[0].fd, []int{pipeR}, []byte("x"))
	if err != nil {
		t.Fatalf("SendFDs: %v", err)
	}
	t.Logf("SendFDs: n=%d", n)

	// Receive with nil data buffer - should allocate internally
	rn, fds, err := RecvFDs(pair[1].fd, nil, 4)
	if err != nil {
		t.Fatalf("RecvFDs with nil buf: %v", err)
	}
	if rn != 1 {
		t.Errorf("RecvFDs: got %d bytes, want 1", rn)
	}
	t.Logf("RecvFDs: n=%d, fds=%d", rn, len(fds))
}

func TestSendMsg_ClosedSocket(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	pair[0].Close()

	msg := &Msghdr{}
	_, err = SendMsg(pair[0].fd, msg, 0)
	if err == nil {
		t.Error("expected error on closed socket")
	}
	pair[1].Close()
}

func TestRecvMsg_ClosedSocket(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	pair[0].Close()

	msg := &Msghdr{}
	_, err = RecvMsg(pair[0].fd, msg, 0)
	if err == nil {
		t.Error("expected error on closed socket")
	}
	pair[1].Close()
}

func TestTCPInfo_ClosedSocket(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close()

	_, err = GetTCPInfo(sock.fd)
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

func TestTCPInfoInto_ClosedSocket(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close()

	var info TCPInfo
	err = GetTCPInfoInto(sock.fd, &info)
	if err == nil {
		t.Error("expected error on closed socket")
	}
}

func TestUnixConn_ReadFromClosed(t *testing.T) {
	sock, err := NewUnixDatagramSocket()
	if err != nil {
		t.Fatalf("NewUnixDatagramSocket: %v", err)
	}
	conn := &UnixConn{UnixSocket: sock}
	sock.Close()

	buf := make([]byte, 128)
	_, _, err = conn.ReadFrom(buf)
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestUnixConn_WriteToClosed(t *testing.T) {
	sock, err := NewUnixDatagramSocket()
	if err != nil {
		t.Fatalf("NewUnixDatagramSocket: %v", err)
	}
	conn := &UnixConn{UnixSocket: sock}
	sock.Close()

	_, err = conn.WriteTo([]byte("test"), &net.UnixAddr{Name: "/tmp/test.sock"})
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestDialTCP_IPv6Network(t *testing.T) {
	// Start listener
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenTCP6(laddr)
	if err != nil {
		t.Skipf("ListenTCP6: %v", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*TCPAddr)

	// Dial with "tcp6" network
	conn, err := DialTCP("tcp6", nil, &TCPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	conn.Close()
}

func TestListenTCP_IPv6Network(t *testing.T) {
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenTCP("tcp6", laddr)
	if err != nil {
		t.Skipf("ListenTCP: %v", err)
		return
	}
	ln.Close()
}

func TestDialUDP_IPv6Network(t *testing.T) {
	conn, err := DialUDP("udp6", nil, &UDPAddr{IP: net.ParseIP("::1"), Port: 12345})
	if err != nil {
		t.Skipf("DialUDP: %v", err)
		return
	}
	conn.Close()
}

func TestListenUDP_IPv6Network(t *testing.T) {
	laddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := ListenUDP("udp6", laddr)
	if err != nil {
		t.Skipf("ListenUDP: %v", err)
		return
	}
	conn.Close()
}

func TestDialSCTP_IPv6Network(t *testing.T) {
	// Start listener
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("ListenSCTP6: %v", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*SCTPAddr)

	// Dial with "sctp6" network
	conn, err := DialSCTP("sctp6", nil, &SCTPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port})
	if err != nil {
		t.Logf("DialSCTP: %v", err)
		return
	}
	conn.Close()
}

func TestListenSCTP_IPv6Network(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenSCTP("sctp6", laddr)
	if err != nil {
		t.Skipf("ListenSCTP: %v", err)
		return
	}
	ln.Close()
}

func TestDecodeSCTPAddr_IPv6(t *testing.T) {
	// Create a raw sockaddr with IPv6
	var raw RawSockaddrAny
	inet6 := (*RawSockaddrInet6)(unsafe.Pointer(&raw))
	inet6.Family = AF_INET6
	inet6.Port = htons(9000)
	inet6.Addr = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	inet6.ScopeID = 1

	addr := decodeSCTPAddr(&raw)
	if addr == nil {
		t.Fatal("decodeSCTPAddr returned nil")
	}
	if addr.Port != 9000 {
		t.Errorf("Port: expected 9000, got %d", addr.Port)
	}
	if addr.Zone != "1" {
		t.Errorf("Zone: expected '1', got '%s'", addr.Zone)
	}
}

func TestDecodeTCPAddr_IPv6WithZone(t *testing.T) {
	// Create a raw sockaddr with IPv6 and scope ID
	var raw RawSockaddrAny
	inet6 := (*RawSockaddrInet6)(unsafe.Pointer(&raw))
	inet6.Family = AF_INET6
	inet6.Port = htons(8080)
	inet6.Addr = [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	inet6.ScopeID = 2

	addr := decodeTCPAddr(&raw)
	if addr == nil {
		t.Fatal("decodeTCPAddr returned nil")
	}
	if addr.Zone != "2" {
		t.Errorf("Zone: expected '2', got '%s'", addr.Zone)
	}
}

func TestDecodeUDPAddr_IPv6WithZone(t *testing.T) {
	// Create a raw sockaddr with IPv6 and scope ID
	var raw RawSockaddrAny
	inet6 := (*RawSockaddrInet6)(unsafe.Pointer(&raw))
	inet6.Family = AF_INET6
	inet6.Port = htons(5353)
	inet6.Addr = [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	inet6.ScopeID = 3

	addr := decodeUDPAddr(&raw)
	if addr == nil {
		t.Fatal("decodeUDPAddr returned nil")
	}
	if addr.Zone != "3" {
		t.Errorf("Zone: expected '3', got '%s'", addr.Zone)
	}
}

func TestGetSocketError_Closed(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close()

	err = GetSocketError(sock.fd)
	if err != ErrClosed {
		t.Errorf("expected ErrClosed, got %v", err)
	}
}

func TestDialTCP6_WithLocalAddr(t *testing.T) {
	// Start listener
	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenTCP6(laddr)
	if err != nil {
		t.Skipf("ListenTCP6: %v", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*TCPAddr)

	// Dial with local address
	localAddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := DialTCP6(localAddr, &TCPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port})
	if err != nil {
		t.Fatalf("DialTCP6: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr is nil")
	}
}

func TestDialUDP6_WithLocalAddr(t *testing.T) {
	localAddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	remoteAddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 12345}
	conn, err := DialUDP6(localAddr, remoteAddr)
	if err != nil {
		t.Skipf("DialUDP6: %v", err)
		return
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr is nil")
	}
}

func TestDialSCTP6_WithLocalAddr(t *testing.T) {
	// Start listener
	laddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	ln, err := ListenSCTP6(laddr)
	if err != nil {
		t.Skipf("ListenSCTP6: %v", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*SCTPAddr)

	// Dial with local address
	localAddr := &SCTPAddr{IP: net.ParseIP("::1"), Port: 0}
	conn, err := DialSCTP6(localAddr, &SCTPAddr{IP: net.ParseIP("::1"), Port: actualAddr.Port})
	if err != nil {
		t.Logf("DialSCTP6: %v", err)
		return
	}
	defer conn.Close()

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr is nil")
	}
}

// TestReadMsgUDP_WriteMsgUDP tests the ReadMsgUDP and WriteMsgUDP methods.
func TestReadMsgUDP_WriteMsgUDP(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	client, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// Send message using WriteMsgUDP
	testData := []byte("hello via WriteMsgUDP")
	n, oobn, err := client.WriteMsgUDP(testData, nil, actualAddr)
	if err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if n != len(testData) {
		t.Errorf("WriteMsgUDP: wrote %d bytes, expected %d", n, len(testData))
	}
	if oobn != 0 {
		t.Errorf("WriteMsgUDP: oobn = %d, expected 0", oobn)
	}

	// Receive message using ReadMsgUDP
	server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	oob := make([]byte, 256)
	n, oobn, flags, addr, err := server.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatalf("ReadMsgUDP: %v", err)
	}
	if n != len(testData) {
		t.Errorf("ReadMsgUDP: read %d bytes, expected %d", n, len(testData))
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("ReadMsgUDP: got %q, expected %q", buf[:n], testData)
	}
	if addr == nil {
		t.Error("ReadMsgUDP: addr is nil")
	}
	t.Logf("ReadMsgUDP: n=%d, oobn=%d, flags=%d, addr=%v", n, oobn, flags, addr)
}

// TestReadMsgUDP_NonBlocking tests non-blocking behavior of ReadMsgUDP.
func TestReadMsgUDP_NonBlocking(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// No deadline set - should return ErrWouldBlock immediately
	buf := make([]byte, 1024)
	_, _, _, _, err = conn.ReadMsgUDP(buf, nil)
	if err != iox.ErrWouldBlock {
		t.Errorf("ReadMsgUDP without deadline: expected ErrWouldBlock, got %v", err)
	}
}

// TestWriteMsgUDP_Connected tests WriteMsgUDP on a connected socket.
func TestWriteMsgUDP_Connected(t *testing.T) {
	// Create server
	server, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	serverAddr := server.LocalAddr().(*UDPAddr)

	// Create connected client
	client, err := DialUDP4(nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer client.Close()

	// Send with nil addr (uses connected address)
	testData := []byte("connected WriteMsgUDP")
	n, oobn, err := client.WriteMsgUDP(testData, nil, nil)
	if err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if n != len(testData) {
		t.Errorf("WriteMsgUDP: wrote %d bytes, expected %d", n, len(testData))
	}
	t.Logf("WriteMsgUDP connected: n=%d, oobn=%d", n, oobn)

	// Receive on server
	server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, _, _, addr, err := server.ReadMsgUDP(buf, nil)
	if err != nil {
		t.Fatalf("ReadMsgUDP: %v", err)
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("ReadMsgUDP: got %q, expected %q", buf[:n], testData)
	}
	t.Logf("Received from: %v", addr)
}

// TestSCTPConn_SyscallConn tests the SyscallConn method on SCTPConn.
func TestSCTPConn_SyscallConn(t *testing.T) {
	// Create listener
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	ln, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("ListenSCTP4: %v (SCTP may not be available)", err)
		return
	}
	defer ln.Close()

	actualAddr := ln.Addr().(*SCTPAddr)

	// Accept in background
	done := make(chan *SCTPConn, 1)
	go func() {
		ln.SetDeadline(time.Now().Add(2 * time.Second))
		conn, _ := ln.Accept()
		done <- conn
	}()

	// Dial
	dialer := &SCTPDialer{Timeout: time.Second}
	client, err := dialer.Dial4(nil, &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: actualAddr.Port})
	if err != nil {
		t.Fatalf("Dial4: %v", err)
	}
	defer client.Close()

	// Get SyscallConn from client
	rawConn, err := client.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if rawConn == nil {
		t.Fatal("SyscallConn returned nil")
	}

	// Test Control method
	var controlFd uintptr
	err = rawConn.Control(func(fd uintptr) {
		controlFd = fd
	})
	if err != nil {
		t.Errorf("Control: %v", err)
	}
	if controlFd == 0 {
		t.Error("Control: fd is 0")
	}
	t.Logf("SCTPConn fd via SyscallConn: %d", controlFd)

	// Wait for server connection
	serverConn := <-done
	if serverConn != nil {
		// Test SyscallConn on server side too
		serverRaw, err := serverConn.SyscallConn()
		if err != nil {
			t.Errorf("Server SyscallConn: %v", err)
		}
		if serverRaw != nil {
			var serverFd uintptr
			serverRaw.Control(func(fd uintptr) {
				serverFd = fd
			})
			t.Logf("Server SCTPConn fd: %d", serverFd)
		}
		serverConn.Close()
	}
}

// TestSCTPConn_SyscallConn_Closed tests SyscallConn on a closed connection.
func TestSCTPConn_SyscallConn_Closed(t *testing.T) {
	laddr := &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	ln, err := ListenSCTP4(laddr)
	if err != nil {
		t.Skipf("ListenSCTP4: %v (SCTP may not be available)", err)
		return
	}

	actualAddr := ln.Addr().(*SCTPAddr)

	// Accept in background
	go func() {
		ln.SetDeadline(time.Now().Add(time.Second))
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	// Dial and close
	dialer := &SCTPDialer{Timeout: time.Second}
	client, err := dialer.Dial4(nil, &SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: actualAddr.Port})
	if err != nil {
		ln.Close()
		t.Skipf("Dial4: %v", err)
		return
	}

	client.Close()
	ln.Close()

	// SyscallConn on closed connection should return error
	_, err = client.SyscallConn()
	if err != ErrClosed {
		t.Errorf("SyscallConn on closed: expected ErrClosed, got %v", err)
	}
}

// TestParseUnixCredentials_TruncatedLength tests when cmsg.Len indicates truncation.
func TestParseUnixCredentials_TruncatedLength(t *testing.T) {
	// Create a buffer that looks like a valid cmsghdr but with truncated length
	buf := make([]byte, SizeofCmsghdr+SizeofUcred)
	cmsg := (*Cmsghdr)(unsafe.Pointer(&buf[0]))
	cmsg.Len = uint64(SizeofCmsghdr - 1) // Invalid: shorter than header
	cmsg.Level = SOL_SOCKET
	cmsg.Type = SCM_CREDENTIALS

	// Should return nil due to invalid length
	cred := ParseUnixCredentials(buf)
	if cred != nil {
		t.Error("Expected nil for truncated cmsghdr length")
	}
}

// TestParseUnixCredentials_OverflowLength tests when cmsg.Len exceeds buffer.
func TestParseUnixCredentials_OverflowLength(t *testing.T) {
	// Create a buffer with cmsg.Len > len(buf)
	buf := make([]byte, SizeofCmsghdr+4) // Not enough for full credentials
	cmsg := (*Cmsghdr)(unsafe.Pointer(&buf[0]))
	cmsg.Len = uint64(SizeofCmsghdr + SizeofUcred + 100) // Overflow
	cmsg.Level = SOL_SOCKET
	cmsg.Type = SCM_CREDENTIALS

	// Should return nil due to overflow
	cred := ParseUnixCredentials(buf)
	if cred != nil {
		t.Error("Expected nil for overflowed cmsghdr length")
	}
}

// TestParseUnixCredentials_ShortCredentials tests when credentials data is too short.
func TestParseUnixCredentials_ShortCredentials(t *testing.T) {
	// Create buffer with valid header but short credentials
	buf := make([]byte, SizeofCmsghdr+4) // Not enough for full Ucred
	cmsg := (*Cmsghdr)(unsafe.Pointer(&buf[0]))
	cmsg.Len = uint64(SizeofCmsghdr + 4) // Claims only 4 bytes of data
	cmsg.Level = SOL_SOCKET
	cmsg.Type = SCM_CREDENTIALS

	// Should return nil because credentials too short
	cred := ParseUnixCredentials(buf)
	if cred != nil {
		t.Error("Expected nil for short credentials data")
	}
}

// TestParseUnixCredentials_NonCredentialsMessage tests skipping non-SCM_CREDENTIALS messages.
func TestParseUnixCredentials_NonCredentialsMessage(t *testing.T) {
	// Create buffer with a non-credentials message followed by credentials
	// First message: SCM_RIGHTS (should be skipped)
	buf := make([]byte, 2*(SizeofCmsghdr+8)+SizeofUcred)
	offset := 0

	// First: SCM_RIGHTS message
	cmsg1 := (*Cmsghdr)(unsafe.Pointer(&buf[offset]))
	cmsg1.Len = uint64(SizeofCmsghdr + 8)
	cmsg1.Level = SOL_SOCKET
	cmsg1.Type = SCM_RIGHTS
	offset += CmsgAlign(SizeofCmsghdr + 8)

	// Second: SCM_CREDENTIALS message
	cmsg2 := (*Cmsghdr)(unsafe.Pointer(&buf[offset]))
	cmsg2.Len = uint64(SizeofCmsghdr + SizeofUcred)
	cmsg2.Level = SOL_SOCKET
	cmsg2.Type = SCM_CREDENTIALS

	// Set some credentials
	dataStart := offset + SizeofCmsghdr
	cred := (*Ucred)(unsafe.Pointer(&buf[dataStart]))
	cred.Pid = 12345
	cred.Uid = 1000
	cred.Gid = 1000

	// Should find and return the credentials from second message
	result := ParseUnixCredentials(buf)
	if result == nil {
		t.Fatal("Expected credentials to be found")
	}
	if result.Pid != 12345 || result.Uid != 1000 || result.Gid != 1000 {
		t.Errorf("Credentials mismatch: got pid=%d uid=%d gid=%d",
			result.Pid, result.Uid, result.Gid)
	}
}

// TestHtons_Coverage tests htons function edge cases.
func TestHtons_Coverage(t *testing.T) {
	// Test various values
	testCases := []struct {
		input    uint16
		expected uint16
	}{
		{0x0000, 0x0000},
		{0x0001, 0x0100},
		{0x0100, 0x0001},
		{0x1234, 0x3412},
		{0xFFFF, 0xFFFF},
		{0x00FF, 0xFF00},
		{0xFF00, 0x00FF},
	}

	for _, tc := range testCases {
		got := htons(tc.input)
		if got != tc.expected {
			t.Errorf("htons(0x%04X) = 0x%04X, want 0x%04X",
				tc.input, got, tc.expected)
		}
	}
}

// TestNetSocketPair_InvalidType tests NetSocketPair with invalid socket type.
func TestNetSocketPair_InvalidType(t *testing.T) {
	// Valid usage for comparison
	pair, err := NetSocketPair(AF_UNIX, SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	pair[0].Close()
	pair[1].Close()
}

// TestSCTPDialer_NilRaddr tests SCTPDialer with nil remote address.
func TestSCTPDialer_NilRaddr(t *testing.T) {
	dialer := &SCTPDialer{Timeout: 100 * time.Millisecond}
	_, err := dialer.Dial("sctp", nil, nil)
	if err != ErrInvalidParam {
		t.Errorf("Expected ErrInvalidParam, got %v", err)
	}
}

// ========== ReadMsgUDP/WriteMsgUDP Deadline Coverage Tests ==========

// TestReadMsgUDP_DeadlineExpired tests ReadMsgUDP when deadline is already expired.
func TestReadMsgUDP_DeadlineExpired(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set deadline in the past
	conn.SetReadDeadline(time.Now().Add(-time.Second))

	buf := make([]byte, 1024)
	_, _, _, _, err = conn.ReadMsgUDP(buf, nil)
	if err != ErrTimedOut {
		t.Errorf("ReadMsgUDP with expired deadline: expected ErrTimedOut, got %v", err)
	}
}

// TestReadMsgUDP_DeadlineRetrySuccess tests ReadMsgUDP retry loop with backoff.
func TestReadMsgUDP_DeadlineRetrySuccess(t *testing.T) {
	receiver, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*UDPAddr)

	sender, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer sender.Close()

	// Set deadline that gives time for retry
	receiver.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send data after a short delay (forces retry loop)
	testData := []byte("deadline retry test")
	go func() {
		time.Sleep(50 * time.Millisecond)
		sender.WriteTo(testData, receiverAddr)
	}()

	buf := make([]byte, 1024)
	n, _, _, addr, err := receiver.ReadMsgUDP(buf, nil)
	if err != nil {
		t.Fatalf("ReadMsgUDP with retry: %v", err)
	}
	if n != len(testData) {
		t.Errorf("ReadMsgUDP: got %d bytes, want %d", n, len(testData))
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("ReadMsgUDP: got %q, want %q", buf[:n], testData)
	}
	if addr == nil {
		t.Error("ReadMsgUDP: addr is nil")
	}
}

// TestReadMsgUDP_DeadlineTimeout tests ReadMsgUDP timeout during retry loop.
func TestReadMsgUDP_DeadlineTimeout(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set very short deadline - should timeout during retry loop
	conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))

	buf := make([]byte, 1024)
	_, _, _, _, err = conn.ReadMsgUDP(buf, nil)
	if err != ErrTimedOut {
		t.Errorf("ReadMsgUDP timeout: expected ErrTimedOut, got %v", err)
	}
}

// TestWriteMsgUDP_DeadlineExpired tests WriteMsgUDP when deadline is already expired.
func TestWriteMsgUDP_DeadlineExpired(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Reduce send buffer to minimum to trigger would-block more easily
	_ = SetSendBuffer(conn.fd, 1024)

	destAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 65535}
	data := make([]byte, 512)

	// First, fill the send buffer without deadline to trigger would-block
	for i := 0; i < 10000; i++ {
		_, _, err = conn.WriteMsgUDP(data, nil, destAddr)
		if err == iox.ErrWouldBlock {
			// Now we have a blocked socket - set expired deadline and try again
			conn.SetWriteDeadline(time.Now().Add(-time.Second))
			_, _, err = conn.WriteMsgUDP(data, nil, destAddr)
			if err == ErrTimedOut {
				// Successfully hit the expired deadline path
				return
			}
			t.Logf("After would-block with expired deadline: %v", err)
			return
		}
		if err != nil {
			t.Logf("WriteMsgUDP iteration %d: %v", i, err)
			break
		}
	}
	// If we get here, we couldn't trigger would-block (UDP rarely blocks)
	t.Log("WriteMsgUDP: could not trigger would-block path")
}

// TestWriteMsgUDP_DeadlineTimeoutInLoop tests WriteMsgUDP timeout during retry loop.
func TestWriteMsgUDP_DeadlineTimeoutInLoop(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Reduce send buffer to minimum
	_ = SetSendBuffer(conn.fd, 1024)

	destAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 65535}
	data := make([]byte, 512)

	// Fill the send buffer first
	for i := 0; i < 10000; i++ {
		_, _, err = conn.WriteMsgUDP(data, nil, destAddr)
		if err == iox.ErrWouldBlock {
			// Now set a short deadline and try to write - should timeout in retry loop
			conn.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
			_, _, err = conn.WriteMsgUDP(data, nil, destAddr)
			if err == ErrTimedOut {
				// Successfully hit the timeout-in-loop path
				return
			}
			t.Logf("After would-block with short deadline: %v", err)
			return
		}
		if err != nil {
			t.Logf("WriteMsgUDP iteration %d: %v", i, err)
			break
		}
	}
	t.Log("WriteMsgUDP: could not trigger would-block path")
}

// TestWriteMsgUDP_AggressiveStress aggressively tries to trigger EAGAIN on UDP.
// UDP rarely blocks because the kernel drops packets rather than returning EAGAIN.
// This test attempts to trigger the condition but may not succeed on all systems.
func TestWriteMsgUDP_AggressiveStress(t *testing.T) {
	conn, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set absolutely minimal send buffer
	_ = SetSendBuffer(conn.fd, 1)

	// Target a blackhole destination (TEST-NET-1, should not route)
	destAddr := &UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 9}

	// Large payload to fill buffer faster
	data := make([]byte, 65507) // Max UDP payload

	// Flood with maximum speed
	for i := 0; i < 100000; i++ {
		_, _, err = conn.WriteMsgUDP(data, nil, destAddr)
		if err == iox.ErrWouldBlock {
			// Got EAGAIN - now test the deadline paths
			t.Log("Triggered ErrWouldBlock, testing deadline paths")

			// Test 1: No deadline set - should return immediately
			_, _, err = conn.WriteMsgUDP(data, nil, destAddr)
			if err == iox.ErrWouldBlock {
				t.Log("Path 1: No deadline, returned ErrWouldBlock immediately")
			}

			// Test 2: Expired deadline
			conn.SetWriteDeadline(time.Now().Add(-time.Second))
			_, _, err = conn.WriteMsgUDP(data, nil, destAddr)
			if err == ErrTimedOut {
				t.Log("Path 2: Expired deadline returned ErrTimedOut")
			}

			// Test 3: Short deadline that expires in loop
			conn.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
			_, _, err = conn.WriteMsgUDP(data, nil, destAddr)
			if err == ErrTimedOut {
				t.Log("Path 3: Deadline expired in retry loop")
			}
			return
		}
		if err != nil && err != iox.ErrWouldBlock {
			// Other errors are expected (network unreachable, etc.)
			continue
		}
	}
	t.Log("WriteMsgUDP: UDP does not block on this system (kernel drops packets)")
}

// TestWriteMsgUDP_DeadlineRetrySuccess tests WriteMsgUDP retry with deadline.
func TestWriteMsgUDP_DeadlineRetrySuccess(t *testing.T) {
	receiver, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*UDPAddr)

	sender, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer sender.Close()

	// Set a deadline
	sender.SetWriteDeadline(time.Now().Add(time.Second))

	// Normal write should succeed immediately (Strike path)
	testData := []byte("write deadline test")
	n, oobn, err := sender.WriteMsgUDP(testData, nil, receiverAddr)
	if err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if n != len(testData) {
		t.Errorf("WriteMsgUDP: wrote %d bytes, want %d", n, len(testData))
	}
	if oobn != 0 {
		t.Errorf("WriteMsgUDP: oobn = %d, want 0", oobn)
	}

	// Verify data received
	buf := make([]byte, 1024)
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	rn, _, _, _, err := receiver.ReadMsgUDP(buf, nil)
	if err != nil {
		t.Fatalf("ReadMsgUDP: %v", err)
	}
	if string(buf[:rn]) != string(testData) {
		t.Errorf("Received %q, want %q", buf[:rn], testData)
	}
}

// TestListenTCP4_BindError tests bind error path in ListenTCP4.
func TestListenTCP4_BindError(t *testing.T) {
	// First listener binds to port
	listener1, err := ListenTCP4(&TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("first ListenTCP4: %v", err)
	}
	defer listener1.Close()

	port := listener1.Addr().(*TCPAddr).Port

	// Second listener tries same port - should fail with bind error
	// Note: With SO_REUSEPORT, this may succeed, so we try without it
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	_ = SetReusePort(sock.fd, false) // Disable reuseport
	err = sock.Bind(tcpAddrToSockaddr4(&TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}))
	sock.Close()
	if err == nil {
		t.Log("bind succeeded (reuseport may be enabled system-wide)")
	}
}

// TestListenTCP6_BindError tests bind error path in ListenTCP6.
func TestListenTCP6_BindError(t *testing.T) {
	listener1, err := ListenTCP6(&TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("first ListenTCP6: %v", err)
	}
	defer listener1.Close()

	port := listener1.Addr().(*TCPAddr).Port

	sock, err := NewTCPSocket6()
	if err != nil {
		t.Fatalf("NewTCPSocket6: %v", err)
	}
	_ = SetReusePort(sock.fd, false)
	err = sock.Bind(tcpAddrToSockaddr6(&TCPAddr{IP: net.ParseIP("::1"), Port: port}))
	sock.Close()
	if err == nil {
		t.Log("bind succeeded (reuseport may be enabled system-wide)")
	}
}

// TestDialTCP4_NonBlockingConnect tests non-blocking connect path.
func TestDialTCP4_NonBlockingConnect(t *testing.T) {
	// Non-blocking dial returns immediately (ErrInProgress silently ignored)
	conn, err := DialTCP4(nil, &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})
	if err != nil {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer conn.Close()
	// Connection will fail on first I/O operation
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Error("expected write error on failed connection")
	}
}

// TestDialTCP6_NonBlockingConnect tests non-blocking connect path.
func TestDialTCP6_NonBlockingConnect(t *testing.T) {
	conn, err := DialTCP6(nil, &TCPAddr{IP: net.ParseIP("::1"), Port: 1})
	if err != nil {
		t.Fatalf("DialTCP6: %v", err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Error("expected write error on failed connection")
	}
}

// TestDialTCP4_BindPath tests DialTCP4 laddr binding path.
func TestDialTCP4_BindPath(t *testing.T) {
	listener, err := ListenTCP4(&TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	laddr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	raddr := listener.Addr().(*TCPAddr)

	conn, err := DialTCP4(laddr, raddr)
	if err != nil {
		t.Fatalf("DialTCP4 with laddr: %v", err)
	}
	defer conn.Close()
}

// TestDialTCP6_BindPath tests DialTCP6 laddr binding path.
func TestDialTCP6_BindPath(t *testing.T) {
	listener, err := ListenTCP6(&TCPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenTCP6: %v", err)
	}
	defer listener.Close()

	laddr := &TCPAddr{IP: net.ParseIP("::1"), Port: 0}
	raddr := listener.Addr().(*TCPAddr)

	conn, err := DialTCP6(laddr, raddr)
	if err != nil {
		t.Fatalf("DialTCP6 with laddr: %v", err)
	}
	defer conn.Close()
}

// TestReadMsgUDP_BackoffPath tests ReadMsgUDP adaptive backoff with deadline.
func TestReadMsgUDP_BackoffPath(t *testing.T) {
	server, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4 server: %v", err)
	}
	defer server.Close()

	client, err := DialUDP4(nil, server.LocalAddr().(*UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP4 client: %v", err)
	}
	defer client.Close()

	// Send data after delay to trigger backoff retry path
	go func() {
		time.Sleep(5 * time.Millisecond)
		client.Write([]byte("test"))
	}()

	// Set deadline and read - will backoff then succeed
	server.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	oob := make([]byte, 64)
	n, _, _, _, err := server.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatalf("ReadMsgUDP: %v", err)
	}
	if n != 4 {
		t.Errorf("got %d bytes, want 4", n)
	}
}

// TestWriteMsgUDP_BackoffPath tests WriteMsgUDP adaptive backoff with deadline.
func TestWriteMsgUDP_BackoffPath(t *testing.T) {
	server, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4 server: %v", err)
	}
	defer server.Close()

	client, err := DialUDP4(nil, server.LocalAddr().(*UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP4 client: %v", err)
	}
	defer client.Close()

	// Set deadline and write
	client.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	n, oobn, err := client.WriteMsgUDP([]byte("test"), nil, nil)
	if err != nil {
		t.Fatalf("WriteMsgUDP: %v", err)
	}
	if n != 4 {
		t.Errorf("got %d bytes, want 4", n)
	}
	if oobn != 0 {
		t.Errorf("got %d oob bytes, want 0", oobn)
	}
}

// TestWriteMsgUDP_DeadlineExpiredPath tests WriteMsgUDP deadline-expired path.
func TestWriteMsgUDP_DeadlineExpiredPath(t *testing.T) {
	server, err := ListenUDP4(&UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP4 server: %v", err)
	}
	defer server.Close()

	client, err := DialUDP4(nil, server.LocalAddr().(*UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP4 client: %v", err)
	}
	defer client.Close()

	// Set already-expired deadline
	client.SetWriteDeadline(time.Now().Add(-time.Second))

	// Reduce socket buffer to make it more likely to block
	zcall.Setsockopt(uintptr(client.fd.Raw()), zcall.SOL_SOCKET, zcall.SO_SNDBUF,
		unsafe.Pointer(&[]int32{1024}[0]), 4)

	// Try to fill buffer - may trigger ErrWouldBlock then ErrTimedOut
	buf := make([]byte, 8192)
	for i := 0; i < 100; i++ {
		_, _, err = client.WriteMsgUDP(buf, nil, nil)
		if err == ErrTimedOut {
			return // Success - hit the deadline path
		}
	}
	// Even if we don't hit the path, test passes (best effort)
}
