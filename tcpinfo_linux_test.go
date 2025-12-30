// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"net"
	"testing"
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/sock"
)

func TestTCPInfoStructSize(t *testing.T) {
	var info sock.TCPInfo
	size := unsafe.Sizeof(info)
	if size != sock.SizeofTCPInfo {
		t.Errorf("TCPInfo size mismatch: got %d, want %d", size, sock.SizeofTCPInfo)
	}
}

func TestGetTCPInfo(t *testing.T) {
	// Create a TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	// Connect to listener
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Accept the connection
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	// Get the underlying file descriptor
	tcpConn := conn.(*net.TCPConn)
	file, err := tcpConn.File()
	if err != nil {
		t.Fatalf("File failed: %v", err)
	}
	defer file.Close()

	// Create iofd.FD from the file descriptor
	fd := iofd.NewFD(int(file.Fd()))

	// Get TCP info
	info, err := sock.GetTCPInfo(&fd)
	if err != nil {
		t.Fatalf("GetTCPInfo failed: %v", err)
	}

	// Check that we got an established connection
	if info.State != sock.TCP_ESTABLISHED {
		t.Errorf("Expected TCP_ESTABLISHED (%d), got %d", sock.TCP_ESTABLISHED, info.State)
	}

	// Check that some basic fields are populated
	if info.SndMss == 0 {
		t.Error("SndMss should not be 0 for established connection")
	}
	if info.RcvMss == 0 {
		t.Error("RcvMss should not be 0 for established connection")
	}
}

func TestGetTCPInfoInto(t *testing.T) {
	// Create a TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	// Connect to listener
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Accept the connection
	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	defer serverConn.Close()

	// Get the underlying file descriptor
	tcpConn := conn.(*net.TCPConn)
	file, err := tcpConn.File()
	if err != nil {
		t.Fatalf("File failed: %v", err)
	}
	defer file.Close()

	// Create iofd.FD from the file descriptor
	fd := iofd.NewFD(int(file.Fd()))

	// Get TCP info into existing struct (zero-allocation path)
	var info sock.TCPInfo
	err = sock.GetTCPInfoInto(&fd, &info)
	if err != nil {
		t.Fatalf("GetTCPInfoInto failed: %v", err)
	}

	// Check that we got an established connection
	if info.State != sock.TCP_ESTABLISHED {
		t.Errorf("Expected TCP_ESTABLISHED (%d), got %d", sock.TCP_ESTABLISHED, info.State)
	}
}

func TestTCPInfoHelpers(t *testing.T) {
	// Test WscaleRcvSnd unpacking
	info := sock.TCPInfo{
		WscaleRcvSnd: 0x73, // rcv=7, snd=3
	}
	if info.SndWscale() != 3 {
		t.Errorf("SndWscale: got %d, want 3", info.SndWscale())
	}
	if info.RcvWscale() != 7 {
		t.Errorf("RcvWscale: got %d, want 7", info.RcvWscale())
	}

	// Test option flags
	info.Options = sock.TCPI_OPT_TIMESTAMPS | sock.TCPI_OPT_SACK | sock.TCPI_OPT_ECN
	if !info.HasTimestamps() {
		t.Error("HasTimestamps should be true")
	}
	if !info.HasSACK() {
		t.Error("HasSACK should be true")
	}
	if !info.HasECN() {
		t.Error("HasECN should be true")
	}
	if info.HasWscale() {
		t.Error("HasWscale should be false")
	}

	// Test delivery rate app limited
	info.DeliveryRateApp = 0x05 // app_limited=1, fastopen_fail=2
	if !info.IsDeliveryRateAppLimited() {
		t.Error("IsDeliveryRateAppLimited should be true")
	}
	if info.FastOpenClientFail() != 2 {
		t.Errorf("FastOpenClientFail: got %d, want 2", info.FastOpenClientFail())
	}
}
