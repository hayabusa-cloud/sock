// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"net"
	"testing"
)

func TestTCPUserTimeout(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Test set
	if err := SetTCPUserTimeout(sock.fd, 30000); err != nil {
		t.Fatalf("SetTCPUserTimeout: %v", err)
	}

	// Test get
	ms, err := GetTCPUserTimeout(sock.fd)
	if err != nil {
		t.Fatalf("GetTCPUserTimeout: %v", err)
	}
	if ms != 30000 {
		t.Errorf("GetTCPUserTimeout: got %d, want 30000", ms)
	}

	// Test with zero (disable)
	if err := SetTCPUserTimeout(sock.fd, 0); err != nil {
		t.Fatalf("SetTCPUserTimeout(0): %v", err)
	}
	ms, err = GetTCPUserTimeout(sock.fd)
	if err != nil {
		t.Fatalf("GetTCPUserTimeout after reset: %v", err)
	}
	if ms != 0 {
		t.Errorf("GetTCPUserTimeout after reset: got %d, want 0", ms)
	}
}

func TestTCPUserTimeoutOnClosed(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close()

	if err := SetTCPUserTimeout(sock.fd, 30000); err != ErrClosed {
		t.Errorf("SetTCPUserTimeout on closed: got %v, want ErrClosed", err)
	}
	if _, err := GetTCPUserTimeout(sock.fd); err != ErrClosed {
		t.Errorf("GetTCPUserTimeout on closed: got %v, want ErrClosed", err)
	}
}

func TestTCPNotsentLowat(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	defer sock.Close()

	// Test set
	if err := SetTCPNotsentLowat(sock.fd, 16384); err != nil {
		t.Fatalf("SetTCPNotsentLowat: %v", err)
	}

	// Test get
	bytes, err := GetTCPNotsentLowat(sock.fd)
	if err != nil {
		t.Fatalf("GetTCPNotsentLowat: %v", err)
	}
	if bytes != 16384 {
		t.Errorf("GetTCPNotsentLowat: got %d, want 16384", bytes)
	}
}

func TestTCPNotsentLowatOnClosed(t *testing.T) {
	sock, err := NewTCPSocket4()
	if err != nil {
		t.Fatalf("NewTCPSocket4: %v", err)
	}
	sock.Close()

	if err := SetTCPNotsentLowat(sock.fd, 16384); err != ErrClosed {
		t.Errorf("SetTCPNotsentLowat on closed: got %v, want ErrClosed", err)
	}
	if _, err := GetTCPNotsentLowat(sock.fd); err != ErrClosed {
		t.Errorf("GetTCPNotsentLowat on closed: got %v, want ErrClosed", err)
	}
}

func TestUDPGSO(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Test set segment size
	if err := SetUDPSegment(sock.fd, 1400); err != nil {
		t.Fatalf("SetUDPSegment: %v", err)
	}

	// Test get
	size, err := GetUDPSegment(sock.fd)
	if err != nil {
		t.Fatalf("GetUDPSegment: %v", err)
	}
	if size != 1400 {
		t.Errorf("GetUDPSegment: got %d, want 1400", size)
	}
}

func TestUDPGSOOnClosed(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	sock.Close()

	if err := SetUDPSegment(sock.fd, 1400); err != ErrClosed {
		t.Errorf("SetUDPSegment on closed: got %v, want ErrClosed", err)
	}
	if _, err := GetUDPSegment(sock.fd); err != ErrClosed {
		t.Errorf("GetUDPSegment on closed: got %v, want ErrClosed", err)
	}
}

func TestUDPGRO(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Test enable
	if err := SetUDPGRO(sock.fd, true); err != nil {
		t.Fatalf("SetUDPGRO(true): %v", err)
	}

	// Test get
	enabled, err := GetUDPGRO(sock.fd)
	if err != nil {
		t.Fatalf("GetUDPGRO: %v", err)
	}
	if !enabled {
		t.Error("GetUDPGRO: expected true")
	}

	// Test disable
	if err := SetUDPGRO(sock.fd, false); err != nil {
		t.Fatalf("SetUDPGRO(false): %v", err)
	}
	enabled, err = GetUDPGRO(sock.fd)
	if err != nil {
		t.Fatalf("GetUDPGRO after disable: %v", err)
	}
	if enabled {
		t.Error("GetUDPGRO after disable: expected false")
	}
}

func TestUDPGROOnClosed(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	sock.Close()

	if err := SetUDPGRO(sock.fd, true); err != ErrClosed {
		t.Errorf("SetUDPGRO on closed: got %v, want ErrClosed", err)
	}
	if _, err := GetUDPGRO(sock.fd); err != ErrClosed {
		t.Errorf("GetUDPGRO on closed: got %v, want ErrClosed", err)
	}
}

func TestBusyPoll(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// Test set
	if err := SetBusyPoll(sock.fd, 50); err != nil {
		t.Fatalf("SetBusyPoll: %v", err)
	}

	// Test get
	usecs, err := GetBusyPoll(sock.fd)
	if err != nil {
		t.Fatalf("GetBusyPoll: %v", err)
	}
	if usecs != 50 {
		t.Errorf("GetBusyPoll: got %d, want 50", usecs)
	}

	// Test disable
	if err := SetBusyPoll(sock.fd, 0); err != nil {
		t.Fatalf("SetBusyPoll(0): %v", err)
	}
	usecs, err = GetBusyPoll(sock.fd)
	if err != nil {
		t.Fatalf("GetBusyPoll after disable: %v", err)
	}
	if usecs != 0 {
		t.Errorf("GetBusyPoll after disable: got %d, want 0", usecs)
	}
}

func TestBusyPollOnClosed(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	sock.Close()

	if err := SetBusyPoll(sock.fd, 50); err != ErrClosed {
		t.Errorf("SetBusyPoll on closed: got %v, want ErrClosed", err)
	}
	if _, err := GetBusyPoll(sock.fd); err != ErrClosed {
		t.Errorf("GetBusyPoll on closed: got %v, want ErrClosed", err)
	}
}

func TestIPTransparent(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	defer sock.Close()

	// IP_TRANSPARENT requires CAP_NET_ADMIN, so we only test that
	// the syscall doesn't crash. EPERM is expected for unprivileged users.
	err = SetIPTransparent(sock.fd, true)
	if err != nil && err != ErrPermission {
		t.Fatalf("SetIPTransparent: unexpected error %v", err)
	}

	// Test get - should work even without privileges
	_, err = GetIPTransparent(sock.fd)
	if err != nil {
		t.Fatalf("GetIPTransparent: %v", err)
	}
}

func TestIPTransparentOnClosed(t *testing.T) {
	sock, err := NewUDPSocket4()
	if err != nil {
		t.Fatalf("NewUDPSocket4: %v", err)
	}
	sock.Close()

	if err := SetIPTransparent(sock.fd, true); err != ErrClosed {
		t.Errorf("SetIPTransparent on closed: got %v, want ErrClosed", err)
	}
	if _, err := GetIPTransparent(sock.fd); err != ErrClosed {
		t.Errorf("GetIPTransparent on closed: got %v, want ErrClosed", err)
	}
}

func TestConstantsExported(t *testing.T) {
	// Verify constants are exported and have expected values
	tests := []struct {
		name  string
		value int
		want  int
	}{
		{"TCP_USER_TIMEOUT", TCP_USER_TIMEOUT, 18},
		{"TCP_NOTSENT_LOWAT", TCP_NOTSENT_LOWAT, 25},
		{"UDP_SEGMENT", UDP_SEGMENT, 103},
		{"UDP_GRO", UDP_GRO, 104},
		{"IP_TRANSPARENT", IP_TRANSPARENT, 19},
		{"SO_BUSY_POLL", SO_BUSY_POLL, 46},
	}

	for _, tt := range tests {
		if tt.value != tt.want {
			t.Errorf("%s: got %d, want %d", tt.name, tt.value, tt.want)
		}
	}
}

func TestTCPSocketOptionsIPv6(t *testing.T) {
	sock, err := NewTCPSocket6()
	if err != nil {
		t.Fatalf("NewTCPSocket6: %v", err)
	}
	defer sock.Close()

	// Test TCP_USER_TIMEOUT on IPv6 socket
	if err := SetTCPUserTimeout(sock.fd, 5000); err != nil {
		t.Fatalf("SetTCPUserTimeout on IPv6: %v", err)
	}
	ms, err := GetTCPUserTimeout(sock.fd)
	if err != nil {
		t.Fatalf("GetTCPUserTimeout on IPv6: %v", err)
	}
	if ms != 5000 {
		t.Errorf("GetTCPUserTimeout on IPv6: got %d, want 5000", ms)
	}

	// Test TCP_NOTSENT_LOWAT on IPv6 socket
	if err := SetTCPNotsentLowat(sock.fd, 8192); err != nil {
		t.Fatalf("SetTCPNotsentLowat on IPv6: %v", err)
	}
	bytes, err := GetTCPNotsentLowat(sock.fd)
	if err != nil {
		t.Fatalf("GetTCPNotsentLowat on IPv6: %v", err)
	}
	if bytes != 8192 {
		t.Errorf("GetTCPNotsentLowat on IPv6: got %d, want 8192", bytes)
	}
}

func TestUDPSocketOptionsIPv6(t *testing.T) {
	sock, err := NewUDPSocket6()
	if err != nil {
		t.Fatalf("NewUDPSocket6: %v", err)
	}
	defer sock.Close()

	// Test UDP_SEGMENT on IPv6 socket
	if err := SetUDPSegment(sock.fd, 1200); err != nil {
		t.Fatalf("SetUDPSegment on IPv6: %v", err)
	}
	size, err := GetUDPSegment(sock.fd)
	if err != nil {
		t.Fatalf("GetUDPSegment on IPv6: %v", err)
	}
	if size != 1200 {
		t.Errorf("GetUDPSegment on IPv6: got %d, want 1200", size)
	}

	// Test UDP_GRO on IPv6 socket
	if err := SetUDPGRO(sock.fd, true); err != nil {
		t.Fatalf("SetUDPGRO on IPv6: %v", err)
	}
	enabled, err := GetUDPGRO(sock.fd)
	if err != nil {
		t.Fatalf("GetUDPGRO on IPv6: %v", err)
	}
	if !enabled {
		t.Error("GetUDPGRO on IPv6: expected true")
	}
}

func TestTCPConnUserTimeout(t *testing.T) {
	// Create a bound listener
	addr := &TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	lis, err := ListenTCP4(addr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer lis.Close()

	// Apply TCP_USER_TIMEOUT to listener socket
	if err := SetTCPUserTimeout(lis.TCPSocket.fd, 10000); err != nil {
		t.Fatalf("SetTCPUserTimeout on listener: %v", err)
	}
	ms, err := GetTCPUserTimeout(lis.TCPSocket.fd)
	if err != nil {
		t.Fatalf("GetTCPUserTimeout on listener: %v", err)
	}
	if ms != 10000 {
		t.Errorf("GetTCPUserTimeout on listener: got %d, want 10000", ms)
	}
}
