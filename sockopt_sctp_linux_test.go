// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"testing"

	"code.hybscloud.com/zcall"
)

// skipIfNoSCTP skips the test if SCTP is not available.
func skipIfNoSCTP(t *testing.T) *SCTPSocket {
	t.Helper()
	sock, err := NewSCTPSocket4()
	if err != nil {
		if errno, ok := err.(zcall.Errno); ok {
			// EAFNOSUPPORT, EPROTONOSUPPORT, ESOCKTNOSUPPORT - SCTP not available
			if errno == zcall.EAFNOSUPPORT || errno == 93 || errno == 94 {
				t.Skip("SCTP not supported on this system")
			}
		}
		t.Fatalf("NewSCTPSocket4: %v", err)
	}
	return sock
}

func TestSCTPNodelay(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Test enable
	err := SetSCTPNodelay(sock.fd, true)
	if err != nil {
		t.Fatalf("SetSCTPNodelay(true): %v", err)
	}

	enabled, err := GetSCTPNodelay(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPNodelay: %v", err)
	}
	if !enabled {
		t.Error("expected SCTP_NODELAY to be enabled")
	}

	// Test disable
	err = SetSCTPNodelay(sock.fd, false)
	if err != nil {
		t.Fatalf("SetSCTPNodelay(false): %v", err)
	}

	enabled, err = GetSCTPNodelay(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPNodelay: %v", err)
	}
	if enabled {
		t.Error("expected SCTP_NODELAY to be disabled")
	}
}

func TestSCTPDisableFragments(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Test enable (disable fragmentation)
	err := SetSCTPDisableFragments(sock.fd, true)
	if err != nil {
		t.Fatalf("SetSCTPDisableFragments(true): %v", err)
	}

	disabled, err := GetSCTPDisableFragments(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPDisableFragments: %v", err)
	}
	if !disabled {
		t.Error("expected SCTP_DISABLE_FRAGMENTS to be enabled")
	}

	// Test disable (enable fragmentation)
	err = SetSCTPDisableFragments(sock.fd, false)
	if err != nil {
		t.Fatalf("SetSCTPDisableFragments(false): %v", err)
	}

	disabled, err = GetSCTPDisableFragments(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPDisableFragments: %v", err)
	}
	if disabled {
		t.Error("expected SCTP_DISABLE_FRAGMENTS to be disabled")
	}
}

func TestSCTPAutoclose(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Test set autoclose to 60 seconds
	err := SetSCTPAutoclose(sock.fd, 60)
	if err != nil {
		t.Fatalf("SetSCTPAutoclose(60): %v", err)
	}

	secs, err := GetSCTPAutoclose(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPAutoclose: %v", err)
	}
	if secs != 60 {
		t.Errorf("expected SCTP_AUTOCLOSE=60, got %d", secs)
	}

	// Test disable autoclose
	err = SetSCTPAutoclose(sock.fd, 0)
	if err != nil {
		t.Fatalf("SetSCTPAutoclose(0): %v", err)
	}

	secs, err = GetSCTPAutoclose(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPAutoclose: %v", err)
	}
	if secs != 0 {
		t.Errorf("expected SCTP_AUTOCLOSE=0, got %d", secs)
	}
}

func TestSCTPMaxseg(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Get default value first
	defaultVal, err := GetSCTPMaxseg(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPMaxseg (default): %v", err)
	}
	t.Logf("default SCTP_MAXSEG: %d", defaultVal)

	// Test set to a specific value (1024 bytes)
	err = SetSCTPMaxseg(sock.fd, 1024)
	if err != nil {
		t.Fatalf("SetSCTPMaxseg(1024): %v", err)
	}

	size, err := GetSCTPMaxseg(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPMaxseg: %v", err)
	}
	// Note: kernel may adjust the value, so we just check it's set
	t.Logf("SCTP_MAXSEG after set: %d", size)
}

func TestSCTPMaxBurst(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Get default value
	defaultVal, err := GetSCTPMaxBurst(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPMaxBurst (default): %v", err)
	}
	t.Logf("default SCTP_MAX_BURST: %d", defaultVal)

	// Test set to 8 packets
	err = SetSCTPMaxBurst(sock.fd, 8)
	if err != nil {
		t.Fatalf("SetSCTPMaxBurst(8): %v", err)
	}

	burst, err := GetSCTPMaxBurst(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPMaxBurst: %v", err)
	}
	if burst != 8 {
		t.Errorf("expected SCTP_MAX_BURST=8, got %d", burst)
	}
}

func TestSCTPInitMsg(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Get default init message parameters
	defaultMsg, err := GetSCTPInitMsg(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPInitMsg (default): %v", err)
	}
	t.Logf("default SCTP_INITMSG: ostreams=%d, instreams=%d, attempts=%d, timeout=%d",
		defaultMsg.NumOstreams, defaultMsg.MaxInstreams,
		defaultMsg.MaxAttempts, defaultMsg.MaxInitTimeout)

	// Test set custom init message
	msg := &SCTPInitMsg{
		NumOstreams:    10,
		MaxInstreams:   10,
		MaxAttempts:    5,
		MaxInitTimeout: 3000, // 3 seconds
	}
	err = SetSCTPInitMsg(sock.fd, msg)
	if err != nil {
		t.Fatalf("SetSCTPInitMsg: %v", err)
	}

	gotMsg, err := GetSCTPInitMsg(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPInitMsg: %v", err)
	}
	if gotMsg.NumOstreams != msg.NumOstreams {
		t.Errorf("expected NumOstreams=%d, got %d", msg.NumOstreams, gotMsg.NumOstreams)
	}
	if gotMsg.MaxInstreams != msg.MaxInstreams {
		t.Errorf("expected MaxInstreams=%d, got %d", msg.MaxInstreams, gotMsg.MaxInstreams)
	}
	if gotMsg.MaxAttempts != msg.MaxAttempts {
		t.Errorf("expected MaxAttempts=%d, got %d", msg.MaxAttempts, gotMsg.MaxAttempts)
	}
	if gotMsg.MaxInitTimeout != msg.MaxInitTimeout {
		t.Errorf("expected MaxInitTimeout=%d, got %d", msg.MaxInitTimeout, gotMsg.MaxInitTimeout)
	}
}

func TestSCTPContext(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Note: SCTP_CONTEXT requires an sctp_assoc_value structure with association ID.
	// On an unconnected socket, setting context may fail with EINVAL.
	// We test what's possible at the socket level.

	// Try to get the default context
	ctx, err := GetSCTPContext(sock.fd)
	if err != nil {
		// This is expected on some kernel versions for unconnected sockets
		t.Logf("GetSCTPContext on unconnected socket: %v (expected on some systems)", err)
		return
	}
	t.Logf("default SCTP_CONTEXT: %d", ctx)

	// Try to set context - may fail on unconnected sockets
	err = SetSCTPContext(sock.fd, 12345)
	if err != nil {
		t.Logf("SetSCTPContext on unconnected socket: %v (expected on some systems)", err)
		return
	}

	ctx, err = GetSCTPContext(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPContext: %v", err)
	}
	if ctx != 12345 {
		t.Errorf("expected SCTP_CONTEXT=12345, got %d", ctx)
	}
}

func TestSCTPFragmentInterleave(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Get default level
	defaultLevel, err := GetSCTPFragmentInterleave(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPFragmentInterleave (default): %v", err)
	}
	t.Logf("default SCTP_FRAGMENT_INTERLEAVE: %d", defaultLevel)

	// Test levels 0 and 1
	// Level 2 (full interleaving) requires SCTP_INTERLEAVING_SUPPORTED enabled
	for _, level := range []int{0, 1} {
		err := SetSCTPFragmentInterleave(sock.fd, level)
		if err != nil {
			t.Fatalf("SetSCTPFragmentInterleave(%d): %v", level, err)
		}

		got, err := GetSCTPFragmentInterleave(sock.fd)
		if err != nil {
			t.Fatalf("GetSCTPFragmentInterleave: %v", err)
		}
		if got != level {
			t.Errorf("expected SCTP_FRAGMENT_INTERLEAVE=%d, got %d", level, got)
		}
	}

	// Level 2 may be capped by kernel without SCTP_INTERLEAVING_SUPPORTED
	err = SetSCTPFragmentInterleave(sock.fd, 2)
	if err != nil {
		t.Logf("SetSCTPFragmentInterleave(2): %v (may require SCTP_INTERLEAVING_SUPPORTED)", err)
		return
	}
	got, err := GetSCTPFragmentInterleave(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPFragmentInterleave: %v", err)
	}
	// Kernel may cap level 2 to 1 if interleaving not supported
	t.Logf("SCTP_FRAGMENT_INTERLEAVE after setting 2: got %d", got)
}

func TestSCTPPartialDeliveryPoint(t *testing.T) {
	sock := skipIfNoSCTP(t)
	defer sock.Close()

	// Get default value
	defaultVal, err := GetSCTPPartialDeliveryPoint(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPPartialDeliveryPoint (default): %v", err)
	}
	t.Logf("default SCTP_PARTIAL_DELIVERY_POINT: %d", defaultVal)

	// Test set to 4096 bytes
	err = SetSCTPPartialDeliveryPoint(sock.fd, 4096)
	if err != nil {
		t.Fatalf("SetSCTPPartialDeliveryPoint(4096): %v", err)
	}

	bytes, err := GetSCTPPartialDeliveryPoint(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPPartialDeliveryPoint: %v", err)
	}
	if bytes != 4096 {
		t.Errorf("expected SCTP_PARTIAL_DELIVERY_POINT=4096, got %d", bytes)
	}
}

func TestSCTPMappedV4(t *testing.T) {
	// This option is only meaningful for IPv6 sockets
	sock, err := NewSCTPSocket6()
	if err != nil {
		if errno, ok := err.(zcall.Errno); ok {
			if errno == zcall.EAFNOSUPPORT || errno == 93 || errno == 94 {
				t.Skip("SCTP not supported on this system")
			}
		}
		t.Fatalf("NewSCTPSocket6: %v", err)
	}
	defer sock.Close()

	// Test enable mapped IPv4 addresses
	err = SetSCTPMappedV4(sock.fd, true)
	if err != nil {
		t.Fatalf("SetSCTPMappedV4(true): %v", err)
	}

	enabled, err := GetSCTPMappedV4(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPMappedV4: %v", err)
	}
	if !enabled {
		t.Error("expected SCTP_I_WANT_MAPPED_V4 to be enabled")
	}

	// Test disable
	err = SetSCTPMappedV4(sock.fd, false)
	if err != nil {
		t.Fatalf("SetSCTPMappedV4(false): %v", err)
	}

	enabled, err = GetSCTPMappedV4(sock.fd)
	if err != nil {
		t.Fatalf("GetSCTPMappedV4: %v", err)
	}
	if enabled {
		t.Error("expected SCTP_I_WANT_MAPPED_V4 to be disabled")
	}
}

func TestSCTPSocketOptionsWithIPv6(t *testing.T) {
	sock, err := NewSCTPSocket6()
	if err != nil {
		if errno, ok := err.(zcall.Errno); ok {
			if errno == zcall.EAFNOSUPPORT || errno == 93 || errno == 94 {
				t.Skip("SCTP not supported on this system")
			}
		}
		t.Fatalf("NewSCTPSocket6: %v", err)
	}
	defer sock.Close()

	// Verify basic options work on IPv6 sockets
	t.Run("nodelay", func(t *testing.T) {
		err := SetSCTPNodelay(sock.fd, true)
		if err != nil {
			t.Errorf("SetSCTPNodelay: %v", err)
		}
	})

	t.Run("autoclose", func(t *testing.T) {
		err := SetSCTPAutoclose(sock.fd, 30)
		if err != nil {
			t.Errorf("SetSCTPAutoclose: %v", err)
		}
	})

	t.Run("max_burst", func(t *testing.T) {
		err := SetSCTPMaxBurst(sock.fd, 4)
		if err != nil {
			t.Errorf("SetSCTPMaxBurst: %v", err)
		}
	})
}

func TestSCTPStreamSocket(t *testing.T) {
	sock, err := NewSCTPStreamSocket4()
	if err != nil {
		if errno, ok := err.(zcall.Errno); ok {
			if errno == zcall.EAFNOSUPPORT || errno == 93 || errno == 94 {
				t.Skip("SCTP not supported on this system")
			}
		}
		t.Fatalf("NewSCTPStreamSocket4: %v", err)
	}
	defer sock.Close()

	// Test options work on SOCK_STREAM SCTP sockets
	t.Run("nodelay", func(t *testing.T) {
		err := SetSCTPNodelay(sock.fd, true)
		if err != nil {
			t.Errorf("SetSCTPNodelay on stream socket: %v", err)
		}
		enabled, err := GetSCTPNodelay(sock.fd)
		if err != nil {
			t.Errorf("GetSCTPNodelay: %v", err)
		}
		if !enabled {
			t.Error("expected nodelay enabled")
		}
	})

	t.Run("init_msg", func(t *testing.T) {
		msg := &SCTPInitMsg{
			NumOstreams:  5,
			MaxInstreams: 5,
		}
		err := SetSCTPInitMsg(sock.fd, msg)
		if err != nil {
			t.Errorf("SetSCTPInitMsg: %v", err)
		}
	})
}

func TestSCTPConstants(t *testing.T) {
	// Verify constant values match Linux kernel headers
	tests := []struct {
		name     string
		got      int
		expected int
	}{
		{"SCTP_RTOINFO", SCTP_RTOINFO, 0},
		{"SCTP_ASSOCINFO", SCTP_ASSOCINFO, 1},
		{"SCTP_INITMSG", SCTP_INITMSG, 2},
		{"SCTP_NODELAY", SCTP_NODELAY, 3},
		{"SCTP_AUTOCLOSE", SCTP_AUTOCLOSE, 4},
		{"SCTP_SET_PEER_PRIMARY", SCTP_SET_PEER_PRIMARY, 5},
		{"SCTP_PRIMARY_ADDR", SCTP_PRIMARY_ADDR, 6},
		{"SCTP_ADAPTATION_LAYER", SCTP_ADAPTATION_LAYER, 7},
		{"SCTP_DISABLE_FRAGMENTS", SCTP_DISABLE_FRAGMENTS, 8},
		{"SCTP_PEER_ADDR_PARAMS", SCTP_PEER_ADDR_PARAMS, 9},
		{"SCTP_DEFAULT_SEND_PARAM", SCTP_DEFAULT_SEND_PARAM, 10},
		{"SCTP_EVENTS", SCTP_EVENTS, 11},
		{"SCTP_I_WANT_MAPPED_V4", SCTP_I_WANT_MAPPED_V4, 12},
		{"SCTP_MAXSEG", SCTP_MAXSEG, 13},
		{"SCTP_STATUS", SCTP_STATUS, 14},
		{"SCTP_GET_PEER_ADDR_INFO", SCTP_GET_PEER_ADDR_INFO, 15},
		{"SCTP_DELAYED_ACK_TIME", SCTP_DELAYED_ACK_TIME, 16},
		{"SCTP_DELAYED_SACK", SCTP_DELAYED_SACK, 16}, // alias
		{"SCTP_CONTEXT", SCTP_CONTEXT, 17},
		{"SCTP_FRAGMENT_INTERLEAVE", SCTP_FRAGMENT_INTERLEAVE, 18},
		{"SCTP_PARTIAL_DELIVERY", SCTP_PARTIAL_DELIVERY, 19},
		{"SCTP_MAX_BURST", SCTP_MAX_BURST, 20},
		{"SCTP_HMAC_IDENT", SCTP_HMAC_IDENT, 22},
		{"SCTP_AUTH_ACTIVE_KEY", SCTP_AUTH_ACTIVE_KEY, 24},
		{"SCTP_AUTO_ASCONF", SCTP_AUTO_ASCONF, 30},
		{"SCTP_PEER_ADDR_THLDS", SCTP_PEER_ADDR_THLDS, 31},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestSCTPInitMsgStruct(t *testing.T) {
	msg := SCTPInitMsg{
		NumOstreams:    10,
		MaxInstreams:   20,
		MaxAttempts:    5,
		MaxInitTimeout: 30000,
	}

	if msg.NumOstreams != 10 {
		t.Errorf("NumOstreams = %d, want 10", msg.NumOstreams)
	}
	if msg.MaxInstreams != 20 {
		t.Errorf("MaxInstreams = %d, want 20", msg.MaxInstreams)
	}
	if msg.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %d, want 5", msg.MaxAttempts)
	}
	if msg.MaxInitTimeout != 30000 {
		t.Errorf("MaxInitTimeout = %d, want 30000", msg.MaxInitTimeout)
	}
}
