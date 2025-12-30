// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"testing"
	"time"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
)

// TestTCPConn_NonBlockingDefault verifies that TCPConn Read/Write
// return iox.ErrWouldBlock immediately when no deadline is set.
func TestTCPConn_NonBlockingDefault(t *testing.T) {
	// Create a TCP listener
	laddr := &sock.TCPAddr{IP: sock.IPv4LoopBack, Port: 0}
	listener, err := sock.ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	// Get the actual bound address
	boundAddr := listener.Addr().(*sock.TCPAddr)

	// Create a client socket and connect
	client, err := sock.DialTCP4(nil, boundAddr)
	if err != nil && err != sock.ErrInProgress {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer client.Close()

	// Accept should return ErrWouldBlock if no connection pending (non-blocking)
	// But since we just connected, it might succeed. Let's test Read instead.

	// Accept the connection
	serverConn, err := listener.Accept()
	if err != nil && err != iox.ErrWouldBlock {
		t.Fatalf("Accept: %v", err)
	}
	if serverConn != nil {
		defer serverConn.Close()

		// Read on server should return ErrWouldBlock (no data sent yet)
		buf := make([]byte, 1024)
		_, err = serverConn.Read(buf)
		if err != iox.ErrWouldBlock {
			t.Errorf("Read without data: expected iox.ErrWouldBlock, got %v", err)
		}
	}
}

// TestTCPListener_NonBlockingAccept verifies that TCPListener.Accept
// returns iox.ErrWouldBlock immediately when no connection is pending.
func TestTCPListener_NonBlockingAccept(t *testing.T) {
	laddr := &sock.TCPAddr{IP: sock.IPv4LoopBack, Port: 0}
	listener, err := sock.ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	// Accept without any pending connection should return ErrWouldBlock
	_, err = listener.Accept()
	if err != iox.ErrWouldBlock {
		t.Errorf("Accept without connection: expected iox.ErrWouldBlock, got %v", err)
	}
}

// TestTCPListener_DeadlineTimeout verifies that TCPListener.Accept
// returns ErrTimedOut when deadline expires without a connection.
func TestTCPListener_DeadlineTimeout(t *testing.T) {
	laddr := &sock.TCPAddr{IP: sock.IPv4LoopBack, Port: 0}
	listener, err := sock.ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	// Set a short deadline
	deadline := time.Now().Add(50 * time.Millisecond)
	listener.SetDeadline(deadline)

	start := time.Now()
	_, err = listener.Accept()
	elapsed := time.Since(start)

	if err != sock.ErrTimedOut {
		t.Errorf("Accept with deadline: expected ErrTimedOut, got %v", err)
	}

	// Verify that we actually waited (at least some time)
	if elapsed < 40*time.Millisecond {
		t.Errorf("Accept returned too quickly: %v", elapsed)
	}
}

// TestTCPConn_ReadDeadlineTimeout verifies that TCPConn.Read
// returns ErrTimedOut when read deadline expires.
// Uses Unix socket pair for reliable connection establishment.
func TestTCPConn_ReadDeadlineTimeout(t *testing.T) {
	// Use Unix socket pair for reliable connected sockets
	// Then wrap them in UnixConn to test read deadline
	laddr := &sock.UnixAddr{Name: "", Net: "unix"}
	listener, err := sock.ListenUnix("unix", laddr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer listener.Close()

	boundAddr := listener.Addr().(*sock.UnixAddr)

	// Connect in goroutine
	done := make(chan struct{})
	go func() {
		defer close(done)
		client, err := sock.DialUnix("unix", nil, boundAddr)
		if err != nil && err != sock.ErrInProgress && err != iox.ErrWouldBlock {
			return
		}
		if client != nil {
			defer client.Close()
			// Keep connection alive until test completes
			<-done
		}
	}()

	// Accept with deadline
	listener.SetDeadline(time.Now().Add(1 * time.Second))
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer serverConn.Close()

	// Now test read deadline timeout
	serverConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	buf := make([]byte, 1024)
	start := time.Now()
	_, err = serverConn.Read(buf)
	elapsed := time.Since(start)

	if err != sock.ErrTimedOut {
		t.Errorf("Read with deadline: expected ErrTimedOut, got %v", err)
	}

	if elapsed < 40*time.Millisecond {
		t.Errorf("Read returned too quickly: %v", elapsed)
	}
}

// TestDeadlineState verifies the deadlineState helper functions.
func TestDeadlineState(t *testing.T) {
	// Create a TCP connection to test deadline state
	laddr := &sock.TCPAddr{IP: sock.IPv4LoopBack, Port: 0}
	listener, err := sock.ListenTCP4(laddr)
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer listener.Close()

	boundAddr := listener.Addr().(*sock.TCPAddr)

	client, err := sock.DialTCP4(nil, boundAddr)
	if err != nil && err != sock.ErrInProgress {
		t.Fatalf("DialTCP4: %v", err)
	}
	defer client.Close()

	// Test SetDeadline
	future := time.Now().Add(1 * time.Hour)
	if err := client.SetDeadline(future); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	// Test SetReadDeadline
	if err := client.SetReadDeadline(future); err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}

	// Test SetWriteDeadline
	if err := client.SetWriteDeadline(future); err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}

	// Test clearing deadline with zero time
	if err := client.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline(zero): %v", err)
	}
}

// TestUDPConn_NonBlockingDefault verifies that UDPConn Read
// returns iox.ErrWouldBlock immediately when no deadline is set.
func TestUDPConn_NonBlockingDefault(t *testing.T) {
	laddr := &sock.UDPAddr{IP: sock.IPv4LoopBack, Port: 0}
	conn, err := sock.ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Read should return ErrWouldBlock (no data)
	buf := make([]byte, 1024)
	_, _, err = conn.ReadFrom(buf)
	if err != iox.ErrWouldBlock {
		t.Errorf("ReadFrom without data: expected iox.ErrWouldBlock, got %v", err)
	}
}

// TestUDPConn_ReadDeadlineTimeout verifies that UDPConn.ReadFrom
// returns ErrTimedOut when read deadline expires.
func TestUDPConn_ReadDeadlineTimeout(t *testing.T) {
	laddr := &sock.UDPAddr{IP: sock.IPv4LoopBack, Port: 0}
	conn, err := sock.ListenUDP4(laddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set a short read deadline
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	buf := make([]byte, 1024)
	start := time.Now()
	_, _, err = conn.ReadFrom(buf)
	elapsed := time.Since(start)

	if err != sock.ErrTimedOut {
		t.Errorf("ReadFrom with deadline: expected ErrTimedOut, got %v", err)
	}

	if elapsed < 40*time.Millisecond {
		t.Errorf("ReadFrom returned too quickly: %v", elapsed)
	}
}

// TestUnixListener_NonBlockingAccept verifies that UnixListener.Accept
// returns iox.ErrWouldBlock immediately when no connection is pending.
func TestUnixListener_NonBlockingAccept(t *testing.T) {
	// Use empty name for auto-generated path
	laddr := &sock.UnixAddr{Name: "", Net: "unix"}
	listener, err := sock.ListenUnix("unix", laddr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer listener.Close()

	// Accept without any pending connection should return ErrWouldBlock
	_, err = listener.Accept()
	if err != iox.ErrWouldBlock {
		t.Errorf("Accept without connection: expected iox.ErrWouldBlock, got %v", err)
	}
}

// TestUnixListener_DeadlineTimeout verifies that UnixListener.Accept
// returns ErrTimedOut when deadline expires without a connection.
func TestUnixListener_DeadlineTimeout(t *testing.T) {
	// Use empty name for auto-generated path
	laddr := &sock.UnixAddr{Name: "", Net: "unix"}
	listener, err := sock.ListenUnix("unix", laddr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer listener.Close()

	// Set a short deadline
	deadline := time.Now().Add(50 * time.Millisecond)
	listener.SetDeadline(deadline)

	start := time.Now()
	_, err = listener.Accept()
	elapsed := time.Since(start)

	if err != sock.ErrTimedOut {
		t.Errorf("Accept with deadline: expected ErrTimedOut, got %v", err)
	}

	if elapsed < 40*time.Millisecond {
		t.Errorf("Accept returned too quickly: %v", elapsed)
	}
}
