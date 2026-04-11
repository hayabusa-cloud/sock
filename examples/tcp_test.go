// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
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

// TestTCPEchoAdaptive demonstrates a TCP echo server and client using
// adaptive I/O (deadline-driven retry with sock's built-in adaptive backoff).
//
// Contrast with net:
//
//	net.Listen / net.Dial:
//	  - Accept blocks the caller until a connection arrives, close, or deadline
//	  - Read blocks until data arrives, close, or deadline
//	  - The runtime network poller manages readiness and deadline wakeups
//
//	sock.ListenTCP4 / sock.TCPDialer:
//	  - Accept returns iox.ErrWouldBlock immediately when no connection pending
//	  - SetDeadline activates adaptive retry inside sock:
//	    Strike → Adapt → ErrTimedOut
//	  - The fd stays at the sock boundary: retry policy stays explicit
//	  - SO_REUSEADDR, SO_REUSEPORT, SO_ZEROCOPY applied by default
func TestTCPEchoAdaptive(t *testing.T) {
	// 1. Create listener on ephemeral port.
	// Port 0 → kernel assigns an available port.
	ln, err := sock.ListenTCP4(&sock.TCPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer ln.Close()

	srvAddr := ln.Addr().(*sock.TCPAddr)

	// 2. Client connects in a background goroutine.
	type clientResult struct {
		echo string
		err  error
	}
	ch := make(chan clientResult, 1)
	go func() {
		// TCPDialer with Timeout activates adaptive connect:
		//   First connect() → EINPROGRESS (non-blocking socket)
		//   Retry with sock's built-in adaptive backoff → EISCONN when
		//   handshake completes
		dialer := sock.TCPDialer{Timeout: 3 * time.Second}
		client, err := dialer.Dial4(nil, srvAddr)
		if err != nil {
			ch <- clientResult{err: err}
			return
		}
		defer client.Close()

		// Write with deadline (adaptive mode).
		client.SetWriteDeadline(time.Now().Add(2 * time.Second))
		const msg = "hello sock"
		if err := copyString(client, msg); err != nil {
			ch <- clientResult{err: err}
			return
		}

		// Read the full echoed payload via the iox copy engine.
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		echo, err := readStringN(client, len(msg))
		if err != nil {
			ch <- clientResult{err: err}
			return
		}
		ch <- clientResult{echo: echo}
	}()

	// 3. Server accepts with deadline.
	// Without deadline: Accept returns (nil, iox.ErrWouldBlock) immediately.
	// With deadline: retries with sock's built-in adaptive backoff until
	// connection or timeout.
	ln.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	// 4. Server reads exactly one message into an iox-compatible buffer and then
	// writes the staged bytes back to the socket.
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := echoFixed(conn, len("hello sock")); err != nil {
		t.Fatalf("echoFixed: %v", err)
	}

	// 6. Verify client received the echo.
	result := <-ch
	if result.err != nil {
		t.Fatalf("Client: %v", result.err)
	}
	if result.echo != "hello sock" {
		t.Errorf("Echo: got %q, want %q", result.echo, "hello sock")
	}
}

// TestTCPNonBlockingSemantics demonstrates pure non-blocking mode.
//
// Without deadlines, every operation returns immediately:
//   - Accept → (nil, iox.ErrWouldBlock) when no pending connection
//   - Read → (0, iox.ErrWouldBlock) when no data available
//   - Write → (0, iox.ErrWouldBlock) when send buffer full
//
// This is the operating mode used by caller-owned event loops and uring-backed
// runtimes above sock. Historically, `sox` (`code.hybscloud.com/sox`) drove
// the same non-blocking pattern before the current `uring` / `urex` split.
// The runtime registers the FD and retries when the kernel signals readiness
// or completion.
//
// In contrast, net.TCPListener.Accept() blocks the caller until a connection
// arrives, the listener closes, or a deadline/error path breaks the wait.
func TestTCPNonBlockingSemantics(t *testing.T) {
	ln, err := sock.ListenTCP4(&sock.TCPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer ln.Close()

	// No deadline set → pure non-blocking Accept.
	_, err = ln.Accept()
	if err != iox.ErrWouldBlock {
		t.Fatalf("Accept without deadline: got %v, want iox.ErrWouldBlock", err)
	}

	// Direct FD access — not available in net package without SyscallConn.
	// This fd can be submitted directly to io_uring for ACCEPT/READ/WRITE ops.
	fd := ln.FD().Raw()
	if fd < 0 {
		t.Fatal("expected valid fd")
	}
	t.Logf("listener fd=%d (usable for io_uring/epoll)", fd)

	// Demonstrate non-blocking read on a connected pair.
	// Create a connected TCP pair via listener + dial.
	srvAddr := ln.Addr().(*sock.TCPAddr)

	dialer := sock.TCPDialer{Timeout: 2 * time.Second}
	client, err := dialer.Dial4(nil, srvAddr)
	if err != nil {
		t.Fatalf("Dial4: %v", err)
	}
	defer client.Close()

	ln.SetDeadline(time.Now().Add(2 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	// Read without deadline: returns ErrWouldBlock (no data yet).
	var buf [64]byte
	_, err = conn.Read(buf[:])
	if err != iox.ErrWouldBlock {
		t.Fatalf("Read without data: got %v, want iox.ErrWouldBlock", err)
	}

	// Now send data and read again with deadline.
	client.SetWriteDeadline(time.Now().Add(time.Second))
	const msg = "data"
	if err := copyString(client, msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	got, err := readStringN(conn, len(msg))
	if err != nil {
		t.Fatalf("Read with data: %v", err)
	}
	if got != msg {
		t.Errorf("Read: got %q, want %q", got, msg)
	}
}

// TestTCPStreamCopy demonstrates using iox.CopyPolicy with sock connections.
//
// iox.CopyPolicy is the non-blocking-aware replacement for io.Copy when the
// caller wants policy-driven retry:
//   - Handles iox.ErrWouldBlock via SemanticPolicy (return or retry)
//   - Uses 32 KB stack buffer by default (no heap allocation)
//   - Supports seeker rollback on partial writes
//   - Returns immediately on (0, nil) to avoid event-loop spinning
//
// With net connections, io.Copy works because Read blocks until data.
// With sock connections (no deadline), Read returns ErrWouldBlock,
// which io.Copy would treat as a terminal error.
// iox.CopyPolicy handles this correctly via policy.
func TestTCPStreamCopy(t *testing.T) {
	ln, err := sock.ListenTCP4(&sock.TCPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer ln.Close()
	srvAddr := ln.Addr().(*sock.TCPAddr)

	const payload = "the quick brown fox jumps over the lazy dog"

	type clientResult struct {
		echo string
		err  error
	}
	done := make(chan clientResult, 1)
	go func() {
		dialer := sock.TCPDialer{Timeout: 2 * time.Second}
		client, err := dialer.Dial4(nil, srvAddr)
		if err != nil {
			done <- clientResult{err: err}
			return
		}
		defer client.Close()

		client.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := copyString(client, payload); err != nil {
			done <- clientResult{err: err}
			return
		}
		if err := client.Shutdown(sock.SHUT_WR); err != nil {
			done <- clientResult{err: err}
			return
		}

		// Read the echoed stream to EOF with the iox copy engine.
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		echo, err := readString(client)
		if err != nil {
			done <- clientResult{err: err}
			return
		}
		done <- clientResult{echo: string(echo)}
	}()

	ln.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	// Echo the full stream by staging it through an iox-compatible buffer:
	//   - Read from conn into the buffer with iox.CopyPolicy until EOF
	//   - Write the buffered bytes back to conn with iox.CopyPolicy
	//   - YieldPolicy retries if either step encounters ErrWouldBlock
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	written, err := echoToEOF(conn)
	if err != nil {
		t.Fatalf("echoToEOF: %v (written %d)", err, written)
	}
	if err := conn.Shutdown(sock.SHUT_WR); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	result := <-done
	if result.err != nil {
		t.Fatalf("Client: %v", result.err)
	}
	if result.echo != payload {
		t.Errorf("Echo: got %q, want %q", result.echo, payload)
	}
}
