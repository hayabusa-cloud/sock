// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"sync"
	"testing"
	"time"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
)

// TestEventLoopEcho demonstrates the minimal accept-loop pattern in caller code
// above sock while preserving the historical sox lineage for the same control
// shape.
//
// Architecture:
//
//	sock provides:
//	  - Non-blocking socket primitives (default: returns iox.ErrWouldBlock)
//	  - Direct FD access (conn.FD().Raw()) for kernel I/O submission
//	  - Zero-allocation address handling
//
//	Code above sock provides:
//	  - Accept / dispatch policy
//	  - Connection lifecycle and handler scheduling
//	  - Optional uring submission/completion, or a higher-level runtime such as urex
//
// In code.hybscloud.com/sox, you would write:
//
//	iface, _ := sox.New()
//	iface.OnAccept(func(ctx context.Context, conn, ln sox.Socket) {
//	    // New connection accepted via io_uring multishot.
//	})
//	iface.OnData(func(ctx context.Context, reply sox.PollWriter, req sox.PollReader) {
//	    iox.Copy(reply, req)
//	})
//	iface.Listen(ctx, "tcp", ":8080")
//	iface.Start(ctx)
//
// Below is the smallest manual pattern using sock + goroutines: a
// single-threaded accept loop that dispatches connections. An uring-based
// runtime keeps the same sock boundary and replaces the caller-owned adaptive
// backoff path with completion-driven wakeups.
func TestEventLoopEcho(t *testing.T) {
	ln, err := sock.ListenTCP4(&sock.TCPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer ln.Close()
	srvAddr := ln.Addr().(*sock.TCPAddr)

	const numClients = 3
	var wg sync.WaitGroup

	// Event loop: polls for new connections and dispatches handlers.
	// In sox, this shape was driven by a single-threaded io_uring_enter() loop.
	// A uring-based runtime would drive the same boundary from CQEs instead of
	// using sleep/retry in a goroutine.
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		var acceptBackoff iox.Backoff
		for {
			select {
			case <-stop:
				return
			default:
			}

			// Non-blocking accept: returns immediately.
			// In sox, this was IORING_OP_ACCEPT submitted to the SQ.
			// A completion-driven runtime would submit ACCEPT on ln.FD().Raw()
			// and wait for the CQE instead of using caller-owned backoff here.
			conn, err := ln.Accept()
			if err == iox.ErrWouldBlock {
				// No pending connection — adaptively back off and retry.
				// iox.Backoff is the software Adapt tier for caller-owned loops
				// above sock when CQE/readiness wakeups are not in use.
				// In sox, the loop waited for the next CQE.
				// A completion-driven loop would park until the next accept CQE.
				acceptBackoff.Wait()
				continue
			}
			if err != nil {
				return
			}
			acceptBackoff.Reset()

			// Dispatch the accepted connection into application code.
			// In sox, this path became HandleAccept -> HandleData.
			go handleConn(conn)
		}
	}()

	// Spawn clients.
	results := make(chan string, numClients)
	for i := range numClients {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			dialer := sock.TCPDialer{Timeout: 3 * time.Second}
			client, err := dialer.Dial4(nil, srvAddr)
			if err != nil {
				t.Errorf("client %d Dial: %v", id, err)
				return
			}
			defer client.Close()

			const msg = "ping"
			client.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := copyString(client, msg); err != nil {
				t.Errorf("client %d Write: %v", id, err)
				return
			}

			client.SetReadDeadline(time.Now().Add(2 * time.Second))
			echo, err := readStringN(client, len(msg))
			if err != nil {
				t.Errorf("client %d Read: %v", id, err)
				return
			}
			results <- echo
		}(i)
	}

	// Collect results.
	for range numClients {
		select {
		case echo := <-results:
			if echo != "ping" {
				t.Errorf("echo: got %q, want %q", echo, "ping")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for echo")
		}
	}

	close(stop)

	wg.Wait()
}

// handleConn is the per-connection application handler.
//
// In sox, the CQE dispatch path invoked HandleData(ctx, reply, request).
// A runtime above sock may invoke this after readiness or completion dispatch.
// Here the handler stages the request through an iox-compatible buffer and then
// writes the staged bytes back with deadline-based adaptive I/O.
func handleConn(conn *sock.TCPConn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := echoFixed(conn, len("ping")); err != nil {
		return
	}
}

// TestFDExtractionForUring demonstrates extracting the raw fd from sock
// types for use with io_uring or epoll.
//
// This is the bridge between sock (socket creation + non-blocking I/O)
// and caller-owned completion code above it:
//
//  1. Create sockets with sock (gets optimal defaults: NONBLOCK, CLOEXEC,
//     REUSEADDR, REUSEPORT, ZEROCOPY)
//  2. Extract fd via FD().Raw()
//  3. Submit fd to io_uring ring (ACCEPT, RECV, SEND, etc.)
//  4. Process CQEs in your event loop or runtime
//
// net.Conn cannot provide this: its fd is managed by the Go runtime's
// netpoller and must not be used directly for kernel I/O submission.
func TestFDExtractionForUring(t *testing.T) {
	// TCP listener fd — used for IORING_OP_ACCEPT.
	ln, err := sock.ListenTCP4(&sock.TCPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenTCP4: %v", err)
	}
	defer ln.Close()
	lnFd := ln.FD().Raw()
	if lnFd < 0 {
		t.Fatal("listener: invalid fd")
	}
	t.Logf("TCP listener fd=%d → IORING_OP_ACCEPT", lnFd)

	// UDP socket fd — used for IORING_OP_RECVMSG / IORING_OP_SENDMSG.
	udp, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer udp.Close()
	udpFd := udp.FD().Raw()
	if udpFd < 0 {
		t.Fatal("udp: invalid fd")
	}
	t.Logf("UDP socket fd=%d → IORING_OP_RECVMSG", udpFd)

	// Connected TCP fd — used for IORING_OP_RECV / IORING_OP_SEND.
	srvAddr := ln.Addr().(*sock.TCPAddr)
	dialer := sock.TCPDialer{Timeout: 2 * time.Second}
	client, err := dialer.Dial4(nil, srvAddr)
	if err != nil {
		t.Fatalf("Dial4: %v", err)
	}
	defer client.Close()
	connFd := client.FD().Raw()
	if connFd < 0 {
		t.Fatal("conn: invalid fd")
	}
	t.Logf("TCP conn fd=%d → IORING_OP_SEND/RECV", connFd)

	// All three fds are valid non-blocking file descriptors ready for io_uring
	// submission. In sox, these descriptors could be registered via
	// IORING_REGISTER_FILES. A uring-based runtime may register them as fixed
	// files for lower per-op overhead.

	// Accept the connection to clean up.
	ln.SetDeadline(time.Now().Add(2 * time.Second))
	srv, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	srv.Close()
}
