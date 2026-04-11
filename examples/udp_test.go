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

// TestUDPEchoAdaptive demonstrates a UDP echo server and client using
// unconnected mode with ReadFrom/WriteTo and adaptive I/O.
//
// Contrast with net:
//
//	net.ListenPacket("udp", ":0"):
//	  - ReadFrom blocks the caller until a datagram arrives, close, or deadline
//	  - WriteTo waits inside the runtime-managed readiness path when needed
//	  - The runtime network poller manages readiness and deadlines
//
//	sock.ListenUDP4:
//	  - ReadFrom returns (0, nil, iox.ErrWouldBlock) immediately when empty
//	  - SetDeadline activates adaptive retry inside sock
//	  - The fd stays at the sock boundary: retry policy stays explicit
//	  - Returns both UDPConn (for ReadFrom/WriteTo) — no separate Listener type
func TestUDPEchoAdaptive(t *testing.T) {
	// 1. Server: bind to ephemeral port (unconnected mode).
	// Unlike TCP, UDP uses UDPConn for both listening and communication.
	srv, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenUDP4 server: %v", err)
	}
	defer srv.Close()
	srvAddr := srv.LocalAddr().(*sock.UDPAddr)

	// 2. Client: bind to ephemeral port (unconnected mode).
	client, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// 3. Client sends datagram to server.
	// WriteTo with deadline: adaptive retry inside sock if send buffer fills.
	client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	msg := []byte("hello udp")
	n, err := client.WriteTo(msg, srvAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("WriteTo: sent %d, want %d", n, len(msg))
	}

	// 4. Server receives datagram.
	// ReadFrom decodes the sender's address from kernel format for the reply path.
	var buf [512]byte
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := srv.ReadFrom(buf[:])
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "hello udp" {
		t.Errorf("Received: got %q, want %q", buf[:n], "hello udp")
	}

	// 5. Server echoes back to the sender address.
	srv.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := srv.WriteTo(buf[:n], from); err != nil {
		t.Fatalf("Echo WriteTo: %v", err)
	}

	// 6. Client receives echo.
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = client.ReadFrom(buf[:])
	if err != nil {
		t.Fatalf("Echo ReadFrom: %v", err)
	}
	if string(buf[:n]) != "hello udp" {
		t.Errorf("Echo: got %q, want %q", buf[:n], "hello udp")
	}
}

// TestUDPConnectedMode demonstrates connected UDP sockets.
//
// A connected UDP socket (via DialUDP4) restricts communication to a single
// peer, enabling Read/Write instead of ReadFrom/WriteTo:
//   - The kernel filters incoming datagrams by source address
//   - Write implicitly sends to the connected peer (no address needed)
//   - Read only receives from the connected peer
//   - ICMP errors (port unreachable) are delivered to the socket
//
// net.DialUDP does the same, but the underlying FD is managed by the runtime.
// sock.DialUDP4 gives direct FD access for io_uring submission.
func TestUDPConnectedMode(t *testing.T) {
	// 1. Server: unconnected mode (accepts from any client).
	srv, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer srv.Close()
	srvAddr := srv.LocalAddr().(*sock.UDPAddr)

	// 2. Client: connected mode (locked to server address).
	// connect(2) on a UDP socket sets the default destination.
	client, err := sock.DialUDP4(nil, srvAddr)
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer client.Close()

	// 3. Client writes using Write (not WriteTo — address is implicit).
	client.SetWriteDeadline(time.Now().Add(2 * time.Second))
	msg := []byte("connected udp")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// 4. Server receives via ReadFrom (unconnected, needs sender address).
	var buf [512]byte
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := srv.ReadFrom(buf[:])
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "connected udp" {
		t.Errorf("Received: got %q, want %q", buf[:n], "connected udp")
	}

	// 5. Server echoes back.
	srv.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := srv.WriteTo(buf[:n], from); err != nil {
		t.Fatalf("Echo WriteTo: %v", err)
	}

	// 6. Client reads using Read (connected mode — no address returned).
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = client.Read(buf[:])
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "connected udp" {
		t.Errorf("Echo: got %q, want %q", buf[:n], "connected udp")
	}
}

// TestUDPNonBlockingSemantics demonstrates pure non-blocking UDP.
//
// Without deadlines:
//   - ReadFrom returns (0, nil, iox.ErrWouldBlock) immediately
//   - WriteTo returns immediately (UDP rarely blocks on send, but can if
//     the socket send buffer is full)
//
// The FD is available via conn.FD().Raw() for external event notification
// (epoll, io_uring IORING_OP_RECVMSG, etc.).
func TestUDPNonBlockingSemantics(t *testing.T) {
	srv, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer srv.Close()

	// No deadline → ReadFrom returns immediately with ErrWouldBlock.
	var buf [64]byte
	_, _, err = srv.ReadFrom(buf[:])
	if err != iox.ErrWouldBlock {
		t.Fatalf("ReadFrom empty socket: got %v, want iox.ErrWouldBlock", err)
	}

	// FD access for event-loop integration.
	fd := srv.FD().Raw()
	if fd < 0 {
		t.Fatal("expected valid fd")
	}
	t.Logf("udp fd=%d (usable for io_uring IORING_OP_RECVMSG)", fd)
}
