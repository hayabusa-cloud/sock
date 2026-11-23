// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock_test

import (
	"io"
	"runtime"
	"testing"
	"time"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
	"code.hybscloud.com/zcall"
)

// Peek with a nonempty buffer so an empty datagram also signals readiness.
func waitForUDPDatagram(t *testing.T, conn *sock.UDPConn) {
	t.Helper()
	var buf [1]byte
	var backoff iox.Backoff
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, errno := zcall.Recvfrom(uintptr(conn.FD().Raw()), buf[:], zcall.MSG_PEEK, nil, nil)
		if errno == 0 {
			return
		}
		if err := zcall.Errno(errno); err != zcall.EAGAIN && err != zcall.EINTR {
			t.Fatalf("peek UDP datagram: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a UDP datagram")
		}
		backoff.Wait()
	}
}

func checkEmptyUDPQueue(t *testing.T, r io.Reader) {
	t.Helper()
	var buf [1]byte
	if n, err := r.Read(buf[:]); n != 0 || err != iox.ErrWouldBlock {
		t.Fatalf("Read on empty UDP socket = (%d, %v)", n, err)
	}
	if runtime.GOOS == "linux" {
		if n, err := r.Read(nil); n != 0 || err != iox.ErrWouldBlock {
			t.Fatalf("Read(nil) on empty UDP socket = (%d, %v)", n, err)
		}
	}
}

func newUDPTestPair(t *testing.T) (listener, connected *sock.UDPConn) {
	t.Helper()
	listener, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	connected, err = sock.DialUDP4(nil, listener.LocalAddr().(*sock.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connected.Close() })
	return listener, connected
}

func TestUDPReadFromSender(t *testing.T) {
	conn, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var buf [1]byte
	if n, from, err := conn.ReadFrom(buf[:]); n != 0 || from != nil || err != iox.ErrWouldBlock {
		t.Errorf("ReadFrom on empty socket = (%d, %#v, %v)", n, from, err)
	}
	target := conn.LocalAddr()
	if n, err := conn.WriteTo(nil, target); n != 0 || err != nil {
		t.Fatalf("WriteTo empty datagram = (%d, %v)", n, err)
	}
	waitForUDPDatagram(t, conn)
	if n, from, err := conn.ReadFrom(buf[:]); n != 0 || err != nil || from == nil || from.String() != target.String() {
		t.Fatalf("ReadFrom empty datagram = (%d, %#v, %v), want sender %v", n, from, err, target)
	}
}

func TestUDPReceiveAllocations(t *testing.T) {
	receiver, sender := newUDPTestPair(t)

	var buf [1]byte
	allocs := testing.AllocsPerRun(100, func() {
		if n, from, err := receiver.ReadFrom(buf[:]); n != 0 || from != nil || err != iox.ErrWouldBlock {
			t.Fatalf("ReadFrom on empty socket = (%d, %#v, %v)", n, from, err)
		}
	})
	if allocs != 0 {
		t.Errorf("ReadFrom on empty socket = %g allocations per call, want 0", allocs)
	}

	if err := receiver.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := [...]byte{'x'}
	allocs = testing.AllocsPerRun(100, func() {
		if n, err := sender.Write(payload[:]); n != len(payload) || err != nil {
			t.Fatalf("Write = (%d, %v)", n, err)
		}
		if n, err := receiver.Read(buf[:]); n != len(payload) || err != nil || buf != payload {
			t.Fatalf("Read = (%d, %v), payload = %q", n, err, buf)
		}
	})
	if allocs != 0 {
		t.Errorf("Write and payload-only Read = %g allocations per datagram, want 0", allocs)
	}
}

func TestUDPReadIntoEmptyBuffer(t *testing.T) {
	conn, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if n, err := conn.WriteTo([]byte{'x'}, conn.LocalAddr()); n != 1 || err != nil {
		t.Fatalf("WriteTo = (%d, %v)", n, err)
	}
	waitForUDPDatagram(t, conn)
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) with queued datagram = (%d, %v)", n, err)
	}
	checkEmptyUDPQueue(t, conn)
}

func TestConnectedUDPDatagrams(t *testing.T) {
	oversize := make([]byte, 1<<16)
	for _, name := range []string{"UDPConn", "UDPSocket"} {
		t.Run(name, func(t *testing.T) {
			peer, conn := newUDPTestPair(t)
			var rw io.ReadWriter = conn
			if name == "UDPSocket" {
				rw = conn.UDPSocket
			}
			var buf [1]byte
			if n, err := rw.Write(nil); n != 0 || err != nil {
				t.Fatalf("Write(nil) = (%d, %v)", n, err)
			}
			waitForUDPDatagram(t, peer)
			if n, from, err := peer.ReadFrom(buf[:]); n != 0 || from == nil || err != nil {
				t.Fatalf("peer ReadFrom after empty write = (%d, %v, %v)", n, from, err)
			}
			if n, err := peer.WriteTo(nil, conn.LocalAddr()); n != 0 || err != nil {
				t.Fatalf("peer WriteTo(nil) = (%d, %v)", n, err)
			}
			waitForUDPDatagram(t, conn)
			if n, err := rw.Read(buf[:]); n != 0 || err != nil {
				t.Fatalf("Read empty datagram = (%d, %v)", n, err)
			}
			if n, err := peer.WriteTo([]byte{'x'}, conn.LocalAddr()); n != 1 || err != nil {
				t.Fatalf("peer WriteTo = (%d, %v)", n, err)
			}
			waitForUDPDatagram(t, conn)
			if n, err := rw.Read(nil); n != 0 || err != nil {
				t.Fatalf("Read(nil) with queued datagram = (%d, %v)", n, err)
			}
			checkEmptyUDPQueue(t, rw)
			if n, err := rw.Write(oversize); n != 0 || err != sock.ErrMessageTooLarge {
				t.Errorf("Write oversized datagram = (%d, %v), want (0, ErrMessageTooLarge)", n, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if n, err := rw.Write(nil); n != 0 || err != sock.ErrClosed {
				t.Errorf("Write(nil) after Close = (%d, %v), want (0, ErrClosed)", n, err)
			}
		})
	}
}

func TestUnixReadFromUnnamedSender(t *testing.T) {
	t.Chdir(t.TempDir())
	addr := &sock.UnixAddr{Name: "receiver.sock", Net: "unixgram"}
	receiver, err := sock.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	var buf [1]byte
	if n, from, err := receiver.ReadFrom(buf[:]); n != 0 || from != nil || err != iox.ErrWouldBlock {
		t.Errorf("ReadFrom on empty socket = (%d, %#v, %v)", n, from, err)
	}
	sender, err := sock.DialUnix("unixgram", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if n, err := sender.Write([]byte{'x'}); n != 1 || err != nil {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	if n, from, err := receiver.ReadFrom(buf[:]); n != 1 || from != nil || err != nil || buf[0] != 'x' {
		t.Fatalf("ReadFrom = (%d, %#v, %v), payload = %q", n, from, err, buf)
	}
}
