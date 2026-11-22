// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock_test

import (
	"testing"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
)

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
	if n, from, err := conn.ReadFrom(buf[:]); n != 0 || err != nil || from == nil || from.String() != target.String() {
		t.Fatalf("ReadFrom empty datagram = (%d, %#v, %v), want sender %v", n, from, err, target)
	}
}

func TestUDPReceiveAllocations(t *testing.T) {
	receiver, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()

	var buf [1]byte
	allocs := testing.AllocsPerRun(100, func() {
		if n, from, err := receiver.ReadFrom(buf[:]); n != 0 || from != nil || err != iox.ErrWouldBlock {
			t.Fatalf("ReadFrom on empty socket = (%d, %#v, %v)", n, from, err)
		}
	})
	if allocs != 0 {
		t.Errorf("ReadFrom on empty socket = %g allocations per call, want 0", allocs)
	}

	sender, err := sock.DialUDP4(nil, receiver.LocalAddr().(*sock.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
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
	if n, err := conn.Read(nil); n != 0 || err != nil {
		t.Fatalf("Read(nil) with queued datagram = (%d, %v)", n, err)
	}
	if n, err := conn.Read(nil); n != 0 || err != iox.ErrWouldBlock {
		t.Fatalf("Read(nil) on empty socket = (%d, %v)", n, err)
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
