// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"testing"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
)

func TestUDPDatagramErrorCounts(t *testing.T) {
	conn, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var buf [1]byte
	if n, err := conn.Read(buf[:]); n != 0 || err != iox.ErrWouldBlock {
		t.Errorf("Read on empty socket = (%d, %v)", n, err)
	}
	if n, oobn, _, _, err := conn.ReadMsgUDP(buf[:], nil); n != 0 || oobn != 0 || err != iox.ErrWouldBlock {
		t.Errorf("ReadMsgUDP on empty socket = (%d, %d, %v)", n, oobn, err)
	}
	slot := []sock.UDPMessage{{Buffers: [][]byte{buf[:]}}}
	if n, err := conn.RecvMessages(slot); n != 0 || err != iox.ErrWouldBlock {
		t.Errorf("RecvMessages on empty socket = (%d, %v)", n, err)
	}

	target := conn.LocalAddr().(*sock.UDPAddr)
	oversize := make([]byte, 1<<16)
	if n, err := conn.WriteTo(oversize, target); n != 0 || err != sock.ErrMessageTooLarge {
		t.Errorf("WriteTo oversized datagram = (%d, %v)", n, err)
	}
	if n, oobn, err := conn.WriteMsgUDP(oversize, nil, target); n != 0 || oobn != 0 || err != sock.ErrMessageTooLarge {
		t.Errorf("WriteMsgUDP oversized datagram = (%d, %d, %v)", n, oobn, err)
	}

	// The first datagram succeeds. Retrying the oversized suffix sends nothing.
	msgs := []sock.UDPMessage{
		{Addr: target, Buffers: [][]byte{{'x'}}},
		{Addr: target, Buffers: [][]byte{oversize}},
	}
	if n, err := conn.SendMessages(msgs); n != 1 || err != nil || msgs[0].N != 1 {
		t.Fatalf("SendMessages = (%d, %v), first datagram size = %d", n, err, msgs[0].N)
	}
	if n, err := conn.SendMessages(msgs[1:]); n != 0 || err != sock.ErrMessageTooLarge {
		t.Errorf("SendMessages oversized suffix = (%d, %v)", n, err)
	}
	if n, _, err := conn.ReadFrom(buf[:]); n != 1 || err != nil || buf[0] != 'x' {
		t.Fatalf("ReadFrom = (%d, %v), payload = %q", n, err, buf)
	}
}

func TestUnixDatagramErrorCounts(t *testing.T) {
	conn, err := sock.ListenUnixgram("unixgram", &sock.UnixAddr{Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if n, _, err := conn.ReadFrom(make([]byte, 1)); n != 0 || err != iox.ErrWouldBlock {
		t.Errorf("ReadFrom on empty socket = (%d, %v)", n, err)
	}
	if err := sock.SetSendBuffer(conn.FD(), 4096); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.WriteTo(make([]byte, 1<<16), conn.LocalAddr()); n != 0 || err != sock.ErrMessageTooLarge {
		t.Errorf("WriteTo oversized datagram = (%d, %v)", n, err)
	}
}
