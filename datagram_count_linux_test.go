// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"bytes"
	"syscall"
	"testing"
	"unsafe"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
	"code.hybscloud.com/zcall"
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
		{Addr: target, Buffers: [][]byte{oversize}, NN: -1},
	}
	if n, err := conn.SendMessages(msgs); n != 1 || err != nil || msgs[0].N != 1 {
		t.Fatalf("SendMessages = (%d, %v), first datagram size = %d", n, err, msgs[0].N)
	}
	if n, err := conn.SendMessages(msgs[1:]); n != 0 || err != sock.ErrMessageTooLarge {
		t.Errorf("SendMessages oversized suffix = (%d, %v)", n, err)
	}
	if msgs[1].NN != -1 {
		t.Errorf("unsent message NN = %d, want -1", msgs[1].NN)
	}
	if n, _, err := conn.ReadFrom(buf[:]); n != 1 || err != nil || buf[0] != 'x' {
		t.Fatalf("ReadFrom = (%d, %v), payload = %q", n, err, buf)
	}
}

func TestUDPBatchControlCounts(t *testing.T) {
	conn, err := sock.ListenUDP4(&sock.UDPAddr{IP: sock.IPv4LoopBack})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	recvTTL := func(on int32) {
		t.Helper()
		if errno := zcall.Setsockopt(uintptr(conn.FD().Raw()), syscall.IPPROTO_IP, syscall.IP_RECVTTL,
			unsafe.Pointer(&on), unsafe.Sizeof(on)); errno != 0 {
			t.Fatalf("IP_RECVTTL = %d: %v", on, syscall.Errno(errno))
		}
	}
	recvTTL(1)

	ttl := make([]byte, sock.CmsgSpace(4))
	header := (*sock.Cmsghdr)(unsafe.Pointer(&ttl[0]))
	*header = sock.Cmsghdr{Len: uint64(sock.CmsgLen(4)), Level: syscall.IPPROTO_IP, Type: syscall.IP_TTL}
	*(*int32)(sock.CmsgData(header)) = 42
	target := conn.LocalAddr().(*sock.UDPAddr)
	send := []sock.UDPMessage{
		{Addr: target, Buffers: [][]byte{{'a'}}, OOB: ttl},
		{Addr: target, Buffers: [][]byte{{'b'}}, NN: -1},
	}
	if n, err := conn.SendMessages(send); n != 2 || err != nil {
		t.Fatalf("SendMessages = (%d, %v)", n, err)
	}
	if send[0].NN != len(ttl) || send[1].NN != 0 {
		t.Fatalf("send control counts = (%d, %d), want (%d, 0)", send[0].NN, send[1].NN, len(ttl))
	}

	recv := []sock.UDPMessage{
		{Buffers: [][]byte{make([]byte, 1)}, OOB: make([]byte, 64)},
		{Buffers: [][]byte{make([]byte, 1)}, OOB: make([]byte, 1)},
	}
	if n, err := conn.RecvMessages(recv); n != 2 || err != nil {
		t.Fatalf("RecvMessages = (%d, %v)", n, err)
	}
	if recv[0].NN != len(ttl) || recv[0].Flags&sock.MSG_CTRUNC != 0 {
		t.Fatalf("TTL control count = %d, flags = %#x", recv[0].NN, recv[0].Flags)
	}
	if !bytes.Equal(recv[0].OOB[:sock.CmsgLen(4)], ttl[:sock.CmsgLen(4)]) {
		t.Fatal("received TTL control message differs from the one sent")
	}
	if recv[1].NN != 0 || recv[1].Flags&sock.MSG_CTRUNC == 0 {
		t.Fatalf("truncated control count = %d, flags = %#x", recv[1].NN, recv[1].Flags)
	}

	recvTTL(0)
	if n, err := conn.WriteTo([]byte{'c'}, target); n != 1 || err != nil {
		t.Fatalf("WriteTo = (%d, %v)", n, err)
	}
	recv[1].NN = -1
	if n, err := conn.RecvMessagesAdaptive(recv); n != 1 || err != nil {
		t.Fatalf("RecvMessagesAdaptive = (%d, %v)", n, err)
	}
	if recv[0].NN != 0 || len(recv[0].OOB) != 64 || recv[1].NN != -1 {
		t.Fatalf("reused batch: control counts = (%d, %d), buffer length = %d", recv[0].NN, recv[1].NN, len(recv[0].OOB))
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
