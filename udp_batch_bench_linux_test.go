// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
)

type udpMessageCall func(*sock.UDPConn, []sock.UDPMessage) (int, error)

func BenchmarkUDPBatch(b *testing.B) {
	for _, work := range []struct{ size, burst int }{{64, 1}, {64, 8}, {64, 32}, {1200, 8}} {
		name := fmt.Sprintf("bytes=%d/burst=%d", work.size, work.burst)
		b.Run(name+"/impl=batch", func(b *testing.B) {
			benchmarkUDPBatch(b, work.size, work.burst, (*sock.UDPConn).SendMessages, (*sock.UDPConn).RecvMessages)
		})
		b.Run(name+"/impl=scalar", func(b *testing.B) {
			benchmarkUDPBatch(b, work.size, work.burst, writeOneUDPMessage, readOneUDPMessage)
		})
	}
}

func writeOneUDPMessage(conn *sock.UDPConn, msgs []sock.UDPMessage) (int, error) {
	msg := &msgs[0]
	var err error
	msg.N, _, err = conn.WriteMsgUDP(msg.Buffers[0], nil, msg.Addr)
	if err != nil && msg.N <= 0 {
		return 0, err
	}
	return 1, err
}

func readOneUDPMessage(conn *sock.UDPConn, msgs []sock.UDPMessage) (int, error) {
	msg := &msgs[0]
	var err error
	msg.N, _, msg.Flags, msg.Addr, err = conn.ReadMsgUDP(msg.Buffers[0], nil)
	if err != nil && msg.N <= 0 {
		return 0, err
	}
	return 1, err
}

// transferUDPMessages advances only over the completed prefix and counts every API call.
func transferUDPMessages(b *testing.B, direction string, call udpMessageCall, conn *sock.UDPConn, msgs []sock.UDPMessage) int {
	var calls int
	var deadline time.Time
	var backoff iox.Backoff
	for len(msgs) > 0 {
		n, err := call(conn, msgs)
		calls++
		if n > len(msgs) || (n <= 0 && err == nil) {
			b.Fatalf("%s: got count %d for %d remaining messages, err %v", direction, n, len(msgs), err)
		}
		if n > 0 {
			msgs = msgs[n:]
		}
		if err == nil {
			continue
		}
		if err != iox.ErrWouldBlock && err != sock.ErrInterrupted {
			b.Fatalf("%s: %v", direction, err)
		}
		if len(msgs) == 0 {
			break
		}
		now := time.Now()
		if deadline.IsZero() {
			deadline = now.Add(5 * time.Second)
		}
		if !now.Before(deadline) {
			b.Fatalf("%s: %d messages still pending: %v", direction, len(msgs), err)
		}
		if err == iox.ErrWouldBlock {
			backoff.Wait()
		}
	}
	return calls
}

func benchmarkUDPBatch(b *testing.B, size, burst int, send, receive udpMessageCall) {
	listen := func() (*sock.UDPConn, error) {
		return sock.ListenUDP4(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	}
	sender := openBenchmarkUDP(b, listen)
	receiver := openBenchmarkUDP(b, listen)
	source := sender.LocalAddr().(*net.UDPAddr)
	target := receiver.LocalAddr().(*net.UDPAddr)
	out := make([]sock.UDPMessage, burst)
	in := make([]sock.UDPMessage, burst)
	for i := range out {
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(j)
		}
		out[i] = sock.UDPMessage{Addr: target, Buffers: [][]byte{payload}}
		in[i].Buffers = [][]byte{make([]byte, size)}
	}
	seen := make([]bool, burst)
	transfer := func(first uint64) (int, int) {
		for i := range out {
			out[i].N, in[i].N = 0, 0
			in[i].Addr = nil
			binary.BigEndian.PutUint64(out[i].Buffers[0], first+uint64(i))
		}
		sends := transferUDPMessages(b, "send", send, sender, out)
		receives := transferUDPMessages(b, "receive", receive, receiver, in)

		clear(seen)
		for i := range in {
			msg := &in[i]
			if out[i].N != size || msg.N != size || msg.Flags&(sock.MSG_TRUNC|sock.MSG_CTRUNC) != 0 {
				b.Fatalf("burst entry %d: sent %d bytes, read %d, flags %#x, want %d bytes", i, out[i].N, msg.N, msg.Flags, size)
			}
			if msg.Addr == nil || msg.Addr.Port != source.Port || !msg.Addr.IP.Equal(source.IP) {
				b.Fatalf("burst entry %d: source = %v, want %v", i, msg.Addr, source)
			}
			data := msg.Buffers[0][:msg.N]
			sequence := binary.BigEndian.Uint64(data)
			if sequence < first || sequence-first >= uint64(burst) {
				b.Fatalf("sequence %d outside burst starting at %d", sequence, first)
			}
			slot := sequence - first
			if seen[slot] {
				b.Fatalf("duplicate datagram %d", sequence)
			}
			if !bytes.Equal(data, out[slot].Buffers[0]) {
				b.Fatalf("datagram %d: payload mismatch", sequence)
			}
			seen[slot] = true
		}
		return sends, receives
	}

	transfer(0)
	b.SetBytes(int64(size * burst))
	b.ReportAllocs()
	var delivered, sendCalls, receiveCalls uint64
	for b.Loop() {
		sends, receives := transfer(delivered + uint64(burst))
		delivered += uint64(burst)
		sendCalls += uint64(sends)
		receiveCalls += uint64(receives)
	}
	elapsed := b.Elapsed()
	b.ReportMetric(float64(delivered)/elapsed.Seconds(), "datagrams/s")
	b.ReportMetric(float64(elapsed.Nanoseconds())/float64(delivered), "ns/datagram")
	b.ReportMetric(float64(delivered)/float64(sendCalls), "datagrams/send-call")
	b.ReportMetric(float64(delivered)/float64(receiveCalls), "datagrams/recv-call")
}
