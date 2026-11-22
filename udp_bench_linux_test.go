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

	"code.hybscloud.com/sock"
)

func BenchmarkUDPDelivery(b *testing.B) {
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	for _, size := range []int{64, 1200} {
		b.Run(fmt.Sprintf("bytes=%d/impl=sock", size), func(b *testing.B) {
			benchmarkUDPDelivery(b, size, func() (net.PacketConn, error) {
				return sock.ListenUDP4(loopback)
			})
		})
		b.Run(fmt.Sprintf("bytes=%d/impl=net", size), func(b *testing.B) {
			benchmarkUDPDelivery(b, size, func() (net.PacketConn, error) {
				return net.ListenUDP("udp4", loopback)
			})
		})
	}
}

func benchmarkUDPDelivery(b *testing.B, size int, listen func() (net.PacketConn, error)) {
	open := func() net.PacketConn {
		b.Helper()
		conn, err := listen()
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() {
			if err := conn.Close(); err != nil {
				b.Error(err)
			}
		})
		return conn
	}
	sender, receiver := open(), open()
	source := sender.LocalAddr().(*net.UDPAddr)
	target := receiver.LocalAddr()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	// One spare byte lets ReadFrom expose an oversized datagram.
	buf := make([]byte, size+1)
	transfer := func(sequence uint64) {
		// Bound a stalled transfer without updating deadlines on every packet.
		if sequence%1024 == 0 {
			deadline := time.Now().Add(5 * time.Second)
			if err := sender.SetWriteDeadline(deadline); err != nil {
				b.Fatal(err)
			}
			if err := receiver.SetReadDeadline(deadline); err != nil {
				b.Fatal(err)
			}
		}
		binary.BigEndian.PutUint64(payload, sequence)
		n, err := sender.WriteTo(payload, target)
		if err != nil || n != size {
			b.Fatalf("datagram %d: WriteTo = (%d, %v), want %d bytes", sequence, n, err, size)
		}
		n, from, err := receiver.ReadFrom(buf)
		if err != nil || n != size {
			b.Fatalf("datagram %d: ReadFrom = (%d, %v), want %d bytes", sequence, n, err, size)
		}
		peer, ok := from.(*net.UDPAddr)
		if !ok || peer == nil || peer.Port != source.Port || !peer.IP.Equal(source.IP) {
			b.Fatalf("datagram %d: source = %v, want %v", sequence, from, source)
		}
		if !bytes.Equal(buf[:n], payload) {
			b.Fatalf("datagram %d: payload mismatch", sequence)
		}
	}

	transfer(0)
	b.SetBytes(int64(size))
	var delivered uint64
	for b.Loop() {
		transfer(delivered + 1)
		delivered++
	}
	b.ReportMetric(float64(delivered)/b.Elapsed().Seconds(), "datagrams/s")
}
