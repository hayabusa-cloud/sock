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

func BenchmarkWouldBlock(b *testing.B) {
	b.Run("empty-stream-read", func(b *testing.B) {
		c := openBenchmarkUnixPair(b, "unix")[0]
		benchmarkWouldBlock(b, make([]byte, 1), c.Read, c.FD().Read)
	})
	b.Run("full-datagram-write", func(b *testing.B) {
		c := openBenchmarkUnixPair(b, "unixgram")[0]
		if err := sock.SetSendBuffer(c.FD(), 4096); err != nil {
			b.Fatal(err)
		}
		payload := make([]byte, 2048)
		deadline := time.Now().Add(benchmarkSocketTimeout)
		for {
			n, err := c.Write(payload)
			if err == iox.ErrWouldBlock && (n == 0 || n == -1) {
				break
			}
			if err != nil || n != len(payload) {
				b.Fatalf("fill datagram queue: Write = (%d, %v)", n, err)
			}
			if time.Now().After(deadline) {
				b.Fatal("datagram queue did not fill")
			}
		}
		benchmarkWouldBlock(b, payload, c.Write, c.FD().Write)
	})
}

// The socket and descriptor cases use the same endpoint while its peer stays idle.
func openBenchmarkUnixPair(b *testing.B, network string) [2]*sock.UnixConn {
	b.Helper()
	pair, err := sock.UnixConnPair(network)
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range pair {
		b.Cleanup(func() { closeBenchmarkSocket(b, c) })
	}
	if err := pair[0].SetDeadline(time.Time{}); err != nil {
		b.Fatal(err)
	}
	return pair
}

func benchmarkWouldBlock(b *testing.B, buf []byte, socket, fd func([]byte) (int, error)) {
	for _, impl := range []struct {
		name string
		call func([]byte) (int, error)
	}{{"sock", socket}, {"iofd", fd}} {
		b.Run("impl="+impl.name, func(b *testing.B) {
			attempt := func() {
				n, err := impl.call(buf)
				if err != iox.ErrWouldBlock || (n != 0 && n != -1) {
					b.Fatalf("got (%d, %v), want no bytes and ErrWouldBlock", n, err)
				}
			}
			attempt()
			for b.Loop() {
				attempt()
			}
		})
	}
}
