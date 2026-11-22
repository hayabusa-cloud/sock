// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"code.hybscloud.com/sock"
)

const benchmarkSocketTimeout = 10 * time.Second

func BenchmarkStreamDelivery(b *testing.B) {
	tcp := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	unix := &net.UnixAddr{Net: "unix"} // Linux assigns an abstract address.

	b.Run("tcp4/impl=sock", func(b *testing.B) {
		l, err := sock.ListenTCP4(tcp)
		if err != nil {
			b.Fatal(err)
		}
		d := sock.TCPDialer{Timeout: benchmarkSocketTimeout}
		benchmarkStreamSizes(b, l, func() (*sock.TCPConn, error) {
			return d.Dial4(nil, l.Addr().(*net.TCPAddr))
		})
	})
	b.Run("tcp4/impl=net", func(b *testing.B) {
		l, err := net.ListenTCP("tcp4", tcp)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkStreamSizes(b, l, func() (net.Conn, error) {
			return net.DialTimeout("tcp4", l.Addr().String(), benchmarkSocketTimeout)
		})
	})
	b.Run("unix/impl=sock", func(b *testing.B) {
		l, err := sock.ListenUnix("unix", unix)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkStreamSizes(b, l, func() (*sock.UnixConn, error) {
			return sock.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
		})
	})
	b.Run("unix/impl=net", func(b *testing.B) {
		l, err := net.ListenUnix("unix", unix)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkStreamSizes(b, l, func() (net.Conn, error) {
			return net.DialTimeout("unix", l.Addr().String(), benchmarkSocketTimeout)
		})
	})
}

func closeBenchmarkSocket(b *testing.B, c io.Closer) {
	if err := c.Close(); err != nil {
		b.Fatal(err)
	}
}

func benchmarkStreamSizes[C net.Conn](b *testing.B, l interface {
	io.Closer
	SetDeadline(time.Time) error
	Accept() (C, error)
}, dial func() (C, error)) {
	defer closeBenchmarkSocket(b, l)
	for _, work := range []struct{ size, write int }{{64, 64}, {1 << 20, 4 << 10}, {1 << 20, 64 << 10}} {
		b.Run(fmt.Sprintf("bytes=%d/write=%d", work.size, work.write), func(b *testing.B) {
			if err := l.SetDeadline(time.Now().Add(benchmarkSocketTimeout)); err != nil {
				b.Fatal(err)
			}
			sender, err := dial()
			if err != nil {
				b.Fatal(err)
			}
			defer closeBenchmarkSocket(b, sender)
			receiver, err := l.Accept()
			if err != nil {
				b.Fatal(err)
			}
			defer closeBenchmarkSocket(b, receiver)
			if tcp, ok := net.Conn(sender).(interface{ SetNoDelay(bool) error }); ok {
				if err := tcp.SetNoDelay(true); err != nil {
					b.Fatal(err)
				}
			}
			benchmarkStreamDelivery(b, sender, receiver, work.size, work.write)
		})
	}
}

// Complete each chunk before starting the next, even after a short read or write.
func transferStream(p []byte, chunkSize int, call func([]byte) (int, error)) error {
	for len(p) > 0 {
		chunk := p[:min(len(p), chunkSize)]
		p = p[len(chunk):]
		for len(chunk) > 0 {
			n, err := call(chunk)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(chunk) {
				return fmt.Errorf("transferred %d bytes from a %d-byte buffer", n, len(chunk))
			}
			chunk = chunk[n:]
		}
	}
	return nil
}

func benchmarkStreamDelivery(b *testing.B, sender, receiver net.Conn, size, writeSize int) {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	buf := make([]byte, size)
	start := make(chan struct{}, 1)
	received := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for range start {
			err := transferStream(buf, 64<<10, receiver.Read)
			if err == nil && !bytes.Equal(buf, payload) {
				err = fmt.Errorf("payload mismatch")
			}
			received <- err
		}
	}()
	defer func() {
		close(start)
		// A failed write may have left the reader waiting for the rest of the frame.
		if err := receiver.SetReadDeadline(time.Now()); err != nil {
			b.Error(err)
		}
		<-stopped
	}()

	transfer := func(sequence uint64) {
		if sequence%64 == 0 {
			deadline := time.Now().Add(benchmarkSocketTimeout)
			if err := sender.SetWriteDeadline(deadline); err != nil {
				b.Fatal(err)
			}
			if err := receiver.SetReadDeadline(deadline); err != nil {
				b.Fatal(err)
			}
		}
		binary.BigEndian.PutUint64(payload, sequence)
		start <- struct{}{}
		if err := transferStream(payload, writeSize, sender.Write); err != nil {
			b.Fatalf("transfer %d write: %v", sequence, err)
		}
		if err := <-received; err != nil {
			b.Fatalf("transfer %d read: %v", sequence, err)
		}
	}

	transfer(0)
	b.SetBytes(int64(size))
	var sequence uint64
	for b.Loop() {
		sequence++
		transfer(sequence)
	}
}
