// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"io"
	"net"
	"testing"
	"time"

	"code.hybscloud.com/sock"
)

func BenchmarkTCPLifecycle(b *testing.B) {
	loopback := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	listenSock := func() (*sock.TCPListener, error) { return sock.ListenTCP4(loopback) }
	listenNet := func() (*net.TCPListener, error) { return net.ListenTCP("tcp4", loopback) }

	b.Run("listen/impl=sock", func(b *testing.B) { benchmarkTCPListen(b, listenSock) })
	b.Run("listen/impl=net", func(b *testing.B) { benchmarkTCPListen(b, listenNet) })
	b.Run("connect/impl=sock", func(b *testing.B) {
		l, err := listenSock()
		if err != nil {
			b.Fatal(err)
		}
		defer closeBenchmarkSocket(b, l)
		target := l.Addr().(*net.TCPAddr)
		d := sock.TCPDialer{Timeout: benchmarkSocketTimeout}
		benchmarkTCPConnections(b, l.SetDeadline, l.Accept, func() (*sock.TCPConn, error) {
			return d.Dial4(nil, target)
		})
	})
	b.Run("connect/impl=net", func(b *testing.B) {
		l, err := listenNet()
		if err != nil {
			b.Fatal(err)
		}
		defer closeBenchmarkSocket(b, l)
		target := l.Addr().String()
		d := net.Dialer{Timeout: benchmarkSocketTimeout}
		benchmarkTCPConnections(b, l.SetDeadline, l.Accept, func() (net.Conn, error) {
			return d.Dial("tcp4", target)
		})
	})
}

func benchmarkTCPListen[L io.Closer](b *testing.B, listen func() (L, error)) {
	listenClose := func() {
		l, err := listen()
		if err != nil {
			b.Fatal(err)
		}
		closeBenchmarkSocket(b, l)
	}
	listenClose()
	for b.Loop() {
		listenClose()
	}
}

func benchmarkTCPConnections[C net.Conn](b *testing.B, setDeadline func(time.Time) error, accept, dial func() (C, error)) {
	connect := func() {
		client, err := dial()
		if err != nil {
			b.Fatal(err)
		}
		defer closeBenchmarkSocket(b, client)
		if err := setDeadline(time.Now().Add(benchmarkSocketTimeout)); err != nil {
			b.Fatal(err)
		}
		server, err := accept()
		if err != nil {
			b.Fatal(err)
		}
		defer closeBenchmarkSocket(b, server)
		if !sameTCPAddr(client.LocalAddr(), server.RemoteAddr()) || !sameTCPAddr(client.RemoteAddr(), server.LocalAddr()) {
			b.Fatalf("dialed %v → %v, accepted %v ← %v", client.LocalAddr(), client.RemoteAddr(), server.LocalAddr(), server.RemoteAddr())
		}
	}
	connect()
	for b.Loop() {
		connect()
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "connections/s")
}

func sameTCPAddr(a, b net.Addr) bool {
	x, y := a.(*net.TCPAddr), b.(*net.TCPAddr)
	return x.Port == y.Port && x.IP.Equal(y.IP)
}
