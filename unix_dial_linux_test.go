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

func TestDialUnixFullAcceptQueue(t *testing.T) {
	for _, network := range []string{"unix", "unixpacket"} {
		t.Run(network, func(t *testing.T) {
			listener, err := sock.ListenUnix(network, &sock.UnixAddr{Net: network})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			// Linux admits one waiting Unix connection at backlog zero.
			if err := listener.Listen(0); err != nil {
				t.Fatal(err)
			}
			remote := listener.Addr().(*sock.UnixAddr)
			queued, err := sock.DialUnix(network, nil, remote)
			if err != nil {
				t.Fatal(err)
			}
			defer queued.Close()

			local := &sock.UnixAddr{Name: remote.Name + "-client", Net: network}
			if conn, err := sock.DialUnix(network, local, remote); conn != nil || err != iox.ErrWouldBlock {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("DialUnix on full queue = (%v, %v), want (nil, ErrWouldBlock)", conn, err)
			}
			first, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()

			// Retrying with the same abstract name also checks that the failed dial closed its socket.
			client, err := sock.DialUnix(network, local, remote)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if n, err := client.Write([]byte{'x'}); n != 1 || err != nil {
				t.Fatalf("Write = (%d, %v)", n, err)
			}
			var buf [1]byte
			if n, err := peer.Read(buf[:]); n != 1 || err != nil || buf[0] != 'x' {
				t.Fatalf("Read = (%d, %v, %q), want x", n, err, buf[:])
			}
		})
	}
}
