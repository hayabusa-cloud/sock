// ©Hayabusa Cloud Co., Ltd. 2023. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"io"
	"testing"
	"time"

	"code.hybscloud.com/sock"
)

func TestSCTPDialRoundTrip(t *testing.T) {
	const timeout = 3 * time.Second
	dialer := sock.SCTPDialer{Timeout: timeout}
	for _, tc := range []struct {
		name string
		ip   sock.IP
		dial func(*sock.SCTPAddr, *sock.SCTPAddr) (*sock.SCTPConn, error)
	}{
		{"DialSCTP4", sock.IPv4LoopBack, sock.DialSCTP4},
		{"DialSCTP6", sock.IPv6LoopBack, sock.DialSCTP6},
		{"SCTPDialer.Dial4", sock.IPv4LoopBack, dialer.Dial4},
		{"SCTPDialer.Dial6", sock.IPv6LoopBack, dialer.Dial6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := sock.ListenSCTP("sctp", &sock.SCTPAddr{IP: tc.ip})
			if err == sock.ErrProtocolNotSupported || err == sock.ErrAddressFamilyNotSupported || err == sock.ErrAddressNotAvailable {
				t.Skipf("SCTP loopback unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			deadline := time.Now().Add(timeout)
			ln.SetDeadline(deadline)

			client, err := tc.dial(nil, ln.Addr().(*sock.SCTPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			client.SetDeadline(deadline)

			server, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			server.SetDeadline(deadline)

			transferSCTPByte(t, client, server, 'a')
			transferSCTPByte(t, server, client, 'b')
			transferSCTPByte(t, client.FD(), server, 'c')
			if got := client.Protocol(); got != sock.UnderlyingProtocolStream {
				t.Errorf("Protocol() = %v, want %v", got, sock.UnderlyingProtocolStream)
			}
		})
	}
}

func transferSCTPByte(t *testing.T, w io.Writer, r io.Reader, want byte) {
	t.Helper()
	if n, err := w.Write([]byte{want}); n != 1 || err != nil {
		t.Fatalf("Write(%q) = %d, %v", want, n, err)
	}
	var buf [1]byte
	if n, err := r.Read(buf[:]); n != 1 || err != nil || buf[0] != want {
		t.Fatalf("Read after Write(%q) = %q, %d, %v", want, buf[:], n, err)
	}
}
