// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build rawsock

package sock_test

import (
	"sync"
	"testing"
	"time"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
	"code.hybscloud.com/zcall"
)

func TestRawDatagramErrorCounts(t *testing.T) {
	addr := &sock.IPAddr{IP: sock.IPv4LoopBack}
	// Use a separate protocol for the empty read on loopback.
	conn, err := sock.ListenRaw4(addr, 253)
	if err == sock.ErrPermission {
		t.Skip("CAP_NET_RAW required")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if n, _, err := conn.RecvFrom(make([]byte, 1)); n != 0 || err != iox.ErrWouldBlock {
		t.Errorf("RecvFrom on empty socket = (%d, %v)", n, err)
	}
	if n, err := conn.SendTo(make([]byte, 1<<16), addr); n != 0 || err != sock.ErrMessageTooLarge {
		t.Errorf("SendTo oversized packet = (%d, %v)", n, err)
	}
}

func TestRawSocket_ReadWrite(t *testing.T) {
	t.Skip("ICMP loopback unreliable on some kernels; covered by coverage_test.go")
	addr0, err := sock.ResolveIPAddr("ip4", "127.0.0.1")
	if err != nil {
		t.Error(err)
		return
	}

	p := []byte{8, 0, 0, 0, 0, 1, 0, 1}
	wg := sync.WaitGroup{}
	skip := false

	wg.Add(1)
	go func() {
		lis, err := sock.ListenRaw4(addr0, zcall.IPPROTO_ICMP)
		if err != nil {
			skip = true
			wg.Done()
			return
		}
		defer func(lis *sock.RawConn) {
			_ = lis.Close()
		}(lis)
		wg.Done()

		time.Sleep(100 * time.Millisecond)
		buf := make([]byte, 64)
		n, _, err := lis.RecvFrom(buf)
		if err != nil {
			t.Errorf("recvfrom: %v", err)
			return
		}
		if n > 0 {
			_, err = lis.SendTo(buf[:n], addr0)
			if err != nil {
				t.Errorf("sendto: %v", err)
			}
		}
	}()
	wg.Wait()
	if skip {
		t.Skipf("listen raw4: %v", err)
		return
	}

	addr1, err := sock.ResolveIPAddr("ip4", "127.0.0.2")
	if err != nil {
		t.Error(err)
		return
	}

	conn, err := sock.DialRaw4(addr1, addr0, zcall.IPPROTO_ICMP)
	if err != nil {
		t.Skipf("dial raw4: %v", err)
		return
	}
	defer func(conn *sock.RawConn) {
		_ = conn.Close()
	}(conn)

	n, err := conn.Write(p)
	if err != nil {
		t.Error(err)
		return
	}
	if n != len(p) {
		t.Errorf("expected %d bytes but wrote %d", len(p), n)
	}

	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
}
