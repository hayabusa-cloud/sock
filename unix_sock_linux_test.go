// ©Hayabusa Cloud Co., Ltd. 2022. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux && sock_uds

package sock_test

import (
	"bytes"
	"io"
	"testing"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
)

func TestUnixSocket_ReadWrite(t *testing.T) {
	addr0, err := sock.ResolveUnixAddr("unixpacket", "@")
	if err != nil {
		t.Error(err)
		return
	}
	p := []byte("test0123456789")
	wait := make(chan struct{}, 1)
	go func() {
		lis, err := sock.ListenUnix(addr0)
		if err != nil {
			t.Error(err)
			return
		}
		defer lis.Close()
		wait <- struct{}{}
		conn, err := lis.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		buf := make([]byte, len(p))
		for {
			r := sock.NewMessageReader(conn)
			rn, err := r.Read(buf)
			if err != nil {
				t.Errorf("read message: %v", err)
				return
			}
			if rn != len(p) || !bytes.Equal(p, buf[:rn]) {
				t.Errorf("read message expected %s but got %s", p, buf[:rn])
				return
			}
			w := sock.NewMessageWriter(conn)
			wn, err := w.Write(buf[:rn])
			if err != nil {
				t.Errorf("write message: %v", err)
				return
			}
			if wn != rn {
				t.Errorf("short write")
				return
			}
			break
		}
	}()

	addr1, err := sock.ResolveUnixAddr("unixpacket", "@")
	if err != nil {
		t.Error(err)
		return
	}

	<-wait
	conn, err := sock.DialUnix(addr1, addr0)
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	for sw := sock.NewParamSpinWait(); !sw.Closed(); sw.Once() {
		w := sock.NewMessageWriter(conn)
		n, err := w.Write(p)
		if err != nil {
			t.Error(err)
			return
		}
		if n != len(p) {
			t.Error(io.ErrShortWrite)
			return
		}

		buf := make([]byte, len(p))
		r := sock.NewMessageReader(conn)
		n, err = r.Read(buf)
		if err == iox.ErrWouldBlock {
			continue
		}
		if err != nil {
			t.Error(err)
			return
		}

		if !bytes.Equal(buf, p) {
			t.Errorf("unix socket read expected %s but %s", p, buf)
			return
		}
		break
	}
}
