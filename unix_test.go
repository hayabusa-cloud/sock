// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"code.hybscloud.com/iox"
)

// seqpacketSupported reports whether SOCK_SEQPACKET is supported on this platform.
// macOS/darwin does not support SOCK_SEQPACKET for Unix domain sockets.
func seqpacketSupported() bool {
	return runtime.GOOS != "darwin"
}

var testSeq atomic.Uint64

func uniqAddr(prefix, net string) *UnixAddr {
	seq := testSeq.Add(1)
	name := fmt.Sprintf("@%s-%d-%s", prefix, seq, time.Now().Format("150405.000"))
	return &UnixAddr{Name: name, Net: net}
}

func TestNewUnixSockets(t *testing.T) {
	t.Run("stream", func(t *testing.T) {
		sock, err := NewUnixStreamSocket()
		if err != nil {
			t.Fatalf("NewUnixStreamSocket: %v", err)
		}
		defer sock.Close()
		if sock.Protocol() != UnderlyingProtocolStream {
			t.Errorf("expected Stream protocol, got %v", sock.Protocol())
		}
	})

	t.Run("dgram", func(t *testing.T) {
		sock, err := NewUnixDatagramSocket()
		if err != nil {
			t.Fatalf("NewUnixDatagramSocket: %v", err)
		}
		defer sock.Close()
		if sock.Protocol() != UnderlyingProtocolDgram {
			t.Errorf("expected Dgram protocol, got %v", sock.Protocol())
		}
	})

	t.Run("seqpacket", func(t *testing.T) {
		if !seqpacketSupported() {
			t.Skip("SOCK_SEQPACKET not supported on this platform")
		}
		sock, err := NewUnixSeqpacketSocket()
		if err != nil {
			t.Fatalf("NewUnixSeqpacketSocket: %v", err)
		}
		defer sock.Close()
		if sock.Protocol() != UnderlyingProtocolSeqPacket {
			t.Errorf("expected SeqPacket protocol, got %v", sock.Protocol())
		}
	})
}

func TestListenUnix(t *testing.T) {
	t.Run("nil_addr", func(t *testing.T) {
		_, err := ListenUnix("unix", nil)
		if err != ErrInvalidParam {
			t.Errorf("expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("unknown_network", func(t *testing.T) {
		addr := uniqAddr("listen", "unix")
		_, err := ListenUnix("invalid", addr)
		if _, ok := err.(UnknownNetworkError); !ok {
			t.Errorf("expected UnknownNetworkError, got %v", err)
		}
	})

	t.Run("unix_stream", func(t *testing.T) {
		addr := uniqAddr("listen", "unix")
		lis, err := ListenUnix("unix", addr)
		if err != nil {
			t.Fatalf("ListenUnix: %v", err)
		}
		defer lis.Close()
		if lis.Addr() == nil {
			t.Error("Addr() returned nil")
		}
	})

	t.Run("unixgram", func(t *testing.T) {
		addr := uniqAddr("listen", "unixgram")
		lis, err := ListenUnix("unixgram", addr)
		if err != nil {
			t.Fatalf("ListenUnix unixgram: %v", err)
		}
		defer lis.Close()
	})

	t.Run("unixpacket", func(t *testing.T) {
		if !seqpacketSupported() {
			t.Skip("SOCK_SEQPACKET not supported on this platform")
		}
		addr := uniqAddr("listen", "unixpacket")
		lis, err := ListenUnix("unixpacket", addr)
		if err != nil {
			t.Fatalf("ListenUnix unixpacket: %v", err)
		}
		defer lis.Close()
	})
}

func TestListenUnixgramErrors(t *testing.T) {
	t.Run("nil_addr", func(t *testing.T) {
		_, err := ListenUnixgram("unixgram", nil)
		if err != ErrInvalidParam {
			t.Errorf("expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("wrong_network", func(t *testing.T) {
		addr := uniqAddr("gram", "unix")
		_, err := ListenUnixgram("unix", addr)
		if _, ok := err.(UnknownNetworkError); !ok {
			t.Errorf("expected UnknownNetworkError, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		addr := uniqAddr("gram", "unixgram")
		conn, err := ListenUnixgram("unixgram", addr)
		if err != nil {
			t.Fatalf("ListenUnixgram: %v", err)
		}
		defer conn.Close()
		if conn.LocalAddr() == nil {
			t.Error("LocalAddr() returned nil")
		}
		// RemoteAddr returns typed nil (*UnixAddr) for unconnected sockets
		raddr := conn.RemoteAddr()
		if raddr != nil {
			if ua, ok := raddr.(*UnixAddr); ok && ua != nil {
				t.Error("RemoteAddr() should be nil for unconnected socket")
			}
		}
	})
}

func TestDialUnix(t *testing.T) {
	t.Run("nil_raddr", func(t *testing.T) {
		_, err := DialUnix("unix", nil, nil)
		if err != ErrInvalidParam {
			t.Errorf("expected ErrInvalidParam, got %v", err)
		}
	})

	t.Run("unknown_network", func(t *testing.T) {
		raddr := uniqAddr("dial", "unix")
		_, err := DialUnix("invalid", nil, raddr)
		if _, ok := err.(UnknownNetworkError); !ok {
			t.Errorf("expected UnknownNetworkError, got %v", err)
		}
	})

	t.Run("unix_stream", func(t *testing.T) {
		addr := uniqAddr("dial", "unix")
		lis, err := ListenUnix("unix", addr)
		if err != nil {
			t.Fatalf("ListenUnix: %v", err)
		}
		defer lis.Close()

		conn, err := DialUnix("unix", nil, addr)
		if err != nil {
			t.Fatalf("DialUnix: %v", err)
		}
		defer conn.Close()
	})

	t.Run("unixgram", func(t *testing.T) {
		raddr := uniqAddr("dial-srv", "unixgram")
		lis, err := ListenUnixgram("unixgram", raddr)
		if err != nil {
			t.Fatalf("ListenUnixgram: %v", err)
		}
		defer lis.Close()

		laddr := uniqAddr("dial-cli", "unixgram")
		conn, err := DialUnix("unixgram", laddr, raddr)
		if err != nil {
			t.Fatalf("DialUnix unixgram: %v", err)
		}
		defer conn.Close()
	})

	t.Run("unixpacket", func(t *testing.T) {
		if !seqpacketSupported() {
			t.Skip("SOCK_SEQPACKET not supported on this platform")
		}
		addr := uniqAddr("dial", "unixpacket")
		lis, err := ListenUnix("unixpacket", addr)
		if err != nil {
			t.Fatalf("ListenUnix: %v", err)
		}
		defer lis.Close()

		conn, err := DialUnix("unixpacket", nil, addr)
		if err != nil {
			t.Fatalf("DialUnix unixpacket: %v", err)
		}
		defer conn.Close()
	})
}

func TestUnixConnPairVariants(t *testing.T) {
	t.Run("unknown_network", func(t *testing.T) {
		_, err := UnixConnPair("invalid")
		if _, ok := err.(UnknownNetworkError); !ok {
			t.Errorf("expected UnknownNetworkError, got %v", err)
		}
	})

	t.Run("unix_stream", func(t *testing.T) {
		pair, err := UnixConnPair("unix")
		if err != nil {
			t.Fatalf("UnixConnPair: %v", err)
		}
		defer pair[0].Close()
		defer pair[1].Close()

		// Test communication
		msg := []byte("hello")
		pair[0].SetWriteDeadline(time.Now().Add(time.Second))
		n, err := pair[0].Write(msg)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(msg) {
			t.Errorf("short write: %d", n)
		}

		buf := make([]byte, 16)
		pair[1].SetReadDeadline(time.Now().Add(time.Second))
		n, err = pair[1].Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if string(buf[:n]) != "hello" {
			t.Errorf("expected 'hello', got %q", buf[:n])
		}
	})

	t.Run("unixgram", func(t *testing.T) {
		pair, err := UnixConnPair("unixgram")
		if err != nil {
			t.Fatalf("UnixConnPair unixgram: %v", err)
		}
		defer pair[0].Close()
		defer pair[1].Close()
	})

	t.Run("unixpacket", func(t *testing.T) {
		if !seqpacketSupported() {
			t.Skip("SOCK_SEQPACKET not supported on this platform")
		}
		pair, err := UnixConnPair("unixpacket")
		if err != nil {
			t.Fatalf("UnixConnPair unixpacket: %v", err)
		}
		defer pair[0].Close()
		defer pair[1].Close()
	})
}

func TestUnixConnDeadlines(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}
	defer pair[0].Close()
	defer pair[1].Close()

	conn := pair[0]

	// Test SetDeadline
	err = conn.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	// Test SetReadDeadline
	err = conn.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("SetReadDeadline: %v", err)
	}

	// Test SetWriteDeadline
	err = conn.SetWriteDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("SetWriteDeadline: %v", err)
	}

	// Test clearing deadlines
	err = conn.SetDeadline(time.Time{})
	if err != nil {
		t.Errorf("SetDeadline zero: %v", err)
	}
}

func TestUnixListenerAcceptSocket(t *testing.T) {
	addr := uniqAddr("accept", "unix")
	lis, err := ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer lis.Close()

	// Set deadline so accept doesn't block
	lis.SetDeadline(time.Now().Add(100 * time.Millisecond))

	// AcceptSocket should return error when no connection pending
	_, err = lis.AcceptSocket()
	if err != iox.ErrWouldBlock && err != ErrTimedOut {
		t.Errorf("expected ErrWouldBlock or ErrTimedOut, got %v", err)
	}
}

func TestUnixConnReadWriteClosed(t *testing.T) {
	pair, err := UnixConnPair("unix")
	if err != nil {
		t.Fatalf("UnixConnPair: %v", err)
	}

	// Close both ends
	pair[0].Close()
	pair[1].Close()

	// Read from closed should fail
	buf := make([]byte, 16)
	_, err = pair[0].Read(buf)
	if err != ErrClosed {
		t.Errorf("Read on closed: expected ErrClosed, got %v", err)
	}

	// Write to closed should fail
	_, err = pair[0].Write([]byte("test"))
	if err != ErrClosed {
		t.Errorf("Write on closed: expected ErrClosed, got %v", err)
	}
}

func TestUnixConnReadFromWriteTo(t *testing.T) {
	// Create unconnected datagram sockets
	addr1 := uniqAddr("rfwt1", "unixgram")
	addr2 := uniqAddr("rfwt2", "unixgram")

	conn1, err := ListenUnixgram("unixgram", addr1)
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer conn1.Close()

	conn2, err := ListenUnixgram("unixgram", addr2)
	if err != nil {
		t.Fatalf("ListenUnixgram: %v", err)
	}
	defer conn2.Close()

	// WriteTo with invalid address type
	_, err = conn1.WriteTo([]byte("test"), &TCPAddr{})
	if err != ErrInvalidParam {
		t.Errorf("WriteTo invalid addr: expected ErrInvalidParam, got %v", err)
	}

	// WriteTo success
	conn1.SetWriteDeadline(time.Now().Add(time.Second))
	n, err := conn1.WriteTo([]byte("hello"), addr2)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != 5 {
		t.Errorf("WriteTo short write: %d", n)
	}

	// ReadFrom success
	buf := make([]byte, 16)
	conn2.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := conn2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 5 || string(buf[:n]) != "hello" {
		t.Errorf("ReadFrom: got %q", buf[:n])
	}
	if from == nil {
		t.Error("ReadFrom: from addr is nil")
	}
}

func TestUnixListenerSetDeadline(t *testing.T) {
	addr := uniqAddr("deadline", "unix")
	lis, err := ListenUnix("unix", addr)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer lis.Close()

	// Set deadline
	err = lis.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Errorf("SetDeadline: %v", err)
	}

	// Clear deadline
	err = lis.SetDeadline(time.Time{})
	if err != nil {
		t.Errorf("SetDeadline zero: %v", err)
	}
}

func TestDecodeUnixAddrNil(t *testing.T) {
	addr := decodeUnixAddr(nil, 0)
	if addr != nil {
		t.Error("decodeUnixAddr(nil) should return nil")
	}
}
