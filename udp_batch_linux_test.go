// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"bytes"
	"net"
	"testing"
	"time"

	"code.hybscloud.com/iox"
)

func TestSendRecvMessages(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	// Get actual bound address
	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	clientAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	client, err := ListenUDP4(clientAddr)
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// Prepare messages to send
	msg1Data := []byte("message one")
	msg2Data := []byte("message two")
	msg3Data := []byte("message three")

	sendMsgs := []UDPMessage{
		{Addr: actualAddr, Buffers: [][]byte{msg1Data}},
		{Addr: actualAddr, Buffers: [][]byte{msg2Data}},
		{Addr: actualAddr, Buffers: [][]byte{msg3Data}},
	}

	// Send messages
	n, err := client.SendMessages(sendMsgs)
	if err != nil {
		t.Fatalf("SendMessages: %v", err)
	}
	if n != 3 {
		t.Fatalf("SendMessages: sent %d messages, want 3", n)
	}

	// Verify N field was updated
	for i, msg := range sendMsgs {
		if msg.N == 0 {
			t.Errorf("sendMsgs[%d].N not updated", i)
		}
	}

	// Give messages time to arrive
	time.Sleep(10 * time.Millisecond)

	// Prepare receive buffers
	recvMsgs := []UDPMessage{
		{Buffers: [][]byte{make([]byte, 64)}},
		{Buffers: [][]byte{make([]byte, 64)}},
		{Buffers: [][]byte{make([]byte, 64)}},
	}

	// Receive messages
	n, err = server.RecvMessages(recvMsgs)
	if err != nil {
		t.Fatalf("RecvMessages: %v", err)
	}
	if n < 1 {
		t.Fatalf("RecvMessages: received %d messages, want at least 1", n)
	}

	// Verify received data
	received := make(map[string]bool)
	for i := range n {
		data := recvMsgs[i].Buffers[0][:recvMsgs[i].N]
		received[string(data)] = true

		// Verify address was populated
		if recvMsgs[i].Addr == nil {
			t.Errorf("recvMsgs[%d].Addr is nil", i)
		}
	}

	// Check that at least one expected message was received
	if !received[string(msg1Data)] && !received[string(msg2Data)] && !received[string(msg3Data)] {
		t.Error("none of the expected messages were received")
	}
}

func TestSendMessagesEmpty(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Empty message slice should succeed with 0
	n, err := conn.SendMessages(nil)
	if err != nil {
		t.Fatalf("SendMessages(nil): %v", err)
	}
	if n != 0 {
		t.Errorf("SendMessages(nil): got %d, want 0", n)
	}

	n, err = conn.SendMessages([]UDPMessage{})
	if err != nil {
		t.Fatalf("SendMessages([]): %v", err)
	}
	if n != 0 {
		t.Errorf("SendMessages([]): got %d, want 0", n)
	}
}

func TestRecvMessagesEmpty(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Empty message slice should succeed with 0
	n, err := conn.RecvMessages(nil)
	if err != nil {
		t.Fatalf("RecvMessages(nil): %v", err)
	}
	if n != 0 {
		t.Errorf("RecvMessages(nil): got %d, want 0", n)
	}

	n, err = conn.RecvMessages([]UDPMessage{})
	if err != nil {
		t.Fatalf("RecvMessages([]): %v", err)
	}
	if n != 0 {
		t.Errorf("RecvMessages([]): got %d, want 0", n)
	}
}

func TestSendMessagesOnClosed(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	conn.Close()

	msgs := []UDPMessage{{Addr: addr, Buffers: [][]byte{[]byte("test")}}}
	_, err = conn.SendMessages(msgs)
	if err != ErrClosed {
		t.Errorf("SendMessages on closed: got %v, want ErrClosed", err)
	}
}

func TestRecvMessagesOnClosed(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	conn.Close()

	msgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}}}
	_, err = conn.RecvMessages(msgs)
	if err != ErrClosed {
		t.Errorf("RecvMessages on closed: got %v, want ErrClosed", err)
	}
}

func TestRecvMessagesWouldBlock(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// No data available, should return ErrWouldBlock
	msgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}}}
	_, err = conn.RecvMessages(msgs)
	if err != iox.ErrWouldBlock {
		t.Errorf("RecvMessages with no data: got %v, want ErrWouldBlock", err)
	}
}

func TestSendRecvMessagesIPv6(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	server, err := ListenUDP6(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP6: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	clientAddr := &UDPAddr{IP: net.ParseIP("::1"), Port: 0}
	client, err := ListenUDP6(clientAddr)
	if err != nil {
		t.Fatalf("ListenUDP6 client: %v", err)
	}
	defer client.Close()

	// Send a message
	data := []byte("ipv6 test message")
	sendMsgs := []UDPMessage{{Addr: actualAddr, Buffers: [][]byte{data}}}

	n, err := client.SendMessages(sendMsgs)
	if err != nil {
		t.Fatalf("SendMessages IPv6: %v", err)
	}
	if n != 1 {
		t.Fatalf("SendMessages IPv6: sent %d, want 1", n)
	}

	// Wait for message
	time.Sleep(10 * time.Millisecond)

	// Receive
	recvMsgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}}}
	n, err = server.RecvMessages(recvMsgs)
	if err != nil {
		t.Fatalf("RecvMessages IPv6: %v", err)
	}
	if n != 1 {
		t.Fatalf("RecvMessages IPv6: received %d, want 1", n)
	}

	received := recvMsgs[0].Buffers[0][:recvMsgs[0].N]
	if !bytes.Equal(received, data) {
		t.Errorf("RecvMessages IPv6: got %q, want %q", received, data)
	}
}

func TestSendMessagesMultipleBuffers(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	clientAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	client, err := ListenUDP4(clientAddr)
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// Send message with multiple buffers (scatter-gather)
	buf1 := []byte("hello ")
	buf2 := []byte("world")
	sendMsgs := []UDPMessage{{Addr: actualAddr, Buffers: [][]byte{buf1, buf2}}}

	n, err := client.SendMessages(sendMsgs)
	if err != nil {
		t.Fatalf("SendMessages: %v", err)
	}
	if n != 1 {
		t.Fatalf("SendMessages: sent %d, want 1", n)
	}

	// Verify total bytes sent
	expectedLen := len(buf1) + len(buf2)
	if sendMsgs[0].N != expectedLen {
		t.Errorf("SendMessages: N=%d, want %d", sendMsgs[0].N, expectedLen)
	}

	// Wait and receive
	time.Sleep(10 * time.Millisecond)

	recvMsgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}}}
	n, err = server.RecvMessages(recvMsgs)
	if err != nil {
		t.Fatalf("RecvMessages: %v", err)
	}
	if n != 1 {
		t.Fatalf("RecvMessages: received %d, want 1", n)
	}

	received := recvMsgs[0].Buffers[0][:recvMsgs[0].N]
	expected := append(buf1, buf2...)
	if !bytes.Equal(received, expected) {
		t.Errorf("RecvMessages: got %q, want %q", received, expected)
	}
}

func TestSendMessagesAdaptiveNoDeadline(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Without deadline, should work same as non-adaptive
	msgs := []UDPMessage{{Addr: conn.laddr, Buffers: [][]byte{[]byte("test")}}}
	n, err := conn.SendMessagesAdaptive(msgs)
	if err != nil {
		t.Fatalf("SendMessagesAdaptive: %v", err)
	}
	if n != 1 {
		t.Errorf("SendMessagesAdaptive: sent %d, want 1", n)
	}
}

func TestRecvMessagesAdaptiveNoDeadline(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Without deadline, should return ErrWouldBlock immediately
	msgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}}}
	_, err = conn.RecvMessagesAdaptive(msgs)
	if err != iox.ErrWouldBlock {
		t.Errorf("RecvMessagesAdaptive no data: got %v, want ErrWouldBlock", err)
	}
}

func TestRecvMessagesAdaptiveTimeout(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set short deadline
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))

	msgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}}}
	_, err = conn.RecvMessagesAdaptive(msgs)
	if err != ErrTimedOut {
		t.Errorf("RecvMessagesAdaptive with deadline: got %v, want ErrTimedOut", err)
	}
}

func TestUDPMessageType(t *testing.T) {
	// Test UDPMessage zero value
	var msg UDPMessage
	if msg.Addr != nil {
		t.Error("zero UDPMessage.Addr should be nil")
	}
	if msg.Buffers != nil {
		t.Error("zero UDPMessage.Buffers should be nil")
	}
	if msg.OOB != nil {
		t.Error("zero UDPMessage.OOB should be nil")
	}
	if msg.Flags != 0 {
		t.Error("zero UDPMessage.Flags should be 0")
	}
	if msg.N != 0 {
		t.Error("zero UDPMessage.N should be 0")
	}
}

func TestEncodeSockaddr(t *testing.T) {
	// Test IPv4
	addr4 := &UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var raw4 RawSockaddrAny
	encodeSockaddr(addr4, &raw4)
	if raw4.Addr.Family != AF_INET {
		t.Errorf("IPv4 family: got %d, want %d", raw4.Addr.Family, AF_INET)
	}

	// Test IPv6
	addr6 := &UDPAddr{IP: net.ParseIP("::1"), Port: 9090}
	var raw6 RawSockaddrAny
	encodeSockaddr(addr6, &raw6)
	if raw6.Addr.Family != AF_INET6 {
		t.Errorf("IPv6 family: got %d, want %d", raw6.Addr.Family, AF_INET6)
	}

	// Test nil addr
	var rawNil RawSockaddrAny
	encodeSockaddr(nil, &rawNil)
	if rawNil.Addr.Family != 0 {
		t.Errorf("nil addr family: got %d, want 0", rawNil.Addr.Family)
	}
}

func TestSendMessagesAdaptiveExpiredDeadline(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set already expired deadline
	conn.SetWriteDeadline(time.Now().Add(-1 * time.Second))

	// UDP send rarely blocks, so the adaptive function will succeed
	// on the first call (before checking the deadline).
	// This test verifies the normal path through SendMessagesAdaptive.
	msgs := []UDPMessage{{Addr: conn.laddr, Buffers: [][]byte{[]byte("test")}}}
	n, err := conn.SendMessagesAdaptive(msgs)
	if err != nil {
		t.Fatalf("SendMessagesAdaptive: %v", err)
	}
	if n != 1 {
		t.Errorf("SendMessagesAdaptive: sent %d, want 1", n)
	}
}

func TestSendMessagesAdaptiveTimeout(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set short deadline
	conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))

	// Try to send - should succeed without hitting timeout since UDP rarely blocks
	msgs := []UDPMessage{{Addr: conn.laddr, Buffers: [][]byte{[]byte("test")}}}
	n, err := conn.SendMessagesAdaptive(msgs)
	if err != nil {
		t.Fatalf("SendMessagesAdaptive: %v", err)
	}
	if n != 1 {
		t.Errorf("SendMessagesAdaptive: sent %d, want 1", n)
	}
}

func TestRecvMessagesAdaptiveSuccess(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	clientAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	client, err := ListenUDP4(clientAddr)
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// Set a deadline on server
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// Send from client in background after a small delay
	go func() {
		time.Sleep(10 * time.Millisecond)
		msgs := []UDPMessage{{Addr: actualAddr, Buffers: [][]byte{[]byte("hello")}}}
		client.SendMessages(msgs)
	}()

	// Receive with adaptive - should succeed after backoff
	recvMsgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}}}
	n, err := server.RecvMessagesAdaptive(recvMsgs)
	if err != nil {
		t.Fatalf("RecvMessagesAdaptive: %v", err)
	}
	if n != 1 {
		t.Fatalf("RecvMessagesAdaptive: received %d, want 1", n)
	}

	received := string(recvMsgs[0].Buffers[0][:recvMsgs[0].N])
	if received != "hello" {
		t.Errorf("RecvMessagesAdaptive: got %q, want %q", received, "hello")
	}
}

func TestRecvMessagesAdaptiveAlreadyExpired(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Set already expired deadline
	conn.SetReadDeadline(time.Now().Add(-1 * time.Second))

	msgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}}}
	_, err = conn.RecvMessagesAdaptive(msgs)
	if err != ErrTimedOut {
		t.Errorf("RecvMessagesAdaptive with expired deadline: got %v, want ErrTimedOut", err)
	}
}

func TestSendMessagesWithOOB(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	clientAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	client, err := ListenUDP4(clientAddr)
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// Send with OOB data (control message)
	// Note: Sending with uninitialized control message may fail with EINVAL.
	// This test verifies the code path handles OOB correctly.
	oob := make([]byte, 24)
	sendMsgs := []UDPMessage{{Addr: actualAddr, Buffers: [][]byte{[]byte("test")}, OOB: oob}}

	n, err := client.SendMessages(sendMsgs)
	// OOB with invalid control message may return EINVAL, which is acceptable
	if err != nil && err != ErrInvalidParam {
		t.Fatalf("SendMessages with OOB: %v", err)
	}
	if err == nil && n != 1 {
		t.Errorf("SendMessages with OOB: sent %d, want 1", n)
	}
}

func TestRecvMessagesWithOOB(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	clientAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	client, err := ListenUDP4(clientAddr)
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// Send
	sendMsgs := []UDPMessage{{Addr: actualAddr, Buffers: [][]byte{[]byte("test")}}}
	client.SendMessages(sendMsgs)

	time.Sleep(10 * time.Millisecond)

	// Receive with OOB buffer
	oob := make([]byte, 64)
	recvMsgs := []UDPMessage{{Buffers: [][]byte{make([]byte, 64)}, OOB: oob}}

	n, err := server.RecvMessages(recvMsgs)
	if err != nil {
		t.Fatalf("RecvMessages with OOB: %v", err)
	}
	if n != 1 {
		t.Errorf("RecvMessages with OOB: received %d, want 1", n)
	}
}

func TestSendMessagesEmptyBuffers(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	clientAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	client, err := ListenUDP4(clientAddr)
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// Send with empty buffers slice
	sendMsgs := []UDPMessage{{Addr: actualAddr, Buffers: [][]byte{}}}

	n, err := client.SendMessages(sendMsgs)
	if err != nil {
		t.Fatalf("SendMessages empty buffers: %v", err)
	}
	if n != 1 {
		t.Errorf("SendMessages empty buffers: sent %d, want 1", n)
	}
}

func TestSendMessagesNilBufferInSlice(t *testing.T) {
	// Create server
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Create client
	clientAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	client, err := ListenUDP4(clientAddr)
	if err != nil {
		t.Fatalf("ListenUDP4 client: %v", err)
	}
	defer client.Close()

	// Send with nil buffer in the slice (zero-length buffer)
	var nilBuf []byte
	sendMsgs := []UDPMessage{{Addr: actualAddr, Buffers: [][]byte{nilBuf, []byte("data")}}}

	n, err := client.SendMessages(sendMsgs)
	if err != nil {
		t.Fatalf("SendMessages nil buffer: %v", err)
	}
	if n != 1 {
		t.Errorf("SendMessages nil buffer: sent %d, want 1", n)
	}
}

func TestRecvMessagesEmptyBuffers(t *testing.T) {
	addr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	conn, err := ListenUDP4(addr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer conn.Close()

	// Receive with empty buffers - should return would-block since no data
	recvMsgs := []UDPMessage{{Buffers: [][]byte{}}}
	_, err = conn.RecvMessages(recvMsgs)
	if err != iox.ErrWouldBlock {
		t.Errorf("RecvMessages empty buffers: got %v, want ErrWouldBlock", err)
	}
}

func TestSendMessagesNilAddr(t *testing.T) {
	// Create connected UDP socket
	serverAddr := &UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	server, err := ListenUDP4(serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP4: %v", err)
	}
	defer server.Close()

	actualAddr := server.LocalAddr().(*UDPAddr)

	// Dial creates a connected socket
	client, err := DialUDP4(nil, actualAddr)
	if err != nil {
		t.Fatalf("DialUDP4: %v", err)
	}
	defer client.Close()

	// Send with nil Addr - should work for connected socket
	sendMsgs := []UDPMessage{{Addr: nil, Buffers: [][]byte{[]byte("connected test")}}}

	n, err := client.SendMessages(sendMsgs)
	if err != nil {
		t.Fatalf("SendMessages nil addr: %v", err)
	}
	if n != 1 {
		t.Errorf("SendMessages nil addr: sent %d, want 1", n)
	}
}
