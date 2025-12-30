// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"os"
	"testing"
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/sock"
	"code.hybscloud.com/zcall"
)

func TestMsghdrSize(t *testing.T) {
	var msg sock.Msghdr
	if unsafe.Sizeof(msg) != sock.SizeofMsghdr {
		t.Errorf("Msghdr size: got %d, want %d", unsafe.Sizeof(msg), sock.SizeofMsghdr)
	}
}

func TestCmsghdrSize(t *testing.T) {
	var cmsg sock.Cmsghdr
	if unsafe.Sizeof(cmsg) != sock.SizeofCmsghdr {
		t.Errorf("Cmsghdr size: got %d, want %d", unsafe.Sizeof(cmsg), sock.SizeofCmsghdr)
	}
}

func TestUcredSize(t *testing.T) {
	var cred sock.Ucred
	if unsafe.Sizeof(cred) != sock.SizeofUcred {
		t.Errorf("Ucred size: got %d, want %d", unsafe.Sizeof(cred), sock.SizeofUcred)
	}
}

func TestCmsgSpace(t *testing.T) {
	// CmsgSpace should include header + aligned data
	space := sock.CmsgSpace(4) // 4 bytes of data (1 fd)
	expected := sock.CmsgAlign(sock.SizeofCmsghdr + 4)
	if space != expected {
		t.Errorf("CmsgSpace(4): got %d, want %d", space, expected)
	}
}

func TestCmsgLen(t *testing.T) {
	// CmsgLen should include header + unaligned data
	length := sock.CmsgLen(4)
	expected := sock.SizeofCmsghdr + 4
	if length != expected {
		t.Errorf("CmsgLen(4): got %d, want %d", length, expected)
	}
}

func TestUnixRights(t *testing.T) {
	// Create a control message for 2 file descriptors
	buf := sock.UnixRights(3, 4)
	if len(buf) < sock.SizeofCmsghdr+8 {
		t.Fatalf("UnixRights buffer too small: %d", len(buf))
	}

	// Parse it back
	fds := sock.ParseUnixRights(buf)
	if len(fds) != 2 {
		t.Fatalf("ParseUnixRights: got %d fds, want 2", len(fds))
	}
	if fds[0] != 3 || fds[1] != 4 {
		t.Errorf("ParseUnixRights: got %v, want [3 4]", fds)
	}
}

func TestSendRecvFDs(t *testing.T) {
	// Create a Unix socket pair
	var fds [2]int32
	errno := zcall.Socketpair(zcall.AF_UNIX, zcall.SOCK_STREAM, 0, &fds)
	if errno != 0 {
		t.Fatalf("Socketpair failed: %v", zcall.Errno(errno))
	}
	fd0 := iofd.NewFD(int(fds[0]))
	fd1 := iofd.NewFD(int(fds[1]))
	defer fd0.Close()
	defer fd1.Close()

	// Create a temporary file to send
	tmpfile, err := os.CreateTemp("", "scm_rights_test")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	// Write something to the file
	_, err = tmpfile.WriteString("hello from fd passing test")
	if err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}

	// Get the fd
	sendFd := int(tmpfile.Fd())

	// Send the file descriptor
	n, err := sock.SendFDs(&fd0, []int{sendFd}, []byte("x"))
	if err != nil {
		t.Fatalf("SendFDs failed: %v", err)
	}
	if n != 1 {
		t.Errorf("SendFDs returned %d, want 1", n)
	}

	// Receive the file descriptor
	buf := make([]byte, 1)
	n, recvFds, err := sock.RecvFDs(&fd1, buf, 1)
	if err != nil {
		t.Fatalf("RecvFDs failed: %v", err)
	}
	if n != 1 {
		t.Errorf("RecvFDs returned %d bytes, want 1", n)
	}
	if len(recvFds) != 1 {
		t.Fatalf("RecvFDs returned %d fds, want 1", len(recvFds))
	}

	// The received fd should be different from the sent one
	recvFd := recvFds[0]
	if recvFd == sendFd {
		t.Error("Received fd should be different from sent fd")
	}

	// Read from the received fd
	recvFile := os.NewFile(uintptr(recvFd), "received")
	defer recvFile.Close()

	// Seek to beginning
	_, err = recvFile.Seek(0, 0)
	if err != nil {
		t.Fatalf("Seek failed: %v", err)
	}

	// Read content
	content := make([]byte, 100)
	n, err = recvFile.Read(content)
	if err != nil {
		t.Fatalf("Read from received fd failed: %v", err)
	}
	expected := "hello from fd passing test"
	if string(content[:n]) != expected {
		t.Errorf("Content mismatch: got %q, want %q", string(content[:n]), expected)
	}
}

func TestSendRecvMultipleFDs(t *testing.T) {
	// Create a Unix socket pair
	var fds [2]int32
	errno := zcall.Socketpair(zcall.AF_UNIX, zcall.SOCK_STREAM, 0, &fds)
	if errno != 0 {
		t.Fatalf("Socketpair failed: %v", zcall.Errno(errno))
	}
	fd0 := iofd.NewFD(int(fds[0]))
	fd1 := iofd.NewFD(int(fds[1]))
	defer fd0.Close()
	defer fd1.Close()

	// Create 3 temporary files
	tmpfiles := make([]*os.File, 3)
	sendFds := make([]int, 3)
	for i := 0; i < 3; i++ {
		tmpfile, err := os.CreateTemp("", "scm_rights_multi_test")
		if err != nil {
			t.Fatalf("CreateTemp failed: %v", err)
		}
		defer os.Remove(tmpfile.Name())
		tmpfiles[i] = tmpfile
		sendFds[i] = int(tmpfile.Fd())
	}

	// Send all 3 file descriptors
	n, err := sock.SendFDs(&fd0, sendFds, []byte("msg"))
	if err != nil {
		t.Fatalf("SendFDs failed: %v", err)
	}
	if n != 3 {
		t.Errorf("SendFDs returned %d, want 3", n)
	}

	// Receive the file descriptors
	buf := make([]byte, 10)
	n, recvFds, err := sock.RecvFDs(&fd1, buf, 3)
	if err != nil {
		t.Fatalf("RecvFDs failed: %v", err)
	}
	if n != 3 {
		t.Errorf("RecvFDs returned %d bytes, want 3", n)
	}
	if len(recvFds) != 3 {
		t.Fatalf("RecvFDs returned %d fds, want 3", len(recvFds))
	}

	// Clean up received fds
	for _, fd := range recvFds {
		zcall.Close(uintptr(fd))
	}

	// Clean up tmpfiles
	for _, f := range tmpfiles {
		f.Close()
	}
}

func TestUnixCredentials(t *testing.T) {
	cred := sock.Ucred{
		Pid: 1234,
		Uid: 1000,
		Gid: 1000,
	}

	buf := sock.UnixCredentials(&cred)
	if len(buf) < sock.SizeofCmsghdr+sock.SizeofUcred {
		t.Fatalf("UnixCredentials buffer too small: %d", len(buf))
	}

	parsed := sock.ParseUnixCredentials(buf)
	if parsed == nil {
		t.Fatal("ParseUnixCredentials returned nil")
	}
	if parsed.Pid != 1234 {
		t.Errorf("Pid: got %d, want 1234", parsed.Pid)
	}
	if parsed.Uid != 1000 {
		t.Errorf("Uid: got %d, want 1000", parsed.Uid)
	}
	if parsed.Gid != 1000 {
		t.Errorf("Gid: got %d, want 1000", parsed.Gid)
	}
}
