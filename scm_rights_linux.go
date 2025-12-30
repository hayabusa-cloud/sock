// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// Socket-level control message types.
const (
	SCM_RIGHTS      = 0x01 // File descriptor passing
	SCM_CREDENTIALS = 0x02 // Process credentials
	SCM_SECURITY    = 0x03 // Security label
	SCM_PIDFD       = 0x04 // PID file descriptor
)

// Iovec represents a single I/O vector for scatter/gather I/O.
type Iovec struct {
	Base *byte  // Starting address
	Len  uint64 // Number of bytes
}

// Msghdr represents a message header for sendmsg/recvmsg.
// Matches struct msghdr in Linux.
type Msghdr struct {
	Name       *byte  // Optional address
	Namelen    uint32 // Size of address
	_          [4]byte
	Iov        *Iovec // Scatter/gather array
	Iovlen     uint64 // # elements in iov
	Control    *byte  // Ancillary data
	Controllen uint64 // Ancillary data buffer len
	Flags      int32  // Flags on received message
	_          [4]byte
}

// Cmsghdr represents a control message header.
// Matches struct cmsghdr in Linux.
type Cmsghdr struct {
	Len   uint64 // Data byte count, including header
	Level int32  // Originating protocol
	Type  int32  // Protocol-specific type
}

// SizeofMsghdr is the size of Msghdr.
const SizeofMsghdr = 56

// SizeofCmsghdr is the size of Cmsghdr.
const SizeofCmsghdr = 16

// CmsgAlign aligns a length to the proper boundary.
func CmsgAlign(length int) int {
	return (length + 7) &^ 7
}

// CmsgSpace returns the space needed for a control message with given data length.
func CmsgSpace(length int) int {
	return CmsgAlign(SizeofCmsghdr + length)
}

// CmsgLen returns the length field value for a control message with given data length.
func CmsgLen(length int) int {
	return SizeofCmsghdr + length
}

// CmsgData returns a pointer to the data portion of a control message.
func CmsgData(cmsg *Cmsghdr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + SizeofCmsghdr)
}

// UnixRights creates a control message buffer for passing file descriptors.
// The returned buffer is properly formatted for use with sendmsg.
func UnixRights(fds ...int) []byte {
	datalen := len(fds) * 4
	buflen := CmsgSpace(datalen)
	buf := make([]byte, buflen)

	cmsg := (*Cmsghdr)(unsafe.Pointer(&buf[0]))
	cmsg.Len = uint64(CmsgLen(datalen))
	cmsg.Level = SOL_SOCKET
	cmsg.Type = SCM_RIGHTS

	// Copy file descriptors into the data portion
	// Use byte-by-byte copy to avoid checkptr issues
	dataOffset := SizeofCmsghdr
	for i, fd := range fds {
		fdBytes := (*[4]byte)(unsafe.Pointer(&fd))
		copy(buf[dataOffset+i*4:dataOffset+(i+1)*4], fdBytes[:])
	}

	return buf
}

// ParseUnixRights extracts file descriptors from a received control message buffer.
func ParseUnixRights(buf []byte) []int {
	if len(buf) < SizeofCmsghdr {
		return nil
	}

	var fds []int
	p := 0
	for p+SizeofCmsghdr <= len(buf) {
		cmsg := (*Cmsghdr)(unsafe.Pointer(&buf[p]))
		if cmsg.Len < SizeofCmsghdr {
			break
		}
		msgLen := int(cmsg.Len)
		if p+msgLen > len(buf) {
			break
		}

		if cmsg.Level == SOL_SOCKET && cmsg.Type == SCM_RIGHTS {
			dataLen := msgLen - SizeofCmsghdr
			numFds := dataLen / 4
			dataStart := p + SizeofCmsghdr
			for i := 0; i < numFds; i++ {
				var fd int32
				fdBytes := (*[4]byte)(unsafe.Pointer(&fd))
				copy(fdBytes[:], buf[dataStart+i*4:dataStart+(i+1)*4])
				fds = append(fds, int(fd))
			}
		}

		p += CmsgAlign(msgLen)
	}

	return fds
}

// SendFDs sends file descriptors over a Unix socket.
// The data parameter can be empty but at least 1 byte is typically sent.
func SendFDs(fd *iofd.FD, fds []int, data []byte) (int, error) {
	if len(data) == 0 {
		// sendmsg requires at least some data
		data = []byte{0}
	}

	iov := Iovec{
		Base: &data[0],
		Len:  uint64(len(data)),
	}

	cmsgBuf := UnixRights(fds...)

	msg := Msghdr{
		Iov:        &iov,
		Iovlen:     1,
		Control:    &cmsgBuf[0],
		Controllen: uint64(len(cmsgBuf)),
	}

	n, errno := zcall.Sendmsg(uintptr(fd.Raw()), unsafe.Pointer(&msg), 0)
	if errno != 0 {
		return 0, errFromErrno(errno)
	}
	return int(n), nil
}

// RecvFDs receives file descriptors from a Unix socket.
// Returns the received data, file descriptors, and any error.
func RecvFDs(fd *iofd.FD, dataBuf []byte, maxFDs int) (int, []int, error) {
	if len(dataBuf) == 0 {
		dataBuf = make([]byte, 1)
	}

	iov := Iovec{
		Base: &dataBuf[0],
		Len:  uint64(len(dataBuf)),
	}

	cmsgBuf := make([]byte, CmsgSpace(maxFDs*4))

	msg := Msghdr{
		Iov:        &iov,
		Iovlen:     1,
		Control:    &cmsgBuf[0],
		Controllen: uint64(len(cmsgBuf)),
	}

	n, errno := zcall.Recvmsg(uintptr(fd.Raw()), unsafe.Pointer(&msg), 0)
	if errno != 0 {
		return 0, nil, errFromErrno(errno)
	}

	fds := ParseUnixRights(cmsgBuf[:msg.Controllen])
	return int(n), fds, nil
}

// SendMsg sends a message on a socket.
func SendMsg(fd *iofd.FD, msg *Msghdr, flags int) (int, error) {
	n, errno := zcall.Sendmsg(uintptr(fd.Raw()), unsafe.Pointer(msg), uintptr(flags))
	if errno != 0 {
		return 0, errFromErrno(errno)
	}
	return int(n), nil
}

// RecvMsg receives a message from a socket.
func RecvMsg(fd *iofd.FD, msg *Msghdr, flags int) (int, error) {
	n, errno := zcall.Recvmsg(uintptr(fd.Raw()), unsafe.Pointer(msg), uintptr(flags))
	if errno != 0 {
		return 0, errFromErrno(errno)
	}
	return int(n), nil
}

// Ucred represents Unix credentials passed via SCM_CREDENTIALS.
type Ucred struct {
	Pid uint32 // Process ID
	Uid uint32 // User ID
	Gid uint32 // Group ID
}

// SizeofUcred is the size of Ucred.
const SizeofUcred = 12

// UnixCredentials creates a control message buffer for passing credentials.
func UnixCredentials(cred *Ucred) []byte {
	buflen := CmsgSpace(SizeofUcred)
	buf := make([]byte, buflen)

	cmsg := (*Cmsghdr)(unsafe.Pointer(&buf[0]))
	cmsg.Len = uint64(CmsgLen(SizeofUcred))
	cmsg.Level = SOL_SOCKET
	cmsg.Type = SCM_CREDENTIALS

	// Copy credentials into the data portion
	*(*Ucred)(CmsgData(cmsg)) = *cred

	return buf
}

// ParseUnixCredentials extracts credentials from a received control message buffer.
func ParseUnixCredentials(buf []byte) *Ucred {
	if len(buf) < SizeofCmsghdr {
		return nil
	}

	p := 0
	for p+SizeofCmsghdr <= len(buf) {
		cmsg := (*Cmsghdr)(unsafe.Pointer(&buf[p]))
		if cmsg.Len < SizeofCmsghdr {
			break
		}
		msgLen := int(cmsg.Len)
		if p+msgLen > len(buf) {
			break
		}

		if cmsg.Level == SOL_SOCKET && cmsg.Type == SCM_CREDENTIALS {
			if msgLen >= SizeofCmsghdr+SizeofUcred {
				dataStart := p + SizeofCmsghdr
				var cred Ucred
				credBytes := (*[SizeofUcred]byte)(unsafe.Pointer(&cred))
				copy(credBytes[:], buf[dataStart:dataStart+SizeofUcred])
				return &cred
			}
		}

		p += CmsgAlign(msgLen)
	}

	return nil
}
