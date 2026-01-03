// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"unsafe"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/zcall"
)

// ReadMsgUDP reads a message from the connection, copying the payload into b
// and the associated out-of-band data into oob. It returns the number of bytes
// copied into b, the number of bytes copied into oob, the flags set on the
// message, and the source address of the message.
//
// This method supports ancillary data (control messages) for advanced use cases
// such as receiving packet info, timestamps, or other socket options.
// The packages golang.org/x/net/ipv4 and golang.org/x/net/ipv6 can be used
// to manipulate IP-level socket options in oob.
//
// By default, this operation is non-blocking and returns iox.ErrWouldBlock
// if no data is available. When a read deadline is set via SetReadDeadline,
// the operation retries with backoff until success or deadline exceeded.
func (c *UDPConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *UDPAddr, err error) {
	n, oobn, flags, addr, err = c.readMsgUDP(b, oob)
	if err != iox.ErrWouldBlock {
		return
	}

	// No deadline set: return immediately (non-blocking contract)
	if !c.deadline.hasReadDeadline() {
		return
	}

	// Check if already expired
	if c.deadline.readExpired() {
		return 0, 0, 0, nil, ErrTimedOut
	}

	// Adapt: retry with backoff until deadline
	var backoff netBackoff
	for {
		backoff.wait()

		n, oobn, flags, addr, err = c.readMsgUDP(b, oob)
		if err != iox.ErrWouldBlock {
			backoff.done()
			return
		}

		if c.deadline.readExpired() {
			return 0, 0, 0, nil, ErrTimedOut
		}
	}
}

func (c *UDPConn) readMsgUDP(b, oob []byte) (n, oobn, flags int, addr *UDPAddr, err error) {
	raw := c.fd.Raw()
	if raw < 0 {
		return 0, 0, 0, nil, ErrClosed
	}

	var rsa RawSockaddrAny
	var iov zcall.Iovec
	if len(b) > 0 {
		iov.Base = &b[0]
		iov.Len = uint64(len(b))
	}

	msg := zcall.Msghdr{
		Name:    (*byte)(unsafe.Pointer(&rsa)),
		Namelen: SizeofSockaddrAny,
		Iov:     &iov,
		Iovlen:  1,
	}
	if len(oob) > 0 {
		msg.Control = &oob[0]
		msg.Controllen = uint64(len(oob))
	}

	rn, errno := zcall.Recvmsg(uintptr(raw), unsafe.Pointer(&msg), 0)
	if errno != 0 {
		return int(rn), 0, 0, nil, errFromErrno(errno)
	}

	return int(rn), int(msg.Controllen), int(msg.Flags), decodeUDPAddr(&rsa), nil
}

// WriteMsgUDP writes a message to addr via c if c isn't connected, or to c's
// remote address if c is connected (in which case addr must be nil). The payload
// is copied from b and the associated out-of-band data is copied from oob.
// It returns the number of payload and out-of-band bytes written.
//
// This method supports ancillary data (control messages) for advanced use cases
// such as setting packet info, timestamps, or other socket options.
// The packages golang.org/x/net/ipv4 and golang.org/x/net/ipv6 can be used
// to manipulate IP-level socket options in oob.
//
// By default, this operation is non-blocking and returns iox.ErrWouldBlock
// if the socket buffer is full. When a write deadline is set via SetWriteDeadline,
// the operation retries with backoff until success or deadline exceeded.
func (c *UDPConn) WriteMsgUDP(b, oob []byte, addr *UDPAddr) (n, oobn int, err error) {
	n, oobn, err = c.writeMsgUDP(b, oob, addr)
	if err != iox.ErrWouldBlock {
		return
	}

	// No deadline set: return immediately (non-blocking contract)
	if !c.deadline.hasWriteDeadline() {
		return
	}

	// Check if already expired
	if c.deadline.writeExpired() {
		return 0, 0, ErrTimedOut
	}

	// Adapt: retry with backoff until deadline
	var backoff netBackoff
	for {
		backoff.wait()

		n, oobn, err = c.writeMsgUDP(b, oob, addr)
		if err != iox.ErrWouldBlock {
			backoff.done()
			return
		}

		if c.deadline.writeExpired() {
			return 0, 0, ErrTimedOut
		}
	}
}

func (c *UDPConn) writeMsgUDP(b, oob []byte, addr *UDPAddr) (n, oobn int, err error) {
	raw := c.fd.Raw()
	if raw < 0 {
		return 0, 0, ErrClosed
	}

	var iov zcall.Iovec
	if len(b) > 0 {
		iov.Base = &b[0]
		iov.Len = uint64(len(b))
	}

	msg := zcall.Msghdr{
		Iov:    &iov,
		Iovlen: 1,
	}

	// Set destination address if provided
	if addr != nil {
		var sa Sockaddr
		if addr.IP.To4() != nil {
			sa = udpAddrToSockaddr4(addr)
		} else {
			sa = udpAddrToSockaddr6(addr)
		}
		ptr, length := sa.Raw()
		msg.Name = (*byte)(ptr)
		msg.Namelen = length
	}

	if len(oob) > 0 {
		msg.Control = &oob[0]
		msg.Controllen = uint64(len(oob))
	}

	wn, errno := zcall.Sendmsg(uintptr(raw), unsafe.Pointer(&msg), 0)
	if errno != 0 {
		return int(wn), 0, errFromErrno(errno)
	}

	return int(wn), len(oob), nil
}
