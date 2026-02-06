// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"unsafe"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/zcall"
)

// UDPMessage represents a single message for batch UDP operations.
// Used with SendMessages and RecvMessages for high-throughput UDP I/O.
type UDPMessage struct {
	// Addr is the remote address. For SendMessages, this is the destination.
	// For RecvMessages, this is populated with the source address.
	Addr *UDPAddr

	// Buffers holds the data buffers. For SendMessages, data is read from
	// these buffers. For RecvMessages, data is written to these buffers.
	Buffers [][]byte

	// OOB holds out-of-band/ancillary data (control messages).
	OOB []byte

	// Flags contains message flags (e.g., MSG_TRUNC, MSG_CTRUNC).
	Flags int

	// N is the number of bytes transferred. For SendMessages, this is set
	// after a successful send. For RecvMessages, this is the number of bytes
	// received into Buffers.
	N int
}

// SendMessages sends multiple UDP messages in a single syscall.
// Returns the number of messages sent and any error.
// Non-blocking: returns iox.ErrWouldBlock if the socket buffer is full.
//
// Each message in msgs should have Addr and Buffers populated.
// After return, the N field of each successfully sent message is updated
// with the number of bytes sent.
func (c *UDPConn) SendMessages(msgs []UDPMessage) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	raw := c.fd.Raw()
	if raw < 0 {
		return 0, ErrClosed
	}

	// Allocate mmsghdr array and iovec arrays
	mmsghdrs := make([]zcall.Mmsghdr, len(msgs))
	iovecs := make([][]zcall.Iovec, len(msgs))
	sockaddrs := make([]RawSockaddrAny, len(msgs))

	for i := range msgs {
		msg := &msgs[i]

		// Build iovec array for this message
		if len(msg.Buffers) > 0 {
			iovecs[i] = make([]zcall.Iovec, len(msg.Buffers))
			for j, buf := range msg.Buffers {
				if len(buf) > 0 {
					iovecs[i][j].Base = &buf[0]
					iovecs[i][j].Len = uint64(len(buf))
				}
			}
			mmsghdrs[i].Hdr.Iov = &iovecs[i][0]
			mmsghdrs[i].Hdr.Iovlen = uint64(len(msg.Buffers))
		}

		// Set destination address
		if msg.Addr != nil {
			encodeSockaddr(msg.Addr, &sockaddrs[i])
			mmsghdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sockaddrs[i]))
			mmsghdrs[i].Hdr.Namelen = SizeofSockaddrAny
		}

		// Set OOB data
		if len(msg.OOB) > 0 {
			mmsghdrs[i].Hdr.Control = &msg.OOB[0]
			mmsghdrs[i].Hdr.Controllen = uint64(len(msg.OOB))
		}
	}

	n, errno := zcall.Sendmmsg(uintptr(raw), unsafe.Pointer(&mmsghdrs[0]), uintptr(len(msgs)), 0)
	if errno != 0 {
		return int(n), errFromErrno(errno)
	}

	// Update N field for each sent message
	for i := range n {
		msgs[i].N = int(mmsghdrs[i].Len)
	}

	return int(n), nil
}

// RecvMessages receives multiple UDP messages in a single syscall.
// Returns the number of messages received and any error.
// Non-blocking: returns iox.ErrWouldBlock if no data is available.
//
// Each message in msgs should have Buffers pre-allocated.
// After return, the Addr, OOB, Flags, and N fields of each successfully
// received message are updated.
func (c *UDPConn) RecvMessages(msgs []UDPMessage) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	raw := c.fd.Raw()
	if raw < 0 {
		return 0, ErrClosed
	}

	// Allocate mmsghdr array and iovec arrays
	mmsghdrs := make([]zcall.Mmsghdr, len(msgs))
	iovecs := make([][]zcall.Iovec, len(msgs))
	sockaddrs := make([]RawSockaddrAny, len(msgs))

	for i := range msgs {
		msg := &msgs[i]

		// Set up sockaddr for receiving source address
		mmsghdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sockaddrs[i]))
		mmsghdrs[i].Hdr.Namelen = SizeofSockaddrAny

		// Build iovec array for this message
		if len(msg.Buffers) > 0 {
			iovecs[i] = make([]zcall.Iovec, len(msg.Buffers))
			for j, buf := range msg.Buffers {
				if len(buf) > 0 {
					iovecs[i][j].Base = &buf[0]
					iovecs[i][j].Len = uint64(len(buf))
				}
			}
			mmsghdrs[i].Hdr.Iov = &iovecs[i][0]
			mmsghdrs[i].Hdr.Iovlen = uint64(len(msg.Buffers))
		}

		// Set OOB buffer
		if len(msg.OOB) > 0 {
			mmsghdrs[i].Hdr.Control = &msg.OOB[0]
			mmsghdrs[i].Hdr.Controllen = uint64(len(msg.OOB))
		}
	}

	n, errno := zcall.Recvmmsg(uintptr(raw), unsafe.Pointer(&mmsghdrs[0]), uintptr(len(msgs)), zcall.MSG_DONTWAIT, nil)
	if errno != 0 {
		return int(n), errFromErrno(errno)
	}

	// Update fields for each received message
	for i := range n {
		msgs[i].Addr = decodeUDPAddr(&sockaddrs[i])
		msgs[i].Flags = int(mmsghdrs[i].Hdr.Flags)
		msgs[i].N = int(mmsghdrs[i].Len)
	}

	return int(n), nil
}

// encodeSockaddr encodes a UDPAddr into a RawSockaddrAny.
func encodeSockaddr(addr *UDPAddr, raw *RawSockaddrAny) {
	if addr == nil {
		return
	}

	if ip4 := addr.IP.To4(); ip4 != nil {
		sa := (*RawSockaddrInet4)(unsafe.Pointer(raw))
		sa.Family = AF_INET
		sa.Port = htons(uint16(addr.Port))
		copy(sa.Addr[:], ip4)
	} else {
		sa := (*RawSockaddrInet6)(unsafe.Pointer(raw))
		sa.Family = AF_INET6
		sa.Port = htons(uint16(addr.Port))
		if ip6 := addr.IP.To16(); ip6 != nil {
			copy(sa.Addr[:], ip6)
		}
		sa.ScopeID = zoneToScopeID(addr.Zone)
	}
}

// SendMessagesAdaptive sends multiple UDP messages with deadline support.
// If a write deadline is set, retries with backoff until success or timeout.
func (c *UDPConn) SendMessagesAdaptive(msgs []UDPMessage) (int, error) {
	n, err := c.SendMessages(msgs)
	if err != iox.ErrWouldBlock {
		return n, err
	}

	// No deadline set: return immediately (non-blocking contract)
	if !c.deadline.hasWriteDeadline() {
		return n, err
	}

	// Check if already expired
	if c.deadline.writeExpired() {
		return 0, ErrTimedOut
	}

	// Adapt: retry with backoff until deadline
	var backoff netBackoff
	for {
		backoff.wait()

		n, err = c.SendMessages(msgs)
		if err != iox.ErrWouldBlock {
			backoff.done()
			return n, err
		}

		if c.deadline.writeExpired() {
			return 0, ErrTimedOut
		}
	}
}

// RecvMessagesAdaptive receives multiple UDP messages with deadline support.
// If a read deadline is set, retries with backoff until success or timeout.
func (c *UDPConn) RecvMessagesAdaptive(msgs []UDPMessage) (int, error) {
	n, err := c.RecvMessages(msgs)
	if err != iox.ErrWouldBlock {
		return n, err
	}

	// No deadline set: return immediately (non-blocking contract)
	if !c.deadline.hasReadDeadline() {
		return n, err
	}

	// Check if already expired
	if c.deadline.readExpired() {
		return 0, ErrTimedOut
	}

	// Adapt: retry with backoff until deadline
	var backoff netBackoff
	for {
		backoff.wait()

		n, err = c.RecvMessages(msgs)
		if err != iox.ErrWouldBlock {
			backoff.done()
			return n, err
		}

		if c.deadline.readExpired() {
			return 0, ErrTimedOut
		}
	}
}
