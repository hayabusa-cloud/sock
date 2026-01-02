// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock

import (
	"sync/atomic"
	"time"

	"code.hybscloud.com/iox"
)

// Adaptive I/O implements the Strike-Spin-Adapt model:
//  1. Strike: Direct syscall (non-blocking) → returns iox.ErrWouldBlock if not ready.
//  2. Spin: (handled by caller if needed via sox.SpinWait)
//  3. Adapt: Software backoff (iox.Backoff) → used when deadline is set.
//
// Contract:
//   - By default, operations are non-blocking and return iox.ErrWouldBlock immediately.
//   - Only when a deadline is explicitly set does the operation enter a retry loop.
//   - The retry loop uses iox.Backoff for progressive sleeping with jitter.

// deadlineState holds read and write deadlines for adaptive I/O.
// Zero time means no deadline (non-blocking mode).
type deadlineState struct {
	read  atomic.Int64 // Unix nano timestamp, 0 = no deadline
	write atomic.Int64 // Unix nano timestamp, 0 = no deadline
}

// setReadDeadline sets the read deadline.
// Zero time disables the deadline (pure non-blocking mode).
func (d *deadlineState) setReadDeadline(t time.Time) {
	if t.IsZero() {
		d.read.Store(0)
	} else {
		d.read.Store(t.UnixNano())
	}
}

// setWriteDeadline sets the write deadline.
// Zero time disables the deadline (pure non-blocking mode).
func (d *deadlineState) setWriteDeadline(t time.Time) {
	if t.IsZero() {
		d.write.Store(0)
	} else {
		d.write.Store(t.UnixNano())
	}
}

// setDeadline sets both read and write deadlines.
func (d *deadlineState) setDeadline(t time.Time) {
	d.setReadDeadline(t)
	d.setWriteDeadline(t)
}

// readDeadline returns the read deadline as time.Time.
// Returns zero time if no deadline is set.
func (d *deadlineState) readDeadline() time.Time {
	ns := d.read.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// writeDeadline returns the write deadline as time.Time.
// Returns zero time if no deadline is set.
func (d *deadlineState) writeDeadline() time.Time {
	ns := d.write.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// hasReadDeadline returns true if a read deadline is set.
func (d *deadlineState) hasReadDeadline() bool {
	return d.read.Load() != 0
}

// hasWriteDeadline returns true if a write deadline is set.
func (d *deadlineState) hasWriteDeadline() bool {
	return d.write.Load() != 0
}

// readExpired returns true if the read deadline has passed.
func (d *deadlineState) readExpired() bool {
	ns := d.read.Load()
	if ns == 0 {
		return false
	}
	return time.Now().UnixNano() >= ns
}

// writeExpired returns true if the write deadline has passed.
func (d *deadlineState) writeExpired() bool {
	ns := d.write.Load()
	if ns == 0 {
		return false
	}
	return time.Now().UnixNano() >= ns
}

// adaptiveRead performs an adaptive read operation.
// If no deadline is set, returns immediately (non-blocking).
// If a deadline is set, retries with backoff until success or deadline exceeded.
//
// Parameters:
//   - readFn: the underlying non-blocking read function
//   - deadline: the deadline state
//
// Returns:
//   - n: bytes read
//   - err: nil on success, iox.ErrWouldBlock if non-blocking and not ready,
//     ErrTimedOut if deadline exceeded
func adaptiveRead(readFn func() (int, error), deadline *deadlineState) (int, error) {
	// First attempt (Strike)
	n, err := readFn()
	if err != iox.ErrWouldBlock {
		return n, err
	}

	// No deadline set: return immediately (non-blocking contract)
	if !deadline.hasReadDeadline() {
		return n, err
	}

	// Check if already expired
	if deadline.readExpired() {
		return n, ErrTimedOut
	}

	// Adapt: retry with backoff until deadline
	var backoff iox.Backoff
	for {
		backoff.Wait()

		n, err = readFn()
		if err != iox.ErrWouldBlock {
			return n, err
		}

		if deadline.readExpired() {
			return n, ErrTimedOut
		}
	}
}

// adaptiveWrite performs an adaptive write operation.
// If no deadline is set, returns immediately (non-blocking).
// If a deadline is set, retries with backoff until success or deadline exceeded.
//
// Parameters:
//   - writeFn: the underlying non-blocking write function
//   - deadline: the deadline state
//
// Returns:
//   - n: bytes written
//   - err: nil on success, iox.ErrWouldBlock if non-blocking and not ready,
//     ErrTimedOut if deadline exceeded
func adaptiveWrite(writeFn func() (int, error), deadline *deadlineState) (int, error) {
	// First attempt (Strike)
	n, err := writeFn()
	if err != iox.ErrWouldBlock {
		return n, err
	}

	// No deadline set: return immediately (non-blocking contract)
	if !deadline.hasWriteDeadline() {
		return n, err
	}

	// Check if already expired
	if deadline.writeExpired() {
		return n, ErrTimedOut
	}

	// Adapt: retry with backoff until deadline
	var backoff iox.Backoff
	for {
		backoff.Wait()

		n, err = writeFn()
		if err != iox.ErrWouldBlock {
			return n, err
		}

		if deadline.writeExpired() {
			return n, ErrTimedOut
		}
	}
}

// adaptiveAccept performs an adaptive accept operation.
// If no deadline is set, returns immediately (non-blocking).
// If a deadline is set, retries with backoff until success or deadline exceeded.
//
// Parameters:
//   - acceptFn: the underlying non-blocking accept function
//   - deadlineNs: deadline as Unix nanoseconds (0 = no deadline)
//
// Returns:
//   - result from acceptFn, or ErrTimedOut if deadline exceeded
func adaptiveAccept[T any](acceptFn func() (T, error), deadlineNs int64) (T, error) {
	var zero T

	// First attempt (Strike)
	result, err := acceptFn()
	if err != iox.ErrWouldBlock {
		return result, err
	}

	// No deadline set: return immediately (non-blocking contract)
	if deadlineNs == 0 {
		return zero, err
	}

	// Check if already expired
	if time.Now().UnixNano() >= deadlineNs {
		return zero, ErrTimedOut
	}

	// Adapt: retry with backoff until deadline
	var backoff iox.Backoff
	for {
		backoff.Wait()

		result, err = acceptFn()
		if err != iox.ErrWouldBlock {
			return result, err
		}

		if time.Now().UnixNano() >= deadlineNs {
			return zero, ErrTimedOut
		}
	}
}

// adaptiveConnect performs an adaptive connect operation.
// If timeout is zero, returns immediately after first connect attempt (non-blocking).
// If timeout is set, probes connection status with backoff until connected or timeout.
//
// The connect operation for non-blocking sockets returns ErrInProgress on first call.
// Connection completion is detected via second connect() call:
//   - Returns nil (EISCONN mapped to nil) when connected
//   - Returns ErrInProgress (EALREADY) while handshake is in progress
//   - Returns other errors if connection failed
//
// This approach works for both TCP (SOCK_STREAM) and SCTP (SOCK_SEQPACKET).
//
// Parameters:
//   - sock: the socket to connect
//   - sa: the destination address
//   - timeout: connection timeout (0 = non-blocking, return immediately)
//
// Returns:
//   - nil on success
//   - ErrInProgress if non-blocking and connection still pending
//   - ErrTimedOut if timeout exceeded
//   - other error if connection failed
func adaptiveConnect(sock *NetSocket, sa Sockaddr, timeout time.Duration) error {
	// First attempt (Strike)
	err := sock.Connect(sa)
	if err == nil {
		return nil // Connected immediately (rare for non-blocking)
	}
	if err != ErrInProgress {
		return err // Real error
	}

	// No timeout set: return immediately (non-blocking contract)
	if timeout == 0 {
		return ErrInProgress
	}

	// Calculate deadline
	deadlineNs := time.Now().Add(timeout).UnixNano()

	// Check if already expired
	if time.Now().UnixNano() >= deadlineNs {
		return ErrTimedOut
	}

	// Adapt: probe with second connect() + backoff until deadline
	// Second connect() on a connecting socket returns:
	// - EISCONN (mapped to nil): connection established
	// - EALREADY (mapped to ErrInProgress): still connecting
	// - Other errors: connection failed (ECONNREFUSED, ETIMEDOUT, etc.)
	var backoff iox.Backoff
	for {
		backoff.Wait()

		// Probe connection status via second connect()
		// Linux kernel behavior (af_inet.c:735): when socket is TCP_CLOSE,
		// connect() calls sock_error() which atomically returns sk_err and
		// clears it. This gives us the actual error directly without needing
		// to check SO_ERROR separately.
		err = sock.Connect(sa)
		if err == nil {
			return nil // Connected (EISCONN mapped to nil)
		}
		if err != ErrInProgress {
			return err // Connection failed with specific error
		}
		// err == ErrInProgress (EALREADY): still connecting, continue backoff

		if time.Now().UnixNano() >= deadlineNs {
			return ErrTimedOut
		}
	}
}
