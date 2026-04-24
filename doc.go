// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package sock provides zero-allocation socket types and address machinery for Unix systems in Go.
//
// The package uses direct syscalls via the zcall assembly package. All sockets
// are created with SOCK_NONBLOCK and SOCK_CLOEXEC flags.
//
// # Overview
//
// sock provides zero-allocation sockaddr encoding, non-blocking socket
// operations, socket option control, and [iofd.FD] access for integration with
// async I/O runtimes.
//
// # Adaptive I/O Model
//
// All I/O operations follow the Three-Tier Progress Model (Strike-Spin-Adapt):
//
//  1. Strike: System call — direct kernel hit via zcall.
//  2. Spin:   Hardware yield — local atomic synchronization (spin.Pause).
//  3. Adapt:  Software backoff — external I/O readiness (progressive sleep).
//
// sock implements Strike and Adapt. Spin is not used here because sock
// operations wait on the kernel or a network peer, not on local atomics.
//
// By default, operations are non-blocking:
//
//	conn, _ := sock.DialTCP4(nil, raddr)
//	n, err := conn.Read(buf)
//	if err == iox.ErrWouldBlock {
//	    // Kernel not ready, try again later (no blocking)
//	}
//
// When a deadline is set, operations retry with progressive backoff:
//
//	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
//	n, err := conn.Read(buf)  // Retries until data or timeout
//	if err == sock.ErrTimedOut {
//	    // Deadline exceeded
//	}
//
// # Error Semantics
//
// Errors follow a layered semantic model:
//
//   - [iox.ErrWouldBlock]: Control flow signal, not a failure. The operation
//     made no progress on this attempt. Retry when the kernel is ready or when
//     your owned wait policy says to try again.
//   - [iox.ErrMore]: Shared `iox` classifier signal: progress already happened
//     and the operation remains active. Plain `sock` socket calls below usually
//     surface [iox.ErrWouldBlock] / [ErrInProgress] directly; [iox.ErrMore]
//     mainly appears from helpers and policies layered above `sock`.
//   - [ErrTimedOut]: Deadline exceeded during adaptive retry.
//   - [ErrInProgress]: Connection attempt started but handshake incomplete.
//     For non-blocking dial, this is expected behavior.
//   - Other errors: Actual failures (connection refused, reset, etc.)
//
// As a rule, counts/results carry progress while semantic errors carry control.
// Use [iox.Classify], [iox.IsSemantic], [iox.IsNonFailure], and
// [iox.IsProgress] when reasoning across package boundaries.
//
// # Architecture
//
// The [Sockaddr] interface is the foundation of zero-allocation address handling:
//
//	type Sockaddr interface {
//	    Raw() (unsafe.Pointer, uint32)  // Direct kernel format
//	    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
//	}
//
// Address types ([SockaddrInet4], [SockaddrInet6], [SockaddrUnix]) embed raw kernel
// structures and return pointers directly—no marshaling, no allocation.
//
// # Socket Types
//
//   - [TCPSocket], [TCPConn], [TCPListener] for TCP streams
//   - [UDPSocket], [UDPConn] for UDP datagrams
//   - [SCTPSocket], [SCTPConn], [SCTPListener] for SCTP (Linux only)
//   - [UnixSocket], [UnixConn], [UnixListener] for Unix domain sockets
//   - [RawSocket], [RawConn] for raw IP (requires CAP_NET_RAW)
//   - [Link], [Links], [LinkByName], [LinkByIndex] for Linux network link queries
//
// All sockets expose [iofd.FD] via the FD method for io_uring integration and
// other async I/O mechanisms.
//
// # Compatibility
//
// Address conversion functions bridge with the standard net package:
//
//   - [TCPAddrToSockaddr], [SockaddrToTCPAddr]
//   - [UDPAddrToSockaddr], [SockaddrToUDPAddr]
//   - [UnixAddrToSockaddr], [SockaddrToUnixAddr]
//
// Type aliases ([Conn], [Addr], [Listener]) provide net.Conn, net.Addr, and
// net.Listener interface compatibility.
//
// # Platforms
//
//   - linux/amd64, linux/arm64, linux/riscv64, linux/loong64: Full support
//   - darwin/arm64: Partial
//   - freebsd/amd64: Cross-compile only
package sock
