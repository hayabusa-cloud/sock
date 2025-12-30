// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package sock provides zero-allocation socket types and address machinery for Unix systems in Go.
//
// This package is designed for ultra-low latency systems where every nanosecond
// matters. Unlike the standard net package, sock uses direct syscalls via the
// zcall assembly package, bypassing Go's runtime hooks entirely.
//
// # When to Use This Package
//
// Use sock instead of net when you need:
//   - Zero-allocation hot paths for address handling
//   - Non-blocking I/O without goroutine-per-connection overhead
//   - Direct control over socket options and kernel interaction
//   - Integration with io_uring for async I/O (via [iofd.FD])
//
// For typical applications where latency is not critical, the standard net
// package provides a simpler and more portable API.
//
// # Adaptive I/O Model
//
// All I/O operations follow the Strike-Spin-Adapt model:
//
//  1. Strike: Direct syscall execution (non-blocking)
//  2. Spin: Hardware-level synchronization (handled by caller if needed)
//  3. Adapt: Software backoff via [iox.Backoff] when deadlines are set
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
//     cannot complete without blocking. Retry when the kernel is ready.
//   - [ErrTimedOut]: Deadline exceeded during adaptive retry.
//   - [ErrInProgress]: Connection attempt started but handshake incomplete.
//     For non-blocking dial, this is expected behavior.
//   - Other errors: Actual failures (connection refused, reset, etc.)
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
//
// All sockets expose [iofd.FD] via the FD() method for io_uring integration
// and other async I/O mechanisms.
//
// # Compatibility
//
// Address conversion functions bridge with the standard net package:
//
//   - [TCPAddrToSockaddr], [SockaddrToTCPAddr]
//   - [UDPAddrToSockaddr], [SockaddrToUDPAddr]
//   - [UnixAddrToSockaddr], [SockaddrToUnixAddr]
//
// Type aliases ([Conn], [Addr], [Listener]) provide net.Conn, net.Addr,
// net.Listener interface compatibility.
//
// # Platforms
//
//   - linux/amd64, linux/arm64, linux/riscv64, linux/loong64: Full support
//   - darwin/arm64: Partial (no SCTP, TCPInfo, multicast, SCM_RIGHTS)
//   - freebsd/amd64: Cross-compile only
package sock
