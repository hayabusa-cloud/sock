# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Go Report Card](https://goreportcard.com/badge/github.com/hayabusa-cloud/sock)](https://goreportcard.com/report/github.com/hayabusa-cloud/sock)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Zero-allocation socket types and address machinery for Unix systems in Go.

Language: **English** | [简体中文](./README.zh-CN.md) | [Español](./README.es.md) | [日本語](./README.ja.md) | [Français](./README.fr.md)

## When to Use This Package

Use `sock` instead of the standard `net` package when you need:

- **Zero-allocation hot paths** — Sockaddr types encode directly to kernel format without heap allocation
- **Non-blocking I/O** — Operations return `iox.ErrWouldBlock` immediately instead of blocking goroutines
- **Direct kernel control** — Socket options, TCP_INFO, and other low-level features
- **io_uring integration** — All sockets expose `iofd.FD` for async I/O

For typical applications where latency is not critical, the standard `net` package provides a simpler and more portable API.

## Features

- **Zero-Allocation Addresses** — Sockaddr types encode directly to kernel format without heap allocation
- **Protocol Support** — TCP, UDP, SCTP, Unix (stream/dgram/seqpacket), Raw IP
- **io_uring Ready** — All sockets expose `iofd.FD` for async I/O integration
- **Zero-Overhead Syscalls** — Direct kernel interaction via `zcall` assembly

## Architecture

### Sockaddr Interface

The `Sockaddr` interface is the foundation of zero-allocation address handling:

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // Direct kernel format
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

Address types (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`) embed raw kernel structures and return pointers directly—no marshaling, no allocation.

### Socket Type Hierarchy

```
NetSocket (base)
├── TCPSocket → TCPConn, TCPListener
├── UDPSocket → UDPConn
├── SCTPSocket → SCTPConn, SCTPListener (Linux)
├── UnixSocket → UnixConn, UnixListener
└── RawSocket → RawConn (CAP_NET_RAW)
```

All sockets expose `FD() *iofd.FD` for integration with io_uring and other async I/O mechanisms.

### Kernel Integration

```
Application
    ↓
sock.TCPConn.Write(data)
    ↓
iofd.FD.Write()
    ↓
zcall.Write() ← Assembly entry point (no Go runtime)
    ↓
Linux Kernel
```

The `zcall` package provides raw syscall entry points that bypass Go's runtime hooks, eliminating scheduler overhead for latency-critical paths.

### Adaptive I/O Semantics

The package implements the **Strike-Spin-Adapt** model for non-blocking I/O:

1. **Strike**: Direct syscall execution (non-blocking)
2. **Spin**: Hardware-level synchronization (handled by `sox` if needed)
3. **Adapt**: Software backoff via `iox.Backoff` when deadlines are set

**Key behaviors:**

- **Non-blocking by default**: `Read`, `Write`, `Accept`, and `Dial` operations return immediately with `iox.ErrWouldBlock` if the kernel is not ready.
- **Deadline-driven adaptation**: Only when a deadline is explicitly set (via `SetDeadline`, `SetReadDeadline`, or `SetWriteDeadline`) does the operation enter a retry loop with progressive backoff.
- **Non-blocking Dial**: Unlike `net.Dial`, functions like `DialTCP4` return immediately once the connection attempt starts. The TCP handshake may still be in progress (`ErrInProgress` is silently ignored). Use `TCPDialer` with a timeout for blocking behavior:

```go
// Non-blocking (returns immediately, handshake may be in progress)
conn, _ := sock.DialTCP4(nil, raddr)

// Blocking with timeout (waits for connection or timeout)
dialer := &sock.TCPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, raddr)
```

## Installation

```bash
go get code.hybscloud.com/sock
```

## Usage

### TCP

```go
// Server
ln, _ := sock.ListenTCP4(&sock.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080})
conn, _ := ln.Accept()
conn.Read(buf)
conn.Close()

// Client
conn, _ := sock.DialTCP4(nil, &sock.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
conn.SetNoDelay(true)
conn.Write(data)
```

### UDP

```go
// Server
conn, _ := sock.ListenUDP4(&sock.UDPAddr{Port: 5353})
n, addr, _ := conn.ReadFrom(buf)
conn.WriteTo(response, addr)

// Client
conn, _ := sock.DialUDP4(nil, &sock.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
conn.Write(query)
conn.Read(response)
```

### SCTP (Linux only)

```go
// Server
ln, _ := sock.ListenSCTP4(&sock.SCTPAddr{IP: net.ParseIP("0.0.0.0"), Port: 9000})
conn, _ := ln.Accept()
conn.Read(buf)

// Client with timeout
dialer := &sock.SCTPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, &sock.SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})
conn.Write(data)
```

### Unix Domain Sockets

```go
// Stream
ln, _ := sock.ListenUnix("unix", &net.UnixAddr{Name: "/tmp/app.sock"})
conn, _ := ln.Accept()

// Datagram
conn, _ := sock.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/app.dgram"})

// Socket pair
pair, _ := sock.UnixConnPair("unix")
pair[0].Write([]byte("ping"))
pair[1].Read(buf)
```

### Raw Sockets (requires CAP_NET_RAW)

```go
// ICMP ping
sock, _ := sock.NewICMPSocket4()
sock.SendTo(icmpPacket, &net.IPAddr{IP: net.ParseIP("8.8.8.8")})
n, addr, _ := sock.RecvFrom(buf)
```

### Socket Options

```go
// TCP tuning
conn.SetNoDelay(true)              // Disable Nagle's algorithm
conn.SetKeepAlive(true)            // Enable keepalive probes
conn.SetKeepAlivePeriod(30 * time.Second)

// Buffer sizes
sock.SetSendBuffer(conn.FD(), 256*1024)
sock.SetRecvBuffer(conn.FD(), 256*1024)

// SO_LINGER for immediate RST on close
sock.SetLinger(conn.FD(), true, 0)
```

### Error Handling

```go
// Non-blocking read with iox.ErrWouldBlock
n, err := conn.Read(buf)
if err == iox.ErrWouldBlock {
    // Kernel not ready, integrate with event loop or retry later
    return
}
if err != nil {
    // Real error (connection reset, closed, etc.)
    return
}

// Blocking read with deadline
conn.SetReadDeadline(time.Now().Add(5 * time.Second))
n, err = conn.Read(buf)
if err == sock.ErrTimedOut {
    // Deadline exceeded
}
```

### Compatibility with net Package

The package provides seamless conversion with Go's standard `net` types:

```go
// Convert net.TCPAddr to Sockaddr (zero-allocation)
netAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
sockaddr := sock.TCPAddrToSockaddr(netAddr)

// Convert back to net.TCPAddr
tcpAddr := sock.SockaddrToTCPAddr(sockaddr)

// Type aliases for compatibility
var _ sock.Conn = conn      // net.Conn compatible
var _ sock.Addr = addr      // net.Addr compatible

// Note: Listeners return concrete types (*TCPConn, *UnixConn) for
// zero-allocation performance, not net.Conn as net.Listener requires.
```

## Supported Platforms

| Platform | Status |
|----------|--------|
| linux/amd64 | Full |
| linux/arm64 | Full |
| linux/riscv64 | Full |
| linux/loong64 | Full |
| darwin/arm64 | Partial (no SCTP, TCPInfo, multicast, SCM_RIGHTS) |
| freebsd/amd64 | Cross-compile only |

## License

MIT — see [LICENSE](./LICENSE).

©2025 Hayabusa Cloud Co., Ltd.
