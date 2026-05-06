# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Go Report Card](https://goreportcard.com/badge/github.com/hayabusa-cloud/sock)](https://goreportcard.com/report/github.com/hayabusa-cloud/sock)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Zero-allocation socket types and address machinery for Unix systems in Go.

Language: **English** | [简体中文](./README.zh-CN.md) | [Español](./README.es.md) | [日本語](./README.ja.md) | [Français](./README.fr.md)

## Overview

`sock` provides zero-allocation sockaddr encoding, non-blocking socket operations, socket option control, and `iofd.FD` access for integration with async I/O runtimes.

## Operations

- **Zero-Allocation Addresses** — Sockaddr types encode directly to kernel-facing structures; `Raw()` returns an `unsafe.Pointer` with no marshaling and no heap allocation.
- **Zero-Overhead Syscalls** — All I/O paths use `zcall` assembly entry points that call into the kernel without routing through the Go runtime scheduler.
- **Protocol Support** — TCP, UDP, SCTP, Unix domain (stream/dgram/seqpacket), and raw IP sockets; IPv4 and IPv6 for each.
- **Adaptive I/O** — Three-Tier Progress Model (Strike-Spin-Adapt): operations return `iox.ErrWouldBlock` immediately by default; deadline-driven backoff engages only when explicitly set
- **io_uring Ready** — Every socket exposes `FD() *iofd.FD` for direct integration with `uring`, `takt`, and other async I/O runtimes.
- **UDP Batch I/O** — `SendMessages`/`RecvMessages` use `sendmmsg(2)`/`recvmmsg(2)` to process multiple datagrams per syscall; adaptive variants add deadline support.
- **Network Link Queries** — `Links`, `LinkByName`, and `LinkByIndex` provide Linux-native link enumeration via `zcall`; used internally for IPv6 zone ID resolution.
- **Socket Option Control** — Type-safe helpers for SO_KEEPALIVE, TCP_NODELAY, SO_LINGER, TCP_USER_TIMEOUT, TCP_NOTSENT_LOWAT, SO_BUSY_POLL, UDP_SEGMENT, UDP_GRO, and more.

## Architecture

### Sockaddr Interface

The `Sockaddr` interface is the foundation of zero-allocation address handling:

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // Direct kernel format
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

Address types (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`) embed raw kernel structures and return pointers directly, with no marshaling and no allocation.

### Socket Type Hierarchy

```
NetSocket (base)
├── TCPSocket → TCPConn, TCPListener
├── UDPSocket → UDPConn
├── SCTPSocket → SCTPConn, SCTPListener (Linux)
├── UnixSocket → UnixConn, UnixListener
└── RawSocket → RawConn (-tags rawsock, CAP_NET_RAW)
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

The `zcall` package provides raw syscall entry points for direct kernel interaction from `sock`.

### Adaptive I/O Semantics

The package follows the **Three-Tier Progress Model** (Strike-Spin-Adapt) for non-blocking I/O:

1. **Strike**: System call — direct kernel hit via `zcall`
2. **Spin**: Hardware yield — local atomic synchronization (`spin.Pause`)
3. **Adapt**: Software backoff — external I/O readiness (progressive sleep)

sock implements **Strike** and **Adapt**. Spin is not used here because socket operations wait on the kernel or a network peer, not on local atomics.

**Key behaviors:**

- **Non-blocking by default**: `Read`, `Write`, `Accept`, and `Dial` operations return immediately with `iox.ErrWouldBlock` if the kernel is not ready.
- **Deadline-driven adaptation**: Only when a deadline is explicitly set (via `SetDeadline`, `SetReadDeadline`, or `SetWriteDeadline`) does the operation enter a retry loop with progressive backoff.
- **Outcome classification**: byte counts and returned values carry progress, while semantic errors carry control.
  Direct `sock` calls usually surface `iox.ErrWouldBlock` on not-ready paths and `sock.ErrInProgress` on pending
  connect;
  `iox.ErrMore`, `iox.Classify`, `iox.IsSemantic`, and `iox.IsProgress` remain shared classifier vocabulary for helpers
  layered above `sock`.
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

### Raw Sockets (requires -tags rawsock and CAP_NET_RAW)

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

// TCP_USER_TIMEOUT for dead connection detection (Linux)
sock.SetTCPUserTimeout(conn.FD(), 30000)  // 30 seconds in milliseconds

// TCP_NOTSENT_LOWAT for reduced memory and latency (Linux)
sock.SetTCPNotsentLowat(conn.FD(), 16384)

// SO_BUSY_POLL for low-latency polling (Linux)
sock.SetBusyPoll(conn.FD(), 50)  // 50 microseconds
```

### UDP Batch Operations (Linux)

```go
// Send multiple messages in a single syscall
msgs := []sock.UDPMessage{
    {Addr: addr1, Buffers: [][]byte{data1}},
    {Addr: addr2, Buffers: [][]byte{data2}},
}
n, _ := conn.SendMessages(msgs)

// Receive multiple messages
recvMsgs := []sock.UDPMessage{
    {Buffers: [][]byte{make([]byte, 1500)}},
    {Buffers: [][]byte{make([]byte, 1500)}},
}
n, _ = conn.RecvMessages(recvMsgs)

// UDP GSO (Generic Segmentation Offload)
sock.SetUDPSegment(conn.FD(), 1400)  // Segment size

// UDP GRO (Generic Receive Offload)
sock.SetUDPGRO(conn.FD(), true)
```

### Linux Network Links

```go
links, _ := sock.Links()
lo, _ := sock.LinkByName("lo")
byIndex, _ := sock.LinkByIndex(lo.Index)
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
// Convert net.TCPAddr to Sockaddr for compatibility
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

## Platform Support

| Platform | Status |
|----------|--------|
| linux/amd64 | Full |
| linux/arm64 | Full |
| linux/riscv64 | Full |
| linux/loong64 | Full |
| darwin/arm64 | Partial |
| freebsd/amd64 | Cross-compile only |

## License

MIT, see [LICENSE](./LICENSE).

©2025 [Hayabusa Cloud Co., Ltd.](https://code.hybscloud.com)
