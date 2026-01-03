# sock

[![Go Reference](https://pkg.go.dev/badge/code.hybscloud.com/sock.svg)](https://pkg.go.dev/code.hybscloud.com/sock)
[![Go Report Card](https://goreportcard.com/badge/github.com/hayabusa-cloud/sock)](https://goreportcard.com/report/github.com/hayabusa-cloud/sock)
[![Codecov](https://codecov.io/gh/hayabusa-cloud/sock/graph/badge.svg)](https://codecov.io/gh/hayabusa-cloud/sock)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Go 语言零分配套接字类型与地址处理库（Unix 系统）。

语言: [English](./README.md) | **简体中文** | [Español](./README.es.md) | [日本語](./README.ja.md) | [Français](./README.fr.md)

## 何时使用本包

在以下场景中使用 `sock` 代替标准 `net` 包：

- **零分配热路径** — Sockaddr 类型直接编码为内核格式，无需堆分配
- **非阻塞 I/O** — 操作立即返回 `iox.ErrWouldBlock` 而非阻塞 goroutine
- **直接内核控制** — 套接字选项、TCP_INFO 及其他底层功能
- **io_uring 集成** — 所有套接字暴露 `iofd.FD` 用于异步 I/O

对于延迟不敏感的典型应用，标准 `net` 包提供了更简单、更具移植性的 API。

## 特性

- **零分配地址** — Sockaddr 类型直接编码为内核格式，无需堆分配
- **协议支持** — TCP、UDP、SCTP、Unix（流/数据报/顺序包）、Raw IP
- **io_uring 就绪** — 所有套接字暴露 `iofd.FD` 以集成异步 I/O
- **零开销系统调用** — 通过 `zcall` 汇编直接与内核交互

## 架构

### Sockaddr 接口

`Sockaddr` 接口是零分配地址处理的基础：

```go
type Sockaddr interface {
    Raw() (unsafe.Pointer, uint32)  // 直接内核格式
    Family() uint16                  // AF_INET, AF_INET6, AF_UNIX
}
```

地址类型（`SockaddrInet4`、`SockaddrInet6`、`SockaddrUnix`）内嵌原始内核结构并直接返回指针——无需序列化，无需分配。

### 套接字类型层次

```
NetSocket（基类）
├── TCPSocket → TCPConn, TCPListener
├── UDPSocket → UDPConn
├── SCTPSocket → SCTPConn, SCTPListener (Linux)
├── UnixSocket → UnixConn, UnixListener
└── RawSocket → RawConn (CAP_NET_RAW)
```

所有套接字都暴露 `FD() *iofd.FD` 以便与 io_uring 和其他异步 I/O 机制集成。

### 内核集成

```
应用程序
    ↓
sock.TCPConn.Write(data)
    ↓
iofd.FD.Write()
    ↓
zcall.Write() ← 汇编入口（绕过 Go 运行时）
    ↓
Linux 内核
```

`zcall` 包提供原始系统调用入口点，绕过 Go 运行时钩子，消除延迟敏感路径的调度开销。

### 自适应 I/O 语义

本包实现了用于非阻塞 I/O 的 **Strike-Spin-Adapt** 模型：

1. **Strike**：直接系统调用执行（非阻塞）
2. **Spin**：硬件级同步（如需要由 `sox` 处理）
3. **Adapt**：设置截止时间时通过网络调优的软件退避

**关键行为：**

- **默认非阻塞**：`Read`、`Write`、`Accept` 和 `Dial` 操作在内核未就绪时立即返回 `iox.ErrWouldBlock`。
- **截止时间驱动的自适应**：只有当显式设置截止时间（通过 `SetDeadline`、`SetReadDeadline` 或 `SetWriteDeadline`）时，操作才会进入带渐进退避的重试循环。
- **非阻塞 Dial**：与 `net.Dial` 不同，`DialTCP4` 等函数在连接尝试开始后立即返回。TCP 握手可能仍在进行中（`ErrInProgress` 被静默忽略）。如需阻塞行为，请使用带超时的 `TCPDialer`：

```go
// 非阻塞（立即返回，握手可能仍在进行）
conn, _ := sock.DialTCP4(nil, raddr)

// 带超时的阻塞（等待连接完成或超时）
dialer := &sock.TCPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, raddr)
```

## 安装

```bash
go get code.hybscloud.com/sock
```

## 使用方法

### TCP

```go
// 服务器
ln, _ := sock.ListenTCP4(&sock.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 8080})
conn, _ := ln.Accept()
conn.Read(buf)
conn.Close()

// 客户端
conn, _ := sock.DialTCP4(nil, &sock.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080})
conn.SetNoDelay(true)
conn.Write(data)
```

### UDP

```go
// 服务器
conn, _ := sock.ListenUDP4(&sock.UDPAddr{Port: 5353})
n, addr, _ := conn.ReadFrom(buf)
conn.WriteTo(response, addr)

// 客户端
conn, _ := sock.DialUDP4(nil, &sock.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
conn.Write(query)
conn.Read(response)
```

### SCTP（仅 Linux）

```go
// 服务器
ln, _ := sock.ListenSCTP4(&sock.SCTPAddr{IP: net.ParseIP("0.0.0.0"), Port: 9000})
conn, _ := ln.Accept()
conn.Read(buf)

// 带超时的客户端
dialer := &sock.SCTPDialer{Timeout: 5 * time.Second}
conn, _ := dialer.Dial4(nil, &sock.SCTPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000})
conn.Write(data)
```

### Unix 域套接字

```go
// 流套接字
ln, _ := sock.ListenUnix("unix", &net.UnixAddr{Name: "/tmp/app.sock"})
conn, _ := ln.Accept()

// 数据报套接字
conn, _ := sock.ListenUnixgram("unixgram", &net.UnixAddr{Name: "/tmp/app.dgram"})

// 套接字对
pair, _ := sock.UnixConnPair("unix")
pair[0].Write([]byte("ping"))
pair[1].Read(buf)
```

### Raw 套接字（需要 CAP_NET_RAW）

```go
// ICMP ping
sock, _ := sock.NewICMPSocket4()
sock.SendTo(icmpPacket, &net.IPAddr{IP: net.ParseIP("8.8.8.8")})
n, addr, _ := sock.RecvFrom(buf)
```

### 套接字选项

```go
// TCP 调优
conn.SetNoDelay(true)              // 禁用 Nagle 算法
conn.SetKeepAlive(true)            // 启用保活探测
conn.SetKeepAlivePeriod(30 * time.Second)

// 缓冲区大小
sock.SetSendBuffer(conn.FD(), 256*1024)
sock.SetRecvBuffer(conn.FD(), 256*1024)

// SO_LINGER 用于关闭时立即发送 RST
sock.SetLinger(conn.FD(), true, 0)
```

### 错误处理

```go
// 使用 iox.ErrWouldBlock 的非阻塞读取
n, err := conn.Read(buf)
if err == iox.ErrWouldBlock {
    // 内核未就绪，与事件循环集成或稍后重试
    return
}
if err != nil {
    // 真正的错误（连接重置、关闭等）
    return
}

// 带截止时间的阻塞读取
conn.SetReadDeadline(time.Now().Add(5 * time.Second))
n, err = conn.Read(buf)
if err == sock.ErrTimedOut {
    // 截止时间已过
}
```

### 与 net 包的兼容性

本包提供与 Go 标准 `net` 类型的无缝转换：

```go
// 将 net.TCPAddr 转换为 Sockaddr（零分配）
netAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
sockaddr := sock.TCPAddrToSockaddr(netAddr)

// 转换回 net.TCPAddr
tcpAddr := sock.SockaddrToTCPAddr(sockaddr)

// 兼容性类型别名
var _ sock.Conn = conn      // 兼容 net.Conn
var _ sock.Addr = addr      // 兼容 net.Addr

// 注意：监听器返回具体类型（*TCPConn, *UnixConn）以实现
// 零分配性能，而非 net.Listener 要求的 net.Conn。
```

## 支持的平台

| 平台 | 状态 |
|------|------|
| linux/amd64 | 完整 |
| linux/arm64 | 完整 |
| linux/riscv64 | 完整 |
| linux/loong64 | 完整 |
| darwin/arm64 | 部分（无 SCTP、TCPInfo、组播、SCM_RIGHTS）|
| freebsd/amd64 | 仅交叉编译 |

## 许可证

MIT — 详见 [LICENSE](./LICENSE)。

©2025 Hayabusa Cloud Co., Ltd.
