# Copilot Code Review Instructions

## Repository Context

This is `sock`, a zero-allocation socket library for Go built on:
- `zcall`: Zero-overhead syscalls (raw assembly, no runtime hooks)
- `iofd`: File descriptor abstractions
- `iox`: Non-blocking I/O semantics (ErrWouldBlock, ErrMore)

Target: Linux kernel 6.12+, Go 1.25+

## Review Focus

Only report issues that are:
- **Critical**: Security vulnerabilities, data loss, crash bugs, race conditions
- **Important**: Logic errors, incorrect syscall usage, wrong errno mapping
- **Must-fix**: Build failures, API contract violations, memory safety issues

## Do NOT Report

- Style suggestions (formatting, naming)
- Documentation improvements
- Performance micro-optimizations (unless hot path)
- Missing tests
- Pragma changes (`//go:nosplit`, `//go:noescape`) - trade-offs are intentional
- Suggestions to add error handling that already exists elsewhere
- "Consider" or "could" suggestions

## Codebase Patterns (Do NOT flag these)

### Error Handling
```go
// Semantic errors are control flow, not failures
if err == iox.ErrWouldBlock { /* retry */ }
if err == ErrInProgress { /* async connect */ }
```

### Unsafe Pointer Usage
```go
// Direct syscall usage - intentional, zero-copy design
zcall.Read(uintptr(fd), buf)  // buf is []byte
unsafe.Add(ptr, offset)       // Go 1.17+ idiom
```

### Build Tags
```go
//go:build linux      // Standard platform code
//go:build rawsock    // Requires CAP_NET_RAW
//go:build unix       // Cross-Unix code
```

### Atomic FD Operations
```go
// Idempotent close pattern - intentional
raw := atomic.SwapInt32(&fd.fd, -1)
if raw < 0 { return nil }
```

## Before Review

1. Read the PR description for intent
2. Check related files for existing patterns
3. Understand Linux kernel behavior for socket operations
4. Verify errno mappings against kernel documentation

## Review Output

- One line per issue maximum
- State the problem, not suggestions
- No praise, no filler text
- Skip if no critical issues found

## Linux Socket Internals

### Non-Blocking Connect Flow
```
connect() → EINPROGRESS (async start)
   ↓
poll/epoll waits for POLLOUT
   ↓
Second connect() OR getsockopt(SO_ERROR)
   ↓
Returns: 0 (success), EISCONN (already connected), or actual error
```

**Kernel behavior (af_inet.c)**: Second connect() on TCP_CLOSE calls `sock_error()` which atomically returns AND clears `sk_err`. The SO_ERROR path is effectively dead code.

### Error Semantics

| Errno | Category | Meaning |
|-------|----------|---------|
| EAGAIN/EWOULDBLOCK | Control flow | Try again (non-blocking) |
| EINPROGRESS | Control flow | Connect started, poll for completion |
| EALREADY | Control flow | Connect already in progress |
| EISCONN | Success | Already connected (treat as success) |
| ECONNREFUSED | Fatal | No listener on port |
| ECONNRESET | Fatal | Peer closed unexpectedly |
| ETIMEDOUT | Fatal | Connection timed out |
| EADDRINUSE | Fatal | Address already bound |

### Socket Options

| Option | Purpose | Notes |
|--------|---------|-------|
| SO_REUSEADDR | Reuse TIME_WAIT addresses | Always set for servers |
| SO_REUSEPORT | Multi-listener load balancing | Linux 3.9+ |
| SO_ZEROCOPY | Zero-copy sendmsg | Requires MSG_ZEROCOPY flag |
| SOCK_NONBLOCK | Non-blocking mode | Set at socket()/accept4() |
| SOCK_CLOEXEC | Close-on-exec | Prevents FD leaks to children |

### Protocol Specifics

**TCP**: SOCK_STREAM, reliable, connection-oriented
- Listen backlog: pending connection queue
- accept4(): Returns new connected socket FD

**UDP**: SOCK_DGRAM, unreliable, connectionless
- connect(): Sets default destination (optional)
- Can use sendto()/recvfrom() without connect()

**SCTP**: SOCK_STREAM or SOCK_SEQPACKET
- Multi-homing, multi-streaming
- socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)
- Listener uses SOCK_STREAM (NOT SOCK_SEQPACKET)

**Unix Domain**: AF_UNIX
- Pathname: /path/to/socket (filesystem visible)
- Abstract: @name (Linux-only, no filesystem entry)
- SCM_RIGHTS: Pass file descriptors between processes

### Address Structures

```c
struct sockaddr_in {   // IPv4, 16 bytes
    sa_family_t sin_family;  // AF_INET
    in_port_t sin_port;      // Network byte order (big-endian)
    struct in_addr sin_addr; // Network byte order
};

struct sockaddr_in6 {  // IPv6, 28 bytes
    sa_family_t sin6_family;
    in_port_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};

struct sockaddr_un {   // Unix, 110 bytes
    sa_family_t sun_family;  // AF_UNIX
    char sun_path[108];      // Pathname or abstract (starts with \0)
};
```

### Common Review Mistakes (Avoid These)

1. **Flagging EISCONN as unhandled error** - It means success for non-blocking connect
2. **Suggesting SO_ERROR after second connect()** - Kernel already returned error directly
3. **Flagging missing EWOULDBLOCK handling** - It's ErrWouldBlock, control flow not error
4. **Suggesting mutex for fd.Close()** - Atomic swap is intentional (lock-free)
5. **Flagging raw pointer in syscall args** - zcall requires unsafe.Pointer, zero-copy design
6. **Suggesting error wrapping** - Sentinel errors enable errors.Is() matching
