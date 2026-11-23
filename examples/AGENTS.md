# sock/examples — Generation Guide

Guide for generating higher layer code above `code.hybscloud.com/sock`.

These files are black-box examples (`package sock_test`): they show how application or runtime code uses `sock` without
reaching into package internals. Start with `doc.go` for the package-level overview, then open the scenario-specific
test files.

Platform: Linux (recommend 6.18 LTS), Go 1.27+.

## Ecosystem Position

| Layer                  | Packages               | Responsibility                                                                                       |
|------------------------|------------------------|------------------------------------------------------------------------------------------------------|
| Below `sock`           | `zcall`, `iofd`, `iox` | Raw syscalls, fd lifecycle, and non-blocking outcome semantics that `sock` exposes                   |
| Examples surface       | `sock` + caller code   | Socket lifecycle, explicit `iox.ErrWouldBlock`, deadline-driven adaptive retry, `FD().Raw()` handoff |
| Direct completion path | `uring`                | SQE/CQE submission on raw fds when caller code wants direct `io_uring` integration                   |

## Boundary

`sock` owns:

- socket creation, listen, dial, accept, read, write, close
- `iox` non-blocking semantics at the API boundary (`iox.ErrWouldBlock`, `iox.ErrMore` where applicable)
- deadline-driven retries and retries of raw `Read` or `Write` callbacks that return `false`
- raw fd exposure via `FD().Raw()` for readiness/completion handoff

Code above `sock` owns:

- accept / dispatch / shutdown policy
- polling with `iox.Backoff` when readiness notifications are unavailable
- readiness or completion integration (`uring`, epoll, or another runtime)
- protocol logic, handler scheduling, and orchestration

## Default Imports

```go
import (
	"bytes"
	"time"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/sock"
)
```

Import `code.hybscloud.com/uring` for examples that submit io_uring operations.

## Choose a Starting Point

| Need                                        | Start from           | Why                                                                        |
|---------------------------------------------|----------------------|----------------------------------------------------------------------------|
| High-level overview of the examples package | `doc.go`             | Explains the examples boundary and reading order                           |
| TCP echo server or client/server round trip | `tcp_test.go`        | Shows dial/listen, adaptive deadlines, and non-blocking semantics          |
| UDP request/response                        | `udp_test.go`        | Shows both unconnected and connected UDP flows                             |
| Manual accept loop above `sock`             | `event_loop_test.go` | Shows caller-owned dispatch and `iox.Backoff` above `sock`                 |
| `uring` handoff via raw fd                  | `event_loop_test.go` | Shows listener, connected TCP, and bound UDP descriptors |

## Higher Layer Code Rules

1. **With readiness notifications, leave the deadline unset.** After `iox.ErrWouldBlock`, retry `Read` or `Accept` when the socket is readable and `Write` when it is writable.
2. **When polling, keep one `iox.Backoff` per loop.** Call `Wait()` after `iox.ErrWouldBlock` and `Reset()` after progress, as in the accept loop below.
3. **Set a deadline to let `sock` retry.** The connection or listener waits internally and returns `sock.ErrTimedOut` if the operation remains blocked past the deadline. [Backoff schedules](../AGENTS.md#backoff)
4. **Keep the fd handoff explicit.** Keep the socket open while the event loop uses the descriptor borrowed through `FD().Raw()`.
5. **Use `iox.Copy`, `iox.CopyPolicy`, or `iox.CopyNPolicy`, not `io.Copy`.**
6. **For TCP streams, prefer `iox.CopyNPolicy` for exact byte counts and `iox.CopyPolicy` for stream-to-EOF flow.**
   Do not assume one `Read` or `Write` transfers a whole logical message.

## Minimal Shapes

### Manual TCP accept loop

```go
ln, err := sock.ListenTCP4(laddr)
if err != nil {
	return err
}
defer ln.Close()

var backoff iox.Backoff
for {
	conn, err := ln.Accept()
	if err == iox.ErrWouldBlock {
		backoff.Wait()
		continue
	}
	if err != nil {
		return err
	}
	backoff.Reset()
	go handleConn(conn)
}
```

### `uring` handoff

Keep the TCP listener `ln` open while the ring has an accept pending on it.

```go
listenerFD := ln.FD().Raw()
if err := ring.Accept(uring.ForFD(listenerFD)); err != nil {
	return err
}
```

When the event loop receives this accept’s completion, check `cqe.Err()`. On success, `cqe.Res` is the new connection descriptor. Submit `RECV` and `SEND` on that descriptor and close it after the connection’s I/O finishes.

### Adaptive read/write

```go
const n = int64(len("hello sock"))

var staging bytes.Buffer // bytes.Buffer satisfies iox.Reader and iox.Writer.

conn.SetReadDeadline(time.Now().Add(2 * time.Second))
if _, err := iox.CopyNPolicy(&staging, conn, n, iox.YieldPolicy{}); err != nil {
return err
}

conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
if _, err := iox.CopyNPolicy(conn, &staging, int64(staging.Len()), iox.YieldPolicy{}); err != nil {
return err
}
```

## Avoid

- Do not assume `sock` blocks like `net`.
- Do not hide `iox.ErrWouldBlock`; it is the control signal for caller-owned loops.
- Do not route non-blocking stream copies through `io.Copy`; use `iox.Copy`, `iox.CopyPolicy`, `iox.CopyNPolicy`, or
  another non-blocking-aware helper instead.
- Do not drop down into `syscall.RawConn` when `FD().Raw()` already gives the descriptor you need.

## File Map

| File                     | Demonstrates                                                                                                                                            |
|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `doc.go`                 | Package overview, boundary, reading order                                                                                                               |
| `tcp_test.go`            | TCP adaptive echo, pure non-blocking semantics, and staged exact-size / stream-to-EOF helpers via `iox.CopyNPolicy` / `iox.CopyPolicy`                  |
| `stream_helpers_test.go` | `iox`-compatible helper layer: fixed-size reads, EOF reads, and staged echo through `bytes.Buffer`                                                      |
| `udp_test.go`            | UDP echo (unconnected `ReadFrom` / `WriteTo`), connected mode (`Read` / `Write`), fd extraction for datagram runtimes                                   |
| `event_loop_test.go`     | Manual accept/dispatch above `sock`, staged per-connection echo, caller-owned `iox.Backoff`, raw-fd handoff to `uring`, and historical `sox` provenance |

## Run

```bash
go test -v -count=1 code.hybscloud.com/sock/examples
```

## `iox` Semantics extension

### The algebra behind `iox`

Every I/O call in `iox` classifies into four observable cases:

```
Outcome = { OK, WouldBlock, More, Failure }
```

`iox.Classify(err)` describes one call. `OK` can mean a short stream write or a complete datagram. On `Failure`, handle the original error. `WouldBlock` and `More` describe how work can resume. For a boolean check, pass `err` to `IsSemantic`, `IsNonFailure`, or `IsProgress`.

For reads and writes, account for the returned count before handling the outcome.

- `WouldBlock` means further progress requires readiness. If a read returns `(2, ErrWouldBlock)`, consume the two bytes before waiting to retry.
- `More` means the operation remains active. On `(0, ErrMore)`, keep observing the same operation.

Any ordering of `WouldBlock` and `More` comes from an explicit merge policy.

For the current `sock/examples` tree specifically, plain `sock` calls mainly
surface `ErrWouldBlock` directly. `ErrMore` belongs to the shared `iox`
classifier vocabulary and appears primarily in the referenced helper/policy
layers above bare socket syscalls.

### Semantic errors as algebraic effects

In the algebraic-effects reading, `ErrWouldBlock` and `ErrMore` are *effect constructors* — they suspend the
copy engine at a well-defined point and yield control to a handler. The handler decides whether to *resume*
(retry) or *discharge* (return the signal to the caller).

Bare `iox.Copy` returns control to the caller on a semantic signal. A partial write can also produce a recovery error as described below.

### SemanticPolicy as effect handler

`SemanticPolicy` is the handler interface. It interprets each suspended effect:

```
SemanticPolicy : (Op × SemanticError) → PolicyAction
PolicyAction   = { Return, Retry }
```

where `Op` identifies the site (read-side vs write-side, direct vs WriterTo/ReaderFrom fast path).

- `PolicyReturn` — discharge the effect: propagate the semantic error to the caller.
- `PolicyRetry`  — resume the effect: call `Yield(op)`, then re-enter the operation.

`Yield(op)` runs before a retry. It can wait for readiness, poll a completion, or yield the processor. The copy loop then resumes.

### Composition: CopyPolicy and CopyNPolicy

`CopyPolicy` and `CopyNPolicy` compose the copy engine with a handler:

```
CopyPolicy(dst, src, policy) = interpret(policy, Copy(dst, src))
```

A nil policy uses `Copy` or `CopyN`. An explicit policy handles exact `ErrWouldBlock` and `ErrMore` signals while work remains. Once the destination accepts the requested count, `CopyNPolicy` returns success.

The copy policies choose which signals to retry.

| Policy                         | WouldBlock         | More   | Character                                     |
|--------------------------------|--------------------|--------|-----------------------------------------------|
| `ReturnPolicy`                 | Return             | Return | Free (uninterpreted); identical to bare Copy  |
| `YieldPolicy`                  | Retry (yield)      | Return | Absorbs readiness stalls, surfaces boundaries |
| `YieldOnWriteWouldBlockPolicy` | Retry writes and delegated copy calls | Return | Direct reads return to the caller |
| `PolicyFunc{…}`                | custom             | custom | Fully programmable handler                    |

### Partial writes

If a destination accepts two bytes of `hello` and returns `ErrWouldBlock`, the generic copy loop has three bytes left to write.

- With `PolicyRetry`, the loop keeps `llo`, calls `Yield`, and retries that suffix. The destination may still be full.
- With `PolicyReturn`, the loop tries to rewind the source by three bytes. A successful seek leaves `llo` available for the caller. A socket source cannot seek, so the copy returns `(2, iox.ErrNoSeeker)`. A failed seek on a seekable source returns the seek error.

When `CopyPolicy` delegates to `WriterTo` or `ReaderFrom`, that method owns recovery of any unwritten bytes.

### Summary: the `iox` effect system

```
  I/O call
    │
    ▼
  Classify ──► Outcome ∈ {OK, WouldBlock, More, Failure}
                 │
            ┌────┴────┐
         terminal   semantic (effect)
         (OK/Fail)     │ exact sentinel and work remains
                       ▼
                 SemanticPolicy.On{WouldBlock,More}(op)
                       │
                 ┌─────┴─────┐
              Return       Retry
           (discharge)   (resume)
                            │
                         Yield(op)
                            │
                         re-enter
```
