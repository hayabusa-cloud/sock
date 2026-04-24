# sock/examples — Generation Guide

Guide for generating higher layer code above `code.hybscloud.com/sock`.

These files are black-box examples (`package sock_test`): they show how application or runtime code uses `sock` without
reaching into package internals. Start with `doc.go` for the package-level overview, then open the scenario-specific
test files.

Platform: Linux (recommend 6.18 LTS), Go 1.26+.

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
- adaptive retry when a deadline is set
- raw fd exposure via `FD().Raw()` for readiness/completion handoff

Code above `sock` owns:

- accept / dispatch / shutdown policy
- caller-owned retry loops using `iox.Backoff`
- readiness or completion integration (`uring`, epoll, or another runtime)
- protocol logic, handler scheduling, and orchestration

The live story is: `sock` exposes non-blocking socket lifecycle over `zcall` / `iofd` with `iox` semantics; caller code
can stay manual, submit raw fds to `uring`, or move up to `urex` when it wants a full runtime surface.

## Default Imports

```go
import (
"bytes"
"net"
"time"

"code.hybscloud.com/iox"
"code.hybscloud.com/sock"
)
```

Add `code.hybscloud.com/uring` when you are actually submitting SQEs. Move up to `code.hybscloud.com/urex`
when the example is about the runtime layer rather than bare socket control flow.

## Choose a Starting Point

| Need                                        | Start from           | Why                                                                        |
|---------------------------------------------|----------------------|----------------------------------------------------------------------------|
| High-level overview of the examples package | `doc.go`             | Explains the examples boundary and reading order                           |
| TCP echo server or client/server round trip | `tcp_test.go`        | Shows dial/listen, adaptive deadlines, and non-blocking semantics          |
| UDP request/response                        | `udp_test.go`        | Shows both unconnected and connected UDP flows                             |
| Manual accept loop above `sock`             | `event_loop_test.go` | Shows caller-owned dispatch and `iox.Backoff` above `sock`                 |
| `uring` handoff via raw fd                  | `event_loop_test.go` | Shows `FD().Raw()` as the boundary for `ACCEPT`, `RECV`, `SEND`, `RECVMSG` |

## Higher Layer Code Rules

1. **No deadline means pure non-blocking.** Expect `iox.ErrWouldBlock` and hand control back to your loop.
2. **In caller-owned retry loops, use `iox.Backoff`.** `sock` keeps its network-tuned adaptive backoff internal to
   deadline-driven APIs.
3. **A deadline enables adaptive retry inside `sock`.** Use it for single-goroutine logic that should keep trying until
   success or `sock.ErrTimedOut`.
4. **Keep the fd handoff explicit.** Create sockets with `sock`, then pass `FD().Raw()` to `uring` or a runtime such as
   `urex`.
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

```go
ln, err := sock.ListenTCP4(laddr)
if err != nil {
return err
}
fd := ln.FD().Raw()

// Caller-owned completion layer:
// submit ACCEPT / RECV / SEND on fd through uring,
// then dispatch CQEs in your loop or runtime.
_ = fd
```

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
- Do not use fixed `time.Sleep` for repeated `ErrWouldBlock` polling; use `iox.Backoff` or a readiness/completion
  wakeup.
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

`OK` and `Failure` are terminal: the operation completed or broke. `WouldBlock`
and `More` are *semantic* (non-terminal): they signal that the operation can
resume. `Classify(err) → Outcome` is the universal classifier; `IsSemantic`,
`IsNonFailure`, and `IsProgress` are derived predicates on this carrier.

For the current canon, the stable facts are:

- counts carry progress; errors carry control;
- `OK` is completion, `Failure` is terminal failure;
- `WouldBlock` means no progress is available yet and the caller must wait or retry;
- `More` means progress happened and more completions remain;
- the base calculus does **not** force a unique global order between `WouldBlock`
  and `More`.

For the current `sock/examples` tree specifically, plain `sock` calls mainly
surface `ErrWouldBlock` directly. `ErrMore` belongs to the shared `iox`
classifier vocabulary and appears primarily in the referenced helper/policy
layers above bare socket syscalls.

### Semantic errors as algebraic effects

In the algebraic-effects reading, `ErrWouldBlock` and `ErrMore` are *effect constructors* — they suspend the
copy engine at a well-defined point and yield control to a handler. The handler decides whether to *resume*
(retry) or *discharge* (return the signal to the caller).

The standard `io.Copy` model has no effects: every non-nil, non-EOF error is terminal. `iox.Copy` extends
this by recognising the two semantic errors as resumable suspension points, but with a fixed handler that
always discharges (returns immediately). This is the *free* (uninterpreted) semantics.

### SemanticPolicy as effect handler

`SemanticPolicy` is the handler interface. It interprets each suspended effect:

```
SemanticPolicy : (Op × SemanticError) → PolicyAction
PolicyAction   = { Return, Retry }
```

where `Op` identifies the site (read-side vs write-side, direct vs WriterTo/ReaderFrom fast path).

- `PolicyReturn` — discharge the effect: propagate the semantic error to the caller.
- `PolicyRetry`  — resume the effect: call `Yield(op)`, then re-enter the operation.

`Yield` is the *delimited continuation*: it represents the wait/park/poll step between suspension and
resumption. Its implementation is pluggable (runtime.Gosched, epoll wait, io_uring reap, backoff, etc.).

### Composition: CopyPolicy and CopyNPolicy

`CopyPolicy` and `CopyNPolicy` compose the copy engine with a handler:

```
CopyPolicy(dst, src, policy) = interpret(policy, Copy(dst, src))
```

Without a policy (nil), the engine degenerates to `Copy` / `CopyN` — pure non-blocking, caller handles
everything. With a policy, the engine becomes an *effect interpreter* that can absorb some or all semantic
signals internally.

The built-in policies form a lattice of handler strategies:

| Policy                         | WouldBlock         | More   | Character                                     |
|--------------------------------|--------------------|--------|-----------------------------------------------|
| `ReturnPolicy`                 | Return             | Return | Free (uninterpreted); identical to bare Copy  |
| `YieldPolicy`                  | Retry (yield)      | Return | Absorbs readiness stalls, surfaces boundaries |
| `YieldOnWriteWouldBlockPolicy` | Retry (write only) | Return | Asymmetric: writer backpressure only          |
| `PolicyFunc{…}`                | custom             | custom | Fully programmable handler                    |

### Partial-write recovery and the Seeker adjunction

When a write-side semantic error occurs with partial progress (`nw < nr`), the engine faces a data-integrity
problem: bytes were read from `src` but not fully written to `dst`. The resolution depends on the policy
action:

- **PolicyRetry**: the engine loops on the remaining slice `buf[off:nr]`, guaranteeing forward progress.
  No rollback needed — the continuation consumes the residual.
- **PolicyReturn**: the engine attempts `src.Seek(delta, SeekCurrent)` to rewind the source. If `src`
  is not seekable, `ErrNoSeeker` is returned to prevent silent data loss.

In categorical terms, `io.Seeker` acts as a *right adjoint* to the read functor: it provides the inverse
morphism (rewind) that makes partial-read recovery natural. Non-seekable sources (sockets, pipes) lack this
adjoint, so the only safe strategy is `PolicyRetry` on write-side effects.

### Summary: the `iox` effect system

```
  I/O call
    │
    ▼
  Classify ──► Outcome ∈ {OK, WouldBlock, More, Failure}
                 │
            ┌────┴────┐
         terminal   semantic (effect)
         (OK/Fail)     │
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

The design is equivalent to a one-shot algebraic effect system with two effect constructors, a binary
handler algebra, and a pluggable delimited continuation. It keeps the non-blocking I/O model compositional:
callers choose their interpretation without modifying the engine, and the engine guarantees data integrity
across all handler choices.
