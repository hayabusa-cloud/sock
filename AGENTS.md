# sock

Use `code.hybscloud.com/sock` for nonblocking socket I/O. [Socket APIs](README.md)

- By default, `Read`, `Write`, and `Accept` return `iox.ErrWouldBlock` when the socket is not ready. With `NetSocket`, wait for readiness and retry. A connection retries `Read` or `Write` when the corresponding deadline is set. A listener uses the deadline in effect when `Accept` starts.
- For a pending TCP or SCTP handshake, `NetSocket.Connect` returns `sock.ErrInProgress`. `DialTCP` and `DialSCTP` return the connection and a nil error. A zero-timeout `TCPDialer` or `SCTPDialer` returns `(nil, sock.ErrInProgress)` in that case. Set a positive timeout to wait for the handshake.
- `FD()` returns a borrowed `*iofd.FD`. Keep the socket open until I/O using it completes. With `SyscallConn()`, keep it open through each `Control`, `Read`, or `Write` call on the returned handle. Use `s.FD().Dup()` for a descriptor you can close independently.
- Submit an ordinary io_uring accept on the listener. The caller owns the connection descriptor returned on success. Use it for sends and receives, then close it after the connection’s I/O finishes. [io_uring example](examples/AGENTS.md#uring-handoff)

## The `iox.Outcome` lattice

For a read or write, account for `n` before handling `err`. If a stream write of `"hello"` accepts three bytes, only `"lo"` remains. Try that suffix immediately on `nil`. If the result carries `iox.ErrWouldBlock`, wait for writability first.

| First matching condition | `iox.Classify(err)` | Caller action |
|---|---|---|
| `err == nil` | `iox.OutcomeOK` | Interpret the count according to the socket and operation. |
| `errors.Is(err, iox.ErrWouldBlock)` | `iox.OutcomeWouldBlock` | Wait for readiness if work remains. |
| `errors.Is(err, iox.ErrMore)` | `iox.OutcomeMore` | Observe the next result of the same operation, as with a multishot request. The byte count can be zero. |
| Otherwise | `iox.OutcomeFailure` | Handle the original error. |

With a nonempty buffer, `TCPConn.Read` returns `(0, io.EOF)` after the peer finishes sending and all queued bytes have been read. At that point `NetSocket.Read` and the borrowed `FD().Read` return `(0, nil)`. On `UDPConn.Read`, `(0, nil)` with a nonempty buffer delivers one empty datagram.

The base lattice places `OK` below both `WouldBlock` and `More`, and `Failure` above both. `WouldBlock` and `More` are incomparable. In Go, treat the named outcomes as unordered labels and switch on `iox.Classify(err)`. It recognizes wrapped sentinels and returns `iox.OutcomeWouldBlock` when both match.

## Backoff

### Caller polling with `iox.Backoff`

After `iox.ErrWouldBlock`, retry on a readiness notification if one is available. If you poll, keep one zero-value `iox.Backoff` per loop. `Wait()` consumes one interval and sleeps. `NextDelay()` consumes one interval and returns it for your timer. Call `Reset()` after transferring bytes, receiving a datagram (even an empty one), or accepting a connection. [Accept loop](examples/event_loop_test.go)

Block `k` supplies `k` intervals of `min(k × base, max)` before jitter. The default schedule starts with one 500 µs interval, two 1 ms intervals, then three 1.5 ms intervals. Jitter of up to 12.5% applies after the 100 ms nominal cap.

### Retries inside `sock`

Deadline-driven `Read`, `Write`, and `Accept` calls use `sock`’s private network backoff. A TCP or SCTP dialer with a positive `Timeout` uses it while the handshake is pending.

On Linux, the UDP batch methods `RecvMessages` and `SendMessages` stay nonblocking even with a deadline set. `RecvMessagesAdaptive` honors the read deadline and `SendMessagesAdaptive` honors the write deadline.

On a `SyscallConn()` handle, `Read` and `Write` ignore connection deadlines. If the operation would block, return `false` from the callback so the handle can back off and retry. Return `true` to finish.

The starting tier adapts across operations. Nominal intervals double from 1 ms through 128 ms, then increase by 64 ms up to 640 ms before jitter.

## Verification

Run `make vet test` with Go 1.27+ on native Linux 6.18+.
