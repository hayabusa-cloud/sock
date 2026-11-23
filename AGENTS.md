# sock

Use `code.hybscloud.com/sock` for nonblocking socket I/O. [Socket APIs](README.md)

- By default, `Read`, `Write`, and `Accept` return `iox.ErrWouldBlock` when the socket is not ready. With `NetSocket`, wait for readiness and retry. For automatic retries, set a deadline on the connection or listener. A listener uses the deadline in effect when `Accept` starts.
- For a pending TCP or SCTP handshake, `NetSocket.Connect` returns `sock.ErrInProgress`. `DialTCP` and `DialSCTP` return the connection and a nil error. A zero-timeout `TCPDialer` or `SCTPDialer` returns `(nil, sock.ErrInProgress)` in that case. Set a positive timeout to wait for the handshake.
- `FD()` returns a borrowed `*iofd.FD`. Keep the socket open until I/O using it completes. With `SyscallConn()`, keep it open through each `Control`, `Read`, or `Write` call on the returned handle. Return `false` from a read or write callback when it needs to wait for readiness. Use `s.FD().Dup()` for a descriptor you can close independently.
- Submit an ordinary io_uring accept on the listener. Its successful completion returns the new connection descriptor. Use that descriptor for sends and receives. [io_uring example](examples/AGENTS.md#uring-handoff)

## The `iox.Outcome` lattice

For a read or write, account for `n` before handling `err`. If a stream write of `"hello"` accepts three bytes, only `"lo"` remains. Try that suffix immediately on `nil`. If the result carries `iox.ErrWouldBlock`, wait for writability first.

| Error | `iox.Classify(err)` | Caller action |
|---|---|---|
| `nil` | `iox.OutcomeOK` | Interpret the count according to the socket and operation. |
| `iox.ErrWouldBlock` | `iox.OutcomeWouldBlock` | Wait for readiness if work remains. |
| `iox.ErrMore` | `iox.OutcomeMore` | Observe the next result of the same operation, as with a multishot request. The byte count can be zero. |
| Other error | `iox.OutcomeFailure` | Handle the original error. |

With a nonempty buffer, `TCPConn.Read` returns `(0, io.EOF)` after the peer finishes sending and all queued bytes have been read. At that point `NetSocket.Read` and the borrowed `FD().Read` return `(0, nil)`. On `UDPConn.Read`, `(0, nil)` with a nonempty buffer delivers one empty datagram.

The base lattice places `OK` below both `WouldBlock` and `More`, and `Failure` above both. `WouldBlock` and `More` are incomparable. When a single error matches both sentinels, `Classify` returns `iox.OutcomeWouldBlock`.

## Backoff

After `iox.ErrWouldBlock`, wait for a readiness notification if one is available. For a polling loop, keep one zero-value `iox.Backoff` across attempts. `Wait()` sleeps for one interval. `NextDelay()` returns an interval for the caller’s timer. Both advance the schedule. Call `Reset()` after transferring bytes, receiving a datagram (even an empty one), or accepting a connection. [Accept loop](examples/event_loop_test.go)

Block `k` supplies `k` intervals of `min(k × base, max)`. The default schedule gives one 500 µs interval, two 1 ms intervals, then three 1.5 ms intervals. The nominal delay caps at 100 ms before jitter of up to 12.5%.

With a deadline, the connection or listener retries internally. The starting tier adapts across operations. Nominal intervals double from 1 ms through 128 ms, then increase by 64 ms up to 640 ms before jitter.

## Verification

Run `make vet test` with Go 1.27+ on native Linux 6.18+.
