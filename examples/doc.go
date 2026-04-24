// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

// Package sock_test provides user-facing examples for using
// `code.hybscloud.com/sock`.
//
// The examples stay at the same boundary available to application code. They
// create sockets with `sock`, observe `iox.ErrWouldBlock` in pure non-blocking
// mode, use `iox.Backoff` in caller-owned retry loops, enable deadline-driven
// adaptive retry inside `sock`, and hand raw file descriptors to caller-owned
// loops or runtimes above `sock`. The direct examples mainly surface the
// `iox.ErrWouldBlock` / `sock.ErrInProgress` boundary; the wider `iox`
// classifier surface (`iox.ErrMore`, `iox.Classify`, `iox.IsSemantic`,
// `iox.IsProgress`) remains relevant for helpers layered above `sock`.
//
// # Reading Order
//
// Start with these files:
//
//  1. `tcp_test.go` for stream dial/listen flow, adaptive deadlines, and
//     non-blocking semantics.
//  2. `udp_test.go` for unconnected and connected datagram flow.
//  3. `event_loop_test.go` for manual accept loops, `iox.Backoff`,
//     `FD().Raw()`, and the boundary to `uring` or higher runtimes such as
//     `urex`.
//
// Run the examples with:
//
//	go test -v code.hybscloud.com/sock/examples
package sock_test
