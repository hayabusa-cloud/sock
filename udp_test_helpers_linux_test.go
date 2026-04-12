// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"testing"
	"time"

	"code.hybscloud.com/iox"
	"code.hybscloud.com/zcall"
)

// newBlockedUDPTestConn wraps one end of a connected Unix SOCK_DGRAM socketpair
// in a UDPConn after forcing the sender into the iox.ErrWouldBlock state.
func newBlockedUDPTestConn(t *testing.T) (*UDPConn, []byte) {
	t.Helper()

	pair, err := NetSocketPair(zcall.AF_UNIX, zcall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("NetSocketPair: %v", err)
	}
	t.Cleanup(func() {
		pair[0].Close()
		pair[1].Close()
	})

	if err := SetSendBuffer(pair[0].fd, 4096); err != nil {
		t.Fatalf("SetSendBuffer: %v", err)
	}

	payload := make([]byte, 2048)
	deadline := time.Now().Add(250 * time.Millisecond)
	var backoff iox.Backoff

	// This helper is a caller-owned test loop above sock, so it uses the public
	// iox Adapt tier rather than sock's internal deadline-tuned netBackoff.
	for time.Now().Before(deadline) {
		_, err := pair[0].Write(payload)
		switch err {
		case nil:
			backoff.Wait()
		case iox.ErrWouldBlock:
			return &UDPConn{UDPSocket: &UDPSocket{NetSocket: pair[0]}}, payload
		default:
			t.Fatalf("fill send buffer: %v", err)
		}
	}

	t.Fatal("failed to force Unix datagram send buffer into ErrWouldBlock before timeout")
	return nil, nil
}
