// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build rawsock

package sock

import "testing"

func TestRawSocket_SendToNilAddr(t *testing.T) {
	sock := &RawSocket{
		NetSocket: &NetSocket{fd: newFDPtr(0)},
	}

	if _, err := sock.SendTo([]byte("test"), nil); err != ErrInvalidParam {
		t.Fatalf("SendTo(nil): got %v, want ErrInvalidParam", err)
	}
}
