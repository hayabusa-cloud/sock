// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build unix

package sock_test

import (
	"testing"

	"code.hybscloud.com/sock"
)

func TestNetSocket_NetworkTypeIPv6(t *testing.T) {
	s, err := sock.NewTCPSocket6()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if got := s.NetworkType(); got != sock.NetworkIPv6 {
		t.Errorf("NetworkType() = %d, want %d", got, sock.NetworkIPv6)
	}
}
