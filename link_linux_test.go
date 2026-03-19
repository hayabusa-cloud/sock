// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock_test

import (
	"net"
	"testing"

	"code.hybscloud.com/sock"
)

func TestLinks(t *testing.T) {
	links, err := sock.Links()
	if err != nil {
		t.Fatalf("sock.Links() failed: %v", err)
	}
	if len(links) == 0 {
		t.Fatal("sock.Links() returned no links")
	}
	var found bool
	for _, l := range links {
		if l.Name == "lo" {
			found = true
			break
		}
	}
	if !found {
		t.Error("sock.Links() did not include loopback interface")
	}
}

func TestLinkLookups(t *testing.T) {
	std, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("net.InterfaceByName(lo) failed: %v", err)
	}

	iface, err := sock.LinkByName("lo")
	if err != nil {
		t.Fatalf("sock.LinkByName(lo) failed: %v", err)
	}
	if iface.Index != std.Index {
		t.Fatalf("sock.LinkByName(lo).Index=%d, want %d", iface.Index, std.Index)
	}
	if iface.Name != std.Name {
		t.Fatalf("sock.LinkByName(lo).Name=%q, want %q", iface.Name, std.Name)
	}
	if iface.MTU != std.MTU {
		t.Fatalf("sock.LinkByName(lo).MTU=%d, want %d", iface.MTU, std.MTU)
	}
	if iface.Flags&net.FlagLoopback == 0 {
		t.Fatalf("sock.LinkByName(lo).Flags=%v, want loopback", iface.Flags)
	}
	if got, want := iface.HardwareAddr.String(), std.HardwareAddr.String(); got != want {
		t.Fatalf("sock.LinkByName(lo).HardwareAddr=%q, want %q", got, want)
	}

	byIndex, err := sock.LinkByIndex(std.Index)
	if err != nil {
		t.Fatalf("sock.LinkByIndex(%d) failed: %v", std.Index, err)
	}
	if byIndex.Name != std.Name {
		t.Fatalf("sock.LinkByIndex(%d).Name=%q, want %q", std.Index, byIndex.Name, std.Name)
	}
	if got, want := byIndex.HardwareAddr.String(), std.HardwareAddr.String(); got != want {
		t.Fatalf("sock.LinkByIndex(%d).HardwareAddr=%q, want %q", std.Index, got, want)
	}
}
