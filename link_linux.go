// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"net"

	"code.hybscloud.com/zcall"
)

// Links returns the system network links.
func Links() ([]Link, error) {
	links, err := zcall.Links()
	if err != nil {
		return nil, err
	}
	out := make([]Link, 0, len(links))
	for _, link := range links {
		out = append(out, linkFrom(link))
	}
	return out, nil
}

// LinkByName returns the network link specified by name.
func LinkByName(name string) (*Link, error) {
	link, err := zcall.LinkByName(name)
	if err != nil {
		return nil, err
	}
	out := linkFrom(*link)
	return &out, nil
}

// LinkByIndex returns the network link specified by index.
func LinkByIndex(index int) (*Link, error) {
	link, err := zcall.LinkByIndex(index)
	if err != nil {
		return nil, err
	}
	out := linkFrom(*link)
	return &out, nil
}

func linkFrom(link zcall.Link) Link {
	hwaddr := append(net.HardwareAddr(nil), link.HardwareAddr...)
	if len(hwaddr) > 0 && (link.Flags&zcall.IFF_LOOPBACK != 0 || isZeroHardwareAddr(hwaddr)) {
		hwaddr = nil
	}

	return Link{
		Index:        link.Index,
		MTU:          link.MTU,
		Name:         link.Name,
		HardwareAddr: hwaddr,
		Flags:        linkFlags(link.Flags),
	}
}

func isZeroHardwareAddr(addr net.HardwareAddr) bool {
	for _, b := range addr {
		if b != 0 {
			return false
		}
	}
	return len(addr) > 0
}

func linkFlags(raw uint32) net.Flags {
	var flags net.Flags
	if raw&zcall.IFF_UP != 0 {
		flags |= net.FlagUp
	}
	if raw&zcall.IFF_BROADCAST != 0 {
		flags |= net.FlagBroadcast
	}
	if raw&zcall.IFF_LOOPBACK != 0 {
		flags |= net.FlagLoopback
	}
	if raw&zcall.IFF_POINTOPOINT != 0 {
		flags |= net.FlagPointToPoint
	}
	if raw&zcall.IFF_RUNNING != 0 {
		flags |= net.FlagRunning
	}
	if raw&zcall.IFF_MULTICAST != 0 {
		flags |= net.FlagMulticast
	}
	return flags
}

func linkIndexByName(name string) int {
	if name == "" {
		return 0
	}
	link, err := LinkByName(name)
	if err != nil {
		return 0
	}
	return link.Index
}

func linkNameByIndex(index int) string {
	if index == 0 {
		return ""
	}
	link, err := LinkByIndex(index)
	if err != nil {
		return ""
	}
	return link.Name
}
