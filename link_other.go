// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build !linux

package sock

import "net"

func linkIndexByName(name string) int {
	if name == "" {
		return 0
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0
	}
	return iface.Index
}

func linkNameByIndex(index int) string {
	if index == 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return ""
	}
	return iface.Name
}
