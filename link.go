// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sock

import "net"

// Link is a snapshot of a network link's attributes.
type Link struct {
	Index        int              // Interface index (if_index).
	MTU          int              // Maximum transmission unit in bytes.
	Name         string           // Interface name (e.g., "eth0", "lo").
	HardwareAddr net.HardwareAddr // MAC address; nil for loopback and zero hardware addresses.
	Flags        net.Flags        // Interface flags (net.FlagUp, net.FlagLoopback, etc.).
}
