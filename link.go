// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sock

import "net"

// Link is a snapshot of a network link's attributes.
type Link struct {
	Index        int
	MTU          int
	Name         string
	HardwareAddr net.HardwareAddr
	Flags        net.Flags
}
