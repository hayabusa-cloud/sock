// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build freebsd

package sock

import "code.hybscloud.com/iofd"

// FreeBSD-specific socket option functions.

// SetZeroCopy is a no-op on FreeBSD (SO_ZEROCOPY not supported).
// Returns nil to allow graceful degradation.
func SetZeroCopy(fd *iofd.FD, enable bool) error {
	return nil
}

// GetZeroCopy always returns false on FreeBSD.
func GetZeroCopy(fd *iofd.FD) (bool, error) {
	return false, nil
}

// SetTCPKeepIdle sets the TCP_KEEPIDLE socket option.
// On FreeBSD, this is TCP_KEEPIDLE (256).
func SetTCPKeepIdle(fd *iofd.FD, secs int) error {
	return setSockoptInt(fd, SOL_TCP, TCP_KEEPIDLE, secs)
}

// GetTCPKeepIdle returns the current TCP_KEEPIDLE setting.
func GetTCPKeepIdle(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_TCP, TCP_KEEPIDLE)
}

// SetIPv6Only enables or disables the IPV6_V6ONLY socket option.
func SetIPv6Only(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_IPV6, IPV6_V6ONLY, boolToInt(enable))
}

// GetIPv6Only returns the current IPV6_V6ONLY setting.
func GetIPv6Only(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_IPV6, IPV6_V6ONLY)
	return v != 0, err
}
