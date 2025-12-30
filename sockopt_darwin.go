// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build darwin

package sock

import "code.hybscloud.com/iofd"

// Darwin-specific socket option functions.
// Some options are not available on Darwin and return ErrNotSupported.

// SetTCPCork is not available on Darwin.
func SetTCPCork(fd *iofd.FD, enable bool) error {
	return ErrNotSupported
}

// GetTCPCork is not available on Darwin.
func GetTCPCork(fd *iofd.FD) (bool, error) {
	return false, ErrNotSupported
}

// SetTCPQuickAck is not available on Darwin.
func SetTCPQuickAck(fd *iofd.FD, enable bool) error {
	return ErrNotSupported
}

// GetTCPQuickAck is not available on Darwin.
func GetTCPQuickAck(fd *iofd.FD) (bool, error) {
	return false, ErrNotSupported
}

// SetZeroCopy is not available on Darwin.
func SetZeroCopy(fd *iofd.FD, enable bool) error {
	return nil // Silently ignore on Darwin
}

// GetZeroCopy is not available on Darwin.
func GetZeroCopy(fd *iofd.FD) (bool, error) {
	return false, nil
}

// SetTCPKeepIdle sets the TCP keepalive idle time on Darwin.
// On Darwin, this is TCP_KEEPALIVE instead of TCP_KEEPIDLE.
func SetTCPKeepIdle(fd *iofd.FD, secs int) error {
	return setSockoptInt(fd, IPPROTO_TCP, TCP_KEEPALIVE, secs)
}

// GetTCPKeepIdle gets the TCP keepalive idle time on Darwin.
func GetTCPKeepIdle(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, IPPROTO_TCP, TCP_KEEPALIVE)
}

// SetTCPDeferAccept is not available on Darwin.
func SetTCPDeferAccept(fd *iofd.FD, secs int) error {
	return ErrNotSupported
}

// GetTCPDeferAccept is not available on Darwin.
func GetTCPDeferAccept(fd *iofd.FD) (int, error) {
	return 0, ErrNotSupported
}

// SetTCPFastOpen is not available on Darwin in the same way as Linux.
func SetTCPFastOpen(fd *iofd.FD, qlen int) error {
	return ErrNotSupported
}

// GetTCPFastOpen is not available on Darwin.
func GetTCPFastOpen(fd *iofd.FD) (int, error) {
	return 0, ErrNotSupported
}

// SetIPv6Only enables or disables the IPV6_V6ONLY socket option.
func SetIPv6Only(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, IPPROTO_IPV6, IPV6_V6ONLY, boolToInt(enable))
}

// GetIPv6Only returns the current IPV6_V6ONLY setting.
func GetIPv6Only(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, IPPROTO_IPV6, IPV6_V6ONLY)
	return v != 0, err
}

// Darwin-specific socket option constants
const (
	TCP_KEEPALIVE = 0x10 // Darwin's equivalent of TCP_KEEPIDLE
)
