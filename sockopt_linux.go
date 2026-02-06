// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import "code.hybscloud.com/iofd"

// Linux-specific socket option functions.
// These options are only available on Linux and should not be used
// in cross-platform code.

// SetTCPCork enables or disables the TCP_CORK socket option.
// When enabled, delays sending data until the cork is removed or
// the socket buffer is full, allowing for more efficient packet packing.
func SetTCPCork(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_TCP, TCP_CORK, boolToInt(enable))
}

// GetTCPCork returns the current TCP_CORK setting.
func GetTCPCork(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_TCP, TCP_CORK)
	return v != 0, err
}

// SetTCPQuickAck enables or disables the TCP_QUICKACK socket option.
// When enabled, sends ACKs immediately rather than delaying them.
func SetTCPQuickAck(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_TCP, TCP_QUICKACK, boolToInt(enable))
}

// GetTCPQuickAck returns the current TCP_QUICKACK setting.
func GetTCPQuickAck(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_TCP, TCP_QUICKACK)
	return v != 0, err
}

// SetZeroCopy enables or disables the SO_ZEROCOPY socket option.
// When enabled, allows zero-copy transmission using MSG_ZEROCOPY flag.
// Requires kernel 4.14+ for TCP and 5.0+ for UDP.
func SetZeroCopy(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_SOCKET, SO_ZEROCOPY, boolToInt(enable))
}

// GetZeroCopy returns the current SO_ZEROCOPY setting.
func GetZeroCopy(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_SOCKET, SO_ZEROCOPY)
	return v != 0, err
}

// SetTCPKeepIdle sets the TCP_KEEPIDLE socket option.
// This sets the time (in seconds) the connection needs to remain idle
// before TCP starts sending keepalive probes.
func SetTCPKeepIdle(fd *iofd.FD, secs int) error {
	return setSockoptInt(fd, SOL_TCP, TCP_KEEPIDLE, secs)
}

// GetTCPKeepIdle returns the current TCP_KEEPIDLE setting.
func GetTCPKeepIdle(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_TCP, TCP_KEEPIDLE)
}

// SetTCPDeferAccept sets the TCP_DEFER_ACCEPT socket option.
// This sets the time (in seconds) to wait for data after accept()
// before waking up the application.
func SetTCPDeferAccept(fd *iofd.FD, secs int) error {
	return setSockoptInt(fd, SOL_TCP, TCP_DEFER_ACCEPT, secs)
}

// GetTCPDeferAccept returns the current TCP_DEFER_ACCEPT setting.
func GetTCPDeferAccept(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_TCP, TCP_DEFER_ACCEPT)
}

// SetTCPFastOpen sets the TCP_FASTOPEN socket option.
// This sets the maximum length of pending SYNs for TFO (TCP Fast Open).
func SetTCPFastOpen(fd *iofd.FD, qlen int) error {
	return setSockoptInt(fd, SOL_TCP, TCP_FASTOPEN, qlen)
}

// GetTCPFastOpen returns the current TCP_FASTOPEN setting.
func GetTCPFastOpen(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_TCP, TCP_FASTOPEN)
}

// SetIPv6Only enables or disables the IPV6_V6ONLY socket option.
// When enabled, restricts the socket to IPv6 communication only.
func SetIPv6Only(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_IPV6, IPV6_V6ONLY, boolToInt(enable))
}

// GetIPv6Only returns the current IPV6_V6ONLY setting.
func GetIPv6Only(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_IPV6, IPV6_V6ONLY)
	return v != 0, err
}

// SetTCPUserTimeout sets the TCP_USER_TIMEOUT socket option.
// This sets the maximum time (in milliseconds) that transmitted data may
// remain unacknowledged before the connection is forcefully closed.
func SetTCPUserTimeout(fd *iofd.FD, ms int) error {
	return setSockoptInt(fd, SOL_TCP, TCP_USER_TIMEOUT, ms)
}

// GetTCPUserTimeout returns the current TCP_USER_TIMEOUT setting.
func GetTCPUserTimeout(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_TCP, TCP_USER_TIMEOUT)
}

// SetTCPNotsentLowat sets the TCP_NOTSENT_LOWAT socket option.
// This sets the threshold in bytes for the amount of unsent data
// in the socket write buffer before the socket becomes writable.
func SetTCPNotsentLowat(fd *iofd.FD, bytes int) error {
	return setSockoptInt(fd, SOL_TCP, TCP_NOTSENT_LOWAT, bytes)
}

// GetTCPNotsentLowat returns the current TCP_NOTSENT_LOWAT setting.
func GetTCPNotsentLowat(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_TCP, TCP_NOTSENT_LOWAT)
}

// SetUDPSegment sets the UDP_SEGMENT socket option for UDP GSO.
// This sets the segment size in bytes for UDP Generic Segmentation Offload.
// The kernel will split large datagrams into segments of this size.
func SetUDPSegment(fd *iofd.FD, segmentSize int) error {
	return setSockoptInt(fd, SOL_UDP, UDP_SEGMENT, segmentSize)
}

// GetUDPSegment returns the current UDP_SEGMENT setting.
func GetUDPSegment(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_UDP, UDP_SEGMENT)
}

// SetUDPGRO enables or disables the UDP_GRO socket option.
// When enabled, the kernel coalesces incoming UDP packets
// before delivering them to the application.
func SetUDPGRO(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_UDP, UDP_GRO, boolToInt(enable))
}

// GetUDPGRO returns the current UDP_GRO setting.
func GetUDPGRO(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_UDP, UDP_GRO)
	return v != 0, err
}

// SetIPTransparent enables or disables the IP_TRANSPARENT socket option.
// When enabled, allows binding to non-local addresses and enables
// transparent proxying. Requires CAP_NET_ADMIN capability.
func SetIPTransparent(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, SOL_IP, IP_TRANSPARENT, boolToInt(enable))
}

// GetIPTransparent returns the current IP_TRANSPARENT setting.
func GetIPTransparent(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, SOL_IP, IP_TRANSPARENT)
	return v != 0, err
}

// SetBusyPoll sets the SO_BUSY_POLL socket option.
// This sets the approximate time in microseconds to busy poll
// waiting for packets when the socket is idle.
func SetBusyPoll(fd *iofd.FD, usecs int) error {
	return setSockoptInt(fd, SOL_SOCKET, SO_BUSY_POLL, usecs)
}

// GetBusyPoll returns the current SO_BUSY_POLL setting.
func GetBusyPoll(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, SOL_SOCKET, SO_BUSY_POLL)
}
