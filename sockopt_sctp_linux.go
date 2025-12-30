// ©Hayabusa Cloud Co., Ltd. 2025. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package sock

import (
	"unsafe"

	"code.hybscloud.com/iofd"
	"code.hybscloud.com/zcall"
)

// SCTP socket option constants.
// Reference: /usr/include/netinet/sctp.h
const (
	SCTP_RTOINFO             = 0
	SCTP_ASSOCINFO           = 1
	SCTP_INITMSG             = 2
	SCTP_NODELAY             = 3
	SCTP_AUTOCLOSE           = 4
	SCTP_SET_PEER_PRIMARY    = 5
	SCTP_PRIMARY_ADDR        = 6
	SCTP_ADAPTATION_LAYER    = 7
	SCTP_DISABLE_FRAGMENTS   = 8
	SCTP_PEER_ADDR_PARAMS    = 9
	SCTP_DEFAULT_SEND_PARAM  = 10
	SCTP_EVENTS              = 11
	SCTP_I_WANT_MAPPED_V4    = 12
	SCTP_MAXSEG              = 13
	SCTP_STATUS              = 14
	SCTP_GET_PEER_ADDR_INFO  = 15
	SCTP_DELAYED_ACK_TIME    = 16
	SCTP_DELAYED_SACK        = SCTP_DELAYED_ACK_TIME
	SCTP_CONTEXT             = 17
	SCTP_FRAGMENT_INTERLEAVE = 18
	SCTP_PARTIAL_DELIVERY    = 19
	SCTP_MAX_BURST           = 20
	SCTP_HMAC_IDENT          = 22
	SCTP_AUTH_ACTIVE_KEY     = 24
	SCTP_AUTO_ASCONF         = 30
	SCTP_PEER_ADDR_THLDS     = 31
)

// SCTPInitMsg represents SCTP association initialization parameters.
type SCTPInitMsg struct {
	NumOstreams    uint16 // Number of outbound streams
	MaxInstreams   uint16 // Maximum inbound streams
	MaxAttempts    uint16 // Max retransmissions during association setup
	MaxInitTimeout uint16 // Max init timeout (ms)
}

// SetSCTPNodelay enables or disables the SCTP_NODELAY socket option.
// When enabled, disables Nagle-like algorithm for lower latency.
func SetSCTPNodelay(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_NODELAY, boolToInt(enable))
}

// GetSCTPNodelay returns the current SCTP_NODELAY setting.
func GetSCTPNodelay(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, zcall.SOL_SCTP, SCTP_NODELAY)
	return v != 0, err
}

// SetSCTPDisableFragments enables or disables the SCTP_DISABLE_FRAGMENTS option.
// When enabled, SCTP will not fragment messages.
func SetSCTPDisableFragments(fd *iofd.FD, disable bool) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_DISABLE_FRAGMENTS, boolToInt(disable))
}

// GetSCTPDisableFragments returns the current SCTP_DISABLE_FRAGMENTS setting.
func GetSCTPDisableFragments(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, zcall.SOL_SCTP, SCTP_DISABLE_FRAGMENTS)
	return v != 0, err
}

// SetSCTPAutoclose sets the SCTP_AUTOCLOSE option.
// When set to a non-zero value, idle associations are closed after
// the specified number of seconds.
func SetSCTPAutoclose(fd *iofd.FD, secs int) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_AUTOCLOSE, secs)
}

// GetSCTPAutoclose returns the current SCTP_AUTOCLOSE setting.
func GetSCTPAutoclose(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, zcall.SOL_SCTP, SCTP_AUTOCLOSE)
}

// SetSCTPMaxseg sets the SCTP_MAXSEG option.
// This sets the maximum segment size for SCTP packets.
func SetSCTPMaxseg(fd *iofd.FD, size int) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_MAXSEG, size)
}

// GetSCTPMaxseg returns the current SCTP_MAXSEG setting.
func GetSCTPMaxseg(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, zcall.SOL_SCTP, SCTP_MAXSEG)
}

// SetSCTPMaxBurst sets the SCTP_MAX_BURST option.
// This limits the number of packets that can be sent in a burst.
func SetSCTPMaxBurst(fd *iofd.FD, burst int) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_MAX_BURST, burst)
}

// GetSCTPMaxBurst returns the current SCTP_MAX_BURST setting.
func GetSCTPMaxBurst(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, zcall.SOL_SCTP, SCTP_MAX_BURST)
}

// SetSCTPInitMsg sets the SCTP_INITMSG option for association initialization.
// This configures the default number of streams and retransmission parameters.
func SetSCTPInitMsg(fd *iofd.FD, msg *SCTPInitMsg) error {
	errno := zcall.Setsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.SOL_SCTP),
		uintptr(SCTP_INITMSG),
		unsafe.Pointer(msg),
		unsafe.Sizeof(*msg),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}

// GetSCTPInitMsg gets the SCTP_INITMSG option.
func GetSCTPInitMsg(fd *iofd.FD) (*SCTPInitMsg, error) {
	var msg SCTPInitMsg
	msgLen := uint32(unsafe.Sizeof(msg))
	errno := zcall.Getsockopt(
		uintptr(fd.Raw()),
		uintptr(zcall.SOL_SCTP),
		uintptr(SCTP_INITMSG),
		unsafe.Pointer(&msg),
		unsafe.Pointer(&msgLen),
	)
	if errno != 0 {
		return nil, errFromErrno(errno)
	}
	return &msg, nil
}

// SetSCTPContext sets the SCTP_CONTEXT option.
// This sets the default context value for outgoing messages.
func SetSCTPContext(fd *iofd.FD, context uint32) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_CONTEXT, int(context))
}

// GetSCTPContext returns the current SCTP_CONTEXT setting.
func GetSCTPContext(fd *iofd.FD) (uint32, error) {
	v, err := getSockoptInt(fd, zcall.SOL_SCTP, SCTP_CONTEXT)
	return uint32(v), err
}

// SetSCTPFragmentInterleave sets the SCTP_FRAGMENT_INTERLEAVE option.
// 0 = no interleaving, 1 = interleave same association, 2 = full interleave
func SetSCTPFragmentInterleave(fd *iofd.FD, level int) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_FRAGMENT_INTERLEAVE, level)
}

// GetSCTPFragmentInterleave returns the current SCTP_FRAGMENT_INTERLEAVE setting.
func GetSCTPFragmentInterleave(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, zcall.SOL_SCTP, SCTP_FRAGMENT_INTERLEAVE)
}

// SetSCTPPartialDeliveryPoint sets the SCTP_PARTIAL_DELIVERY_POINT option.
// This sets the threshold (in bytes) for partial delivery.
func SetSCTPPartialDeliveryPoint(fd *iofd.FD, bytes int) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_PARTIAL_DELIVERY, bytes)
}

// GetSCTPPartialDeliveryPoint returns the current SCTP_PARTIAL_DELIVERY_POINT setting.
func GetSCTPPartialDeliveryPoint(fd *iofd.FD) (int, error) {
	return getSockoptInt(fd, zcall.SOL_SCTP, SCTP_PARTIAL_DELIVERY)
}

// SetSCTPMappedV4 enables or disables IPv4 mapped addresses.
func SetSCTPMappedV4(fd *iofd.FD, enable bool) error {
	return setSockoptInt(fd, zcall.SOL_SCTP, SCTP_I_WANT_MAPPED_V4, boolToInt(enable))
}

// GetSCTPMappedV4 returns the current SCTP_I_WANT_MAPPED_V4 setting.
func GetSCTPMappedV4(fd *iofd.FD) (bool, error) {
	v, err := getSockoptInt(fd, zcall.SOL_SCTP, SCTP_I_WANT_MAPPED_V4)
	return v != 0, err
}
