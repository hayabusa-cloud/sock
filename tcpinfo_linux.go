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

// TCPInfo contains detailed information about a TCP connection.
// This structure matches the Linux kernel's struct tcp_info (uapi/linux/tcp.h).
// All fields are in host byte order.
type TCPInfo struct {
	State           uint8 // TCP state (e.g., TCP_ESTABLISHED)
	CAState         uint8 // Congestion avoidance state
	Retransmits     uint8 // Number of retransmits for current SYN/data
	Probes          uint8 // Number of unanswered 0-window probes
	Backoff         uint8 // Backoff timer counter
	Options         uint8 // Bitmask of TCPI_OPT_* flags
	WscaleRcvSnd    uint8 // Packed: snd_wscale:4, rcv_wscale:4
	DeliveryRateApp uint8 // Packed: delivery_rate_app_limited:1, fastopen_client_fail:2

	RTO    uint32 // Retransmit timeout (usec)
	ATO    uint32 // Predicted tick of soft clock (usec)
	SndMss uint32 // Send maximum segment size
	RcvMss uint32 // Receive maximum segment size

	Unacked uint32 // Packets sent but not yet ACKed
	Sacked  uint32 // SACKed packets
	Lost    uint32 // Lost packets
	Retrans uint32 // Retransmitted packets
	Fackets uint32 // FACKed packets

	// Times (msec)
	LastDataSent uint32 // Time since last data sent
	LastAckSent  uint32 // Not remembered, sorry (always 0)
	LastDataRecv uint32 // Time since last data received
	LastAckRecv  uint32 // Time since last ACK received

	// Metrics
	PMTU        uint32 // Path MTU
	RcvSsthresh uint32 // Receive slow start threshold
	RTT         uint32 // Smoothed round trip time (usec)
	RTTVar      uint32 // RTT variance (usec)
	SndSsthresh uint32 // Send slow start threshold
	SndCwnd     uint32 // Send congestion window
	AdvMss      uint32 // Advertised MSS
	Reordering  uint32 // Reordering metric

	RcvRTT   uint32 // Receiver RTT estimate (usec)
	RcvSpace uint32 // Receive buffer space

	TotalRetrans uint32 // Total number of retransmits

	PacingRate    uint64 // Pacing rate (bytes/sec)
	MaxPacingRate uint64 // Max pacing rate (bytes/sec)
	BytesAcked    uint64 // Bytes ACKed (RFC4898)
	BytesReceived uint64 // Bytes received (RFC4898)
	SegsOut       uint32 // Segments sent (RFC4898)
	SegsIn        uint32 // Segments received (RFC4898)

	NotsentBytes uint32 // Bytes not yet sent
	MinRTT       uint32 // Minimum RTT observed (usec)
	DataSegsIn   uint32 // Data segments received (RFC4898)
	DataSegsOut  uint32 // Data segments sent (RFC4898)

	DeliveryRate uint64 // Delivery rate (bytes/sec)

	BusyTime      uint64 // Time busy sending (usec)
	RwndLimited   uint64 // Time limited by receive window (usec)
	SndbufLimited uint64 // Time limited by send buffer (usec)

	Delivered   uint32 // Packets delivered
	DeliveredCE uint32 // Packets delivered with CE mark

	BytesSent    uint64 // Data bytes sent (RFC4898)
	BytesRetrans uint64 // Bytes retransmitted (RFC4898)
	DSACKDups    uint32 // DSACK duplicates
	ReordSeen    uint32 // Reordering events seen

	RcvOoopack uint32 // Out-of-order packets received

	SndWnd uint32 // Peer's receive window after scaling
	RcvWnd uint32 // Local receive window after scaling

	Rehash uint32 // PLB or timeout triggered rehash attempts

	TotalRTO           uint16 // Total RTO timeouts
	TotalRTORecoveries uint16 // Total RTO recoveries
	TotalRTOTime       uint32 // Time in RTO recovery (msec)
	ReceivedCE         uint32 // CE marks received

	// Accurate ECN byte counters (kernel 6.x+)
	DeliveredE1Bytes uint32
	DeliveredE0Bytes uint32
	DeliveredCEBytes uint32
	ReceivedE1Bytes  uint32
	ReceivedE0Bytes  uint32
	ReceivedCEBytes  uint32
	AccECNFailMode   uint16
	AccECNOptSeen    uint16
}

// SizeofTCPInfo is the size of the TCPInfo structure.
// This matches the Linux kernel's struct tcp_info (kernel 6.12+).
const SizeofTCPInfo = 280

// TCP states from Linux kernel.
const (
	TCP_ESTABLISHED = 1
	TCP_SYN_SENT    = 2
	TCP_SYN_RECV    = 3
	TCP_FIN_WAIT1   = 4
	TCP_FIN_WAIT2   = 5
	TCP_TIME_WAIT   = 6
	TCP_CLOSE       = 7
	TCP_CLOSE_WAIT  = 8
	TCP_LAST_ACK    = 9
	TCP_LISTEN      = 10
	TCP_CLOSING     = 11
)

// TCP congestion avoidance states.
const (
	TCP_CA_Open     = 0 // Normal operation
	TCP_CA_Disorder = 1 // DUPACKs or SACKs received
	TCP_CA_CWR      = 2 // ECN congestion window reduction
	TCP_CA_Recovery = 3 // Fast recovery in progress
	TCP_CA_Loss     = 4 // Loss recovery (RTO)
)

// TCPI_OPT_* option flags.
const (
	TCPI_OPT_TIMESTAMPS = 1  // Timestamps enabled
	TCPI_OPT_SACK       = 2  // SACK enabled
	TCPI_OPT_WSCALE     = 4  // Window scaling enabled
	TCPI_OPT_ECN        = 8  // ECN was negotiated
	TCPI_OPT_ECN_SEEN   = 16 // At least one ECT packet received
	TCPI_OPT_SYN_DATA   = 32 // SYN-ACK acked SYN data
	TCPI_OPT_USEC_TS    = 64 // Microsecond timestamps
)

// SndWscale returns the send window scaling factor.
func (info *TCPInfo) SndWscale() uint8 {
	return info.WscaleRcvSnd & 0x0f
}

// RcvWscale returns the receive window scaling factor.
func (info *TCPInfo) RcvWscale() uint8 {
	return (info.WscaleRcvSnd >> 4) & 0x0f
}

// IsDeliveryRateAppLimited returns true if delivery rate is application-limited.
func (info *TCPInfo) IsDeliveryRateAppLimited() bool {
	return (info.DeliveryRateApp & 0x01) != 0
}

// FastOpenClientFail returns the Fast Open client failure code.
func (info *TCPInfo) FastOpenClientFail() uint8 {
	return (info.DeliveryRateApp >> 1) & 0x03
}

// HasTimestamps returns true if TCP timestamps are enabled.
func (info *TCPInfo) HasTimestamps() bool {
	return (info.Options & TCPI_OPT_TIMESTAMPS) != 0
}

// HasSACK returns true if SACK is enabled.
func (info *TCPInfo) HasSACK() bool {
	return (info.Options & TCPI_OPT_SACK) != 0
}

// HasWscale returns true if window scaling is enabled.
func (info *TCPInfo) HasWscale() bool {
	return (info.Options & TCPI_OPT_WSCALE) != 0
}

// HasECN returns true if ECN was negotiated.
func (info *TCPInfo) HasECN() bool {
	return (info.Options & TCPI_OPT_ECN) != 0
}

// GetTCPInfo retrieves TCP connection information.
// This is a zero-allocation call that reads the kernel's tcp_info structure.
func GetTCPInfo(fd *iofd.FD) (*TCPInfo, error) {
	var info TCPInfo
	infoLen := uint32(SizeofTCPInfo)
	errno := zcall.Getsockopt(
		uintptr(fd.Raw()),
		uintptr(SOL_TCP),
		uintptr(TCP_INFO),
		unsafe.Pointer(&info),
		unsafe.Pointer(&infoLen),
	)
	if errno != 0 {
		return nil, errFromErrno(errno)
	}
	return &info, nil
}

// GetTCPInfoInto retrieves TCP connection information into an existing TCPInfo.
// This avoids allocation when called repeatedly.
func GetTCPInfoInto(fd *iofd.FD, info *TCPInfo) error {
	infoLen := uint32(SizeofTCPInfo)
	errno := zcall.Getsockopt(
		uintptr(fd.Raw()),
		uintptr(SOL_TCP),
		uintptr(TCP_INFO),
		unsafe.Pointer(info),
		unsafe.Pointer(&infoLen),
	)
	if errno != 0 {
		return errFromErrno(errno)
	}
	return nil
}
