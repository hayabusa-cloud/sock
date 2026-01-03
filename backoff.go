// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sock

import (
	"sync/atomic"
	"time"
)

// netBackoff constants.
const (
	netBackoffMaxTier     = 15
	netBackoffMaxDuration = 640 * time.Millisecond
)

// globalStartTier is the adaptive starting tier for network backoff.
// Uses atomic access to silence race detector. The value is not
// correctness-critical: stale reads only affect efficiency, not correctness.
var globalStartTier atomic.Int32

// netBackoff implements tier-based backoff for network I/O.
// Uses exponential growth (tiers 0-7) then linear growth (tiers 8-15).
//
// Tier durations (ms): 1, 2, 4, 8, 16, 32, 64, 128, 192, 256, 320, 384, 448, 512, 576, 640
//
// Design rationale: Tuned for 4G mobile TCP establishment at ~800km distance,
// where typical connection times are 100-400ms depending on network conditions.
type netBackoff struct {
	tier    int    // current tier
	fastSrc uint64 // PRNG state for jitter
}

// wait sleeps for the current tier duration (with jitter) and advances to the next tier.
func (b *netBackoff) wait() {
	if b.tier == 0 && b.fastSrc == 0 {
		// First call: initialize from global start tier
		b.tier = int(globalStartTier.Load())
		b.fastSrc = uint64(time.Now().UnixNano()) | 1
	}

	d := b.duration()
	time.Sleep(b.applyJitter(d))

	if b.tier < netBackoffMaxTier {
		b.tier++
	}
}

// done signals that the operation completed at the current tier.
// Updates globalStartTier to (tier >> 1) for future operations.
func (b *netBackoff) done() {
	globalStartTier.Store(int32(b.tier >> 1))
}

// duration returns the current tier duration without jitter.
func (b *netBackoff) duration() time.Duration {
	tier := b.tier
	if tier <= 7 {
		return time.Millisecond << tier // 1, 2, 4, 8, 16, 32, 64, 128
	}
	d := 128*time.Millisecond + time.Duration(tier-7)*64*time.Millisecond
	if d > netBackoffMaxDuration {
		return netBackoffMaxDuration
	}
	return d
}

// applyJitter adds ±12.5% jitter to prevent thundering herd.
func (b *netBackoff) applyJitter(d time.Duration) time.Duration {
	// Xorshift PRNG
	b.fastSrc ^= b.fastSrc << 13
	b.fastSrc ^= b.fastSrc >> 7
	b.fastSrc ^= b.fastSrc << 17
	r := int64(b.fastSrc>>32) % 256
	factor := int64(d) * (r - 128) / 1024
	return d + time.Duration(factor)
}
