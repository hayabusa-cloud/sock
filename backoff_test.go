// ©Hayabusa Cloud Co., Ltd. 2026. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package sock

import (
	"sync"
	"testing"
	"time"
)

func TestNetBackoffTierDurations(t *testing.T) {
	expected := []time.Duration{
		1 * time.Millisecond,   // tier 0
		2 * time.Millisecond,   // tier 1
		4 * time.Millisecond,   // tier 2
		8 * time.Millisecond,   // tier 3
		16 * time.Millisecond,  // tier 4
		32 * time.Millisecond,  // tier 5
		64 * time.Millisecond,  // tier 6
		128 * time.Millisecond, // tier 7
		192 * time.Millisecond, // tier 8
		256 * time.Millisecond, // tier 9
		320 * time.Millisecond, // tier 10
		384 * time.Millisecond, // tier 11
		448 * time.Millisecond, // tier 12
		512 * time.Millisecond, // tier 13
		576 * time.Millisecond, // tier 14
		640 * time.Millisecond, // tier 15
	}

	for tier, want := range expected {
		b := netBackoff{tier: tier}
		got := b.duration()
		if got != want {
			t.Errorf("tier %d: got %v, want %v", tier, got, want)
		}
	}
}

func TestNetBackoffMaxCap(t *testing.T) {
	// Tiers beyond 15 should still return 640ms
	b := netBackoff{tier: 20}
	got := b.duration()
	if got != 640*time.Millisecond {
		t.Errorf("tier 20: got %v, want 640ms", got)
	}
}

func TestNetBackoffSmartStartTier(t *testing.T) {
	// Reset global state
	globalStartTier.Store(0)

	// Simulate completion at tier 3
	b := netBackoff{tier: 3}
	b.done()
	if got := globalStartTier.Load(); got != 1 {
		t.Errorf("after tier 3 completion: globalStartTier = %d, want 1", got)
	}

	// Simulate completion at tier 1
	b = netBackoff{tier: 1}
	b.done()
	if got := globalStartTier.Load(); got != 0 {
		t.Errorf("after tier 1 completion: globalStartTier = %d, want 0", got)
	}

	// Simulate completion at tier 7
	b = netBackoff{tier: 7}
	b.done()
	if got := globalStartTier.Load(); got != 3 {
		t.Errorf("after tier 7 completion: globalStartTier = %d, want 3", got)
	}

	// Reset for other tests
	globalStartTier.Store(0)
}

func TestNetBackoffWaitAdvancesTier(t *testing.T) {
	globalStartTier.Store(0)
	var b netBackoff

	// First wait initializes and advances
	b.wait()
	if b.tier != 1 {
		t.Errorf("after first wait: tier = %d, want 1", b.tier)
	}

	// Second wait advances again
	b.wait()
	if b.tier != 2 {
		t.Errorf("after second wait: tier = %d, want 2", b.tier)
	}

	// Reset for other tests
	globalStartTier.Store(0)
}

func TestNetBackoffWaitRespectsGlobalStart(t *testing.T) {
	globalStartTier.Store(5)
	var b netBackoff

	b.wait()
	// Should have started at tier 5 and advanced to 6
	if b.tier != 6 {
		t.Errorf("with globalStartTier=5, after wait: tier = %d, want 6", b.tier)
	}

	// Reset for other tests
	globalStartTier.Store(0)
}

func TestNetBackoffJitterBounds(t *testing.T) {
	b := netBackoff{fastSrc: 12345}

	// Test jitter on 128ms (tier 7)
	base := 128 * time.Millisecond
	minExpected := base - base/8 // -12.5%
	maxExpected := base + base/8 // +12.5%

	for range 100 {
		jittered := b.applyJitter(base)
		if jittered < minExpected || jittered > maxExpected {
			t.Errorf("jitter out of bounds: got %v, expected [%v, %v]", jittered, minExpected, maxExpected)
		}
	}
}

func TestNetBackoffTierCap(t *testing.T) {
	var b netBackoff
	b.tier = netBackoffMaxTier

	initialTier := b.tier
	b.wait()

	// Tier should not exceed max
	if b.tier != netBackoffMaxTier {
		t.Errorf("tier exceeded max: got %d, want %d", b.tier, netBackoffMaxTier)
	}
	if b.tier != initialTier {
		t.Errorf("tier changed at max: got %d, want %d", b.tier, initialTier)
	}
}

func TestNetBackoffConcurrentAccess(t *testing.T) {
	globalStartTier.Store(0)

	var wg sync.WaitGroup
	const goroutines = 10

	// Concurrent done() calls should not panic or corrupt state
	for i := range goroutines {
		wg.Add(1)
		go func(tier int) {
			defer wg.Done()
			b := netBackoff{tier: tier}
			b.done()
		}(i)
	}
	wg.Wait()

	// globalStartTier should be a valid tier (0 to maxTier/2)
	got := globalStartTier.Load()
	if got < 0 || got > netBackoffMaxTier {
		t.Errorf("globalStartTier out of range: got %d", got)
	}

	globalStartTier.Store(0)
}

func TestNetBackoffZeroValue(t *testing.T) {
	globalStartTier.Store(0)

	// Zero-value netBackoff should initialize on first wait()
	var b netBackoff
	if b.tier != 0 || b.fastSrc != 0 {
		t.Fatal("zero value should have tier=0, fastSrc=0")
	}

	b.wait()

	// After wait, tier should advance and fastSrc should be initialized
	if b.tier != 1 {
		t.Errorf("after wait: tier = %d, want 1", b.tier)
	}
	if b.fastSrc == 0 {
		t.Error("fastSrc should be initialized after wait")
	}

	globalStartTier.Store(0)
}
