/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"sync"
	"testing"
)

func TestUintRangeFromUint32AndAccessors(t *testing.T) {
	cases := []struct {
		lo, hi uint32
	}{
		{0, 0},
		{1, 1},
		{0, 1},
		{5, 10},
		{100, 100},
		{0, 0xFFFFFFFF},
		{0xFFFFFFFF, 0xFFFFFFFF},
		{1000, 2000},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("lo=%d/hi=%d", c.lo, c.hi), func(t *testing.T) {
			var r UintRange
			r.FromUint32(c.lo, c.hi)
			if r.Lo() != c.lo {
				t.Errorf("Lo() = %d, want %d", r.Lo(), c.lo)
			}
			if r.Hi() != c.hi {
				t.Errorf("Hi() = %d, want %d", r.Hi(), c.hi)
			}
			if got := r.IsZero(); got != (c.lo == 0 && c.hi == 0) {
				t.Errorf("IsZero() = %v, want %v", got, c.lo == 0 && c.hi == 0)
			}
		})
	}
}

func TestUintRangeFromStringValid(t *testing.T) {
	cases := []struct {
		in     string
		lo, hi uint32
	}{
		{"0", 0, 0},
		{"5", 5, 5},
		{"5-5", 5, 5},
		{"5-10", 5, 10},
		{"0-4294967295", 0, 0xFFFFFFFF},
		{"100-200", 100, 200},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			var r UintRange
			if err := r.FromString(c.in); err != nil {
				t.Fatalf("FromString(%q) unexpected error: %v", c.in, err)
			}
			if r.Lo() != c.lo || r.Hi() != c.hi {
				t.Errorf("FromString(%q) = [%d,%d], want [%d,%d]", c.in, r.Lo(), r.Hi(), c.lo, c.hi)
			}
		})
	}
}

func TestUintRangeFromStringInvalid(t *testing.T) {
	cases := []string{
		"",
		"abc",
		"5-",
		"-5",
		"5-10-15",
		"10-5",
		"4294967296",   // overflows uint32
		"5-4294967296", // hi overflows uint32
		"-1",
		"5- 10",
		" 5-10",
	}
	for _, in := range cases {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			var r UintRange
			if err := r.FromString(in); err == nil {
				t.Errorf("FromString(%q) = nil error, want error (parsed as [%d,%d])", in, r.Lo(), r.Hi())
			}
		})
	}
}

func TestUintRangeToStringRoundTrip(t *testing.T) {
	cases := []struct{ lo, hi uint32 }{
		{0, 0}, {5, 5}, {5, 10}, {0, 100}, {1000, 1000}, {0, 0xFFFFFFFF},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("lo=%d/hi=%d", c.lo, c.hi), func(t *testing.T) {
			var r UintRange
			r.FromUint32(c.lo, c.hi)
			s := r.ToString()

			var r2 UintRange
			if err := r2.FromString(s); err != nil {
				t.Fatalf("FromString(%q) after ToString: %v", s, err)
			}
			if r2 != r {
				t.Errorf("round trip mismatch: %q -> [%d,%d], want [%d,%d]", s, r2.Lo(), r2.Hi(), c.lo, c.hi)
			}
		})
	}
}

func TestUintRangeContains(t *testing.T) {
	var r UintRange
	r.FromUint32(10, 20)

	for num := uint32(0); num <= 30; num++ {
		t.Run(fmt.Sprintf("num=%d", num), func(t *testing.T) {
			want := num >= 10 && num <= 20
			if got := r.Contains(num); got != want {
				t.Errorf("Contains(%d) = %v, want %v", num, got, want)
			}
		})
	}
}

// TestUintRangePickOneBounds exercises PickOne() across a wide variety of
// ranges (including single-value and the maximum-uint32 edge case, which
// triggers an unsigned overflow of hi-lo+1 inside PickOne) and asserts every
// draw stays within [lo, hi]. Each range gets its own subtest, and each
// subtest draws many times, so this alone produces hundreds of checks.
func TestUintRangePickOneBounds(t *testing.T) {
	type rng struct{ lo, hi uint32 }
	ranges := []rng{
		{0, 0},
		{5, 5},
		{0, 1},
		{0, 10},
		{10, 10},
		{100, 105},
		{0, 65535},
		{1, 4294967295},
		{4294967295, 4294967295}, // lo == hi == max uint32: hi-lo+1 overflows to 0
		{4294967290, 4294967295},
	}
	for _, r := range ranges {
		r := r
		t.Run(fmt.Sprintf("lo=%d/hi=%d", r.lo, r.hi), func(t *testing.T) {
			var ur UintRange
			ur.FromUint32(r.lo, r.hi)
			for i := 0; i < 200; i++ {
				got := ur.PickOne()
				if got < r.lo || got > r.hi {
					t.Fatalf("PickOne() draw %d = %d, out of range [%d,%d]", i, got, r.lo, r.hi)
				}
			}
		})
	}
}

func TestUintRangeOverlap(t *testing.T) {
	cases := []struct {
		aLo, aHi, bLo, bHi uint32
		want               bool
	}{
		{0, 10, 5, 15, true},
		{0, 10, 10, 20, true}, // touching at boundary counts as overlap
		{0, 10, 11, 20, false},
		{5, 5, 5, 5, true},
		{0, 100, 200, 300, false},
		{200, 300, 0, 100, false},
		{0, 0, 0, 0, true},
		{0, 0xFFFFFFFF, 5, 5, true}, // full range overlaps everything
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("[%d,%d]vs[%d,%d]", c.aLo, c.aHi, c.bLo, c.bHi), func(t *testing.T) {
			var a, b UintRange
			a.FromUint32(c.aLo, c.aHi)
			b.FromUint32(c.bLo, c.bHi)

			if got := a.Overlap(b); got != c.want {
				t.Errorf("a.Overlap(b) = %v, want %v", got, c.want)
			}
			// Overlap must be symmetric.
			if got := b.Overlap(a); got != c.want {
				t.Errorf("b.Overlap(a) = %v, want %v (symmetry)", got, c.want)
			}
		})
	}
}

func TestAtomicUintRangeLoadStoreSwap(t *testing.T) {
	var a AtomicUintRange

	if !a.Load().IsZero() {
		t.Fatalf("zero-value AtomicUintRange.Load() should be zero range")
	}

	var r1, r2 UintRange
	r1.FromUint32(1, 2)
	r2.FromUint32(3, 4)

	a.Store(r1)
	if got := a.Load(); got != r1 {
		t.Fatalf("Load() after Store(r1) = %v, want %v", got, r1)
	}

	old := a.Swap(r2)
	if old != r1 {
		t.Fatalf("Swap returned %v, want previous value %v", old, r1)
	}
	if got := a.Load(); got != r2 {
		t.Fatalf("Load() after Swap(r2) = %v, want %v", got, r2)
	}
}

// TestAtomicUintRangeConcurrent hammers a single AtomicUintRange from many
// goroutines to make sure Load/Store/Swap never tear (run with -race).
func TestAtomicUintRangeConcurrent(t *testing.T) {
	var a AtomicUintRange
	var wg sync.WaitGroup

	const goroutines = 50
	const itersPerGoroutine = 50

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			var r UintRange
			for i := 0; i < itersPerGoroutine; i++ {
				r.FromUint32(uint32(g), uint32(g+i))
				a.Store(r)
				got := a.Load()
				// got must always be a value written by *some* goroutine's
				// FromUint32(x, x+k) with x==k's goroutine id range shape:
				// hi >= lo always holds regardless of interleaving.
				if got.Hi() < got.Lo() {
					t.Errorf("torn read: hi(%d) < lo(%d)", got.Hi(), got.Lo())
				}
				a.Swap(r)
			}
		}(g)
	}
	wg.Wait()
}
