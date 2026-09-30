/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// newBareTestDevice builds a *Device without going through NewDevice (which
// requires a real tun.Device and conn.Bind). This is enough for exercising
// the padding/header-protection code paths, which only touch the fields set
// up here.
func newBareTestDevice() *Device {
	d := &Device{log: NewLogger(LogLevelSilent, "")}

	var r UintRange
	r.FromUint32(MessageInitiationType, MessageInitiationType)
	d.headers.init.Store(r)
	r.FromUint32(MessageResponseType, MessageResponseType)
	d.headers.response.Store(r)
	r.FromUint32(MessageCookieReplyType, MessageCookieReplyType)
	d.headers.cookie.Store(r)
	r.FromUint32(MessageTransportType, MessageTransportType)
	d.headers.transport.Store(r)

	return d
}

// ---------------------------------------------------------------------
// calculatePaddingSize
// ---------------------------------------------------------------------

// TestCalculatePaddingSize checks the classic (non-random) content padding
// used to round packets up to a multiple of PaddingMultiple (16), both with
// and without an MTU ceiling, across a wide sweep of packet sizes and MTUs.
func TestCalculatePaddingSize(t *testing.T) {
	sizes := []int{}
	for s := 0; s <= 300; s++ {
		sizes = append(sizes, s)
	}
	for _, s := range []int{500, 1000, 1279, 1280, 1281, 1500, 1420, 9000} {
		sizes = append(sizes, s)
	}

	mtus := []int{0, 1, 15, 16, 17, 20, 500, 1280, 1420, 9000}

	for _, mtu := range mtus {
		mtu := mtu
		t.Run(fmt.Sprintf("mtu=%d", mtu), func(t *testing.T) {
			for _, size := range sizes {
				size := size
				t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
					got := calculatePaddingSize(size, mtu)

					if got < 0 {
						t.Fatalf("calculatePaddingSize(%d,%d) = %d, negative padding", size, mtu, got)
					}

					lastUnit := size
					if mtu != 0 && lastUnit > mtu {
						lastUnit %= mtu
					}
					padded := lastUnit + got

					if mtu == 0 {
						if padded%PaddingMultiple != 0 {
							t.Fatalf("calculatePaddingSize(%d,%d): padded size %d not a multiple of %d", size, mtu, padded, PaddingMultiple)
						}
						if got >= PaddingMultiple {
							t.Fatalf("calculatePaddingSize(%d,%d) = %d, want < %d", size, mtu, got, PaddingMultiple)
						}
						return
					}

					if padded > mtu {
						t.Fatalf("calculatePaddingSize(%d,%d): padded size %d exceeds mtu %d", size, mtu, padded, mtu)
					}
					if padded < lastUnit {
						t.Fatalf("calculatePaddingSize(%d,%d): padded size %d smaller than input %d", size, mtu, padded, lastUnit)
					}
					if padded != mtu && padded%PaddingMultiple != 0 {
						t.Fatalf("calculatePaddingSize(%d,%d): padded size %d neither multiple of %d nor clamped to mtu", size, mtu, padded, PaddingMultiple)
					}
				})
			}
		})
	}
}

// ---------------------------------------------------------------------
// randomPaddingAddition (content_padding_addition, i.e. random extra padding
// on top of the classic 16-byte alignment)
// ---------------------------------------------------------------------

func TestRandomPaddingAdditionDisabledByDefault(t *testing.T) {
	d := newBareTestDevice()

	sizes := []int{0, 1, 100, 1279, 1280, 1281, 9000}
	mtus := []int{0, 1280, 1420}

	for _, mtu := range mtus {
		for _, size := range sizes {
			t.Run(fmt.Sprintf("size=%d/mtu=%d", size, mtu), func(t *testing.T) {
				if got := d.randomPaddingAddition(size, mtu); got != -1 {
					t.Fatalf("randomPaddingAddition(%d,%d) = %d, want -1 (feature unset)", size, mtu, got)
				}
			})
		}
	}
}

func TestRandomPaddingAdditionFixedValueNoMTU(t *testing.T) {
	d := newBareTestDevice()

	// addition=0 is intentionally excluded: a [0,0] range is indistinguishable
	// from "unset" (UintRange.IsZero()), so the feature is treated as
	// disabled and randomPaddingAddition returns -1 -- see
	// TestRandomPaddingAdditionDisabledByDefault.
	for _, addition := range []uint32{1, 16, 64, 500, 1400} {
		addition := addition
		t.Run(fmt.Sprintf("addition=%d", addition), func(t *testing.T) {
			var r UintRange
			r.FromUint32(addition, addition)
			d.contentPaddingAddition.Store(r)

			for _, size := range []int{0, 1, 100, 1500, 9000} {
				got := d.randomPaddingAddition(size, 0)
				if got != int(addition) {
					t.Fatalf("randomPaddingAddition(%d,0) = %d, want exactly %d (mtu=0 means no clamping)", size, got, addition)
				}
			}
		})
	}
}

// TestRandomPaddingAdditionClampedByMTU verifies that, whatever value is
// drawn from the configured range, the padded packet (content + addition)
// never exceeds the MTU, and the returned addition is never negative.
func TestRandomPaddingAdditionClampedByMTU(t *testing.T) {
	d := newBareTestDevice()

	var r UintRange
	r.FromUint32(0, 2000) // wide range, larger than most of the MTUs below
	d.contentPaddingAddition.Store(r)

	mtus := []int{1, 16, 100, 500, 1280, 1420}
	sizes := []int{0, 1, 50, 100, 500, 1000, 1280, 1421, 2000, 5000}

	for _, mtu := range mtus {
		mtu := mtu
		t.Run(fmt.Sprintf("mtu=%d", mtu), func(t *testing.T) {
			for _, size := range sizes {
				size := size
				t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
					// Draw many times: PickOne is randomized, so repeat to
					// exercise the clamp for a spread of drawn values.
					for i := 0; i < 20; i++ {
						got := d.randomPaddingAddition(size, mtu)
						if got < 0 {
							t.Fatalf("randomPaddingAddition(%d,%d) = %d, want >= 0", size, mtu, got)
						}

						effectiveSize := size
						if effectiveSize > mtu {
							effectiveSize %= mtu
						}
						if effectiveSize+got > mtu {
							t.Fatalf("randomPaddingAddition(%d,%d) = %d, padded size %d exceeds mtu %d",
								size, mtu, got, effectiveSize+got, mtu)
						}
					}
				})
			}
		})
	}
}

// ---------------------------------------------------------------------
// DeterminePacketTypeAndPadding (receive-side S1-S4 / H1-H4 detection)
// ---------------------------------------------------------------------

func putType(packet []byte, offset uint32, msgType uint32, xorMask []byte) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], msgType)
	for i := range b {
		b[i] ^= xorMask[i%len(xorMask)]
	}
	copy(packet[offset:offset+4], b[:])
}

// fillDeterministic fills a buffer with a fixed, non-zero pattern that never
// happens to equal any of the small header type constants used in these
// tests (1-4), so accidental matches can't make a test flaky.
func fillDeterministic(buf []byte) {
	for i := range buf {
		buf[i] = 0xAB
	}
}

var zeroTypeHash = [4]byte{}

func TestDeterminePacketTypeAndPadding_DefaultHeadersNoPadding(t *testing.T) {
	d := newBareTestDevice()

	cases := []struct {
		name       string
		size       int
		msgType    uint32
		wantType   uint32
		wantOffset uint32
	}{
		{"initiation", MessageInitiationSize, MessageInitiationType, MessageInitiationType, 0},
		{"response", MessageResponseSize, MessageResponseType, MessageResponseType, 0},
		{"cookie_reply", MessageCookieReplySize, MessageCookieReplyType, MessageCookieReplyType, 0},
		{"transport_min", MessageTransportSize, MessageTransportType, MessageTransportType, 0},
		{"transport_with_content", MessageTransportSize + 100, MessageTransportType, MessageTransportType, 0},
		{"unknown_type_value", MessageInitiationSize, 99, MessageUnknownType, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			packet := make([]byte, c.size)
			fillDeterministic(packet)
			putType(packet, 0, c.msgType, zeroTypeHash[:])

			gotType, gotPadding := d.DeterminePacketTypeAndPadding(packet, MessageUnknownType, zeroTypeHash[:])
			if gotType != c.wantType {
				t.Errorf("type = %d, want %d", gotType, c.wantType)
			}
			if gotPadding != c.wantOffset {
				t.Errorf("padding = %d, want %d", gotPadding, c.wantOffset)
			}
		})
	}
}

// TestDeterminePacketTypeAndPadding_WithPadding sweeps S1-S4 padding values
// and confirms the message is correctly located after the padding prefix.
func TestDeterminePacketTypeAndPadding_WithPadding(t *testing.T) {
	d := newBareTestDevice()

	type kind struct {
		name    string
		msgSize int
		msgType uint32
	}
	kinds := []kind{
		{"initiation", MessageInitiationSize, MessageInitiationType},
		{"response", MessageResponseSize, MessageResponseType},
		{"cookie_reply", MessageCookieReplySize, MessageCookieReplyType},
		{"transport", MessageTransportSize, MessageTransportType},
	}

	paddings := []uint32{0, 1, 4, 12, 16, 32, 100}

	for _, k := range kinds {
		for _, padding := range paddings {
			k, padding := k, padding
			t.Run(fmt.Sprintf("%s/padding=%d", k.name, padding), func(t *testing.T) {
				switch k.msgType {
				case MessageInitiationType:
					d.paddings.init.Store(padding)
				case MessageResponseType:
					d.paddings.response.Store(padding)
				case MessageCookieReplyType:
					d.paddings.cookie.Store(padding)
				case MessageTransportType:
					d.paddings.transport.Store(padding)
				}
				defer func() {
					d.paddings.init.Store(0)
					d.paddings.response.Store(0)
					d.paddings.cookie.Store(0)
					d.paddings.transport.Store(0)
				}()

				packet := make([]byte, int(padding)+k.msgSize)
				fillDeterministic(packet)
				putType(packet, padding, k.msgType, zeroTypeHash[:])

				gotType, gotPadding := d.DeterminePacketTypeAndPadding(packet, MessageUnknownType, zeroTypeHash[:])
				if gotType != k.msgType {
					t.Fatalf("type = %d, want %d", gotType, k.msgType)
				}
				if gotPadding != padding {
					t.Fatalf("padding = %d, want %d", gotPadding, padding)
				}
			})
		}
	}
}

// TestDeterminePacketTypeAndPadding_TypeHashXOR verifies that the type field
// is correctly recovered when it has been obfuscated with a non-zero
// typeHash (as happens when header_protection_key / S1-S4 are combined),
// across many (padding, hash) combinations.
func TestDeterminePacketTypeAndPadding_TypeHashXOR(t *testing.T) {
	d := newBareTestDevice()
	d.paddings.transport.Store(16)
	defer d.paddings.transport.Store(0)

	hashes := [][4]byte{
		{0x00, 0x00, 0x00, 0x00},
		{0xFF, 0xFF, 0xFF, 0xFF},
		{0xAA, 0x55, 0xF0, 0x0F},
		{0x01, 0x02, 0x03, 0x04},
		{0xDE, 0xAD, 0xBE, 0xEF},
	}

	for _, hash := range hashes {
		hash := hash
		t.Run(fmt.Sprintf("hash=%x", hash), func(t *testing.T) {
			packet := make([]byte, 16+MessageTransportSize)
			fillDeterministic(packet)
			putType(packet, 16, MessageTransportType, hash[:])

			gotType, gotPadding := d.DeterminePacketTypeAndPadding(packet, MessageUnknownType, hash[:])
			if gotType != MessageTransportType {
				t.Fatalf("type = %d, want %d (hash=%x)", gotType, MessageTransportType, hash)
			}
			if gotPadding != 16 {
				t.Fatalf("padding = %d, want 16 (hash=%x)", gotPadding, hash)
			}

			// Using the wrong hash to undo the XOR must not match.
			wrongHash := [4]byte{hash[0] ^ 0xFF, hash[1], hash[2], hash[3]}
			gotType2, _ := d.DeterminePacketTypeAndPadding(packet, MessageUnknownType, wrongHash[:])
			if gotType2 == MessageTransportType {
				t.Fatalf("type unexpectedly matched with wrong hash (hash=%x, wrong=%x)", hash, wrongHash)
			}
		})
	}
}

// TestDeterminePacketTypeAndPadding_RangedHeader checks detection against a
// multi-value H1-H4 range, both inside and outside the configured window.
func TestDeterminePacketTypeAndPadding_RangedHeader(t *testing.T) {
	d := newBareTestDevice()

	var r UintRange
	r.FromUint32(100, 200)
	d.headers.init.Store(r)
	defer func() {
		var single UintRange
		single.FromUint32(MessageInitiationType, MessageInitiationType)
		d.headers.init.Store(single)
	}()

	inRange := []uint32{100, 101, 150, 199, 200}
	outOfRange := []uint32{0, 5, 99, 201, 300, 5000}

	for _, v := range inRange {
		v := v
		t.Run(fmt.Sprintf("in_range=%d", v), func(t *testing.T) {
			packet := make([]byte, MessageInitiationSize)
			fillDeterministic(packet)
			putType(packet, 0, v, zeroTypeHash[:])

			gotType, gotPadding := d.DeterminePacketTypeAndPadding(packet, MessageUnknownType, zeroTypeHash[:])
			if gotType != MessageInitiationType {
				t.Fatalf("type = %d, want %d for in-range value %d", gotType, MessageInitiationType, v)
			}
			if gotPadding != 0 {
				t.Fatalf("padding = %d, want 0", gotPadding)
			}
		})
	}

	for _, v := range outOfRange {
		v := v
		t.Run(fmt.Sprintf("out_of_range=%d", v), func(t *testing.T) {
			packet := make([]byte, MessageInitiationSize)
			fillDeterministic(packet)
			putType(packet, 0, v, zeroTypeHash[:])

			gotType, _ := d.DeterminePacketTypeAndPadding(packet, MessageUnknownType, zeroTypeHash[:])
			if gotType == MessageInitiationType {
				t.Fatalf("type unexpectedly matched Initiation for out-of-range value %d", v)
			}
		})
	}
}

// TestDeterminePacketTypeAndPadding_TransportFallbackToZeroPadding covers the
// backward-compatibility branch: S4 is configured non-zero, but this
// particular packet was sent with no padding at all (offset 0). Detection
// must still succeed with padding=0.
func TestDeterminePacketTypeAndPadding_TransportFallbackToZeroPadding(t *testing.T) {
	d := newBareTestDevice()
	d.paddings.transport.Store(16)
	defer d.paddings.transport.Store(0)

	packet := make([]byte, MessageTransportSize)
	fillDeterministic(packet)
	putType(packet, 0, MessageTransportType, zeroTypeHash[:])

	gotType, gotPadding := d.DeterminePacketTypeAndPadding(packet, MessageUnknownType, zeroTypeHash[:])
	if gotType != MessageTransportType {
		t.Fatalf("type = %d, want %d", gotType, MessageTransportType)
	}
	if gotPadding != 0 {
		t.Fatalf("padding = %d, want 0 (fallback path)", gotPadding)
	}
}

// TestDeterminePacketTypeAndPadding_TooSmall ensures undersized packets are
// safely rejected (no panics, no false positives) for every padding size.
func TestDeterminePacketTypeAndPadding_TooSmall(t *testing.T) {
	d := newBareTestDevice()

	for padding := uint32(0); padding <= 64; padding++ {
		padding := padding
		t.Run(fmt.Sprintf("padding=%d", padding), func(t *testing.T) {
			d.paddings.init.Store(padding)
			d.paddings.response.Store(padding)
			d.paddings.cookie.Store(padding)
			d.paddings.transport.Store(padding)
			defer func() {
				d.paddings.init.Store(0)
				d.paddings.response.Store(0)
				d.paddings.cookie.Store(0)
				d.paddings.transport.Store(0)
			}()

			// One byte short of the smallest possible valid message
			// (transport, MessageTransportHeaderSize) at this padding.
			size := int(padding) + MessageTransportHeaderSize - 1
			if size < 0 {
				size = 0
			}
			packet := make([]byte, size)
			fillDeterministic(packet)

			gotType, gotPadding := d.DeterminePacketTypeAndPadding(packet, MessageUnknownType, zeroTypeHash[:])
			if gotType != MessageUnknownType || gotPadding != 0 {
				t.Fatalf("padding=%d, size=%d: got (%d,%d), want (%d,0)", padding, size, gotType, gotPadding, MessageUnknownType)
			}
		})
	}
}

// ---------------------------------------------------------------------
// HeaderProtectionCipher
// ---------------------------------------------------------------------

func TestHeaderProtectionCipherNilWhenKeyUnset(t *testing.T) {
	d := newBareTestDevice()

	salt := make([]byte, HeaderCipherNonceSize)
	cip, err := d.HeaderProtectionCipher(salt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cip != nil {
		t.Fatalf("expected nil cipher when header_protection_key is unset")
	}
}

// TestHeaderProtectionCipherRoundTrip verifies that encrypting with one
// cipher instance and decrypting with a fresh one obtained from the same
// salt recovers the original bytes -- exactly the send/receive pattern used
// in send.go and receive.go. Run across many random salts and payloads.
func TestHeaderProtectionCipherRoundTrip(t *testing.T) {
	d := newBareTestDevice()

	var key HeaderCipherKey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("rand.Read key: %v", err)
	}
	d.headerProtection.key = key

	for i := 0; i < 256; i++ {
		i := i
		t.Run(fmt.Sprintf("trial=%d", i), func(t *testing.T) {
			salt := make([]byte, HeaderCipherNonceSize)
			if _, err := rand.Read(salt); err != nil {
				t.Fatalf("rand.Read salt: %v", err)
			}

			plaintext := make([]byte, MessageTransportHeaderSize)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatalf("rand.Read plaintext: %v", err)
			}

			encCipher, err := d.HeaderProtectionCipher(salt)
			if err != nil {
				t.Fatalf("HeaderProtectionCipher (encrypt): %v", err)
			}
			if encCipher == nil {
				t.Fatalf("expected non-nil cipher when key is set")
			}
			ciphertext := make([]byte, len(plaintext))
			encCipher.XORKeyStream(ciphertext, plaintext)

			if bytes.Equal(ciphertext, plaintext) {
				t.Fatalf("ciphertext unexpectedly equals plaintext")
			}

			decCipher, err := d.HeaderProtectionCipher(salt)
			if err != nil {
				t.Fatalf("HeaderProtectionCipher (decrypt): %v", err)
			}
			recovered := make([]byte, len(ciphertext))
			decCipher.XORKeyStream(recovered, ciphertext)

			if !bytes.Equal(recovered, plaintext) {
				t.Fatalf("round trip mismatch: got %x, want %x", recovered, plaintext)
			}
		})
	}
}

// ---------------------------------------------------------------------
// Regression test for the keepalive/dataSent miscount when S4 (transport
// padding) is configured: device/send.go used to compare
// len(elem.packet[MessageEncapsulatingTransportSize:]) against
// MessageKeepaliveSize, which ignored the crypto padding prefix and so
// always misclassified keepalives as data whenever S4 > 0. The fixed
// comparison also subtracts elem.padding.
// ---------------------------------------------------------------------

// sealKeepaliveLikeRoutineEncryption reproduces exactly the buffer layout
// and Seal() call performed by (*Device).RoutineEncryption for a keepalive
// (i.e. an outbound element with an empty plaintext packet), for a given
// transport padding size.
func sealKeepaliveLikeRoutineEncryption(t *testing.T, aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
}, padding uint32) []byte {
	t.Helper()

	buffer := make([]byte, MessageEncapsulatingTransportSize+padding+MessageTransportHeaderSize+64)
	nonce := make([]byte, chacha20poly1305.NonceSize)

	dst := buffer[:MessageEncapsulatingTransportSize+padding+MessageTransportHeaderSize]
	sealed := aead.Seal(dst, nonce, nil, nil)
	return sealed
}

func TestKeepaliveLengthMatchesConstantAcrossTransportPadding(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read key: %v", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}

	for padding := uint32(0); padding <= 256; padding++ {
		padding := padding
		t.Run(fmt.Sprintf("padding=%d", padding), func(t *testing.T) {
			sealed := sealKeepaliveLikeRoutineEncryption(t, aead, padding)

			// This is exactly the fixed comparison from
			// RoutineSequentialSender in device/send.go.
			strippedLen := len(sealed[MessageEncapsulatingTransportSize+padding:])
			if strippedLen != MessageKeepaliveSize {
				t.Fatalf("padding=%d: keepalive misdetected as data: stripped length %d != MessageKeepaliveSize (%d)",
					padding, strippedLen, MessageKeepaliveSize)
			}

			// And demonstrate why the old, unfixed comparison
			// (not subtracting elem.padding) breaks for padding>0:
			// it's only expected to match when there is no padding.
			oldComparisonLen := len(sealed[MessageEncapsulatingTransportSize:])
			oldComparisonMatches := oldComparisonLen == MessageKeepaliveSize
			wantOldMatches := padding == 0
			if oldComparisonMatches != wantOldMatches {
				t.Fatalf("padding=%d: sanity check on old formula failed: old formula match=%v, want %v",
					padding, oldComparisonMatches, wantOldMatches)
			}
		})
	}
}

// TestDataPacketNeverMistakenForKeepalive is the complementary check: a
// packet that actually carries content must never be reported as a
// keepalive by the fixed length comparison, regardless of S4 padding.
func TestDataPacketNeverMistakenForKeepalive(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read key: %v", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}

	paddings := []uint32{0, 1, 12, 16, 64, 200}
	contentSizes := []int{1, 16, 100, 1400}

	for _, padding := range paddings {
		for _, contentSize := range contentSizes {
			padding, contentSize := padding, contentSize
			t.Run(fmt.Sprintf("padding=%d/content=%d", padding, contentSize), func(t *testing.T) {
				buffer := make([]byte, MessageEncapsulatingTransportSize+padding+MessageTransportHeaderSize+uint32(contentSize)+64)
				nonce := make([]byte, chacha20poly1305.NonceSize)
				content := make([]byte, contentSize)

				dst := buffer[:MessageEncapsulatingTransportSize+padding+MessageTransportHeaderSize]
				sealed := aead.Seal(dst, nonce, content, nil)

				strippedLen := len(sealed[MessageEncapsulatingTransportSize+padding:])
				if strippedLen == MessageKeepaliveSize {
					t.Fatalf("padding=%d/content=%d: data packet misdetected as keepalive (length %d)",
						padding, contentSize, strippedLen)
				}
			})
		}
	}
}
