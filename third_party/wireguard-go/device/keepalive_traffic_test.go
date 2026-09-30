/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * Real-traffic regression test for the S4/elem.padding keepalive
 * classification fix in device/send.go's RoutineSequentialSender. Before the
 * fix, len(elem.packet[MessageEncapsulatingTransportSize:]) was compared
 * against MessageKeepaliveSize without subtracting the S4 transport padding
 * prefix, so with S4>0 every keepalive was misclassified as data traffic,
 * which spuriously armed the newHandshake timer and caused periodic
 * unnecessary re-handshakes on an otherwise idle connection -- exactly the
 * traffic pattern obfuscation is meant to avoid drawing attention to.
 *
 * This test drives two real *Device instances over loopback UDP with S4
 * configured, sends an actual keepalive through the real encryption queue
 * and RoutineSequentialSender, and asserts the sending peer's newHandshake
 * timer stays unarmed -- then, as a sanity check that the fix didn't just
 * make the check permissive, confirms a genuine data packet under the same
 * S4 padding *does* arm it.
 */

package device

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestKeepaliveWithTransportPaddingDoesNotTriggerSpuriousRehandshake(t *testing.T) {
	aIP := net.ParseIP("10.52.0.1")
	bIP := net.ParseIP("10.52.0.2")

	// S4 (transport padding) is the field implicated in the fixed bug.
	// Sweep several nonzero values, since the bug reproduced for *any*
	// S4>0, not just one specific size.
	for _, s4 := range []uint32{1, 12, 16, 32, 63, 200} {
		s4 := s4
		t.Run(fmt.Sprintf("s4=%d", s4), func(t *testing.T) {
			a := newTestEndpoint(t)
			defer a.Close()
			b := newTestEndpoint(t)
			defer b.Close()

			connectPair(t, a, b, aIP, bIP, fmt.Sprintf("s4=%d\n", s4))

			peerB := a.device.LookupPeer(b.pub)
			if peerB == nil {
				t.Fatalf("peer B not found on device A")
			}

			// Warm up: complete the handshake via a real data packet.
			warmup := buildIPv4Packet(aIP, bIP, []byte("warmup"))
			a.tun.Inject(warmup)
			if _, ok := b.tun.WaitReceived(8 * time.Second); !ok {
				t.Fatalf("handshake/warm-up packet never arrived")
			}

			// Start from a clean slate so we can observe just the effect
			// of the keepalive below.
			peerB.timers.newHandshake.DelSync()

			// Send a pure keepalive through the real queue pipeline
			// (device.queue.encryption -> RoutineEncryption ->
			// RoutineSequentialSender), with S4 padding active.
			peerB.SendKeepalive()
			time.Sleep(300 * time.Millisecond)

			if peerB.timers.newHandshake.IsPending() {
				t.Fatalf(
					"regression: newHandshake timer armed after a pure keepalive with s4=%d -- "+
						"keepalive was misclassified as data traffic", s4)
			}

			// Sanity check the complementary case: real data under the
			// same S4 padding must still arm newHandshake. This guards
			// against a fix that's merely permissive (e.g. never setting
			// dataSent) rather than correctly accounting for padding.
			data := buildIPv4Packet(aIP, bIP, []byte("this is real data, not a keepalive"))
			a.tun.Inject(data)
			if _, ok := b.tun.WaitReceived(2 * time.Second); !ok {
				t.Fatalf("data packet never arrived")
			}
			time.Sleep(300 * time.Millisecond)

			if !peerB.timers.newHandshake.IsPending() {
				t.Fatalf("sanity check failed: newHandshake timer NOT armed after a real data packet (s4=%d)", s4)
			}
		})
	}
}

// TestKeepaliveWithoutPaddingStillDetectedCorrectly is the s4=0 control:
// this path worked even before the fix (elem.padding is 0, so subtracting
// it is a no-op), and must keep working.
func TestKeepaliveWithoutPaddingStillDetectedCorrectly(t *testing.T) {
	aIP := net.ParseIP("10.53.0.1")
	bIP := net.ParseIP("10.53.0.2")

	a := newTestEndpoint(t)
	defer a.Close()
	b := newTestEndpoint(t)
	defer b.Close()

	connectPair(t, a, b, aIP, bIP, "") // no obfuscation at all

	peerB := a.device.LookupPeer(b.pub)
	if peerB == nil {
		t.Fatalf("peer B not found on device A")
	}

	warmup := buildIPv4Packet(aIP, bIP, []byte("warmup"))
	a.tun.Inject(warmup)
	if _, ok := b.tun.WaitReceived(8 * time.Second); !ok {
		t.Fatalf("handshake/warm-up packet never arrived")
	}

	peerB.timers.newHandshake.DelSync()
	peerB.SendKeepalive()
	time.Sleep(300 * time.Millisecond)

	if peerB.timers.newHandshake.IsPending() {
		t.Fatalf("newHandshake timer armed after a pure keepalive with no padding (s4=0)")
	}
}

// TestKeepaliveDeliveredUnderHeaderProtection sends a real keepalive (via
// peer.SendKeepalive(), the same path idle connections use) while both S4
// transport padding and header_protection_key are active, and confirms the
// receiving peer actually authenticates it (observed via peer.rxBytes,
// since keepalives carry no payload and are never handed to the TUN).
//
// Keepalives are built via Device.NewOutboundElement(), which is the only
// place elem.padding is populated for a staged keepalive (unlike data
// packets from RoutineReadFromTUN, nothing re-reads device.paddings.transport
// afterwards) -- so this exercises that assignment specifically, on a
// configuration (header_protection_key set) where the receiver's "packet was
// sent with legacy zero padding" fallback in DeterminePacketTypeAndPadding
// cannot mask a wrong elem.padding, because that fallback never undoes the
// header-protection XOR.
func TestKeepaliveDeliveredUnderHeaderProtection(t *testing.T) {
	aIP := net.ParseIP("10.54.0.1")
	bIP := net.ParseIP("10.54.0.2")

	a := newTestEndpoint(t)
	defer a.Close()
	b := newTestEndpoint(t)
	defer b.Close()

	var hpKey HeaderCipherKey
	if _, err := rand.Read(hpKey[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	obfConfig := fmt.Sprintf("s1=16\ns2=16\ns3=16\ns4=16\nheader_protection_key=%s\n", hex.EncodeToString(hpKey[:]))
	connectPair(t, a, b, aIP, bIP, obfConfig)

	peerB := a.device.LookupPeer(b.pub) // A's record of B
	if peerB == nil {
		t.Fatalf("peer B not found on device A")
	}
	peerAOnB := b.device.LookupPeer(a.pub) // B's record of A
	if peerAOnB == nil {
		t.Fatalf("peer A not found on device B")
	}

	warmup := buildIPv4Packet(aIP, bIP, []byte("warmup"))
	a.tun.Inject(warmup)
	if _, ok := b.tun.WaitReceived(8 * time.Second); !ok {
		t.Fatalf("handshake/warm-up packet never arrived")
	}

	for i := 0; i < 10; i++ {
		before := peerAOnB.rxBytes.Load()

		peerB.SendKeepalive()
		time.Sleep(200 * time.Millisecond)

		after := peerAOnB.rxBytes.Load()
		if after <= before {
			t.Fatalf(
				"keepalive %d was not received/authenticated by B under header_protection_key+S4 "+
					"(rxBytes before=%d, after=%d) -- likely dropped as unknown type due to wrong elem.padding",
				i, before, after)
		}
	}
}
