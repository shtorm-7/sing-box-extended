/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * Tests for Device.InputPacket and Device.InputPackets, the direct
 * injection entry points used by transport/wireguard's gVisor LinkEndpoint
 * (device_system_stack.go) to hand outbound packets straight to the
 * encryption queue, bypassing the normal tun.Device.Read() polling loop.
 *
 * Reuses the real two-*Device-over-loopback-UDP harness from
 * traffic_padding_test.go (newTestEndpoint/connectPair/buildIPv4Packet),
 * so these exercise the genuine allowedips lookup, encryption, and wire
 * transmission -- not a mock.
 */

package device

import (
	"net"
	"testing"
	"time"
)

func TestInputPacketRoutesToPeer(t *testing.T) {
	aIP := net.ParseIP("10.60.0.1")
	bIP := net.ParseIP("10.60.0.2")

	a := newTestEndpoint(t)
	defer a.Close()
	b := newTestEndpoint(t)
	defer b.Close()

	connectPair(t, a, b, aIP, bIP, "")

	pkt := buildIPv4Packet(aIP, bIP, []byte("input-packet single slice"))

	a.device.InputPacket(bIP.To4(), [][]byte{pkt})

	got, ok := b.tun.WaitReceived(8 * time.Second)
	if !ok {
		t.Fatalf("packet injected via InputPacket never arrived")
	}
	if string(got) != string(pkt) {
		t.Fatalf("payload mismatch:\n got  %x\n want %x", got, pkt)
	}
}

func TestInputPacketReassemblesMultipleSlices(t *testing.T) {
	aIP := net.ParseIP("10.60.1.1")
	bIP := net.ParseIP("10.60.1.2")

	a := newTestEndpoint(t)
	defer a.Close()
	b := newTestEndpoint(t)
	defer b.Close()

	connectPair(t, a, b, aIP, bIP, "")

	pkt := buildIPv4Packet(aIP, bIP, []byte("this payload gets split across several scatter-gather slices"))

	var slices [][]byte
	for i := 0; i < len(pkt); {
		n := 7
		if i+n > len(pkt) {
			n = len(pkt) - i
		}
		slices = append(slices, pkt[i:i+n])
		i += n
	}

	a.device.InputPacket(bIP.To4(), slices)

	got, ok := b.tun.WaitReceived(8 * time.Second)
	if !ok {
		t.Fatalf("packet injected via InputPacket (scatter-gather) never arrived")
	}
	if string(got) != string(pkt) {
		t.Fatalf("reassembled payload mismatch:\n got  %x\n want %x", got, pkt)
	}
}

func TestInputPacketUnknownDestinationIsDropped(t *testing.T) {
	aIP := net.ParseIP("10.60.2.1")
	bIP := net.ParseIP("10.60.2.2")

	a := newTestEndpoint(t)
	defer a.Close()
	b := newTestEndpoint(t)
	defer b.Close()

	connectPair(t, a, b, aIP, bIP, "")

	unrouted := net.ParseIP("10.99.99.99")
	pkt := buildIPv4Packet(aIP, unrouted, []byte("nobody should get this"))

	a.device.InputPacket(unrouted.To4(), [][]byte{pkt})

	if _, ok := b.tun.WaitReceived(300 * time.Millisecond); ok {
		t.Fatalf("packet with no matching peer was delivered; it should have been dropped")
	}

	// The device must still be healthy afterwards: a normal packet on the
	// same device works fine, i.e. the drop didn't leak/corrupt buffer pool
	// state.
	good := buildIPv4Packet(aIP, bIP, []byte("still alive"))
	a.device.InputPacket(bIP.To4(), [][]byte{good})
	got, ok := b.tun.WaitReceived(8 * time.Second)
	if !ok || string(got) != string(good) {
		t.Fatalf("device did not recover after a dropped unrouted InputPacket")
	}
}

func TestInputPacketOversizedIsDroppedNotPanicked(t *testing.T) {
	aIP := net.ParseIP("10.60.3.1")
	bIP := net.ParseIP("10.60.3.2")

	a := newTestEndpoint(t)
	defer a.Close()
	b := newTestEndpoint(t)
	defer b.Close()

	connectPair(t, a, b, aIP, bIP, "")

	huge := make([]byte, MaxContentSize+1000)
	for i := range huge {
		huge[i] = byte(i)
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("InputPacket panicked on an oversized packet: %v", r)
			}
		}()
		a.device.InputPacket(bIP.To4(), [][]byte{huge})
	}()

	if _, ok := b.tun.WaitReceived(300 * time.Millisecond); ok {
		t.Fatalf("oversized packet should have been dropped, not delivered")
	}

	good := buildIPv4Packet(aIP, bIP, []byte("still alive after oversized drop"))
	a.device.InputPacket(bIP.To4(), [][]byte{good})
	got, ok := b.tun.WaitReceived(8 * time.Second)
	if !ok || string(got) != string(good) {
		t.Fatalf("device did not recover after a dropped oversized InputPacket")
	}
}

func TestInputPacketsBatchRoutesAndReportsUnmatched(t *testing.T) {
	aIP := net.ParseIP("10.60.4.1")
	bIP := net.ParseIP("10.60.4.2")

	a := newTestEndpoint(t)
	defer a.Close()
	b := newTestEndpoint(t)
	defer b.Close()

	connectPair(t, a, b, aIP, bIP, "")

	unrouted := net.ParseIP("10.99.98.97")

	pkt1 := buildIPv4Packet(aIP, bIP, []byte("batched packet one"))
	pkt2 := buildIPv4Packet(aIP, bIP, []byte("batched packet two"))
	pktUnrouted := buildIPv4Packet(aIP, unrouted, []byte("this one has no peer"))

	refs := []*InputPacketRef{
		{Destination: bIP.To4(), PacketSlices: [][]byte{pkt1}},
		{Destination: unrouted.To4(), PacketSlices: [][]byte{pktUnrouted}},
		{Destination: bIP.To4(), PacketSlices: [][]byte{pkt2}},
	}

	unmatched := a.device.InputPackets(refs)

	if len(unmatched) != 1 {
		t.Fatalf("expected exactly 1 unmatched packet ref, got %d", len(unmatched))
	}
	if string(unmatched[0].PacketSlices[0]) != string(pktUnrouted) {
		t.Fatalf("unmatched ref does not correspond to the unrouted packet")
	}

	want := map[string]bool{string(pkt1): true, string(pkt2): true}
	for len(want) > 0 {
		got, ok := b.tun.WaitReceived(8 * time.Second)
		if !ok {
			t.Fatalf("timed out waiting for batched packets; still missing %d", len(want))
		}
		if !want[string(got)] {
			t.Fatalf("received unexpected/duplicate packet: %x", got)
		}
		delete(want, string(got))
	}

	if _, ok := b.tun.WaitReceived(300 * time.Millisecond); ok {
		t.Fatalf("unmatched packet was delivered despite having no matching peer")
	}
}
