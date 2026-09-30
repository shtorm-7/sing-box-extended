/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * End-to-end traffic tests for the AmneziaWG padding/obfuscation features
 * (S1-S4 handshake/transport padding, H1-H4 ranged magic headers, junk
 * packets, header_protection_key, content_padding_addition). Two real
 * *Device instances talk over loopback UDP via conn.StdNetBind; plaintext
 * IPv4 packets are pushed in on one side's fake TUN and must arrive
 * byte-for-byte identical on the other side's fake TUN, despite the
 * padding/crypto machinery adding and stripping bytes along the way.
 */

package device

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"
)

// ---------------------------------------------------------------------
// fakeTUN: a minimal in-memory tun.Device for driving a real *Device
// without touching the OS network stack.
// ---------------------------------------------------------------------

type fakeTUN struct {
	mtu      int
	events   chan tun.Event
	toSend   chan []byte // test -> device: plaintext packets to be encrypted and sent
	received chan []byte // device -> test: plaintext packets decrypted from the peer

	closeOnce sync.Once
	closed    chan struct{}
}

func newFakeTUN(mtu int) *fakeTUN {
	return &fakeTUN{
		mtu:      mtu,
		events:   make(chan tun.Event),
		toSend:   make(chan []byte, 64),
		received: make(chan []byte, 64),
		closed:   make(chan struct{}),
	}
}

func (f *fakeTUN) File() *os.File { return nil }

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt, ok := <-f.toSend:
		if !ok {
			return 0, os.ErrClosed
		}
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	case <-f.closed:
		return 0, os.ErrClosed
	}
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		select {
		case f.received <- pkt:
		case <-f.closed:
			return 0, os.ErrClosed
		}
	}
	return len(bufs), nil
}

func (f *fakeTUN) MTU() (int, error)        { return f.mtu, nil }
func (f *fakeTUN) Name() (string, error)    { return "faketun0", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return f.events }
func (f *fakeTUN) BatchSize() int           { return 1 }
func (f *fakeTUN) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

// Inject enqueues a plaintext packet to be read (and thus encrypted+sent) by
// the Device driving this fakeTUN.
func (f *fakeTUN) Inject(pkt []byte) {
	f.toSend <- pkt
}

// WaitReceived blocks until a decrypted packet is delivered or the timeout
// elapses.
func (f *fakeTUN) WaitReceived(timeout time.Duration) ([]byte, bool) {
	select {
	case pkt := <-f.received:
		return pkt, true
	case <-time.After(timeout):
		return nil, false
	}
}

// ---------------------------------------------------------------------
// Test device/peer harness
// ---------------------------------------------------------------------

type testEndpoint struct {
	device *Device
	tun    *fakeTUN
	port   uint16
	priv   NoisePrivateKey
	pub    NoisePublicKey
}

func genKeypair(t *testing.T) (NoisePrivateKey, NoisePublicKey) {
	t.Helper()
	var priv NoisePrivateKey
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	priv.clamp()
	return priv, priv.publicKey()
}

// newTestEndpoint creates a Device bound to an ephemeral loopback UDP port,
// with the given private key already configured, and brings it Up (which
// allocates the real port).
func newTestEndpoint(t *testing.T) *testEndpoint {
	t.Helper()

	priv, pub := genKeypair(t)

	tunDev := newFakeTUN(DefaultMTU)
	bind := conn.NewStdNetBind(nil)
	logger := NewLogger(LogLevelSilent, "")

	dev := NewDevice(context.Background(), tunDev, bind, logger, 2, 0, true)

	if err := setUAPI(t, dev, "private_key="+hex.EncodeToString(priv[:])); err != nil {
		t.Fatalf("set private_key: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("Up(): %v", err)
	}

	out := getUAPI(t, dev)
	port := parseListenPort(t, out)

	return &testEndpoint{device: dev, tun: tunDev, port: port, priv: priv, pub: pub}
}

func (e *testEndpoint) Close() {
	e.device.Close()
	e.tun.Close()
}

func parseListenPort(t *testing.T, uapiDump string) uint16 {
	t.Helper()
	for _, line := range strings.Split(uapiDump, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			var port uint16
			if _, err := fmt.Sscanf(line, "listen_port=%d", &port); err != nil {
				t.Fatalf("failed to parse %q: %v", line, err)
			}
			return port
		}
	}
	t.Fatalf("listen_port not found in UAPI dump:\n%s", uapiDump)
	return 0
}

// connectPair wires two endpoints together as peers of each other, applying
// the same obfConfig (a block of AmneziaWG UAPI lines, e.g. "s1=10\ns2=10\n")
// to both sides so their obfuscation parameters match. localIP/remoteIP are
// the /32 tunnel addresses used for allowedips-based routing.
func connectPair(t *testing.T, a, b *testEndpoint, aIP, bIP net.IP, obfConfig string) {
	t.Helper()

	bodyA := obfConfig +
		fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\n",
			hex.EncodeToString(b.pub[:]), b.port, bIP.String())
	if err := setUAPI(t, a.device, bodyA); err != nil {
		t.Fatalf("configure peer on A: %v", err)
	}

	bodyB := obfConfig +
		fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\n",
			hex.EncodeToString(a.pub[:]), a.port, aIP.String())
	if err := setUAPI(t, b.device, bodyB); err != nil {
		t.Fatalf("configure peer on B: %v", err)
	}
}

// buildIPv4Packet constructs a minimal (header-valid-enough) IPv4 packet
// carrying payload, with the given source/destination addresses. Only the
// fields wireguard-go actually inspects (version/IHL nibble, total length,
// source, destination) are meaningful; the rest are zero.
func buildIPv4Packet(src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, IPv4offsetDst+net.IPv4len+len(payload))
	pkt[0] = 0x45 // version 4, IHL 5 (20-byte header, no options)
	binary.BigEndian.PutUint16(pkt[IPv4offsetTotalLength:], uint16(len(pkt)))
	copy(pkt[IPv4offsetSrc:IPv4offsetSrc+net.IPv4len], src.To4())
	copy(pkt[IPv4offsetDst:IPv4offsetDst+net.IPv4len], dst.To4())
	copy(pkt[IPv4offsetDst+net.IPv4len:], payload)
	return pkt
}

// ---------------------------------------------------------------------
// The main traffic sweep.
// ---------------------------------------------------------------------

// obfuscationConfigs enumerates the AmneziaWG padding/obfuscation setups to
// validate against real, end-to-end encrypted traffic. Every config is
// applied identically to both peers (as required for interop).
func obfuscationConfigs(t *testing.T) map[string]string {
	t.Helper()

	var hpKey HeaderCipherKey
	if _, err := rand.Read(hpKey[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	hpKeyHex := hex.EncodeToString(hpKey[:])

	return map[string]string{
		"baseline_no_obfuscation": "",

		"s1s4_padding_only": "s1=7\ns2=13\ns3=5\ns4=21\n",

		"s1s4_large_padding": "s1=64\ns2=64\ns3=64\ns4=64\n",

		"header_protection": fmt.Sprintf(
			"s1=16\ns2=16\ns3=16\ns4=16\nheader_protection_key=%s\n", hpKeyHex),

		"content_padding_addition": "content_padding_addition=32-128\n",

		"junk_packets": "jc=4\njmin=10\njmax=64\n",

		"ranged_headers": "h1=1000-1010\nh2=2000-2010\nh3=3000-3010\nh4=4000-4010\n",

		"kitchen_sink": fmt.Sprintf(
			"s1=20\ns2=20\ns3=20\ns4=20\n"+
				"h1=1000-1010\nh2=2000-2010\nh3=3000-3010\nh4=4000-4010\n"+
				"jc=2\njmin=10\njmax=30\n"+
				"content_padding_addition=16-64\n"+
				"header_protection_key=%s\n", hpKeyHex),
	}
}

// packetSizesToTest returns a spread of IPv4 payload sizes (bytes after the
// 20-byte header) covering: empty, tiny, boundary-of-16 (PaddingMultiple),
// medium, and near-MTU payloads.
func packetSizesToTest() []int {
	sizes := []int{0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65}
	for s := 100; s <= 1300; s += 100 {
		sizes = append(sizes, s)
	}
	return sizes
}

// TestTrafficRoundTripAcrossObfuscationConfigs is the core correctness test
// requested: for every AmneziaWG padding/obfuscation configuration, and for
// a wide sweep of packet sizes, a plaintext IPv4 packet sent from peer A
// must arrive at peer B byte-for-byte identical, and vice versa. Between the
// per-config and per-size/per-direction subtests, this exercises hundreds of
// individual packet round trips through the real send/receive/encryption
// pipeline (device/send.go, device/receive.go, device/obf*.go).
func TestTrafficRoundTripAcrossObfuscationConfigs(t *testing.T) {
	aIP := net.ParseIP("10.50.0.1")
	bIP := net.ParseIP("10.50.0.2")

	for name, obfConfig := range obfuscationConfigs(t) {
		name, obfConfig := name, obfConfig
		t.Run(name, func(t *testing.T) {
			a := newTestEndpoint(t)
			defer a.Close()
			b := newTestEndpoint(t)
			defer b.Close()

			connectPair(t, a, b, aIP, bIP, obfConfig)

			// Warm-up packet: triggers and waits out the handshake so the
			// timing-sensitive per-size assertions below aren't the ones
			// paying for it.
			warmup := buildIPv4Packet(aIP, bIP, []byte("warmup"))
			a.tun.Inject(warmup)
			got, ok := b.tun.WaitReceived(8 * time.Second)
			if !ok {
				t.Fatalf("handshake/warm-up packet A->B never arrived")
			}
			if string(got) != string(warmup) {
				t.Fatalf("warm-up packet mismatch: got %x, want %x", got, warmup)
			}

			sizes := packetSizesToTest()
			for _, size := range sizes {
				size := size
				t.Run(fmt.Sprintf("A_to_B/size=%d", size), func(t *testing.T) {
					payload := make([]byte, size)
					if _, err := rand.Read(payload); err != nil {
						t.Fatalf("rand.Read: %v", err)
					}
					pkt := buildIPv4Packet(aIP, bIP, payload)

					a.tun.Inject(pkt)
					got, ok := b.tun.WaitReceived(2 * time.Second)
					if !ok {
						t.Fatalf("packet never arrived at B (size=%d)", size)
					}
					if len(got) != len(pkt) {
						t.Fatalf("length mismatch: got %d, want %d", len(got), len(pkt))
					}
					if string(got) != string(pkt) {
						t.Fatalf("content mismatch at size=%d", size)
					}
				})

				t.Run(fmt.Sprintf("B_to_A/size=%d", size), func(t *testing.T) {
					payload := make([]byte, size)
					if _, err := rand.Read(payload); err != nil {
						t.Fatalf("rand.Read: %v", err)
					}
					pkt := buildIPv4Packet(bIP, aIP, payload)

					b.tun.Inject(pkt)
					got, ok := a.tun.WaitReceived(2 * time.Second)
					if !ok {
						t.Fatalf("packet never arrived at A (size=%d)", size)
					}
					if len(got) != len(pkt) {
						t.Fatalf("length mismatch: got %d, want %d", len(got), len(pkt))
					}
					if string(got) != string(pkt) {
						t.Fatalf("content mismatch at size=%d", size)
					}
				})
			}
		})
	}
}

// TestTrafficMismatchedHeaderProtectionKeyDrops is a negative control: if
// the two peers disagree on header_protection_key, packets must simply be
// dropped (never corrupted-but-delivered, never panic), because the type
// field can no longer be recovered on the receiving side.
func TestTrafficMismatchedHeaderProtectionKeyDrops(t *testing.T) {
	aIP := net.ParseIP("10.51.0.1")
	bIP := net.ParseIP("10.51.0.2")

	a := newTestEndpoint(t)
	defer a.Close()
	b := newTestEndpoint(t)
	defer b.Close()

	var keyA, keyB HeaderCipherKey
	if _, err := rand.Read(keyA[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if _, err := rand.Read(keyB[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	obfA := fmt.Sprintf("s1=16\ns2=16\ns3=16\ns4=16\nheader_protection_key=%s\n", hex.EncodeToString(keyA[:]))
	obfB := fmt.Sprintf("s1=16\ns2=16\ns3=16\ns4=16\nheader_protection_key=%s\n", hex.EncodeToString(keyB[:]))

	bodyA := obfA + fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\n",
		hex.EncodeToString(b.pub[:]), b.port, bIP.String())
	if err := setUAPI(t, a.device, bodyA); err != nil {
		t.Fatalf("configure peer on A: %v", err)
	}
	bodyB := obfB + fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=%s/32\n",
		hex.EncodeToString(a.pub[:]), a.port, aIP.String())
	if err := setUAPI(t, b.device, bodyB); err != nil {
		t.Fatalf("configure peer on B: %v", err)
	}

	pkt := buildIPv4Packet(aIP, bIP, []byte("should not arrive"))
	a.tun.Inject(pkt)

	if got, ok := b.tun.WaitReceived(1500 * time.Millisecond); ok {
		t.Fatalf("packet unexpectedly delivered despite mismatched header_protection_key: %x", got)
	}
}
