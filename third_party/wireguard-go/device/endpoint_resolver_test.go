package device_test

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"
	"github.com/sagernet/wireguard-go/tun"

	"golang.org/x/crypto/curve25519"
)

// TestEndpointResolver proves the endpoint resolver contract end to end over
// real localhost UDP sockets and real Noise handshakes:
//
//  1. A peer without a configured endpoint completes a handshake purely from
//     resolver candidates, converging on the live server even when a dead
//     address is ordered first (fan-out racing, not first-address-only).
//  2. After the server moves to a new port, the next handshake picks up the
//     changed candidate list from the resolver and re-converges.
func TestEndpointResolver(t *testing.T) {
	t.Parallel()
	serverPrivate, serverPublic := generateTestKeyPair(t)
	clientPrivate, clientPublic := generateTestKeyPair(t)

	server, _ := startTestDevice(t, "server", serverPrivate, clientPublic, "10.0.0.2/32")
	serverPort := devicePort(t, server)

	deadConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer deadConn.Close()
	deadAddr := netip.MustParseAddrPort(deadConn.LocalAddr().String())

	client, clientTUN := startTestDevice(t, "client", clientPrivate, serverPublic, "10.0.0.1/32")
	defer client.Close()

	var candidates atomic.Pointer[[]netip.AddrPort]
	setCandidates := func(addrs ...netip.AddrPort) {
		candidates.Store(&addrs)
	}
	setCandidates(deadAddr, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), serverPort))

	var serverKey device.NoisePublicKey
	err = serverKey.FromHex(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	peer, found := client.LookupActivePeer(serverKey)
	if !found {
		t.Fatal("missing server peer on client device")
	}
	peer.SetEndpointResolver(func() ([]conn.Endpoint, error) {
		var endpoints []conn.Endpoint
		for _, addrPort := range *candidates.Load() {
			endpoint, parseErr := client.Bind().ParseEndpoint(addrPort.String())
			if parseErr != nil {
				return nil, parseErr
			}
			endpoints = append(endpoints, endpoint)
		}
		return endpoints, nil
	})

	clientTUN.inbound <- buildTestPacket()
	waitForEndpoint(t, client, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), serverPort))

	server.Close()
	server, _ = startTestDevice(t, "server", serverPrivate, clientPublic, "10.0.0.2/32")
	defer server.Close()
	movedPort := devicePort(t, server)
	setCandidates(deadAddr, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), movedPort))

	peer.ExpireCurrentKeypairs()
	clientTUN.inbound <- buildTestPacket()
	waitForEndpoint(t, client, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), movedPort))
}

func generateTestKeyPair(t *testing.T) (privateHex string, publicHex string) {
	var privateKey [32]byte
	_, err := rand.Read(privateKey[:])
	if err != nil {
		t.Fatal(err)
	}
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64
	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(privateKey[:]), hex.EncodeToString(publicKey)
}

func startTestDevice(t *testing.T, name string, privateHex string, peerPublicHex string, peerAllowedIP string) (*device.Device, *testTUN) {
	tunDevice := &testTUN{
		name:    name,
		inbound: make(chan []byte, 16),
		events:  make(chan tun.Event, 1),
		done:    make(chan struct{}),
	}
	wgDevice := device.NewDevice(context.Background(), tunDevice, conn.NewStdNetBind(nil), device.NewLogger(device.LogLevelError, name+": "), 0)
	err := wgDevice.IpcSet("private_key=" + privateHex +
		"\npublic_key=" + peerPublicHex +
		"\nallowed_ip=" + peerAllowedIP)
	if err != nil {
		t.Fatal(err)
	}
	err = wgDevice.Up()
	if err != nil {
		t.Fatal(err)
	}
	return wgDevice, tunDevice
}

func devicePort(t *testing.T, wgDevice *device.Device) uint16 {
	config, err := wgDevice.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(config, "\n") {
		value, isPort := strings.CutPrefix(line, "listen_port=")
		if !isPort {
			continue
		}
		port, portErr := netip.ParseAddrPort("127.0.0.1:" + value)
		if portErr != nil {
			t.Fatal(portErr)
		}
		return port.Port()
	}
	t.Fatal("missing listen_port in device config")
	return 0
}

func waitForEndpoint(t *testing.T, wgDevice *device.Device, expected netip.AddrPort) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		config, err := wgDevice.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		var (
			endpoint     string
			handshakeSec string
		)
		for _, line := range strings.Split(config, "\n") {
			if value, isEndpoint := strings.CutPrefix(line, "endpoint="); isEndpoint {
				endpoint = value
			}
			if value, isHandshake := strings.CutPrefix(line, "last_handshake_time_sec="); isHandshake {
				handshakeSec = value
			}
		}
		if endpoint == expected.String() && handshakeSec != "" && handshakeSec != "0" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for endpoint to converge on ", expected)
}

func buildTestPacket() []byte {
	packet := make([]byte, 28)
	packet[0] = 4<<4 | 5
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], netip.MustParseAddr("10.0.0.2").AsSlice())
	copy(packet[16:20], netip.MustParseAddr("10.0.0.1").AsSlice())
	binary.BigEndian.PutUint16(packet[20:], 1000)
	binary.BigEndian.PutUint16(packet[22:], 1001)
	binary.BigEndian.PutUint16(packet[24:], 8)
	return packet
}

type testTUN struct {
	name    string
	inbound chan []byte
	events  chan tun.Event
	done    chan struct{}
}

func (t *testTUN) File() *os.File { return nil }

func (t *testTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-t.inbound:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-t.done:
		return 0, os.ErrClosed
	}
}

func (t *testTUN) Write(bufs [][]byte, offset int) (int, error) {
	return len(bufs), nil
}

func (t *testTUN) MTU() (int, error) {
	return 1420, nil
}

func (t *testTUN) Name() (string, error) {
	return t.name, nil
}

func (t *testTUN) Events() <-chan tun.Event {
	return t.events
}

func (t *testTUN) Close() error {
	select {
	case <-t.done:
	default:
		close(t.done)
	}
	return nil
}

func (t *testTUN) BatchSize() int {
	return 1
}
