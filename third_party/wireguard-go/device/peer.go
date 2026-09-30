/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/wireguard-go/conn"
)

type Peer struct {
	isRunning         atomic.Bool
	keypairs          Keypairs
	handshake         Handshake
	device            *Device
	stopping          sync.WaitGroup // routines pending stop
	txBytes           atomic.Uint64  // bytes send to peer (endpoint)
	rxBytes           atomic.Uint64  // bytes received from peer
	lastHandshakeNano atomic.Int64   // nano seconds since epoch

	sessionState struct {
		sync.Mutex
		current        PeerSessionState
		sessionExpires time.Time
	}

	queuedOutboundPackets atomic.Int32 // packets in staged+outbound queues, for input backpressure

	// deleteOnIdle indicates whether the peer should be deleted when idle
	// because it was auto-created via a Device.PeerLookupFunc.
	//
	// This field should only be set once, before the peer is started.
	deleteOnIdle bool

	endpoint struct {
		sync.Mutex
		val            conn.Endpoint
		candidates     []conn.Endpoint
		resolver       func() ([]conn.Endpoint, error)
		clearSrcOnTx   bool // signal to val.ClearSrc() prior to next packet transmission
		disableRoaming bool
	}

	timers struct {
		retransmitHandshake     *Timer
		sendKeepalive           *Timer
		newHandshake            *Timer
		sessionExpired          *Timer
		zeroKeyMaterial         *Timer
		persistentKeepalive     *Timer
		handshakeAttempts       atomic.Uint32
		maxHandshakeAttempts    atomic.Uint32
		needAnotherKeepalive    atomic.Bool
		sentLastMinuteHandshake atomic.Bool
	}

	state struct {
		sync.Mutex // protects against concurrent Start/Stop, and fields below

		allowedIPs []netip.Prefix

		// testAllowedIP, if non-nil, is used to test whether the peer is
		// allowed to send a packet from the given IP address. It can be read
		// without locking, but must be set with the state mutex locked.
		testAllowedIP atomic.Pointer[func(netip.Addr) bool]
	}

	queue struct {
		staged   chan *QueueOutboundElementsContainer // staged packets before a handshake is available
		outbound *autodrainingOutboundQueue           // sequential ordering of udp transmission
		inbound  *autodrainingInboundQueue            // sequential ordering of tun writing
	}

	cookieGenerator             CookieGenerator
	trieEntries                 list.List
	persistentKeepaliveInterval AtomicUintRange
	udpWindow                   atomic.Uint32
}

func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	if device.isClosed() {
		return nil, errors.New("device closed")
	}

	// lock resources
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.peers.Lock()
	defer device.peers.Unlock()

	// check if over limit
	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer
	peer := new(Peer)

	peer.udpWindow.Store(DefaultUdpWindow)

	peer.cookieGenerator.Init(pk)
	peer.device = device
	peer.queue.outbound = newAutodrainingOutboundQueue(device)
	peer.queue.inbound = newAutodrainingInboundQueue(device)
	peer.queue.staged = make(chan *QueueOutboundElementsContainer, QueueStagedSize)

	// map public key
	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errAddExistingPeer
	}

	// pre-compute DH
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// reset endpoint
	peer.endpoint.Lock()
	peer.endpoint.val = nil
	peer.endpoint.disableRoaming = false
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.Unlock()

	// init timers
	peer.timersInit()

	// add
	device.peers.keyMap[pk] = peer

	return peer, nil
}

// SetAllowedIPs sets the allowed IP prefixes for this peer.
//
// If the allowedIPs are unchanged since the last call, this method is a no-op.
// It's the caller's responsibility to ensure that no two peers have duplicate
// allowed IPs. If so, the last writer wins.
func (p *Peer) SetAllowedIPs(allowedIPs []netip.Prefix) {
	p.state.Lock()
	defer p.state.Unlock()

	if slices.Equal(p.state.allowedIPs, allowedIPs) {
		return
	}
	p.device.allowedips.setPeerPrefixes(p, allowedIPs)

	allowedIPs = slices.Clone(allowedIPs) // avoid retaining caller's slice
	p.state.allowedIPs = allowedIPs

	f := mkIPInCIDRsTestFunc(allowedIPs)
	p.state.testAllowedIP.Store(&f)
}

// SendBuffers sends buffers to peer. WireGuard packet data in each element of
// buffers must be preceded by MessageEncapsulatingTransportSize number of
// bytes.
func (peer *Peer) SendBuffers(buffers [][]byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.isClosed() {
		return nil
	}

	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	if endpoint == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}
	if peer.endpoint.clearSrcOnTx {
		endpoint.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()

	err := peer.device.net.bind.Send(buffers, endpoint, MessageEncapsulatingTransportSize)
	if err == nil {
		var totalLen uint64
		for _, b := range buffers {
			totalLen += uint64(len(b))
		}
		peer.txBytes.Add(totalLen)
	} else if errors.Is(err, conn.ErrRebindRequired) {
		peer.device.scheduleBindUpdate()
	}
	return err
}

func (peer *Peer) String() string {
	// The awful goo that follows is identical to:
	//
	//   base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	//   abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	//   return fmt.Sprintf("peer(%s)", abbreviatedKey)
	//
	// except that it is considerably more efficient.
	src := peer.handshake.remoteStatic
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	return string(b)
}

func (peer *Peer) Start() {
	// should never start a peer on a closed device
	if peer.device.isClosed() {
		return
	}

	// prevent simultaneous start/stop operations
	peer.state.Lock()
	defer peer.state.Unlock()

	if peer.isRunning.Load() {
		return
	}

	device := peer.device
	device.log.Verbosef("%v - Starting", peer)

	// reset routine state
	peer.stopping.Wait()
	peer.stopping.Add(2)
	peer.queuedOutboundPackets.Store(0)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(peer.device.rekeyMinTimeout() + time.Second))
	peer.handshake.mutex.Unlock()

	peer.device.queue.encryption.wg.Add(1) // keep encryption queue open for our writes

	peer.timersStart()

	device.flushInboundQueue(peer.queue.inbound.c)
	device.flushOutboundQueue(peer.queue.outbound.c)

	// Use the device batch size, not the bind batch size, as the device size is
	// the size of the batch pools.
	batchSize := peer.device.BatchSize()
	go peer.RoutineSequentialSender(batchSize)
	go peer.RoutineSequentialReceiver(batchSize)

	peer.isRunning.Store(true)

	// A lazily-created peer that never completes a handshake otherwise never
	// arms its reaping timer. Arm it here, while running under state.Lock, so
	// it's reclaimed after RejectAfterTime*3 of no session and is guaranteed to
	// be torn down by a matching Stop. A completed handshake re-Mods it.
	if peer.deleteOnIdle {
		peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
	}
}

func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device
	if peer.timers.sessionExpired != nil {
		peer.timers.sessionExpired.Del()
	}

	// clear key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.next.Load())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushStagedPackets()

	peer.sessionState.Lock()
	peer.sessionState.sessionExpires = time.Time{}
	peer.noteSessionStateLocked(PeerSessionNone)
	peer.sessionState.Unlock()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	peer.handshake.lastSentHandshake = time.Now().Add(-(peer.device.rekeyMinTimeout() + time.Second))
	handshake.mutex.Unlock()

	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()

	peer.sessionState.Lock()
	peer.sessionState.sessionExpires = time.Time{}
	peer.noteSessionStateLocked(PeerSessionExpired)
	peer.sessionState.Unlock()
}

func (peer *Peer) Stop() {
	peer.state.Lock()
	defer peer.state.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.device.log.Verbosef("%v - Stopping", peer)

	peer.timersStop()
	// Signal that RoutineSequentialSender and RoutineSequentialReceiver should exit.
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	peer.stopping.Wait()
	peer.device.queue.encryption.wg.Done() // no more writes to encryption queue from us

	peer.ZeroAndFlushAll()
}

func (peer *Peer) noteSessionState(state PeerSessionState) {
	peer.sessionState.Lock()
	defer peer.sessionState.Unlock()
	peer.noteSessionStateLocked(state)
}

// noteSessionStateLocked records a session state transition and delivers the
// callback. The caller must hold peer.sessionState.Mutex during the
// state determination and transition.
func (peer *Peer) noteSessionStateLocked(state PeerSessionState) {
	if peer.sessionState.current == state {
		return
	}
	peer.sessionState.current = state
	if f := peer.device.peerStateFn.Load(); f != nil {
		(*f)(peer.handshake.remoteStatic, state)
	}
}

func (peer *Peer) noteSessionHandshakeStarted() {
	peer.sessionState.Lock()
	defer peer.sessionState.Unlock()
	if peer.sessionState.current == PeerSessionEstablished {
		return
	}
	peer.noteSessionStateLocked(PeerSessionHandshake)
}

func (peer *Peer) noteSessionHandshakeStopped() {
	peer.sessionState.Lock()
	defer peer.sessionState.Unlock()
	state := PeerSessionNone
	if peer.hasKeyMaterial() {
		state = PeerSessionExpired
	}
	peer.noteSessionStateLocked(state)
}

func (peer *Peer) hasKeyMaterial() bool {
	keypairs := &peer.keypairs
	keypairs.RLock()
	defer keypairs.RUnlock()
	return keypairs.previous != nil || keypairs.current != nil || keypairs.next.Load() != nil
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.disableRoaming {
		return
	}
	if peer.endpoint.val != endpoint {
		peer.udpWindow.Store(DefaultUdpWindow)
	}
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.val = endpoint
}

// SetEndpointResolver sets a function providing the candidate endpoints for
// this peer. It is invoked on every handshake initiation, and the initiation
// is sent to the current endpoint and every candidate; the source of the
// first valid reply becomes the current endpoint via roaming. When the
// resolver fails, the candidates from its last successful invocation are
// reused.
func (peer *Peer) SetEndpointResolver(resolver func() ([]conn.Endpoint, error)) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	peer.endpoint.resolver = resolver
}

func (peer *Peer) resolveEndpoints() []conn.Endpoint {
	peer.endpoint.Lock()
	resolver := peer.endpoint.resolver
	peer.endpoint.Unlock()
	if resolver == nil {
		return nil
	}
	resolved, err := resolver()
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to resolve endpoints: %v", peer, err)
	} else if len(resolved) > 0 {
		peer.endpoint.candidates = resolved
	}
	return peer.endpoint.candidates
}

// sendHandshakeBuffers sends buffers to the peer's current endpoint and every
// candidate. It succeeds when at least one endpoint accepted the send.
func (peer *Peer) sendHandshakeBuffers(buffers [][]byte, candidates []conn.Endpoint) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.isClosed() {
		return nil
	}

	peer.endpoint.Lock()
	current := peer.endpoint.val
	if current != nil && peer.endpoint.clearSrcOnTx {
		current.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()

	endpoints := make([]conn.Endpoint, 0, len(candidates)+1)
	if current != nil {
		endpoints = append(endpoints, current)
	}
	for _, candidate := range candidates {
		duplicate := slices.ContainsFunc(endpoints, func(endpoint conn.Endpoint) bool {
			return endpoint.DstToString() == candidate.DstToString()
		})
		if !duplicate {
			endpoints = append(endpoints, candidate)
		}
	}
	if len(endpoints) == 0 {
		return errors.New("no known endpoint for peer")
	}

	var totalLen uint64
	for _, buffer := range buffers {
		totalLen += uint64(len(buffer))
	}

	var firstErr error
	sent := false
	for _, endpoint := range endpoints {
		err := peer.device.net.bind.Send(buffers, endpoint, MessageEncapsulatingTransportSize)
		if err == nil {
			sent = true
			peer.txBytes.Add(totalLen)
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if sent {
		return nil
	}
	return firstErr
}

func (peer *Peer) markEndpointSrcForClearing() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	if peer.endpoint.val == nil {
		return
	}
	peer.endpoint.clearSrcOnTx = true
}
