package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpClient struct {
	pending chan []byte
	closed  atomic.Bool
	addr    string
}

type RelayBridge struct {
	tunnelMu   sync.RWMutex
	tunnel     DataTunnel
	conns      sync.Map
	udpClients sync.Map
	nextID     atomic.Uint32
	logger     logger.ContextLogger
	mode       string
	readBuf    int
	ready      chan struct{}
	once       sync.Once
	closed     atomic.Bool
	dialer     N.Dialer

	acceptHandlerMu sync.Mutex
	acceptHandler   func(conn net.Conn, destination string)

	udpAcceptHandlerMu sync.Mutex
	udpAcceptHandler   func(conn net.Conn, destination string)

	onPeerConfigMu sync.Mutex
	onPeerConfig   func(fps, batch, trackCount int)
}

func NewRelayBridge(tunnel DataTunnel, mode string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) *RelayBridge {
	rb := &RelayBridge{
		tunnel:  tunnel,
		logger:  logger,
		mode:    mode,
		readBuf: readBuf,
		dialer:  dialer,
		ready:   make(chan struct{}),
	}
	tunnel.SetOnData(rb.handleTunnelData)
	tunnel.SetOnClose(rb.handleTunnelClose)
	return rb
}

func (rb *RelayBridge) SetAcceptHandler(fn func(conn net.Conn, destination string)) {
	rb.acceptHandlerMu.Lock()
	rb.acceptHandler = fn
	rb.acceptHandlerMu.Unlock()
}

func (rb *RelayBridge) SetUDPAcceptHandler(fn func(conn net.Conn, destination string)) {
	rb.udpAcceptHandlerMu.Lock()
	rb.udpAcceptHandler = fn
	rb.udpAcceptHandlerMu.Unlock()
}

func (rb *RelayBridge) SetOnPeerConfig(fn func(fps, batch, trackCount int)) {
	rb.onPeerConfigMu.Lock()
	rb.onPeerConfig = fn
	rb.onPeerConfigMu.Unlock()
}

func (rb *RelayBridge) DialContext(ctx context.Context, destination string) (net.Conn, error) {
	if rb.closed.Load() {
		return nil, fmt.Errorf("relay: bridge already closed")
	}
	if M.ParseSocksaddr(destination).IsIPv6() {
		return nil, fmt.Errorf("relay: network unreachable (ipv6): %s", common.MaskAddr(destination))
	}
	select {
	case <-rb.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	id := rb.nextID.Add(1)
	tc := newTunnelConn(id, rb)
	rb.conns.Store(id, tc)
	rb.logger.Debug(fmt.Sprintf("relay: DIAL %d -> %s", id, common.MaskAddr(destination)))
	rb.send(id, MsgConnect, []byte(destination))
	select {
	case err := <-tc.rdy:
		if err != nil {
			rb.conns.Delete(id)
			return nil, err
		}
		return tc, nil
	case <-ctx.Done():
		rb.conns.Delete(id)
		rb.send(id, MsgClose, nil)
		return nil, ctx.Err()
	}
}

func (rb *RelayBridge) ListenPacket(ctx context.Context, destination string) (net.Conn, error) {
	if rb.closed.Load() {
		return nil, fmt.Errorf("relay: bridge already closed")
	}
	if M.ParseSocksaddr(destination).IsIPv6() {
		return nil, fmt.Errorf("relay: network unreachable (ipv6): %s", common.MaskAddr(destination))
	}
	select {
	case <-rb.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	id := rb.nextID.Add(1)
	uc := &udpClient{pending: make(chan []byte, 64), addr: destination}
	rb.udpClients.Store(id, uc)
	return &tunnelPacketConn{id: id, rb: rb, uc: uc, destStr: destination}, nil
}

func (rb *RelayBridge) Reset() {
	rb.closeAll()
}

func (rb *RelayBridge) Close() {
	if !rb.closed.CompareAndSwap(false, true) {
		return
	}
	rb.closeAll()
}

func (rb *RelayBridge) MarkReady() {
	rb.once.Do(func() { close(rb.ready) })
}

func (rb *RelayBridge) currentTunnel() DataTunnel {
	rb.tunnelMu.RLock()
	defer rb.tunnelMu.RUnlock()
	return rb.tunnel
}

func (rb *RelayBridge) SwapTunnel(newTunnel DataTunnel) {
	rb.tunnelMu.Lock()
	rb.tunnel = newTunnel
	rb.tunnelMu.Unlock()
	newTunnel.SetOnData(rb.handleTunnelData)
	newTunnel.SetOnClose(rb.handleTunnelClose)
	rb.closeAll()
}

func (rb *RelayBridge) IsClosed() bool {
	return rb.closed.Load()
}

func (rb *RelayBridge) handleTunnelClose() {
	rb.closeAll()
}

func (rb *RelayBridge) closeAll() {
	var ids []uint32
	rb.conns.Range(func(key, value any) bool {
		if id, ok := key.(uint32); ok {
			ids = append(ids, id)
		}
		if c, ok := value.(net.Conn); ok {
			c.Close()
		}
		rb.conns.Delete(key)
		return true
	})
	udpCount := 0
	rb.udpClients.Range(func(key, value any) bool {
		udpCount++
		if uc, ok := value.(*udpClient); ok {
			uc.closed.Store(true)
			close(uc.pending)
		}
		rb.udpClients.Delete(key)
		return true
	})
	rb.logger.Debug(fmt.Sprintf("relay: closeAll mode=%s tcp=%d udp=%d ids=%v nextID=%d", rb.mode, len(ids), udpCount, ids, rb.nextID.Load()))
}

func (rb *RelayBridge) send(connID uint32, msgType byte, payload []byte) {
	frame := EncodeFrame(connID, msgType, payload)
	rb.currentTunnel().SendData(frame)
}

func (rb *RelayBridge) handleTunnelData(data []byte) {
	DecodeFrames(data, func(connID uint32, msgType byte, payload []byte) {
		if connID == ControlConnID && msgType == MsgConfig {
			fps, batch, trackCount, ok := DecodeVP8Config(payload)
			if !ok {
				return
			}
			if rb.mode == "creator" {
				rb.logger.Debug(fmt.Sprintf("relay: peer requested vp8 pacing fps=%d batch=%d trackCount=%d", fps, batch, trackCount))
				rb.currentTunnel().Reconfigure(fps, batch)
				rb.send(ControlConnID, MsgConfigAck, nil)
				rb.onPeerConfigMu.Lock()
				cb := rb.onPeerConfig
				rb.onPeerConfigMu.Unlock()
				if cb != nil {
					cb(fps, batch, trackCount)
				}
			}
			return
		}
		if connID == ControlConnID && msgType == MsgConfigAck {
			return
		}
		switch rb.mode {
		case "joiner":
			rb.handleJoinerMessage(connID, msgType, payload)
		case "creator":
			rb.handleCreatorMessage(connID, msgType, payload)
		}
	})
}

func (rb *RelayBridge) handleJoinerMessage(connID uint32, msgType byte, payload []byte) {
	if msgType == MsgUDPReply {
		uval, ok := rb.udpClients.Load(connID)
		if !ok {
			return
		}
		uc := uval.(*udpClient)
		if uc.closed.Load() {
			return
		}
		cp := make([]byte, len(payload))
		copy(cp, payload)
		select {
		case uc.pending <- cp:
		default:
		}
		return
	}
	val, ok := rb.conns.Load(connID)
	if !ok {
		if msgType != MsgClose {
			rb.logger.Debug(fmt.Sprintf("relay[joiner]: drop msgType=%d for unknown conn %d (payload=%dB)", msgType, connID, len(payload)))
		}
		return
	}
	tc := val.(*tunnelConn)
	switch msgType {
	case MsgConnectOK:
		select {
		case tc.rdy <- nil:
		default:
		}
	case MsgConnectErr:
		select {
		case tc.rdy <- fmt.Errorf("%s", payload):
		default:
		}
	case MsgData:
		tc.deliver(payload)
	case MsgClose:
		tc.remoteClosed()
		rb.conns.Delete(connID)
	}
}

func (rb *RelayBridge) handleCreatorMessage(connID uint32, msgType byte, payload []byte) {
	switch msgType {
	case MsgConnect:
		rb.acceptHandlerMu.Lock()
		handler := rb.acceptHandler
		rb.acceptHandlerMu.Unlock()
		if handler != nil {
			destination := string(payload)
			tc := newTunnelConn(connID, rb)
			rb.conns.Store(connID, tc)
			rb.send(connID, MsgConnectOK, nil)
			go handler(tc, destination)
			return
		}
		go rb.connectTCP(connID, string(payload))
	case MsgUDP:
		payloadCopy := make([]byte, len(payload))
		copy(payloadCopy, payload)
		go rb.handleUDP(connID, payloadCopy)
	case MsgData:
		val, ok := rb.conns.Load(connID)
		if !ok {
			rb.logger.Debug(fmt.Sprintf("relay[creator]: drop MsgData for unknown conn %d (payload=%dB)", connID, len(payload)))
			rb.send(connID, MsgClose, nil)
			return
		}
		switch c := val.(type) {
		case *tunnelConn:
			c.deliver(payload)
		case net.Conn:
			if _, err := c.Write(payload); err != nil {
				rb.logger.Debug(fmt.Sprintf("relay[creator]: write to target %d failed: %s", connID, common.MaskError(err)))
			}
		}
	case MsgClose:
		found := false
		if val, ok := rb.conns.LoadAndDelete(connID); ok {
			found = true
			switch c := val.(type) {
			case *tunnelConn:
				c.remoteClosed()
			case net.Conn:
				c.Close()
			}
		}
		if uval, ok := rb.udpClients.LoadAndDelete(connID); ok {
			found = true
			switch uc := uval.(type) {
			case *creatorUDPConn:
				uc.remoteClosed()
			case net.Conn:
				uc.Close()
			}
		}
		if !found {
			rb.logger.Debug(fmt.Sprintf("relay[creator]: drop MsgClose for unknown conn %d", connID))
		}
	}
}

func (rb *RelayBridge) handleUDP(connID uint32, payload []byte) {
	if len(payload) < 2 {
		return
	}
	addrLen := int(payload[0])
	if addrLen == 0 || len(payload) < 1+addrLen {
		return
	}
	if bytes.IndexByte(payload[1:1+addrLen], 0) != -1 {
		return
	}
	addr := string(payload[1 : 1+addrLen])
	data := payload[1+addrLen:]
	rb.udpAcceptHandlerMu.Lock()
	handler := rb.udpAcceptHandler
	rb.udpAcceptHandlerMu.Unlock()
	if handler != nil {
		var cuc *creatorUDPConn
		if val, ok := rb.udpClients.Load(connID); ok {
			existing, ok := val.(*creatorUDPConn)
			if !ok {
				return
			}
			cuc = existing
		} else {
			created := newCreatorUDPConn(connID, rb, addr)
			if actual, loaded := rb.udpClients.LoadOrStore(connID, created); loaded {
				existing, ok := actual.(*creatorUDPConn)
				if !ok {
					return
				}
				cuc = existing
			} else {
				cuc = created
				go handler(cuc, addr)
			}
		}
		cuc.deliver(data)
		return
	}
	var egress net.Conn
	if val, ok := rb.udpClients.Load(connID); ok {
		existing, ok := val.(net.Conn)
		if !ok {
			return
		}
		egress = existing
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		created, err := rb.dialer.DialContext(ctx, N.NetworkUDP, M.ParseSocksaddr(addr))
		cancel()
		if err != nil {
			rb.logger.Warn(fmt.Sprintf("relay[creator]: UDP %d open %s failed: %v", connID, common.MaskAddr(addr), err))
			return
		}
		if actual, loaded := rb.udpClients.LoadOrStore(connID, created); loaded {
			created.Close()
			existing, ok := actual.(net.Conn)
			if !ok {
				return
			}
			egress = existing
		} else {
			egress = created
			go func(conn net.Conn, id uint32, target string) {
				defer conn.Close()
				defer rb.udpClients.Delete(id)
				defer rb.send(id, MsgClose, nil)
				buf := make([]byte, common.UDPBufSize)
				for {
					conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					rb.send(id, MsgUDPReply, buf[:n])
				}
			}(egress, connID, addr)
		}
	}
	egress.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := egress.Write(data); err != nil {
		rb.logger.Debug(fmt.Sprintf("relay[creator]: UDP %d write %s failed: %v", connID, common.MaskAddr(addr), err))
	}
}

func (rb *RelayBridge) connectTCP(connID uint32, addr string) {
	rb.logger.Debug(fmt.Sprintf("relay: CONNECT %d -> %s", connID, common.MaskAddr(addr)))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := rb.dialer.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(addr))
	cancel()
	if err != nil {
		rb.logger.Warn(fmt.Sprintf("relay: CONNECT %d failed: %s", connID, common.MaskError(err)))
		rb.send(connID, MsgConnectErr, []byte(common.MaskError(err)))
		return
	}
	rb.conns.Store(connID, conn)
	rb.send(connID, MsgConnectOK, nil)
	rb.logger.Debug(fmt.Sprintf("relay: CONNECTED %d -> %s", connID, common.MaskAddr(addr)))
	buf := make([]byte, rb.readBuf)
	var totalRead int64
	var reads int
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			rb.send(connID, MsgData, buf[:n])
			totalRead += int64(n)
			reads++
		}
		if err != nil {
			if err != io.EOF {
				rb.logger.Warn(fmt.Sprintf("relay: conn %d read error: %s (read %d times, %dB)", connID, common.MaskError(err), reads, totalRead))
			}
			break
		}
	}
	rb.send(connID, MsgClose, nil)
	rb.conns.Delete(connID)
}

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "call" }
func (tunnelAddr) String() string  { return "call" }

type tunnelConn struct {
	id       uint32
	rb       *RelayBridge
	rdy      chan error
	readBuf  bytes.Buffer
	readMu   sync.Mutex
	readCond chan struct{}
	closed   atomic.Bool
	closeCh  chan struct{}
}

func newTunnelConn(id uint32, rb *RelayBridge) *tunnelConn {
	return &tunnelConn{
		id:       id,
		rb:       rb,
		rdy:      make(chan error, 1),
		readCond: make(chan struct{}, 1),
		closeCh:  make(chan struct{}),
	}
}

func (tc *tunnelConn) Read(b []byte) (int, error) {
	for {
		tc.readMu.Lock()
		if tc.readBuf.Len() > 0 {
			n, _ := tc.readBuf.Read(b)
			tc.readMu.Unlock()
			return n, nil
		}
		tc.readMu.Unlock()
		select {
		case <-tc.closeCh:
			tc.readMu.Lock()
			if tc.readBuf.Len() > 0 {
				n, _ := tc.readBuf.Read(b)
				tc.readMu.Unlock()
				return n, nil
			}
			tc.readMu.Unlock()
			return 0, io.EOF
		case <-tc.readCond:
		}
	}
}

func (tc *tunnelConn) Write(b []byte) (int, error) {
	if tc.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	tc.rb.send(tc.id, MsgData, b)
	return len(b), nil
}

func (tc *tunnelConn) Close() error {
	if tc.closed.CompareAndSwap(false, true) {
		close(tc.closeCh)
		tc.rb.send(tc.id, MsgClose, nil)
		tc.rb.conns.Delete(tc.id)
	}
	return nil
}

func (tc *tunnelConn) LocalAddr() net.Addr                { return tunnelAddr{} }
func (tc *tunnelConn) RemoteAddr() net.Addr               { return tunnelAddr{} }
func (tc *tunnelConn) SetDeadline(t time.Time) error      { return nil }
func (tc *tunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (tc *tunnelConn) SetWriteDeadline(t time.Time) error { return nil }

func (tc *tunnelConn) deliver(payload []byte) {
	tc.readMu.Lock()
	tc.readBuf.Write(payload)
	tc.readMu.Unlock()
	select {
	case tc.readCond <- struct{}{}:
	default:
	}
}

func (tc *tunnelConn) remoteClosed() {
	if tc.closed.CompareAndSwap(false, true) {
		close(tc.closeCh)
	}
}

type tunnelPacketConn struct {
	id      uint32
	rb      *RelayBridge
	uc      *udpClient
	destStr string
}

func (pc *tunnelPacketConn) Read(b []byte) (int, error) {
	data, ok := <-pc.uc.pending
	if !ok {
		return 0, io.EOF
	}
	n := copy(b, data)
	return n, nil
}

func (pc *tunnelPacketConn) Write(b []byte) (int, error) {
	if pc.uc.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	payload := make([]byte, 1+len(pc.destStr)+len(b))
	payload[0] = byte(len(pc.destStr))
	copy(payload[1:], pc.destStr)
	copy(payload[1+len(pc.destStr):], b)
	pc.rb.send(pc.id, MsgUDP, payload)
	return len(b), nil
}

func (pc *tunnelPacketConn) Close() error {
	if pc.uc.closed.CompareAndSwap(false, true) {
		close(pc.uc.pending)
		pc.rb.udpClients.Delete(pc.id)
		pc.rb.send(pc.id, MsgClose, nil)
	}
	return nil
}

func (pc *tunnelPacketConn) LocalAddr() net.Addr                { return tunnelAddr{} }
func (pc *tunnelPacketConn) RemoteAddr() net.Addr               { return tunnelAddr{} }
func (pc *tunnelPacketConn) SetDeadline(t time.Time) error      { return nil }
func (pc *tunnelPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (pc *tunnelPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type creatorUDPConn struct {
	id       uint32
	rb       *RelayBridge
	addr     string
	readBuf  bytes.Buffer
	readMu   sync.Mutex
	readCond chan struct{}
	closed   atomic.Bool
	closeCh  chan struct{}
}

func newCreatorUDPConn(id uint32, rb *RelayBridge, addr string) *creatorUDPConn {
	return &creatorUDPConn{
		id:       id,
		rb:       rb,
		addr:     addr,
		readCond: make(chan struct{}, 1),
		closeCh:  make(chan struct{}),
	}
}

func (uc *creatorUDPConn) Read(b []byte) (int, error) {
	for {
		uc.readMu.Lock()
		if uc.readBuf.Len() > 0 {
			n, _ := uc.readBuf.Read(b)
			uc.readMu.Unlock()
			return n, nil
		}
		uc.readMu.Unlock()
		select {
		case <-uc.closeCh:
			return 0, io.EOF
		case <-uc.readCond:
		}
	}
}

func (uc *creatorUDPConn) Write(b []byte) (int, error) {
	if uc.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	uc.rb.send(uc.id, MsgUDPReply, b)
	return len(b), nil
}

func (uc *creatorUDPConn) Close() error {
	if uc.closed.CompareAndSwap(false, true) {
		close(uc.closeCh)
		uc.rb.send(uc.id, MsgClose, nil)
		uc.rb.udpClients.Delete(uc.id)
	}
	return nil
}

func (uc *creatorUDPConn) LocalAddr() net.Addr                { return tunnelAddr{} }
func (uc *creatorUDPConn) RemoteAddr() net.Addr               { return tunnelAddr{} }
func (uc *creatorUDPConn) SetDeadline(t time.Time) error      { return nil }
func (uc *creatorUDPConn) SetReadDeadline(t time.Time) error  { return nil }
func (uc *creatorUDPConn) SetWriteDeadline(t time.Time) error { return nil }

func (uc *creatorUDPConn) deliver(payload []byte) {
	uc.readMu.Lock()
	uc.readBuf.Write(payload)
	uc.readMu.Unlock()
	select {
	case uc.readCond <- struct{}{}:
	default:
	}
}

func (uc *creatorUDPConn) remoteClosed() {
	if uc.closed.CompareAndSwap(false, true) {
		close(uc.closeCh)
	}
}
