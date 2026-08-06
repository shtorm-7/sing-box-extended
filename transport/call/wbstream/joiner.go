package wbstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	reconnectInitialDelay = time.Second
	reconnectMaxDelay     = 16 * time.Second
)

type WBStreamJoiner struct {
	logger      logger.ContextLogger
	OnConnected func(tunnel.DataTunnel)
	dialer      N.Dialer
	dnsRouter   adapter.DNSRouter
	PCConfig    common.PeerConnectionConfigurer

	mu       sync.Mutex
	session  *Session
	closed   bool
	stopCh   chan struct{}
	stopOnce sync.Once
}

func NewWBStreamJoiner(logger logger.ContextLogger, dialer N.Dialer, dnsRouter adapter.DNSRouter, pcConfig common.PeerConnectionConfigurer) *WBStreamJoiner {
	return &WBStreamJoiner{
		logger:    logger,
		dialer:    dialer,
		dnsRouter: dnsRouter,
		PCConfig:  pcConfig,
		stopCh:    make(chan struct{}),
	}
}

func (j *WBStreamJoiner) RunWithParams(jsonParams string) {
	var params struct {
		RoomID      string `json:"roomId"`
		DisplayName string `json:"displayName"`
		TunnelMode  string `json:"tunnelMode"`
		VP8FPS      int    `json:"vp8Fps"`
		VP8Batch    int    `json:"vp8Batch"`
		DualTrack   bool   `json:"dualTrack"`
		Reliable    *bool  `json:"reliable"`
	}
	if err := json.Unmarshal([]byte(jsonParams), &params); err != nil {
		j.logger.Error(fmt.Sprintf("wbstream-joiner: failed to parse params: %v", err))
		return
	}
	if params.RoomID == "" {
		j.logger.Error("wbstream-joiner: missing roomId")
		return
	}
	if params.DisplayName == "" {
		params.DisplayName = "Joiner"
	}
	reliable := params.Reliable != nil && *params.Reliable
	httpClient := j.makeHTTPClient()
	j.logger.Info(fmt.Sprintf("wbstream-joiner: room=%s name=%s vp8Fps=%d vp8Batch=%d dualTrack=%v", params.RoomID, params.DisplayName, params.VP8FPS, params.VP8Batch, params.DualTrack))
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(params.RoomID))
	if err != nil {
		j.logger.Error(fmt.Sprintf("wbstream-joiner: obfuscator init failed: %v", err))
		return
	}
	j.logger.Debug(fmt.Sprintf("wbstream-joiner: obf key-source=%q localEpoch=0x%08x", params.RoomID, obf.LocalEpoch()))
	var settingEngine *webrtc.SettingEngine
	if j.PCConfig != nil {
		se := webrtc.SettingEngine{}
		j.PCConfig.ConfigureSettingEngine(&se)
		settingEngine = &se
	}
	var attempt atomic.Int32
	j.logger.Info("wbstream-joiner: connecting")
	if err := j.runOnce(httpClient, params.RoomID, params.DisplayName, params.TunnelMode, obf, settingEngine, params.VP8FPS, params.VP8Batch, params.DualTrack, reliable, &attempt); err != nil {
		j.logger.Error(fmt.Sprintf("wbstream-joiner: %v", err))
		return
	}
	for {
		if j.isClosed() {
			j.logger.Info("wbstream-joiner: stopped")
			return
		}
		j.logger.Info("wbstream-joiner: tunnel lost")
		if !j.waitBeforeRetry(int(attempt.Load())) {
			return
		}
		attempt.Add(1)
		if j.isClosed() {
			return
		}
		j.logger.Info(fmt.Sprintf("wbstream-joiner: reconnect attempt #%d", attempt.Load()))
		if err := j.runOnce(httpClient, params.RoomID, params.DisplayName, params.TunnelMode, obf, settingEngine, params.VP8FPS, params.VP8Batch, params.DualTrack, reliable, &attempt); err != nil {
			j.logger.Warn(fmt.Sprintf("wbstream-joiner: %v, will retry", err))
		}
	}
}

func (j *WBStreamJoiner) MarkConfigAcked() {
	j.mu.Lock()
	sess := j.session
	j.mu.Unlock()
	if sess != nil {
		sess.MarkConfigAcked()
	}
}

func (j *WBStreamJoiner) Close() {
	j.stopOnce.Do(func() { close(j.stopCh) })
	j.mu.Lock()
	j.closed = true
	sess := j.session
	j.session = nil
	j.mu.Unlock()
	if sess != nil {
		sess.Close()
	}
}

func (j *WBStreamJoiner) runOnce(httpClient *http.Client, roomID, displayName, tunnelMode string, obf *tunnel.TunnelObfuscator, settingEngine *webrtc.SettingEngine, vp8FPS, vp8Batch int, dualTrack, reliable bool, attempt *atomic.Int32) error {
	_, roomToken, _, serverURL, authErr := AuthAndGetToken(httpClient, roomID, displayName)
	if authErr != nil {
		return fmt.Errorf("auth: %w", authErr)
	}
	j.logger.Debug(fmt.Sprintf("wbstream-joiner: server=%s", serverURL))
	sess := NewSession(SessionConfig{
		RoomToken:     roomToken,
		ServerURL:     serverURL,
		DisplayName:   displayName,
		TunnelMode:    tunnelMode,
		Obfuscator:    obf,
		Logger:        j.logger,
		SettingEngine: settingEngine,
		Dialer:        j.dialer,
		DNSRouter:     j.dnsRouter,
		VP8FPS:        vp8FPS,
		VP8Batch:      vp8Batch,
		ScreenShare:   dualTrack,
		IsJoiner:      true,
		Reliable:      reliable,
	})
	sess.OnConnected = func(tun tunnel.DataTunnel) {
		attempt.Store(0)
		j.logger.Info("wbstream-joiner: === TUNNEL CONNECTED ===")
		if j.OnConnected != nil {
			j.OnConnected(tun)
		}
	}
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		sess.Close()
		return nil
	}
	j.session = sess
	j.mu.Unlock()
	if err := sess.Start(); err != nil {
		j.clearSession(sess)
		return fmt.Errorf("session: %w", err)
	}
	<-sess.Done()
	sess.Close()
	j.clearSession(sess)
	return nil
}

func (j *WBStreamJoiner) waitBeforeRetry(attempt int) bool {
	delay := common.BackoffWithJitter(attempt, reconnectInitialDelay, reconnectMaxDelay)
	j.logger.Debug(fmt.Sprintf("wbstream-joiner: waiting %s before reconnect", delay))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return !j.isClosed()
	case <-j.stopCh:
		return false
	}
}

func (j *WBStreamJoiner) clearSession(sess *Session) {
	j.mu.Lock()
	if j.session == sess {
		j.session = nil
	}
	j.mu.Unlock()
}

func (j *WBStreamJoiner) isClosed() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.closed
}

func (j *WBStreamJoiner) makeDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return j.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
	}
}

func (j *WBStreamJoiner) makeHTTPClient() *http.Client {
	transport := &http.Transport{DialContext: j.makeDialContext()}
	return &http.Client{Timeout: 60 * time.Second, Transport: transport}
}
