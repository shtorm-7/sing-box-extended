package dion

import (
	"context"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func ConnectCreator(ctx context.Context, cookieStr, roomID, email, password string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) (*tunnel.RelayBridge, string, error) {
	auth, err := NewSession(dialer)
	if err != nil {
		return nil, "", fmt.Errorf("dion: new session: %w", err)
	}
	if err := auth.LoadCookieString(cookieStr); err != nil {
		return nil, "", fmt.Errorf("dion: load cookies: %w", err)
	}
	auth.SetCredentials(email, password)
	if err := auth.EnsureValidToken(); err != nil {
		return nil, "", fmt.Errorf("dion: ensure valid token: %w", err)
	}
	requestedRoom := ParseRoom(roomID)
	var event *EventInfo
	if requestedRoom != "" {
		event, err = auth.GetEventBySlug(requestedRoom)
		if err != nil {
			return nil, "", fmt.Errorf("dion: get event by slug: %w", err)
		}
	} else {
		event, err = auth.CreateRoom()
		if err != nil {
			return nil, "", fmt.Errorf("dion: create room: %w", err)
		}
	}
	joinLink := WebBase + "/event/" + event.Slug
	if readBuf <= 0 {
		readBuf = 32768
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(event.Slug))
	if err != nil {
		return nil, "", fmt.Errorf("dion: obfuscator init: %w", err)
	}
	relayCh := make(chan *tunnel.RelayBridge, 1)
	var activeRelay *tunnel.RelayBridge
	call := NewCall(CallConfig{
		Auth:        auth,
		Event:       event,
		Obfuscator:  obf,
		DisplayName: "Creator",
		Logger:      logger,
		Dialer:      dialer,
		Role:        RoleCreator,
	})
	call.OnConnected = func(tun tunnel.DataTunnel) {
		if activeRelay != nil {
			activeRelay.Reset()
		}
		bridgeReadBuf := common.VP8BufSize
		if _, ok := tun.(*tunnel.DCTunnel); ok {
			bridgeReadBuf = readBuf
		}
		activeRelay = tunnel.NewRelayBridge(tun, "creator", bridgeReadBuf, dialer, logger)
		activeRelay.MarkReady()
		select {
		case relayCh <- activeRelay:
		default:
		}
	}
	call.OnPeerRestart = func() {
		if activeRelay != nil {
			activeRelay.Reset()
		}
	}
	go func() {
		if err := call.Start(); err != nil {
			logger.Error(fmt.Sprintf("dion: call start failed: %v", err))
		}
	}()
	select {
	case relay := <-relayCh:
		return relay, joinLink, nil
	case <-ctx.Done():
		call.Close()
		return nil, "", ctx.Err()
	case <-time.After(60 * time.Second):
		call.Close()
		return nil, "", fmt.Errorf("dion: creator tunnel timed out")
	}
}

func ConnectJoiner(ctx context.Context, roomID, displayName string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) (tunnel.DataTunnel, error) {
	if displayName == "" {
		displayName = "Joiner"
	}
	slug := ParseRoom(roomID)
	if slug == "" {
		return nil, fmt.Errorf("dion: missing room")
	}
	auth, event, err := JoinAsGuest(dialer, slug, displayName)
	if err != nil {
		return nil, fmt.Errorf("dion: join as guest: %w", err)
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(event.Slug))
	if err != nil {
		return nil, fmt.Errorf("dion: obfuscator init: %w", err)
	}
	call := NewCall(CallConfig{
		Auth:        auth,
		Event:       event,
		Obfuscator:  obf,
		DisplayName: displayName,
		Logger:      logger,
		Dialer:      dialer,
		Role:        RoleJoiner,
	})
	tunCh := make(chan tunnel.DataTunnel, 1)
	call.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	go func() {
		if err := call.Start(); err != nil {
			logger.Error(fmt.Sprintf("dion: call start failed: %v", err))
		}
	}()
	select {
	case tun := <-tunCh:
		return tun, nil
	case <-ctx.Done():
		call.Close()
		return nil, ctx.Err()
	}
}
