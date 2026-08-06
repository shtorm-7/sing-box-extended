package vk

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func ConnectCreator(ctx context.Context, cookieStr, joinLink string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) (*tunnel.RelayBridge, string, error) {
	cfg, err := FetchConfig(logger)
	if err != nil {
		return nil, "", err
	}
	var callInfo *CallInfo
	if joinLink != "" {
		callInfo, err = JoinExistingCall(dialer, cookieStr, joinLink, cfg, logger)
	} else {
		callInfo, err = CreateAndJoinCall(dialer, cookieStr, "", cfg, logger)
	}
	if err != nil {
		return nil, "", err
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(callInfo.JoinLink))
	if err != nil {
		return nil, "", fmt.Errorf("vk: obfuscator init: %w", err)
	}
	bridge := &Bridge{
		dialer:  dialer,
		readBuf: readBuf,
		logger:  logger,
	}
	bridge.newRelay = func() Relay {
		ur := NewTunnelRelay(dialer, logger)
		ur.readBufSize = readBuf
		ur.SetObfuscator(obf)
		ur.OnConnected = func(tun tunnel.DataTunnel) {
			bridgeReadBuf := common.VP8BufSize
			if _, ok := tun.(*tunnel.DCTunnel); ok {
				bridgeReadBuf = readBuf
			}
			rb := tunnel.NewRelayBridge(tun, "creator", bridgeReadBuf, dialer, logger)
			rb.MarkReady()
			if st, ok := tun.(*tunnel.SymmetricScreenTunnel); ok {
				rb.SetOnPeerConfig(func(fps, batch, trackCount int) {
					st.SetTrackCount(trackCount)
					bridge.setScreenSharing(trackCount > 1)
				})
			}
			bridge.mu.Lock()
			bridge.activeBridge = rb
			bridge.mu.Unlock()
		}
		return ur
	}
	go bridge.Run(callInfo, cookieStr, cfg)
	deadline := time.Now().Add(60 * time.Second)
	for {
		bridge.mu.Lock()
		rb := bridge.activeBridge
		bridge.mu.Unlock()
		if rb != nil {
			return rb, callInfo.JoinLink, nil
		}
		if time.Now().After(deadline) {
			return nil, "", fmt.Errorf("vk: creator tunnel timed out")
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func ConnectJoiner(ctx context.Context, joinLink, displayName string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, logger logger.ContextLogger) (tunnel.DataTunnel, error) {
	if displayName == "" {
		displayName = "Joiner"
	}
	authJSON, err := RunVKAuth(dialer, joinLink, displayName, logger)
	if err != nil {
		return nil, fmt.Errorf("vk: auth: %w", err)
	}
	var params VKAuthParams
	if err := json.Unmarshal([]byte(authJSON), &params); err != nil {
		return nil, fmt.Errorf("vk: decode auth params: %w", err)
	}
	params.TunnelMode = "video"
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("vk: encode auth params: %w", err)
	}
	joiner := NewVKJoiner(
		logger,
		nil,
		common.AddTunnelTracks,
		common.ReadTrack,
		dialer,
		dnsRouter,
	)
	tunCh := make(chan tunnel.DataTunnel, 1)
	joiner.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	go joiner.RunWithParams(string(paramsJSON))
	select {
	case tun := <-tunCh:
		return tun, nil
	case <-ctx.Done():
		joiner.Close()
		return nil, ctx.Err()
	}
}
