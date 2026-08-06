package telemost

import (
	"context"
	"fmt"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func ConnectCreator(ctx context.Context, cookieStr, joinLink string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) (*tunnel.RelayBridge, string, error) {
	cfg, err := FetchConfig(dialer, logger)
	if err != nil {
		return nil, "", err
	}
	var connInfo *ConnInfo
	if joinLink != "" {
		connInfo, err = joinExistingConference(dialer, cookieStr, joinLink, cfg, logger)
	} else {
		connInfo, err = CreateAndJoinCall(dialer, cookieStr, cfg, logger)
	}
	if err != nil {
		return nil, "", err
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	bridge := &Bridge{
		connInfo:  connInfo,
		config:    cfg,
		cookieStr: cookieStr,
		peers:     make(map[string]string),
		readBuf:   readBuf,
		dialer:    dialer,
		logger:    logger,
	}
	go bridge.Run()
	deadline := time.Now().Add(60 * time.Second)
	for bridge.activeBridge == nil {
		if time.Now().After(deadline) {
			return nil, "", fmt.Errorf("telemost: creator tunnel timed out")
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return bridge.activeBridge, connInfo.ConferenceURI, nil
}

func ConnectJoiner(ctx context.Context, joinLink, displayName string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, logger logger.ContextLogger) (tunnel.DataTunnel, error) {
	if displayName == "" {
		displayName = "Joiner"
	}
	joiner := NewTelemostJoiner(
		logger,
		dialer,
		dnsRouter,
		nil,
		common.AddTunnelTracks,
		common.ReadTrack,
	)
	tunCh := make(chan tunnel.DataTunnel, 1)
	joiner.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	params := fmt.Sprintf(`{"joinLink":%q,"displayName":%q}`, joinLink, displayName)
	go joiner.RunWithParams(params)
	select {
	case tun := <-tunCh:
		return tun, nil
	case <-ctx.Done():
		joiner.Close()
		return nil, ctx.Err()
	}
}

func CreateConferenceForTest(dialer N.Dialer, cookieStr string) (string, error) {
	nop := logger.NOP()
	cfg, err := FetchConfig(dialer, nop)
	if err != nil {
		return "", err
	}
	connInfo, err := CreateAndJoinCall(dialer, cookieStr, cfg, nop)
	if err != nil {
		return "", err
	}
	return connInfo.ConferenceURI, nil
}
