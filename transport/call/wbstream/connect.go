package wbstream

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func ConnectCreator(ctx context.Context, cookieStr, roomID, mode string, readBuf int, dialer N.Dialer, logger logger.ContextLogger) (*tunnel.RelayBridge, string, error) {
	deviceID := common.CookieValue(cookieStr, "__wb_device_id")
	if deviceID == "" {
		return nil, "", fmt.Errorf("wbstream: cookies missing __wb_device_id")
	}
	cookieHeader := common.FilterCookies(cookieStr, WBStreamCookieAllowlist)
	httpClient := common.HttpClient(dialer)
	bearer, err := RefreshAccessToken(httpClient, cookieHeader, deviceID)
	if err != nil {
		return nil, "", fmt.Errorf("wbstream: slide-v3 refresh: %w", err)
	}
	requestedRoom := ParseRoomID(roomID)
	resolvedRoomID, roomToken, accessToken, serverURL, err := AuthAsLoggedIn(httpClient, cookieHeader, bearer, requestedRoom, "Creator")
	if err != nil {
		return nil, "", fmt.Errorf("wbstream: auth: %w", err)
	}
	if readBuf <= 0 {
		readBuf = 32768
	}
	if mode == "" {
		mode = TunnelModeDC
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(resolvedRoomID))
	if err != nil {
		return nil, "", fmt.Errorf("wbstream: obfuscator init: %w", err)
	}

	joinSession := func(token, access, server string) (*Session, <-chan tunnel.DataTunnel) {
		tunCh := make(chan tunnel.DataTunnel, 1)
		sess := NewSession(SessionConfig{
			RoomToken:   token,
			ServerURL:   server,
			DisplayName: "Creator",
			TunnelMode:  mode,
			Obfuscator:  obf,
			Logger:      logger,
			Dialer:      dialer,
			RoomID:      resolvedRoomID,
			AccessToken: access,
			ReadBuf:     readBuf,
		})
		sess.OnConnected = func(tun tunnel.DataTunnel) {
			select {
			case tunCh <- tun:
			default:
			}
		}
		return sess, tunCh
	}

	sess, tunCh := joinSession(roomToken, accessToken, serverURL)
	if err := sess.Start(); err != nil {
		return nil, "", fmt.Errorf("wbstream: session start: %w", err)
	}
	var firstTun tunnel.DataTunnel
	select {
	case firstTun = <-tunCh:
	case <-ctx.Done():
		sess.Close()
		return nil, "", ctx.Err()
	case <-time.After(60 * time.Second):
		sess.Close()
		return nil, "", fmt.Errorf("wbstream: creator tunnel timed out")
	}

	relay := tunnel.NewRelayBridge(firstTun, "creator", bridgeReadBufFor(firstTun, readBuf), dialer, logger)
	go creatorReconnectLoop(ctx, relay, sess, joinSession, httpClient, cookieHeader, deviceID, resolvedRoomID, readBuf, logger)
	return relay, APIBase + "/room/" + resolvedRoomID, nil
}

func ConnectJoiner(ctx context.Context, roomID, displayName, mode string, readBuf int, dialer N.Dialer, dnsRouter adapter.DNSRouter, logger logger.ContextLogger) (tunnel.DataTunnel, error) {
	roomID = ParseRoomID(roomID)
	if displayName == "" {
		displayName = "Joiner"
	}
	if mode == "" {
		mode = TunnelModeDC
	}
	joiner := NewWBStreamJoiner(logger, dialer, dnsRouter, nil)
	tunCh := make(chan tunnel.DataTunnel, 1)
	joiner.OnConnected = func(tun tunnel.DataTunnel) {
		select {
		case tunCh <- tun:
		default:
		}
	}
	params := fmt.Sprintf(`{"roomId":%q,"displayName":%q,"tunnelMode":%q}`, roomID, displayName, mode)
	go joiner.RunWithParams(params)
	select {
	case tun := <-tunCh:
		return tun, nil
	case <-ctx.Done():
		joiner.Close()
		return nil, ctx.Err()
	}
}

func creatorReconnectLoop(
	ctx context.Context,
	relay *tunnel.RelayBridge,
	sess *Session,
	joinSession func(token, access, server string) (*Session, <-chan tunnel.DataTunnel),
	httpClient *http.Client,
	cookieHeader, deviceID, roomID string,
	readBuf int,
	logger logger.ContextLogger,
) {
	current := sess
	for {
		select {
		case <-current.Done():
		case <-ctx.Done():
			return
		}
		current.Close()
		if relay.IsClosed() {
			return
		}
		logger.Debug("wbstream: creator session ended, rejoining")

		var newTun tunnel.DataTunnel
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			if relay.IsClosed() {
				return
			}
			bearer, err := RefreshAccessToken(httpClient, cookieHeader, deviceID)
			if err != nil {
				logger.Warn(fmt.Sprintf("wbstream: rejoin token refresh failed: %v, retrying", err))
				continue
			}
			_, roomToken, accessToken, serverURL, err := AuthAsLoggedIn(httpClient, cookieHeader, bearer, roomID, "Creator")
			if err != nil {
				logger.Warn(fmt.Sprintf("wbstream: rejoin auth failed: %v, retrying", err))
				continue
			}
			newSess, tunCh := joinSession(roomToken, accessToken, serverURL)
			if err := newSess.Start(); err != nil {
				logger.Warn(fmt.Sprintf("wbstream: rejoin session start failed: %v, retrying", err))
				continue
			}
			select {
			case newTun = <-tunCh:
			case <-ctx.Done():
				newSess.Close()
				return
			case <-time.After(60 * time.Second):
				logger.Warn("wbstream: rejoin tunnel timed out, retrying")
				newSess.Close()
				continue
			}
			current = newSess
			break
		}
		relay.SwapTunnel(newTun)
		logger.Info(fmt.Sprintf("wbstream: creator tunnel reconnected, buf=%d", bridgeReadBufFor(newTun, readBuf)))
	}
}

func bridgeReadBufFor(tun tunnel.DataTunnel, readBuf int) int {
	switch tun.(type) {
	case *tunnel.DCTunnel, *tunnel.MultiTrackKCPTunnel:
		return readBuf
	}
	return common.VP8BufSize
}
