package vk

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const topologyDirect = "DIRECT"
const maxServerBounces = 5

type Bridge struct {
	mu            sync.Mutex
	vkWs          *websocket.Conn
	vkSeq         int
	iceServers    []webrtc.ICEServer
	topology      string
	peers         map[int64]struct{}
	relay         Relay
	newRelay      func() Relay
	p2p           *P2PHandler
	screenSharing bool

	serverBounces       int
	suppressScreenshare bool
	bouncing            bool

	dialer       N.Dialer
	activeBridge *tunnel.RelayBridge
	readBuf      int
	logger       logger.ContextLogger
}

func (b *Bridge) setScreenSharing(enabled bool) {
	b.mu.Lock()
	if b.vkWs == nil || b.screenSharing == enabled {
		b.mu.Unlock()
		return
	}
	if enabled && b.suppressScreenshare {
		b.mu.Unlock()
		b.logger.Debug("[vk-ws] screenshare suppressed after SERVER flap, staying single-track DIRECT")
		return
	}
	b.screenSharing = enabled
	b.mu.Unlock()
	b.logger.Debug(fmt.Sprintf("[vk-ws] peer track count change, screenshare=%v", enabled))
	b.sendMediaSettings(enabled)
}

func (b *Bridge) vkSend(command string, extra map[string]interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.vkWs == nil {
		return
	}
	b.vkSeq++
	seq := b.vkSeq
	var out []byte
	if pid, ok := extra["participantId"]; ok {
		dataJSON, _ := json.Marshal(extra["data"])
		out = []byte(fmt.Sprintf(`{"command":%q,"sequence":%d,"participantId":%v,"data":%s}`,
			command, seq, pid, dataJSON))
	} else {
		extra["command"] = command
		extra["sequence"] = seq
		out, _ = json.Marshal(extra)
	}
	b.vkWs.WriteMessage(websocket.TextMessage, out)
	b.logger.Debug(fmt.Sprintf("[vk-ws] -> %s", command))
}

func (b *Bridge) sendMediaSettings(screenSharing bool) {
	b.vkSend("change-media-settings", map[string]interface{}{
		"mediaSettings": map[string]interface{}{
			"isAudioEnabled": false, "isVideoEnabled": true,
			"isScreenSharingEnabled": screenSharing, "isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled": false, "isAnimojiEnabled": false,
		},
	})
}

func (b *Bridge) handleVKMessage(raw []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	msgType, _ := msg["type"].(string)
	switch msgType {
	case "notification":
		notif, _ := msg["notification"].(string)
		b.logger.Debug(fmt.Sprintf("[vk-ws] <- notification: %s", notif))
		switch notif {
		case "connection":
			b.logger.Debug("[vk-ws]    TURN creds received")
		case "transmitted-data":
			data, _ := msg["data"].(map[string]interface{})
			if data != nil && b.topology == topologyDirect && b.p2p != nil {
				b.p2p.OnTransmittedData(data)
			}
		case "registered-peer":
			pid, _ := msg["participantId"].(float64)
			if b.topology == topologyDirect && b.p2p != nil {
				b.p2p.OnRegisteredPeer(int64(pid))
			}
		case "topology-changed":
			topo, _ := msg["topology"].(string)
			b.logger.Debug(fmt.Sprintf("[vk-ws]    Topology changed to %s", topo))
			b.topology = topo
			if topo != topologyDirect {
				b.bounceForServerTopology("SERVER topology")
				return
			}
		case "participant-joined", "participant-added":
			if pid, ok := msg["participantId"].(float64); ok {
				b.peers[int64(pid)] = struct{}{}
				b.logger.Debug(fmt.Sprintf("[vk-ws]    Participant %d joined (total: %d)", int64(pid), len(b.peers)))
				if b.topology != topologyDirect {
					b.bounceForServerTopology("participant joined under SERVER")
					return
				}
			}
		case "participant-left":
			if pid, ok := msg["participantId"].(float64); ok {
				delete(b.peers, int64(pid))
				b.logger.Debug(fmt.Sprintf("[vk-ws]    Participant %d left (total: %d)", int64(pid), len(b.peers)))
			}
		case "hungup":
			if pid, ok := msg["participantId"].(float64); ok {
				delete(b.peers, int64(pid))
				b.logger.Debug(fmt.Sprintf("[vk-ws]    Participant %d hung up (total: %d)", int64(pid), len(b.peers)))
			} else {
				b.logger.Debug("[vk-ws]    Participant hung up")
			}
		case "closed-conversation":
			reason, _ := msg["reason"].(string)
			b.logger.Debug(fmt.Sprintf("[vk-ws]    Conversation closed: %s", reason))
			b.mu.Lock()
			if b.vkWs != nil {
				b.vkWs.Close()
			}
			b.mu.Unlock()
		default:
			snippet, _ := json.Marshal(msg)
			if len(snippet) > 1000 {
				snippet = append(snippet[:1000], '.', '.', '.')
			}
			b.logger.Debug(fmt.Sprintf("[vk-ws]    unhandled: %s", string(snippet)))
		}
	case "response":
		seq, _ := msg["sequence"].(float64)
		snippet, _ := json.Marshal(msg)
		if len(snippet) > 1000 {
			snippet = append(snippet[:1000], '.', '.', '.')
		}
		b.logger.Debug(fmt.Sprintf("[vk-ws] <- response seq=%d: %s", int(seq), string(snippet)))
	case "error":
		errMsg, _ := msg["message"].(string)
		errCode, _ := msg["error"].(string)
		b.logger.Warn(fmt.Sprintf("[vk-ws] <- error: %s %s", errCode, errMsg))
	}
}

func (b *Bridge) connectVKWs(wsURL string) error {
	vkHeader := http.Header{}
	vkHeader.Set("User-Agent", common.UserAgent)
	vkHeader.Set("Origin", "https://vk.com")
	vkDialer := websocket.Dialer{
		WriteBufferSize: common.RTPBufSize,
		NetDialContext:  b.dialContext,
	}
	vkWs, _, err := vkDialer.Dial(wsURL, vkHeader)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.vkWs = vkWs
	b.vkSeq = 0
	b.mu.Unlock()
	return nil
}

func (b *Bridge) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return b.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
}

func (b *Bridge) initRelay() {
	if b.relay != nil {
		b.relay.Close()
	}
	b.topology = topologyDirect
	b.peers = make(map[int64]struct{})
	b.relay = b.newRelay()
	b.p2p = NewP2PHandler(b)
	b.p2p.Init()
}

func (b *Bridge) bounceForServerTopology(reason string) {
	b.mu.Lock()
	if b.bouncing {
		b.mu.Unlock()
		return
	}
	b.bouncing = true
	b.serverBounces++
	count := b.serverBounces
	if count > maxServerBounces {
		b.suppressScreenshare = true
	}
	suppress := b.suppressScreenshare
	ws := b.vkWs
	b.mu.Unlock()
	if suppress {
		b.logger.Debug(fmt.Sprintf("[vk-ws]    %s -> reconnect #%d, suppressing screenshare to settle single-track DIRECT", reason, count))
	} else {
		b.logger.Debug(fmt.Sprintf("[vk-ws]    %s -> manual reconnect #%d to recover DIRECT", reason, count))
	}
	if ws != nil {
		ws.Close()
	}
}

func (b *Bridge) readLoop() error {
	for {
		_, msg, err := b.vkWs.ReadMessage()
		if err != nil {
			return err
		}
		if string(msg) == "ping" {
			b.mu.Lock()
			b.vkWs.WriteMessage(websocket.TextMessage, []byte("pong"))
			b.mu.Unlock()
			continue
		}
		b.handleVKMessage(msg)
	}
}

func (b *Bridge) Run(callInfo *CallInfo, cookieStr string, cfg VKConfig) {
	b.logger.Info(fmt.Sprintf("CALL CREATED join_link=%s turn=%s protocol=v%s sdk=%s",
		callInfo.JoinLink, strings.Join(callInfo.TurnServer.URLs, ", "), cfg.ProtocolVersion, cfg.SDKVersion))
	b.iceServers = buildWebRTCICEServers(BuildICEServers(callInfo))
	wsEndpoint := callInfo.WSEndpoint
	capabilities := "2F7F"
	makeWSURL := func(ep string) string {
		return ep +
			"&platform=WEB" +
			"&appVersion=" + cfg.AppVersion +
			"&version=" + cfg.ProtocolVersion +
			"&device=browser&capabilities=" + capabilities + "&clientType=VK&tgt=join"
	}
	go func() {
		for {
			time.Sleep(15 * time.Second)
			b.mu.Lock()
			ws := b.vkWs
			b.mu.Unlock()
			if ws != nil {
				b.mu.Lock()
				ws.WriteMessage(websocket.PingMessage, nil)
				b.mu.Unlock()
			}
		}
	}()
	for {
		b.initRelay()
		b.logger.Debug("[vk-ws] Connecting...")
		if err := b.connectVKWs(makeWSURL(wsEndpoint)); err != nil {
			b.logger.Warn(fmt.Sprintf("[vk-ws] Connect failed: %s, retrying in 5s...", common.MaskError(err)))
			time.Sleep(5 * time.Second)
			continue
		}
		b.logger.Debug("[vk-ws] Connected")
		b.mu.Lock()
		b.screenSharing = false
		b.bouncing = false
		b.mu.Unlock()
		b.sendMediaSettings(false)
		err := b.readLoop()
		b.logger.Debug(fmt.Sprintf("[vk-ws] Closed: %s", common.MaskError(err)))
		b.mu.Lock()
		b.vkWs = nil
		b.mu.Unlock()
		b.logger.Debug("[vk-ws] Rejoining in 3s...")
		time.Sleep(3 * time.Second)
		joinResp, rerr := authAndJoin(b.dialer, cookieStr, callInfo.OKJoinLink, cfg)
		if rerr != nil {
			b.logger.Warn(fmt.Sprintf("[rejoin] Failed: %v, retrying in 5s...", rerr))
			time.Sleep(5 * time.Second)
			continue
		}
		wsEndpoint = joinResp.Endpoint
		callInfo.TurnServer = joinResp.TurnServer
		callInfo.StunServer = joinResp.StunServer
		b.iceServers = buildWebRTCICEServers(BuildICEServers(callInfo))
	}
}

func buildWebRTCICEServers(specs []ICEServerSpec) []webrtc.ICEServer {
	out := make([]webrtc.ICEServer, len(specs))
	for i, s := range specs {
		out[i] = webrtc.ICEServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential}
	}
	return out
}
