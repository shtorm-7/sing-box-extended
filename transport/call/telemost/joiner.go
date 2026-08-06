package telemost

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/transport/call/common"
	"github.com/sagernet/sing-box/transport/call/tunnel"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	TmAPIBase                     = APIBase
	TmOrigin                      = Origin
	TmPingPeriod                  = 5 * time.Second
	telemostReconnectInitialDelay = time.Second
	telemostReconnectMaxDelay     = 16 * time.Second
)

type TelemostJoiner struct {
	logger      logger.ContextLogger
	OnConnected func(tunnel.DataTunnel)

	OnRemoteCandidate func(target int, candidateOrSDP string)
	dialer            N.Dialer
	dnsRouter         adapter.DNSRouter
	PCConfig          common.PeerConnectionConfigurer
	AddTracks         common.AddTunnelTracksFunc
	ReadTrackFn       common.ReadTrackFunc

	joinLink    string
	displayName string

	ws   *websocket.Conn
	wsMu sync.Mutex

	subPC        *webrtc.PeerConnection
	subSeq       int
	subRemoteSet bool
	subPending   []webrtc.ICECandidateInit

	pubPC        *webrtc.PeerConnection
	pubSeq       int
	pubRemoteSet bool
	pubPending   []webrtc.ICECandidateInit

	sampleTrack *webrtc.TrackLocalStaticSample
	vp8tunnel   *tunnel.VP8DataTunnel
	obf         *tunnel.TunnelObfuscator
	vp8FPS      int
	vp8Batch    int

	httpClient *http.Client
	instanceID string

	peerID              string
	roomID              string
	credentials         string
	serviceName         string
	mediaURL            string
	iceServers          []webrtc.ICEServer
	stateCheckIntervalS int

	closeMu sync.Mutex
	closed  bool

	stopCh           chan struct{}
	stopOnce         sync.Once
	configAck        tunnel.ConfigAckTracker
	reconnectAttempt atomic.Int32

	setSlotsKey    int
	initBundleSent bool
	boundPeers     map[string]bool
	unboundPeers   map[string]bool
	boundMu        sync.Mutex
}

func NewTelemostJoiner(logger logger.ContextLogger, dialer N.Dialer, dnsRouter adapter.DNSRouter, pcConfig common.PeerConnectionConfigurer, addTracks common.AddTunnelTracksFunc, readTrackFn common.ReadTrackFunc) *TelemostJoiner {
	return &TelemostJoiner{
		logger:      logger,
		dialer:      dialer,
		dnsRouter:   dnsRouter,
		PCConfig:    pcConfig,
		AddTracks:   addTracks,
		ReadTrackFn: readTrackFn,
		instanceID:  uuid.New().String(),
		stopCh:      make(chan struct{}),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
				},
			},
		},
	}
}

func (j *TelemostJoiner) RunWithParams(jsonParams string) {
	var params struct {
		JoinLink    string `json:"joinLink"`
		DisplayName string `json:"displayName"`
		VP8FPS      int    `json:"vp8Fps"`
		VP8Batch    int    `json:"vp8Batch"`
	}
	if err := json.Unmarshal([]byte(jsonParams), &params); err != nil {
		j.logger.Error(fmt.Sprintf("telemost-joiner: failed to parse params: %v", err))
		return
	}
	j.joinLink = params.JoinLink
	j.displayName = params.DisplayName
	if j.displayName == "" {
		j.displayName = "Joiner"
	}
	obf, err := tunnel.NewTunnelObfuscator(tunnel.DeriveSecretFromJoinLink(params.JoinLink))
	if err != nil {
		j.logger.Error(fmt.Sprintf("telemost-joiner: obfuscator init failed: %v", err))
		return
	}
	j.obf = obf
	j.vp8FPS = params.VP8FPS
	j.vp8Batch = params.VP8Batch
	j.logger.Info(fmt.Sprintf("telemost-joiner: link=%s name=%s vp8Fps=%d vp8Batch=%d localEpoch=0x%08x",
		j.joinLink, j.displayName, params.VP8FPS, params.VP8Batch, obf.LocalEpoch()))
	j.logger.Info("telemost-joiner: connecting")
	if err := j.runOnce(); err != nil {
		j.logger.Error(fmt.Sprintf("telemost-joiner: %v", err))
		return
	}
	for {
		if j.isClosed() {
			return
		}
		j.logger.Info("telemost-joiner: tunnel lost")
		j.resetSessionState()
		if !j.waitBeforeRetry(int(j.reconnectAttempt.Load())) {
			return
		}
		j.reconnectAttempt.Add(1)
		if j.isClosed() {
			return
		}
		j.logger.Info(fmt.Sprintf("telemost-joiner: reconnect attempt #%d", j.reconnectAttempt.Load()))
		if err := j.runOnce(); err != nil {
			j.logger.Warn(fmt.Sprintf("telemost-joiner: %v, will retry", err))
		}
	}
}

func (j *TelemostJoiner) Close() {
	j.closeMu.Lock()
	j.closed = true
	j.closeMu.Unlock()
	j.stopOnce.Do(func() { close(j.stopCh) })
	j.wsMu.Lock()
	ws := j.ws
	j.ws = nil
	j.wsMu.Unlock()
	common.CloseWS(ws)
	if j.vp8tunnel != nil {
		j.vp8tunnel.Stop()
	}
	if j.subPC != nil {
		j.subPC.Close()
	}
	if j.pubPC != nil {
		j.pubPC.Close()
	}
}

func TmParseMids(sdp string) (audioMid, videoMid string) {
	var media string
	for _, line := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(line, "m=audio") {
			media = "audio"
		} else if strings.HasPrefix(line, "m=video") {
			media = "video"
		}
		if strings.HasPrefix(line, "a=mid:") {
			mid := strings.TrimPrefix(line, "a=mid:")
			if media == "audio" && audioMid == "" {
				audioMid = mid
			} else if media == "video" && videoMid == "" {
				videoMid = mid
			}
		}
	}
	return
}

func (j *TelemostJoiner) runOnce() error {
	if err := j.getConnection(); err != nil {
		return err
	}
	j.connectAndRun()
	return nil
}

func (j *TelemostJoiner) MarkConfigAcked() { j.configAck.Mark() }

func (j *TelemostJoiner) waitBeforeRetry(attempt int) bool {
	delay := common.BackoffWithJitter(attempt, telemostReconnectInitialDelay, telemostReconnectMaxDelay)
	j.logger.Debug(fmt.Sprintf("telemost-joiner: waiting %s before reconnect", delay))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return !j.isClosed()
	case <-j.stopCh:
		return false
	}
}

func (j *TelemostJoiner) resetSessionState() {
	j.wsMu.Lock()
	j.ws = nil
	j.wsMu.Unlock()
	j.subPC = nil
	j.subSeq = 0
	j.subRemoteSet = false
	j.subPending = nil
	j.pubPC = nil
	j.pubSeq = 0
	j.pubRemoteSet = false
	j.pubPending = nil
	j.sampleTrack = nil
	j.vp8tunnel = nil
	j.initBundleSent = false
	j.boundMu.Lock()
	j.boundPeers = nil
	j.unboundPeers = nil
	j.boundMu.Unlock()
}

func (j *TelemostJoiner) isClosed() bool {
	j.closeMu.Lock()
	defer j.closeMu.Unlock()
	return j.closed
}

func (j *TelemostJoiner) apiClient() *Client {
	return &Client{HTTP: j.httpClient, InstanceID: j.instanceID}
}

func (j *TelemostJoiner) getConnection() error {
	confURL := url.QueryEscape(j.joinLink)
	name := url.QueryEscape(j.displayName)
	if name == "" {
		name = "Joiner"
	}
	connPath := "/conferences/" + confURL + "/connection?next_gen_media_platform_allowed=true&display_name=" + name + "&waiting_room_supported=true"
	j.logger.Debug(fmt.Sprintf("telemost-joiner: getting connection for %s", j.joinLink))
	responseBody, status, err := j.apiClient().TMRequest("GET", connPath)
	if err != nil {
		return fmt.Errorf("get connection: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("get connection: status %d: %s", status, string(responseBody))
	}
	var initial struct {
		ConnectionType string `json:"connection_type"`
		ClientConfig   struct {
			CheckInterval int `json:"conference_check_access_interval_ms"`
		} `json:"client_configuration"`
	}
	json.Unmarshal(responseBody, &initial)
	if initial.ConnectionType == "WAITING_ROOM" {
		interval := initial.ClientConfig.CheckInterval
		if interval <= 0 {
			interval = 3000
		}
		checkPath := "/conferences/" + confURL + "/waiting-rooms/check-access"
		j.logger.Info(fmt.Sprintf("telemost-joiner: in waiting room, polling check-access every %dms...", interval))
		for {
			time.Sleep(time.Duration(interval) * time.Millisecond)
			checkBody, checkStatus, checkErr := j.apiClient().TMRequest("GET", checkPath)
			if checkErr != nil {
				return fmt.Errorf("waiting room check-access: %w", checkErr)
			}
			if checkStatus != 200 {
				return fmt.Errorf("waiting room check-access: status %d", checkStatus)
			}
			var check struct {
				Admitted bool `json:"admitted"`
			}
			json.Unmarshal(checkBody, &check)
			if check.Admitted {
				j.logger.Info("telemost-joiner: admitted!")
				break
			}
		}
		responseBody, status, err = j.apiClient().TMRequest("GET", connPath)
		if err != nil {
			return fmt.Errorf("post-admit connection: %w", err)
		}
		if status != 200 {
			return fmt.Errorf("post-admit connection: status %d: %s", status, string(responseBody))
		}
	}
	var conn struct {
		PeerID       string `json:"peer_id"`
		RoomID       string `json:"room_id"`
		Credentials  string `json:"credentials"`
		ClientConfig struct {
			MediaServerURL         string          `json:"media_server_url"`
			ServiceName            string          `json:"service_name"`
			ICEServers             json.RawMessage `json:"ice_servers"`
			StateCheckIntervalSecs int             `json:"state_check_interval_seconds"`
		} `json:"client_configuration"`
	}
	json.Unmarshal(responseBody, &conn)
	if conn.ClientConfig.MediaServerURL == "" {
		return fmt.Errorf("empty media_server_url: %s", string(responseBody))
	}
	j.peerID = conn.PeerID
	j.roomID = conn.RoomID
	j.credentials = conn.Credentials
	j.mediaURL = conn.ClientConfig.MediaServerURL
	j.serviceName = conn.ClientConfig.ServiceName
	j.stateCheckIntervalS = conn.ClientConfig.StateCheckIntervalSecs
	var rawIce []struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	}
	json.Unmarshal(conn.ClientConfig.ICEServers, &rawIce)
	for _, s := range rawIce {
		ice := webrtc.ICEServer{URLs: s.URLs}
		if s.Username != "" {
			ice.Username = s.Username
			ice.Credential = s.Credential
		}
		j.iceServers = append(j.iceServers, ice)
	}
	j.logger.Debug(fmt.Sprintf("telemost-joiner: peer_id=%s room_id=%s media_url=%s", j.peerID, j.roomID, j.mediaURL))
	return nil
}

func (j *TelemostJoiner) wsSend(msg interface{}) {
	j.wsMu.Lock()
	defer j.wsMu.Unlock()
	if j.ws != nil {
		data, _ := json.Marshal(msg)
		j.logger.Debug(fmt.Sprintf("telemost-joiner: [DIAG] -> %s", string(data)))
		j.ws.WriteJSON(msg)
	}
}

func (j *TelemostJoiner) ack(uid string) {
	if uid == "" {
		return
	}
	j.wsSend(map[string]interface{}{
		"uid": uid,
		"ack": map[string]interface{}{
			"status": map[string]interface{}{"code": "OK", "description": ""},
		},
	})
}

func (j *TelemostJoiner) sendHello() {
	j.wsSend(map[string]interface{}{
		"uid": uuid.New().String(),
		"hello": map[string]interface{}{
			"participantMeta":       map[string]interface{}{"name": j.displayName, "role": "SPEAKER", "description": "", "sendAudio": false, "sendVideo": true},
			"participantAttributes": map[string]interface{}{"name": j.displayName, "role": "SPEAKER", "description": ""},
			"sendAudio":             false, "sendVideo": true, "sendSharing": false,
			"participantId":       j.peerID,
			"roomId":              j.roomID,
			"serviceName":         j.serviceName,
			"credentials":         j.credentials,
			"capabilitiesOffer":   CapabilitiesOffer,
			"sdkInfo":             map[string]interface{}{"implementation": "browser", "version": "6.0.0", "userAgent": common.UserAgent, "hwConcurrency": 8},
			"sdkInitializationId": uuid.New().String(),
			"disablePublisher":    false, "disableSubscriber": false, "disableSubscriberAudio": false,
		},
	})
	j.logger.Debug("telemost-joiner: -> hello")
}

func (j *TelemostJoiner) sendICE(cand *webrtc.ICECandidate, target string, pcSeq int) {
	candidate := cand.ToJSON()
	j.wsSend(map[string]interface{}{
		"uid": uuid.New().String(),
		"webrtcIceCandidate": map[string]interface{}{
			"candidate": candidate.Candidate, "sdpMid": *candidate.SDPMid,
			"sdpMlineIndex": *candidate.SDPMLineIndex, "target": target, "pcSeq": pcSeq,
		},
	})
}

func (j *TelemostJoiner) initPC() {
	config := webrtc.Configuration{ICEServers: j.iceServers}
	settingEngine := webrtc.SettingEngine{}
	settingEngine.DetachDataChannels()
	if j.PCConfig != nil {
		j.PCConfig.ConfigureSettingEngine(&settingEngine)
	}
	api, err := NewAPI(&settingEngine)
	if err != nil {
		j.logger.Error(fmt.Sprintf("telemost-joiner: ERROR: create webrtc API: %v", err))
		return
	}
	subPC, err := api.NewPeerConnection(config)
	if err != nil {
		j.logger.Error(fmt.Sprintf("telemost-joiner: ERROR: create sub PC: %v", err))
		return
	}
	j.subPC = subPC
	subPC.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand != nil {
			j.sendICE(cand, "SUBSCRIBER", j.subSeq)
		}
	})
	subPC.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		j.logger.Debug(fmt.Sprintf("telemost-joiner: sub PC state: %s", state.String()))
		if state == webrtc.PeerConnectionStateFailed {
			j.logger.Error("telemost-joiner: ERROR: subscriber connection failed")
		}
	})
	subPC.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		j.logger.Debug(fmt.Sprintf("telemost-joiner: sub remote track: %s", track.Codec().MimeType))
		go j.ReadTrackFn(track, func(frame []byte) {
			if j.vp8tunnel != nil {
				j.vp8tunnel.HandleFrame(frame)
			}
		}, j.logger, "telemost-joiner")
	})
	pubPC, err := api.NewPeerConnection(config)
	if err != nil {
		j.logger.Error(fmt.Sprintf("telemost-joiner: ERROR: create pub PC: %v", err))
		return
	}
	j.pubPC = pubPC
	j.pubSeq = 1
	j.sampleTrack = j.AddTracks(pubPC, j.logger, "telemost-joiner [pub]")
	pubPC.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand != nil {
			j.sendICE(cand, "PUBLISHER", j.pubSeq)
		}
	})
	pubPC.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		j.logger.Debug(fmt.Sprintf("telemost-joiner: pub PC state: %s", state.String()))
		if state == webrtc.PeerConnectionStateConnected && j.vp8tunnel == nil {
			j.reconnectAttempt.Store(0)
			j.logger.Info("telemost-joiner: === VP8 TUNNEL CONNECTED ===")
			j.vp8tunnel = tunnel.NewVP8DataTunnel(j.sampleTrack, j.obf, j.logger)
			vp8tun := j.vp8tunnel
			vp8tun.Start(j.vp8FPS, j.vp8Batch)
			if !j.configAck.Acknowledged() {
				acked, cancel := j.configAck.Arm()
				go tunnel.SendVP8ConfigUntilAcked(acked, cancel, j.stopCh, vp8tun,
					vp8tun.FPS(), vp8tun.Batch(), 1, j.logger, "telemost-joiner")
				j.logger.Debug(fmt.Sprintf("telemost-joiner: pushed vp8 config to creator fps=%d batch=%d", vp8tun.FPS(), vp8tun.Batch()))
			}
			if j.OnConnected != nil {
				j.OnConnected(j.vp8tunnel)
			}
		}
	})
	j.logger.Debug(fmt.Sprintf("telemost-joiner: sub+pub PCs created with %d ICE servers", len(j.iceServers)))
}

func (j *TelemostJoiner) sendPubOffer() {
	if j.pubPC == nil {
		return
	}
	offer, err := j.pubPC.CreateOffer(nil)
	if err != nil {
		j.logger.Warn(fmt.Sprintf("telemost-joiner: pub offer failed: %v", err))
		return
	}
	if err := j.pubPC.SetLocalDescription(offer); err != nil {
		j.logger.Warn(fmt.Sprintf("telemost-joiner: set pub local desc: %v", err))
		return
	}
	offer.SDP = MungeSDPAddVideoContent(offer.SDP)
	audioMid, videoMid := TmParseMids(offer.SDP)
	j.logger.Debug(fmt.Sprintf("telemost-joiner: -> publisherSdpOffer pcSeq=%d audioMid=%s videoMid=%s", j.pubSeq, audioMid, videoMid))
	var tracks []map[string]interface{}
	if audioMid != "" {
		tracks = append(tracks, map[string]interface{}{"mid": audioMid, "transceiverMid": audioMid, "kind": "AUDIO", "priority": 0, "label": "", "codecs": map[string]interface{}{}, "groupId": 1, "description": ""})
	}
	if videoMid != "" {
		tracks = append(tracks, map[string]interface{}{"mid": videoMid, "transceiverMid": videoMid, "kind": "VIDEO", "priority": 0, "label": "", "codecs": map[string]interface{}{}, "groupId": 2, "description": ""})
	}
	j.wsSend(map[string]interface{}{
		"uid":               uuid.New().String(),
		"publisherSdpOffer": map[string]interface{}{"pcSeq": j.pubSeq, "sdp": offer.SDP, "tracks": tracks},
	})
}

func (j *TelemostJoiner) handlePubAnswer(sdp string) {
	if j.pubPC == nil {
		return
	}
	if j.OnRemoteCandidate != nil {
		j.OnRemoteCandidate(-1, sdp)
	}
	err := j.pubPC.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  sdp,
	})
	if err != nil {
		j.logger.Warn(fmt.Sprintf("telemost-joiner: set pub remote desc: %v", err))
		return
	}
	j.pubRemoteSet = true
	for _, candidate := range j.pubPending {
		j.pubPC.AddICECandidate(candidate)
	}
	j.pubPending = nil
	j.sendInitBundle()
}

func (j *TelemostJoiner) sendInitBundle() {
	if j.initBundleSent {
		return
	}
	j.initBundleSent = true
	j.logger.Debug("telemost-joiner: -> sdkCodecsInfo + updatePublisherTrackDescription")
	j.wsSend(SdkCodecsInfoMessage())
	j.wsSend(UpdatePublisherTrackDescriptionMessage(j.pubPC, "Microphone", "MacBook Pro Camera (0000:0001)"))
	j.sendStartupSlotsRamp()
}

func (j *TelemostJoiner) requestVideoSlots() {
	j.setSlotsKey++
	j.logger.Debug(fmt.Sprintf("telemost-joiner: -> setSlots key=%d", j.setSlotsKey))
	j.wsSend(SetSlotsMessage(j.setSlotsKey))
}

func (j *TelemostJoiner) forceReconnect(reason string) {
	j.reconnectAttempt.Store(0)
	oldPeerID := j.peerID
	j.logger.Info(fmt.Sprintf("telemost-joiner: forcing reconnect: %s", reason))
	if oldPeerID != "" {
		j.logger.Debug(fmt.Sprintf("telemost-joiner: kicking self pid=%s to leave call cleanly", oldPeerID))
		confURL := url.QueryEscape(j.joinLink)
		_, status, err := j.apiClient().TMRequest("POST", "/conferences/"+confURL+"/commands/kick?peer_id="+url.QueryEscape(oldPeerID)+"&with_ban=false")
		if err != nil || status >= 400 {
			j.logger.Warn(fmt.Sprintf("telemost-joiner: self-kick failed: status=%d err=%v", status, err))
		}
	}
	j.instanceID = uuid.New().String()
	j.logger.Debug(fmt.Sprintf("telemost-joiner: new instance-id=%s", j.instanceID))
	j.wsMu.Lock()
	ws := j.ws
	j.wsMu.Unlock()
	common.CloseWS(ws)
}

func (j *TelemostJoiner) sendStartupSlotsRamp() {
	for i := 0; i < 4; i++ {
		j.setSlotsKey++
		j.logger.Debug(fmt.Sprintf("telemost-joiner: -> setSlots key=%d (startup %d/4)", j.setSlotsKey, i+1))
		j.wsSend(StartupSetSlotsMessage(i, j.setSlotsKey))
	}
}

func (j *TelemostJoiner) handleSubOffer(sdp string, pcSeq int) {
	j.subSeq = pcSeq
	if j.subPC == nil {
		j.logger.Warn("telemost-joiner: sub PC not ready for offer")
		return
	}
	if j.OnRemoteCandidate != nil {
		j.OnRemoteCandidate(-1, sdp)
	}
	err := j.subPC.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  sdp,
	})
	if err != nil {
		j.logger.Warn(fmt.Sprintf("telemost-joiner: set sub remote desc: %v", err))
		return
	}
	j.subRemoteSet = true
	for _, candidate := range j.subPending {
		j.subPC.AddICECandidate(candidate)
	}
	j.subPending = nil
	answer, err := j.subPC.CreateAnswer(nil)
	if err != nil {
		j.logger.Warn(fmt.Sprintf("telemost-joiner: create sub answer: %v", err))
		return
	}
	j.subPC.SetLocalDescription(answer)
	j.logger.Debug(fmt.Sprintf("telemost-joiner: -> subscriberSdpAnswer pcSeq=%d", pcSeq))
	j.wsSend(map[string]interface{}{
		"uid":                 uuid.New().String(),
		"subscriberSdpAnswer": map[string]interface{}{"sdp": answer.SDP, "pcSeq": pcSeq},
	})
	j.sendPubOffer()
}

func (j *TelemostJoiner) handleMessage(raw []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	uid, _ := msg["uid"].(string)
	if _, ok := msg["serverHello"]; ok {
		j.logger.Debug("telemost-joiner: <- serverHello")
		if sh, ok := msg["serverHello"].(map[string]interface{}); ok {
			j.parseICEServersFromHello(sh)
		}
		j.ack(uid)
		j.initPC()
		return
	}
	if so, ok := msg["subscriberSdpOffer"]; ok {
		soMap, _ := so.(map[string]interface{})
		sdp, _ := soMap["sdp"].(string)
		pcSeq, _ := soMap["pcSeq"].(float64)
		j.logger.Debug(fmt.Sprintf("telemost-joiner: <- subscriberSdpOffer pcSeq=%d len=%d", int(pcSeq), len(sdp)))
		j.ack(uid)
		j.handleSubOffer(sdp, int(pcSeq))
		return
	}
	if pa, ok := msg["publisherSdpAnswer"]; ok {
		paMap, _ := pa.(map[string]interface{})
		sdp, _ := paMap["sdp"].(string)
		j.logger.Debug(fmt.Sprintf("telemost-joiner: <- publisherSdpAnswer %d bytes", len(sdp)))
		j.handlePubAnswer(sdp)
		return
	}
	if ic, ok := msg["webrtcIceCandidate"]; ok {
		icMap, _ := ic.(map[string]interface{})
		candidate, _ := icMap["candidate"].(string)
		sdpMid, _ := icMap["sdpMid"].(string)
		target, _ := icMap["target"].(string)
		sdpIdx, _ := icMap["sdpMlineIndex"].(float64)
		idx := uint16(sdpIdx)
		cand := webrtc.ICECandidateInit{Candidate: candidate, SDPMid: &sdpMid, SDPMLineIndex: &idx}
		if j.OnRemoteCandidate != nil {
			tgt := 1
			if target == "SUBSCRIBER" {
				tgt = 0
			}
			j.OnRemoteCandidate(tgt, candidate)
		}
		if target == "SUBSCRIBER" {
			if j.subRemoteSet {
				j.subPC.AddICECandidate(cand)
			} else {
				j.subPending = append(j.subPending, cand)
			}
		} else if target == "PUBLISHER" {
			if j.pubRemoteSet {
				j.pubPC.AddICECandidate(cand)
			} else {
				j.pubPending = append(j.pubPending, cand)
			}
		}
		j.ack(uid)
		return
	}
	if ackData, ok := msg["ack"]; ok {
		if ackMap, ok := ackData.(map[string]interface{}); ok {
			if status, ok := ackMap["status"].(map[string]interface{}); ok {
				if code, _ := status["code"].(string); code != "OK" {
					desc, _ := status["description"].(string)
					j.logger.Warn(fmt.Sprintf("telemost-joiner: ack error: %s %s", code, desc))
				}
			}
		}
		return
	}
	if ud, ok := msg["upsertDescription"]; ok {
		udMap, _ := ud.(map[string]interface{})
		if descs, ok := udMap["description"].([]interface{}); ok {
			for _, d := range descs {
				dm, _ := d.(map[string]interface{})
				pid, _ := dm["id"].(string)
				if pid != "" && pid != j.peerID {
					participantName := ""
					if meta, ok := dm["meta"].(map[string]interface{}); ok {
						participantName, _ = meta["name"].(string)
					}
					j.logger.Debug(fmt.Sprintf("telemost-joiner: participant: %s (%s)", participantName, pid))
				}
			}
		}
		j.ack(uid)
		return
	}
	if ud, ok := msg["updateDescription"]; ok {
		j.logger.Debug(fmt.Sprintf("telemost-joiner: <- updateDescription %s", BriefJSON(ud)))
		j.ack(uid)
		return
	}
	if _, ok := msg["removeDescription"]; ok {
		j.logger.Info("telemost-joiner: participant left")
		j.ack(uid)
		return
	}
	if sc, ok := msg["slotsConfig"]; ok {
		j.logger.Debug(fmt.Sprintf("telemost-joiner: <- slotsConfig %s", BriefJSON(sc)))
		needRebind := false
		presentPids := make(map[string]bool)
		for _, ev := range SlotsConfigBindings(sc) {
			fullPid := ev.ParticipantID
			if fullPid != "" {
				presentPids[fullPid] = true
			}
			pid := fullPid
			if len(pid) > 8 {
				pid = pid[:8]
			}
			if ev.Reason == "NO_LIMITATION" && ev.Mid != "" {
				j.logger.Debug(fmt.Sprintf("telemost-joiner: [bind] BOUND slot=%d pid=%s mid=%s", ev.Slot, pid, ev.Mid))
				j.boundMu.Lock()
				if j.boundPeers == nil {
					j.boundPeers = make(map[string]bool)
				}
				j.boundPeers[fullPid] = true
				delete(j.unboundPeers, fullPid)
				j.boundMu.Unlock()
			} else if fullPid != "" {
				j.boundMu.Lock()
				wasBound := j.boundPeers[fullPid]
				if wasBound {
					if j.unboundPeers == nil {
						j.unboundPeers = make(map[string]bool)
					}
					j.unboundPeers[fullPid] = true
					delete(j.boundPeers, fullPid)
				}
				j.boundMu.Unlock()
				if wasBound {
					j.logger.Debug(fmt.Sprintf("telemost-joiner: [bind] KILL slot=%d pid=%s reason=%s - rebinding", ev.Slot, pid, ev.Reason))
					needRebind = true
				} else {
					j.logger.Debug(fmt.Sprintf("telemost-joiner: [bind] UNBOUND slot=%d pid=%s reason=%s mid=%q", ev.Slot, pid, ev.Reason, ev.Mid))
				}
			}
		}
		j.boundMu.Lock()
		for boundPid := range j.boundPeers {
			if !presentPids[boundPid] {
				short := boundPid
				if len(short) > 8 {
					short = short[:8]
				}
				j.logger.Debug(fmt.Sprintf("telemost-joiner: [bind] VANISHED pid=%s - rebinding", short))
				delete(j.boundPeers, boundPid)
				needRebind = true
			}
		}
		j.boundMu.Unlock()
		if needRebind {
			go j.forceReconnect("slot binding killed")
		}
		j.ack(uid)
		return
	}
	for k, v := range msg {
		if k == "uid" || k == "ack" {
			continue
		}
		j.logger.Debug(fmt.Sprintf("telemost-joiner: <- %s (unhandled) %s", k, BriefJSON(v)))
		break
	}
	if uid != "" {
		j.ack(uid)
	}
}

func (j *TelemostJoiner) parseICEServersFromHello(sh map[string]interface{}) {
	rtcCfg, ok := sh["rtcConfiguration"].(map[string]interface{})
	if !ok {
		return
	}
	servers, ok := rtcCfg["iceServers"].([]interface{})
	if !ok {
		return
	}
	var iceServers []webrtc.ICEServer
	for _, s := range servers {
		sm, _ := s.(map[string]interface{})
		var urls []string
		if u, ok := sm["urls"].([]interface{}); ok {
			for _, v := range u {
				if vs, ok := v.(string); ok {
					urls = append(urls, common.FixICEURL(vs))
				}
			}
		}
		ice := webrtc.ICEServer{URLs: urls}
		if u, ok := sm["username"].(string); ok && u != "" {
			ice.Username = u
			ice.Credential, _ = sm["credential"].(string)
		}
		iceServers = append(iceServers, ice)
	}
	resolved := make(map[string]string)
	for i, s := range iceServers {
		for k, u := range s.URLs {
			host := common.ExtractICEHost(u)
			if host == "" || net.ParseIP(host) != nil {
				continue
			}
			_, ok := resolved[host]
			if !ok {
				rd, hasRD := j.dialer.(dialer.ResolveDialer)
				if j.dnsRouter == nil || !hasRD {
					continue
				}
				var err error
				var addrs []netip.Addr
				addrs, err = j.dnsRouter.Lookup(context.Background(), host, rd.QueryOptions())
				if err != nil {
					j.logger.Warn(fmt.Sprintf("telemost-joiner: resolve ICE host %s failed: %s", common.MaskAddr(host), common.MaskError(err)))
					continue
				}
				resolved[host] = addrs[0].String()
				j.logger.Debug(fmt.Sprintf("telemost-joiner: resolved ICE host %s -> %s", host, addrs[0]))
			}
			iceServers[i].URLs[k] = strings.Replace(u, host, resolved[host], 1)
		}
	}
	j.iceServers = iceServers
	for i, s := range iceServers {
		j.logger.Debug(fmt.Sprintf("telemost-joiner: ICE server %d: urls=%v", i, s.URLs))
	}
	j.logger.Debug(fmt.Sprintf("telemost-joiner: %d ICE servers from serverHello", len(iceServers)))
}

func (j *TelemostJoiner) connectAndRun() {
	parsed, err := url.Parse(j.mediaURL)
	if err != nil {
		j.logger.Error(fmt.Sprintf("telemost-joiner: ERROR: bad media URL: %s", common.MaskError(err)))
		return
	}
	hostname := parsed.Hostname()
	wsHeader := http.Header{}
	wsHeader.Set("User-Agent", common.UserAgent)
	wsHeader.Set("Origin", TmOrigin)
	j.logger.Debug(fmt.Sprintf("telemost-joiner: connecting to %s", j.mediaURL))
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		WriteBufferSize:  65536,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: hostname},
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return j.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
	}
	ws, _, err := dialer.Dial(j.mediaURL, wsHeader)
	if err != nil {
		j.logger.Error(fmt.Sprintf("telemost-joiner: ERROR: ws connect: %s", common.MaskError(err)))
		return
	}
	j.wsMu.Lock()
	j.ws = ws
	j.wsMu.Unlock()
	j.logger.Debug("telemost-joiner: ws connected")
	j.sendHello()
	stopPing := make(chan struct{})
	go func() {
		ticker := time.NewTicker(TmPingPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-stopPing:
				return
			case <-ticker.C:
				j.wsSend(map[string]interface{}{"uid": uuid.New().String(), "ping": map[string]interface{}{}})
			}
		}
	}()
	stopStateKeepalive := make(chan struct{})
	go func() {
		interval := j.stateCheckIntervalS
		if interval <= 0 {
			interval = 30
		}
		if err := j.apiClient().RequestStates(j.joinLink, j.peerID); err != nil {
			j.logger.Debug(fmt.Sprintf("telemost-joiner: initial request-states: %v", err))
		}
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopStateKeepalive:
				return
			case <-ticker.C:
				if err := j.apiClient().RequestStates(j.joinLink, j.peerID); err != nil {
					j.logger.Debug(fmt.Sprintf("telemost-joiner: request-states: %v", err))
				}
			}
		}
	}()
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			j.logger.Debug(fmt.Sprintf("telemost-joiner: ws read error: %s", common.MaskError(err)))
			break
		}
		j.handleMessage(raw)
	}
	close(stopPing)
	close(stopStateKeepalive)
	if j.vp8tunnel != nil {
		j.vp8tunnel.Stop()
	}
	if j.subPC != nil {
		j.subPC.Close()
	}
	if j.pubPC != nil {
		j.pubPC.Close()
	}
	j.logger.Info("telemost-joiner: disconnected")
}
