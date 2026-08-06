package dion

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/pion/webrtc/v4"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type TransceiverPlan struct {
	Mid       int
	Direction webrtc.RTPTransceiverDirection
	Kind      webrtc.RTPCodecType
	Ctype     string
}

type DataChannelPlan struct {
	ID    uint16
	Label string
}

var DionTransceiverLayout = []TransceiverPlan{
	{Mid: 0, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 1, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 2, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 3, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 4, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 5, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 6, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 7, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 8, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 9, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeAudio, Ctype: "Audio"},
	{Mid: 10, Direction: webrtc.RTPTransceiverDirectionSendonly, Kind: webrtc.RTPCodecTypeAudio, Ctype: "Audio"},
	{Mid: 11, Direction: webrtc.RTPTransceiverDirectionSendonly, Kind: webrtc.RTPCodecTypeAudio, Ctype: "AudioScreenSharing"},
	{Mid: 12, Direction: webrtc.RTPTransceiverDirectionSendonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 13, Direction: webrtc.RTPTransceiverDirectionSendonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "ScreenSharing"},
	{Mid: 14, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "ScreenSharing"},
	{Mid: 15, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Video"},
	{Mid: 16, Direction: webrtc.RTPTransceiverDirectionRecvonly, Kind: webrtc.RTPCodecTypeVideo, Ctype: "Padding"},
}

var DionDataChannels = []DataChannelPlan{
	{ID: 0, Label: "vad"},
	{ID: 1, Label: "stats"},
	{ID: 2, Label: "speed"},
	{ID: 3, Label: "video_quality"},
	{ID: 4, Label: "media_messages"},
}

type PionPeer struct {
	PC               *webrtc.PeerConnection
	Transceivers     []*webrtc.RTPTransceiver
	DataChannels     map[string]*webrtc.DataChannel
	TransceiverDescs []TransceiverDesc
	DatachannelDescs []DataChannelDesc
}

func NewPionAPI(customEngine ...*webrtc.SettingEngine) *webrtc.API {
	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		panic(fmt.Errorf("dion: register default codecs: %w", err))
	}
	engine := webrtc.SettingEngine{}
	if len(customEngine) > 0 && customEngine[0] != nil {
		engine = *customEngine[0]
	}
	return webrtc.NewAPI(
		webrtc.WithMediaEngine(mediaEngine),
		webrtc.WithSettingEngine(engine),
	)
}

func ResolveICEServerHosts(entries []ICEServerEntry, dnsRouter adapter.DNSRouter, d N.Dialer, logger logger.ContextLogger) []ICEServerEntry {
	if dnsRouter == nil {
		return entries
	}
	resolved := make(map[string]string)
	out := make([]ICEServerEntry, 0, len(entries))
	for _, entry := range entries {
		urls := make([]string, len(entry.URLs))
		copy(urls, entry.URLs)
		for k, raw := range urls {
			host := extractICEHost(raw)
			if host == "" {
				continue
			}
			ip, ok := resolved[host]
			if !ok {
				var addrs []netip.Addr
				var err error
				addrs, err = dnsRouter.Lookup(context.Background(), host, d.(dialer.ResolveDialer).QueryOptions())
				if err != nil {
					logger.Warn(fmt.Sprintf("[dion] resolve ICE host %s failed: %v", host, err))
					continue
				}
				ip = addrs[0].String()
				resolved[host] = ip
				logger.Debug(fmt.Sprintf("[dion] resolved ICE host %s -> %s", host, addrs[0]))
			}
			urls[k] = strings.Replace(raw, host, ip, 1)
		}
		out = append(out, ICEServerEntry{URLs: urls, Username: entry.Username, Credential: entry.Credential})
	}
	return out
}

func IceServerEntriesToWebRTC(entries []ICEServerEntry) []webrtc.ICEServer {
	out := make([]webrtc.ICEServer, 0, len(entries))
	for _, entry := range entries {
		out = append(out, webrtc.ICEServer{
			URLs:       entry.URLs,
			Username:   entry.Username,
			Credential: entry.Credential,
		})
	}
	return out
}

func BuildPionPeer(api *webrtc.API, iceServers []ICEServerEntry) (*PionPeer, error) {
	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers:    IceServerEntriesToWebRTC(iceServers),
		BundlePolicy:  webrtc.BundlePolicyMaxBundle,
		RTCPMuxPolicy: webrtc.RTCPMuxPolicyRequire,
	})
	if err != nil {
		return nil, fmt.Errorf("new peer connection: %w", err)
	}
	transceivers := make([]*webrtc.RTPTransceiver, 0, len(DionTransceiverLayout))
	for _, plan := range DionTransceiverLayout {
		transceiver, err := pc.AddTransceiverFromKind(plan.Kind, webrtc.RTPTransceiverInit{
			Direction: plan.Direction,
		})
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("add transceiver mid=%d kind=%s dir=%s: %w", plan.Mid, plan.Kind, plan.Direction, err)
		}
		transceivers = append(transceivers, transceiver)
	}
	dataChannels := make(map[string]*webrtc.DataChannel, len(DionDataChannels))
	for _, plan := range DionDataChannels {
		negotiated := true
		id := plan.ID
		dc, err := pc.CreateDataChannel(plan.Label, &webrtc.DataChannelInit{
			Negotiated: &negotiated,
			ID:         &id,
		})
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("create datachannel %s id=%d: %w", plan.Label, plan.ID, err)
		}
		dataChannels[plan.Label] = dc
	}
	dcDescs := make([]DataChannelDesc, 0, len(DionDataChannels))
	for _, plan := range DionDataChannels {
		dcDescs = append(dcDescs, DataChannelDesc{ID: int(plan.ID), Label: plan.Label})
	}
	return &PionPeer{
		PC:               pc,
		Transceivers:     transceivers,
		DataChannels:     dataChannels,
		DatachannelDescs: dcDescs,
	}, nil
}

func (p *PionPeer) BuildOfferDescriptors() error {
	if len(p.Transceivers) != len(DionTransceiverLayout) {
		return fmt.Errorf("transceiver count drift: have %d want %d", len(p.Transceivers), len(DionTransceiverLayout))
	}
	descs := make([]TransceiverDesc, 0, len(p.Transceivers))
	for index, transceiver := range p.Transceivers {
		mid := transceiver.Mid()
		if mid == "" {
			return fmt.Errorf("transceiver index=%d has empty mid; call SetLocalDescription first", index)
		}
		plan := DionTransceiverLayout[index]
		descs = append(descs, TransceiverDesc{
			TransceiverID: mid,
			SessionID:     "",
			Direction:     directionToDion(plan.Direction),
			Ctype:         plan.Ctype,
		})
	}
	p.TransceiverDescs = descs
	return nil
}

func (p *PionPeer) CreateAndSetOffer() (offerEnvelope string, sdpOffer string, err error) {
	offer, err := p.PC.CreateOffer(nil)
	if err != nil {
		return "", "", fmt.Errorf("create offer: %w", err)
	}
	if err := p.PC.SetLocalDescription(offer); err != nil {
		return "", "", fmt.Errorf("set local description: %w", err)
	}
	if err := p.BuildOfferDescriptors(); err != nil {
		return "", "", err
	}
	envelope, err := BuildSDPOfferEnvelope(offer.SDP)
	if err != nil {
		return "", "", fmt.Errorf("build envelope: %w", err)
	}
	return envelope, offer.SDP, nil
}

func (p *PionPeer) ApplyAnswerEnvelope(answerEnvelope string) error {
	sdp, err := DecodeSDPAnswerInner(answerEnvelope)
	if err != nil {
		return fmt.Errorf("decode answer envelope: %w", err)
	}
	return p.PC.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  sdp,
	})
}

func (p *PionPeer) Close() error {
	if p.PC == nil {
		return nil
	}
	return p.PC.Close()
}

func directionToDion(direction webrtc.RTPTransceiverDirection) string {
	switch direction {
	case webrtc.RTPTransceiverDirectionSendonly:
		return "SendOnly"
	case webrtc.RTPTransceiverDirectionRecvonly:
		return "RecvOnly"
	case webrtc.RTPTransceiverDirectionSendrecv:
		return "SendRecv"
	case webrtc.RTPTransceiverDirectionInactive:
		return "Inactive"
	}
	return "Unknown"
}

func extractICEHost(raw string) string {
	value := raw
	for _, prefix := range []string{"stun:", "turn:", "turns:"} {
		value = strings.TrimPrefix(value, prefix)
	}
	if idx := strings.Index(value, "?"); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.LastIndex(value, ":"); idx >= 0 {
		value = value[:idx]
	}
	if value == "" {
		return ""
	}
	if net.ParseIP(value) != nil {
		return ""
	}
	return value
}
